/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;

/**
 * A read-only {@link FileChannel} that reads with {@code pread(2)} on a raw file descriptor.
 *
 * <p>The JDK's FileChannel is interruptible: if a thread is interrupted while it reads, the channel
 * is closed for every thread that shares it. The block loader shares one channel per file across
 * the node, so one cancelled search or recovery could fail reads of that file everywhere. This
 * channel never registers with the interrupt machinery, so an interrupt does not close it. A read
 * that is already in the kernel finishes; the interrupted thread sees its interrupt flag afterwards.
 *
 * <p>Only positional and relative reads, {@link #size()} and {@link #position()} are supported.
 * {@link #open} falls back to {@link FileChannel#open} on other platforms (anything but Linux x86_64
 * or aarch64) or if linking the libc functions fails, for example when native access is denied with
 * {@code --illegal-native-access=deny}.
 *
 * <p>{@code open(2)} is called directly, bypassing any file-permission checks the JVM applies to
 * {@link FileChannel#open}. Use this class only for files the plugin already owns, such as shard files.
 */
@SuppressForbidden(reason = "Uses Panama FFI for uninterruptible positional reads")
public final class NativeFileChannel extends FileChannel {

    private static final Logger LOGGER = LogManager.getLogger(NativeFileChannel.class);

    private static final int O_RDONLY = 0;
    private static final int O_CLOEXEC = 02000000;
    private static final int EINTR = 4;
    private static final int ENOENT = 2;
    private static final int EACCES = 13;
    private static final int SEEK_END = 2;
    // Temp buffers for heap reads are aligned so they also satisfy O_DIRECT
    private static final long BOUNCE_ALIGNMENT = 4096;

    private static final MethodHandle OPEN;
    private static final MethodHandle PREAD;
    private static final MethodHandle LSEEK;
    private static final MethodHandle CLOSE;
    private static final VarHandle ERRNO;
    private static final long CAPTURE_SIZE;
    private static final int O_DIRECT;
    private static final boolean AVAILABLE;

    static {
        MethodHandle open = null, pread = null, lseek = null, close = null;
        VarHandle errno = null;
        long captureSize = 0;
        int oDirect = 0;
        boolean available = false;
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if (os.contains("linux") && (arch.equals("amd64") || arch.equals("x86_64") || arch.equals("aarch64"))) {
            // O_DIRECT differs between architectures
            oDirect = arch.equals("aarch64") ? 0200000 : 040000;
            try {
                Linker linker = Linker.nativeLinker();
                SymbolLookup libc = linker.defaultLookup();
                Linker.Option ccs = Linker.Option.captureCallState("errno");
                StructLayout captureLayout = Linker.Option.captureStateLayout();
                errno = captureLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"));
                captureSize = captureLayout.byteSize();
                open = linker
                    .downcallHandle(
                        libc.find("open").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
                        // open(2) is variadic (the optional mode follows flags), and we pass no variadic args
                        Linker.Option.firstVariadicArg(2),
                        ccs
                    );
                pread = linker
                    .downcallHandle(
                        libc.find("pread").orElseThrow(),
                        FunctionDescriptor
                            .of(
                                ValueLayout.JAVA_LONG,
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_LONG,
                                ValueLayout.JAVA_LONG
                            ),
                        ccs
                    );
                lseek = linker
                    .downcallHandle(
                        libc.find("lseek").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                        ccs
                    );
                close = linker
                    .downcallHandle(libc.find("close").orElseThrow(), FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
                available = true;
            } catch (Throwable t) {
                LOGGER.warn("Native file reads unavailable, falling back to interruptible FileChannel", t);
            }
        }
        OPEN = open;
        PREAD = pread;
        LSEEK = lseek;
        CLOSE = close;
        ERRNO = errno;
        CAPTURE_SIZE = captureSize;
        O_DIRECT = oDirect;
        AVAILABLE = available;
    }

    // Per-thread errno capture buffer, freed with the thread
    private static final ThreadLocal<MemorySegment> CAPTURE = ThreadLocal.withInitial(() -> Arena.ofAuto().allocate(CAPTURE_SIZE));

    private final int fd;
    private final String path;
    // Reads hold the read lock and close takes the write lock, so the fd is never closed (and its
    // number reused for another file) while a read is using it.
    private final ReentrantReadWriteLock closeLock = new ReentrantReadWriteLock();
    private long position;

    private NativeFileChannel(int fd, String path) {
        this.fd = fd;
        this.path = path;
    }

    /**
     * Returns true if reads go through {@code pread(2)} rather than the JDK's interruptible FileChannel.
     */
    public static boolean isAvailable() {
        return AVAILABLE;
    }

    /**
     * Opens {@code path} for reading.
     *
     * @param path the file to open
     * @param direct whether to bypass the page cache with O_DIRECT
     * @param directOpenOption the JDK's O_DIRECT open option, used only for the fallback channel
     * @return an uninterruptible native channel, or a JDK FileChannel where native access is unavailable
     * @throws IOException if the file cannot be opened
     */
    public static FileChannel open(Path path, boolean direct, java.nio.file.OpenOption directOpenOption) throws IOException {
        if (!AVAILABLE) {
            return direct
                ? FileChannel.open(path, StandardOpenOption.READ, directOpenOption)
                : FileChannel.open(path, StandardOpenOption.READ);
        }
        String file = path.toString();
        int flags = O_RDONLY | O_CLOEXEC | (direct ? O_DIRECT : 0);
        MemorySegment capture = CAPTURE.get();
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment cPath = arena.allocateFrom(file);
            while (true) {
                int fd = (int) OPEN.invokeExact(capture, cPath, flags);
                if (fd >= 0) {
                    return new NativeFileChannel(fd, file);
                }
                int err = errno(capture);
                if (err == EINTR) {
                    continue;
                }
                switch (err) {
                    case ENOENT:
                        throw new NoSuchFileException(file);
                    case EACCES:
                        throw new AccessDeniedException(file);
                    default:
                        throw new IOException("open failed with errno " + err + ": " + file);
                }
            }
        } catch (IOException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("open failed: " + file, t);
        }
    }

    private static int errno(MemorySegment capture) {
        return (int) ERRNO.get(capture, 0L);
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        if (position < 0) {
            throw new IllegalArgumentException("Negative position");
        }
        if (dst.isReadOnly()) {
            throw new IllegalArgumentException("Read-only buffer");
        }
        int len = dst.remaining();
        if (len == 0) {
            ensureOpen();
            return 0;
        }
        closeLock.readLock().lock();
        try {
            if (!isOpen()) {
                throw new ClosedChannelException();
            }
            int n;
            if (dst.isDirect()) {
                n = pread(MemorySegment.ofBuffer(dst), len, position);
                if (n > 0) {
                    dst.position(dst.position() + n);
                }
            } else {
                try (Arena arena = Arena.ofConfined()) {
                    MemorySegment bounce = arena.allocate(len, BOUNCE_ALIGNMENT);
                    n = pread(bounce, len, position);
                    if (n > 0) {
                        dst.put(bounce.asSlice(0, n).asByteBuffer());
                    }
                }
            }
            return n == 0 ? -1 : n;
        } finally {
            closeLock.readLock().unlock();
        }
    }

    private int pread(MemorySegment buf, int len, long offset) throws IOException {
        MemorySegment capture = CAPTURE.get();
        try {
            while (true) {
                long n = (long) PREAD.invokeExact(capture, fd, buf, (long) len, offset);
                if (n >= 0) {
                    return (int) n;
                }
                int err = errno(capture);
                if (err != EINTR) {
                    throw new IOException("pread failed with errno " + err + ": " + path);
                }
            }
        } catch (IOException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("pread failed: " + path, t);
        }
    }

    @Override
    public synchronized int read(ByteBuffer dst) throws IOException {
        int n = read(dst, position);
        if (n > 0) {
            position += n;
        }
        return n;
    }

    @Override
    public synchronized long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        long total = 0;
        for (int i = offset; i < offset + length; i++) {
            if (!dsts[i].hasRemaining()) {
                continue;
            }
            int want = dsts[i].remaining();
            int n = read(dsts[i]);
            if (n < 0) {
                return total == 0 ? -1 : total;
            }
            total += n;
            if (n < want) {
                break;
            }
        }
        return total;
    }

    @Override
    public synchronized long position() throws IOException {
        ensureOpen();
        return position;
    }

    @Override
    public synchronized FileChannel position(long newPosition) throws IOException {
        if (newPosition < 0) {
            throw new IllegalArgumentException("Negative position");
        }
        ensureOpen();
        position = newPosition;
        return this;
    }

    @Override
    public long size() throws IOException {
        closeLock.readLock().lock();
        try {
            ensureOpen();
            // Reads are positional, so moving the fd's own offset is harmless
            MemorySegment capture = CAPTURE.get();
            long size = (long) LSEEK.invokeExact(capture, fd, 0L, SEEK_END);
            if (size < 0) {
                throw new IOException("lseek failed with errno " + errno(capture) + ": " + path);
            }
            return size;
        } catch (IOException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("lseek failed: " + path, t);
        } finally {
            closeLock.readLock().unlock();
        }
    }

    private void ensureOpen() throws ClosedChannelException {
        if (!isOpen()) {
            throw new ClosedChannelException();
        }
    }

    @Override
    protected void implCloseChannel() throws IOException {
        closeLock.writeLock().lock();
        try {
            int rc = (int) CLOSE.invokeExact(fd);
            if (rc != 0) {
                throw new IOException("close failed: " + path);
            }
        } catch (IOException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IOException("close failed: " + path, t);
        } finally {
            closeLock.writeLock().unlock();
        }
    }

    @Override
    public int write(ByteBuffer src) {
        throw new NonWritableChannelException();
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) {
        throw new NonWritableChannelException();
    }

    @Override
    public int write(ByteBuffer src, long position) {
        throw new NonWritableChannelException();
    }

    @Override
    public FileChannel truncate(long size) {
        throw new NonWritableChannelException();
    }

    @Override
    public void force(boolean metaData) {}

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) {
        throw new UnsupportedOperationException("transferTo is not supported");
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) {
        throw new NonWritableChannelException();
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) {
        throw new UnsupportedOperationException("map is not supported");
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) {
        throw new UnsupportedOperationException("lock is not supported");
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) {
        throw new UnsupportedOperationException("tryLock is not supported");
    }
}
