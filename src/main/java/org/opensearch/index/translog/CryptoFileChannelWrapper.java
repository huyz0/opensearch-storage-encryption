/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.zip.CRC32;

import org.apache.lucene.codecs.CodecUtil;
import org.apache.lucene.util.IOUtils;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A FileChannel wrapper that transparently encrypts translog files.
 *
 * <p>The data after the plaintext TranslogHeader is stored as sealed AES-256-GCM frames; see
 * {@link TranslogChunkManager} for the format. Callers see logical positions: the header at
 * {@code [0, headerSize)} and data right after it, as if the file were plaintext. The header stays
 * at offset 0 because core also reads it through a plain FileChannel.
 *
 * <p>The format header is written just before the first data byte. A file that only has its header
 * (as core creates for an empty translog) is valid and has no data.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "FileChannel operations required for encrypted translog implementation")
public class CryptoFileChannelWrapper extends FileChannel {

    private static final int TRANSFER_BUFFER_SIZE = 8192;

    private final FileChannel delegate;
    private final int headerSize;
    private final TranslogChunkManager chunkManager;
    private final AtomicLong position;
    private final ReentrantReadWriteLock positionLock;
    private volatile boolean closed = false;

    /**
     * Creates a new CryptoFileChannelWrapper that wraps the provided FileChannel.
     *
     * @param delegate the underlying FileChannel to wrap
     * @param keyResolver the key resolver for encryption (unified with index files)
     * @param path the file path (used for logging and debugging)
     * @param options the file open options (used for logging and debugging)
     * @param translogUUID the translog UUID, used to compute the exact header size
     * @throws IOException if there is an error setting up the channel
     */
    public CryptoFileChannelWrapper(FileChannel delegate, KeyResolver keyResolver, Path path, Set<OpenOption> options, String translogUUID)
        throws IOException {
        this(delegate, keyResolver, path, options, translogUUID, TranslogChunkManager.DEFAULT_MAX_FRAME_SIZE);
    }

    /**
     * Creates a new CryptoFileChannelWrapper with a given maximum frame size for a new file.
     *
     * @param delegate the underlying FileChannel to wrap
     * @param keyResolver the key resolver for encryption (unified with index files)
     * @param path the file path (used for error messages)
     * @param options the file open options
     * @param translogUUID the translog UUID, used to compute the exact header size
     * @param newFileMaxFrameSize the maximum frame size if the file is new; an existing file keeps its own
     * @throws IOException if the existing file content cannot be indexed
     */
    CryptoFileChannelWrapper(
        FileChannel delegate,
        KeyResolver keyResolver,
        Path path,
        Set<OpenOption> options,
        String translogUUID,
        int newFileMaxFrameSize
    )
        throws IOException {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.delegate = delegate;
        Objects.requireNonNull(keyResolver, "keyResolver");
        // Non-translog files (.ckp) are never wrapped by CryptoChannelFactory; treat them as all data.
        this.headerSize = path.getFileName().toString().endsWith(".tlog") ? calculateTranslogHeaderSize(translogUUID) : 0;
        this.chunkManager = new TranslogChunkManager(delegate, keyResolver, path, headerSize, newFileMaxFrameSize);
        this.position = new AtomicLong(delegate.position());
        this.positionLock = new ReentrantReadWriteLock();
    }

    /** Returns the frame manager, for tests. */
    TranslogChunkManager getChunkManager() {
        return chunkManager;
    }

    /**
     * Local copy of TranslogHeader.headerSizeInBytes() to avoid cross-classloader access.
     *
     * @param translogUUID the translog UUID
     * @return the header size in bytes
     */
    private static int calculateTranslogHeaderSize(String translogUUID) {
        int uuidLength = translogUUID.getBytes(StandardCharsets.UTF_8).length;
        int size = CodecUtil.headerLength(TranslogHeader.TRANSLOG_CODEC); // Lucene codec header
        size += Integer.BYTES + uuidLength; // uuid length field + uuid bytes
        if (TranslogHeader.CURRENT_VERSION >= TranslogHeader.VERSION_PRIMARY_TERM) {
            size += Long.BYTES;    // primary term
            size += Integer.BYTES; // checksum
        }
        return size;
    }

    /**
     * Returns the size of the plaintext header that precedes the encrypted data.
     *
     * @return the header size in bytes
     */
    public int headerSize() {
        return headerSize;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        ensureOpen();
        if (dst.remaining() == 0) {
            return 0;
        }

        // updates channel position, needs writeLock for position update
        positionLock.writeLock().lock();
        try {
            long currentPosition = position.get();
            int bytesRead = readAtPosition(dst, currentPosition);
            if (bytesRead > 0) {
                position.addAndGet(bytesRead);
            }
            return bytesRead;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public int read(ByteBuffer dst, long position) throws IOException {
        ensureOpen();
        if (dst.remaining() == 0) {
            return 0;
        }

        // Positional read: does NOT update channel position, can use readLock for better concurrency
        positionLock.readLock().lock();
        try {
            return readAtPosition(dst, position);
        } finally {
            positionLock.readLock().unlock();
        }
    }

    /** Reads at a logical position without touching the channel position. */
    private int readAtPosition(ByteBuffer dst, long position) throws IOException {
        return chunkManager.read(dst, position);
    }

    @Override
    public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        ensureOpen();

        positionLock.writeLock().lock();
        try {
            long totalBytesRead = 0;
            long currentPosition = position.get();
            for (int i = offset; i < offset + length && i < dsts.length; i++) {
                ByteBuffer dst = dsts[i];
                while (dst.hasRemaining()) {
                    int bytesRead = readAtPosition(dst, currentPosition + totalBytesRead);
                    if (bytesRead <= 0) {
                        if (totalBytesRead == 0 && bytesRead < 0) {
                            return -1;
                        }
                        position.addAndGet(totalBytesRead);
                        return totalBytesRead;
                    }
                    totalBytesRead += bytesRead;
                }
            }
            position.addAndGet(totalBytesRead);
            return totalBytesRead;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        ensureOpen();
        positionLock.writeLock().lock();
        try {
            long currentPosition = position.get();
            int bytesWritten = writeAtPosition(src, currentPosition);
            position.addAndGet(bytesWritten);
            return bytesWritten;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public int write(ByteBuffer src, long position) throws IOException {
        ensureOpen();
        positionLock.writeLock().lock();
        try {
            return writeAtPosition(src, position);
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    /**
     * Writes all of {@code src} at a logical position: header bytes as they are, data bytes sealed
     * as frames. Data may only be appended at the current end; core only ever appends to translog files.
     */
    private int writeAtPosition(ByteBuffer src, long position) throws IOException {
        return chunkManager.write(src, position);
    }

    @Override
    public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        ensureOpen();

        positionLock.writeLock().lock();
        try {
            long totalBytesWritten = 0;
            long currentPosition = position.get();
            for (int i = offset; i < offset + length && i < srcs.length; i++) {
                totalBytesWritten += writeAtPosition(srcs[i], currentPosition + totalBytesWritten);
            }
            position.addAndGet(totalBytesWritten);
            return totalBytesWritten;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    /** Per-file locks so two opens of one file cannot race on its temporary file. */
    private static final ConcurrentHashMap<Path, Object> CONVERSION_LOCKS = new ConcurrentHashMap<>();

    /**
     * Encrypts a translog file in place if its data is plaintext, and returns whether it did.
     *
     * <p>Remote-store translog files are uploaded decrypted, because each node has its own data
     * key, and core downloads them byte for byte into the translog directory. Such a file has the
     * core header followed directly by plaintext operations instead of the format header. It is
     * rewritten in this format under this node's key to a temporary file, synced, and atomically
     * moved over the original, so a crash leaves either the plaintext or the encrypted file.
     *
     * <p>A file counts as plaintext only if its data starts with a complete translog operation
     * whose CRC32 checks out. Anything else, such as a damaged prefix, is left alone so that
     * reading it fails with a clear error instead of being encrypted a second time.
     *
     * @param path the translog ({@code .tlog}) file
     * @param keyResolver the key resolver for this node's data key
     * @param translogUUID the translog UUID, which sets the header size
     * @return true if the file was plaintext and has been encrypted
     * @throws IOException if the file cannot be read or rewritten
     */
    static boolean encryptIfPlaintext(Path path, KeyResolver keyResolver, String translogUUID) throws IOException {
        int headerSize = calculateTranslogHeaderSize(translogUUID);
        // Fast path without a lock: an encrypted or header-only file needs nothing.
        try (FileChannel raw = FileChannel.open(path, StandardOpenOption.READ)) {
            if (startsWithPlaintextOperation(raw, headerSize) == false) {
                return false;
            }
        }
        Path key = path.toAbsolutePath().normalize();
        Object lock = CONVERSION_LOCKS.computeIfAbsent(key, k -> new Object());
        try {
            synchronized (lock) {
                return encryptLocked(path, keyResolver, translogUUID, headerSize);
            }
        } finally {
            CONVERSION_LOCKS.remove(key, lock);
        }
    }

    private static boolean encryptLocked(Path path, KeyResolver keyResolver, String translogUUID, int headerSize) throws IOException {
        Path tmp = path.resolveSibling(path.getFileName() + ".encrypting");
        try (FileChannel raw = FileChannel.open(path, StandardOpenOption.READ)) {
            // Check again: another open may have converted the file while this one waited.
            if (startsWithPlaintextOperation(raw, headerSize) == false) {
                return false;
            }
            Files.deleteIfExists(tmp);
            Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.READ);
            try {
                try (
                    CryptoFileChannelWrapper out = new CryptoFileChannelWrapper(
                        FileChannel.open(tmp, options.toArray(new OpenOption[0])),
                        keyResolver,
                        path,
                        options,
                        translogUUID
                    )
                ) {
                    ByteBuffer buf = ByteBuffer.allocate(64 * 1024);
                    long pos = 0;
                    int n;
                    while ((n = raw.read(buf, pos)) >= 0) {
                        pos += n;
                        buf.flip();
                        while (buf.hasRemaining()) {
                            out.write(buf);
                        }
                        buf.clear();
                    }
                    out.force(true);
                }
                Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException | RuntimeException e) {
                IOUtils.deleteFilesIgnoringExceptions(tmp);
                throw e;
            }
        }
        IOUtils.fsync(path.toAbsolutePath().getParent(), true);
        return true;
    }

    /**
     * Returns whether the data after the header starts with a whole plaintext translog operation:
     * a size of at least 4, followed by that many bytes whose last 4 are the CRC32 of the rest.
     */
    private static boolean startsWithPlaintextOperation(FileChannel raw, int headerSize) throws IOException {
        long dataLength = raw.size() - headerSize;
        if (dataLength < 2 * Integer.BYTES) {
            return false;
        }
        int opSize = readInt(raw, headerSize);
        if (opSize == TranslogChunkManager.FORMAT_MAGIC) {
            return false; // already encrypted
        }
        if (opSize < Integer.BYTES || opSize > dataLength - Integer.BYTES) {
            return false;
        }
        CRC32 crc = new CRC32();
        ByteBuffer buf = ByteBuffer.allocate((int) Math.min(64 * 1024, opSize - Integer.BYTES));
        long pos = headerSize + Integer.BYTES;
        long end = pos + opSize - Integer.BYTES;
        while (pos < end) {
            buf.clear().limit((int) Math.min(buf.capacity(), end - pos));
            int n = raw.read(buf, pos);
            if (n < 0) {
                return false;
            }
            crc.update(buf.flip());
            pos += n;
        }
        return Integer.toUnsignedLong(readInt(raw, end)) == crc.getValue();
    }

    private static int readInt(FileChannel channel, long position) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES);
        while (buf.hasRemaining()) {
            if (channel.read(buf, position + buf.position()) < 0) {
                throw new IOException("Unexpected end of translog file at " + position);
            }
        }
        return buf.getInt(0);
    }

    @Override
    public long position() throws IOException {
        ensureOpen();
        return position.get();
    }

    @Override
    public FileChannel position(long newPosition) throws IOException {
        ensureOpen();
        if (newPosition < 0) {
            throw new IllegalArgumentException("negative position: " + newPosition);
        }
        positionLock.writeLock().lock();
        try {
            position.set(newPosition);
        } finally {
            positionLock.writeLock().unlock();
        }
        return this;
    }

    /**
     * Returns the logical size: header plus the data in every complete frame.
     */
    @Override
    public long size() throws IOException {
        ensureOpen();
        return chunkManager.logicalSize();
    }

    /**
     * Truncation is only supported as a no-op (to the current size or beyond). Core never truncates
     * translog files.
     */
    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen();
        if (size < 0) {
            throw new IllegalArgumentException("negative size: " + size);
        }
        positionLock.writeLock().lock();
        try {
            chunkManager.truncate(size);
            if (position.get() > size) {
                position.set(size);
            }
            return this;
        } finally {
            positionLock.writeLock().unlock();
        }
    }

    @Override
    public void force(boolean metaData) throws IOException {
        ensureOpen();
        delegate.force(metaData);
    }

    @Override
    public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
        ensureOpen();
        ByteBuffer buffer = ByteBuffer.allocate(TRANSFER_BUFFER_SIZE);
        long transferred = 0;
        while (transferred < count) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), count - transferred));
            int n = read(buffer, position + transferred);
            if (n <= 0) {
                break;
            }
            buffer.flip();
            while (buffer.hasRemaining()) {
                target.write(buffer);
            }
            transferred += n;
        }
        return transferred;
    }

    @Override
    public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        ensureOpen();
        ByteBuffer buffer = ByteBuffer.allocate(TRANSFER_BUFFER_SIZE);
        long transferred = 0;
        while (transferred < count) {
            buffer.clear();
            buffer.limit((int) Math.min(buffer.capacity(), count - transferred));
            int n = src.read(buffer);
            if (n <= 0) {
                break;
            }
            buffer.flip();
            write(buffer, position + transferred);
            transferred += n;
        }
        return transferred;
    }

    @Override
    public FileLock lock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.lock(position, size, shared);
    }

    @Override
    public FileLock tryLock(long position, long size, boolean shared) throws IOException {
        ensureOpen();
        return delegate.tryLock(position, size, shared);
    }

    @Override
    public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
        ensureOpen();

        // The mapped memory would contain ciphertext.
        throw new UnsupportedOperationException(
            "Memory mapping is not supported for encrypted translog files. "
                + "Encrypted files require data to be decrypted during read operations."
        );
    }

    @Override
    protected void implCloseChannel() throws IOException {
        if (!closed) {
            closed = true;
            delegate.close();
        }
    }

    private void ensureOpen() throws ClosedChannelException {
        if (closed || !delegate.isOpen()) {
            throw new ClosedChannelException();
        }
    }
}
