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
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A FileChannel wrapper that transparently encrypts translog files.
 *
 * <p>File format:
 * <pre>
 * [TranslogHeader            - plaintext, written and read by core]
 * [magic "OST1"  (4 bytes)   - plaintext]
 * [nonce         (16 bytes)  - plaintext, random per file]
 * [data                      - AES-CTR, see {@link TranslogCipher}]
 * </pre>
 *
 * <p>Callers see logical positions: the header at {@code [0, headerSize)} and data right after
 * it, as if the file were plaintext. The magic and nonce are hidden, so a data byte at logical
 * position {@code p} lives at physical position {@code p + PREFIX_LENGTH}. The header stays at
 * offset 0 because core also reads it through a plain FileChannel.
 *
 * <p>The nonce is written just before the first data byte. A file that only has its header
 * (as core creates for an empty translog) is valid and has no data.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "FileChannel operations required for encrypted translog implementation")
public class CryptoFileChannelWrapper extends FileChannel {

    /** "OST1": OpenSearch translog, encryption format version 1. */
    static final int MAGIC = 0x4F535431;

    /** Bytes between the core header and the encrypted data: magic plus nonce. */
    static final int PREFIX_LENGTH = Integer.BYTES + TranslogCipher.NONCE_LENGTH;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int TRANSFER_BUFFER_SIZE = 8192;

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final int headerSize;
    private final AtomicLong position;
    private final ReentrantReadWriteLock positionLock;
    private final Object cipherLock = new Object();
    private volatile TranslogCipher cipher;
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
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.delegate = delegate;
        this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
        this.filePath = path;
        // Non-translog files (.ckp) are never wrapped by CryptoChannelFactory; treat them as all data.
        this.headerSize = path.getFileName().toString().endsWith(".tlog") ? calculateTranslogHeaderSize(translogUUID) : 0;
        this.position = new AtomicLong(delegate.position());
        this.positionLock = new ReentrantReadWriteLock();
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

    /**
     * Reads at a logical position without touching the channel position. A read never crosses
     * from the header into the data, so a caller can't get ciphertext as if it were header bytes.
     */
    private int readAtPosition(ByteBuffer dst, long position) throws IOException {
        if (position < headerSize) {
            ByteBuffer header = dst.duplicate();
            header.limit(header.position() + (int) Math.min(header.remaining(), headerSize - position));
            int n = delegate.read(header, position);
            if (n > 0) {
                dst.position(dst.position() + n);
            }
            return n;
        }

        TranslogCipher c = loadCipher();
        if (c == null) {
            return -1; // only the header exists
        }

        int start = dst.position();
        int n = delegate.read(dst, position + PREFIX_LENGTH);
        if (n <= 0) {
            return -1;
        }
        decryptInPlace(c, dst, start, n, position - headerSize);
        return n;
    }

    private static void decryptInPlace(TranslogCipher c, ByteBuffer buf, int start, int len, long dataOffset) throws IOException {
        if (buf.hasArray()) {
            c.apply(buf.array(), buf.arrayOffset() + start, len, dataOffset);
        } else {
            byte[] tmp = new byte[len];
            buf.get(start, tmp);
            c.apply(tmp, 0, len, dataOffset);
            buf.put(start, tmp);
        }
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
     * Writes all of {@code src} at a logical position: header bytes as they are, data bytes
     * encrypted for their offset. Never modifies the caller's bytes.
     *
     * <p>Data may only be appended at the current end. Overwriting data would encrypt different
     * bytes with the same keystream, and writing past the end would leave a hole that decrypts to
     * raw keystream. Core only ever appends to translog files.
     */
    private int writeAtPosition(ByteBuffer src, long position) throws IOException {
        int total = src.remaining();
        if (total == 0) {
            return 0;
        }

        long pos = position;
        if (pos + total > headerSize) {
            long end = size();
            if (Math.max(pos, headerSize) != Math.max(end, headerSize)) {
                throw new IOException(
                    "Encrypted translog data can only be appended at the end (size " + end + "), not written at " + pos + ": " + filePath
                );
            }
        }
        if (pos < headerSize) {
            ByteBuffer header = src.duplicate();
            header.limit(header.position() + (int) Math.min(header.remaining(), headerSize - pos));
            int headerBytes = header.remaining();
            writeFully(header, pos);
            src.position(src.position() + headerBytes);
            pos += headerBytes;
        }

        if (src.hasRemaining()) {
            TranslogCipher c = cipherForWrite();
            byte[] data = new byte[src.remaining()];
            src.get(data);
            c.apply(data, 0, data.length, pos - headerSize);
            writeFully(ByteBuffer.wrap(data), pos + PREFIX_LENGTH);
        }
        return total;
    }

    private void writeFully(ByteBuffer buf, long physicalPosition) throws IOException {
        long pos = physicalPosition;
        while (buf.hasRemaining()) {
            pos += delegate.write(buf, pos);
        }
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

    /** Returns the cipher for an existing file's data, or null if the file has no data yet. */
    private TranslogCipher loadCipher() throws IOException {
        TranslogCipher c = cipher;
        if (c != null) {
            return c;
        }
        synchronized (cipherLock) {
            if (cipher == null && delegate.size() >= headerSize + PREFIX_LENGTH) {
                ByteBuffer prefix = ByteBuffer.allocate(PREFIX_LENGTH);
                long pos = headerSize;
                while (prefix.hasRemaining()) {
                    int n = delegate.read(prefix, pos);
                    if (n < 0) {
                        throw new IOException("Truncated encryption prefix in translog file " + filePath);
                    }
                    pos += n;
                }
                prefix.flip();
                int magic = prefix.getInt();
                if (magic != MAGIC) {
                    throw new IOException(
                        "Unsupported translog encryption format in "
                            + filePath
                            + ": expected magic 0x"
                            + Integer.toHexString(MAGIC)
                            + ", found 0x"
                            + Integer.toHexString(magic)
                    );
                }
                byte[] nonce = new byte[TranslogCipher.NONCE_LENGTH];
                prefix.get(nonce);
                cipher = new TranslogCipher(keyResolver.getDataKey(), nonce);
            }
            return cipher;
        }
    }

    /** Returns the cipher for writing data, creating and persisting a fresh nonce for a new file. */
    private TranslogCipher cipherForWrite() throws IOException {
        TranslogCipher c = loadCipher();
        if (c != null) {
            return c;
        }
        synchronized (cipherLock) {
            if (cipher == null) {
                byte[] nonce = new byte[TranslogCipher.NONCE_LENGTH];
                RANDOM.nextBytes(nonce);
                ByteBuffer prefix = ByteBuffer.allocate(PREFIX_LENGTH);
                prefix.putInt(MAGIC).put(nonce).flip();
                writeFully(prefix, headerSize);
                cipher = new TranslogCipher(keyResolver.getDataKey(), nonce);
            }
            return cipher;
        }
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
        position.set(newPosition);
        return this;
    }

    /**
     * Returns the logical size: header plus data, without the hidden magic and nonce.
     */
    @Override
    public long size() throws IOException {
        ensureOpen();
        long physical = delegate.size();
        if (physical >= headerSize + PREFIX_LENGTH) {
            return physical - PREFIX_LENGTH;
        }
        return Math.min(physical, headerSize);
    }

    /**
     * Truncation is only supported while the file has no data. Cutting off encrypted data and
     * writing different bytes at the same offsets would reuse keystream under the file's nonce,
     * and replacing the nonce would leave other channels on the file with a stale one. Core never
     * truncates translog files.
     */
    @Override
    public FileChannel truncate(long size) throws IOException {
        ensureOpen();
        if (size < 0) {
            throw new IllegalArgumentException("negative size: " + size);
        }
        positionLock.writeLock().lock();
        try {
            long current = size();
            if (size < current) {
                if (current > headerSize) {
                    throw new IOException("Truncating an encrypted translog file that has data is not supported: " + filePath);
                }
                delegate.truncate(size);
            }
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
