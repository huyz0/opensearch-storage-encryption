/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.CryptoProviders;
import org.opensearch.index.store.key.KeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

/**
 * Encrypts the data of a translog ({@code .tlog}) file as a sequence of sealed AES-256-GCM frames.
 *
 * <p>This follows the frame format of upstream opensearch-storage-encryption #181, with the nonce and
 * key handling of {@link ChunkCipher} so that the FIPS build can seal frames inside the AWS-LC FIPS module.
 *
 * <p>On-disk layout:
 * <pre>
 * [TranslogHeader - plaintext, written and read by core]
 * [format header: magic "TLGF" (4) | version (4) | max frame size (4) | message ID (16)]
 * [frame 0][frame 1]...   frame = [plaintext length (4) | ciphertext | nonce (12) | tag (16)]
 * </pre>
 *
 * <p>Every write is sealed immediately as one or more frames of at most the maximum frame size, so
 * every byte OpenSearch has written can be read and authenticated right away (realtime gets during
 * live indexing, translog replay after a crash). A frame holds whatever one write contained, so
 * frames vary in size: a 6 KiB flush is one 6 KiB frame.
 *
 * <p>Each file has its own AES-256 key, derived from the index data key and the file's random message
 * ID with the SP 800-108 KDF. Each frame is sealed with {@link ChunkCipher#seal}, so the cryptographic
 * module generates its 96-bit nonce, and its AAD is the frame index. GCM authenticates the ciphertext
 * length, the index ties the frame to its position, and the per-file key ties it to its file, so a frame
 * cannot be modified, resized, reordered, moved or copied into another file without failing
 * authentication. Since every frame before it authenticates its own length, the frame's logical offset
 * is authenticated as well.
 *
 * <p>OpenSearch addresses the file by logical (plaintext) offsets. Frame start offsets are kept in
 * memory, and rebuilt on open by scanning the frame length headers. The scan stops at the first
 * incomplete or invalid frame. A frame torn by a crash lies beyond the last checkpoint, because
 * TranslogWriter forces the channel before it writes a checkpoint, so it is never read. A channel
 * that finds such a frame, or whose own frame write fails part way, rejects every later write, so a
 * file never holds two different frames for one index. OpenSearch never appends to such a file;
 * recovery reads it and writes new operations to a new generation.
 *
 * <p>The maximum frame size is stored in the format header, so a file is always read with the size
 * it was written with.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "Channel operations required for translog encryption")
final class TranslogChunkManager {

    /** Default maximum plaintext bytes per frame; also the largest allowed, one {@link ChunkCipher} chunk. */
    static final int DEFAULT_MAX_FRAME_SIZE = ChunkCipher.CHUNK_SIZE;

    static final int FORMAT_MAGIC = 0x544C4746; // "TLGF"
    /** Version 1 is upstream's layout (derived nonces, no message ID); it is not supported. */
    static final int FORMAT_VERSION = 2;
    static final int MESSAGE_ID_LENGTH = 16;
    static final int FORMAT_HEADER_SIZE = 3 * Integer.BYTES + MESSAGE_ID_LENGTH;
    static final int FRAME_HEADER_SIZE = Integer.BYTES;
    static final int FRAME_OVERHEAD = FRAME_HEADER_SIZE + ChunkCipher.ENTRY_LENGTH;

    /** SP 800-108 label for translog file keys. */
    static final String KEY_LABEL = "translog-gcm";

    private static final ThreadLocal<Cipher> SEAL_CIPHER = ThreadLocal.withInitial(ChunkCipher::newCipher);

    /** A frame: its index, logical (plaintext) and physical (on-disk) start offsets, and plaintext length. */
    private record Frame(int index, long logicalStart, long physicalStart, int length) {
    }

    /** The last decrypted frame. Frames never change once written, so it can be shared by readers. */
    private record DecryptedFrame(int index, byte[] plaintext) {
    }

    private final FileChannel delegate;
    private final KeyResolver keyResolver;
    private final Path filePath;
    private final int headerSize;
    private final int newFileMaxFrameSize;

    // Frame index, guarded by this: frame i starts at logicalStarts[i] / physicalStarts[i] and holds lengths[i] bytes.
    private long[] logicalStarts = new long[64];
    private long[] physicalStarts = new long[64];
    private int[] lengths = new int[64];
    private int frameCount;
    private int maxFrameSize;
    private long logicalEnd;
    private long physicalEnd;
    // Set when the file has bytes after its last complete frame (a write torn by a crash) or a frame
    // write failed part way. Appending would then write a second frame under the index of the partial
    // one, so every later write is rejected. Reads of complete frames are unaffected.
    private boolean appendsBlocked;

    // Set once the format header is known (read from the file or written by this channel).
    private volatile Key fileKey;
    private volatile DecryptedFrame lastDecrypted;

    /**
     * Creates a frame manager for one translog file and indexes the frames it already holds.
     *
     * @param delegate the underlying FileChannel for actual I/O
     * @param keyResolver resolves the index data key
     * @param filePath the translog file path, for error messages
     * @param headerSize the size of the plaintext TranslogHeader at the start of the file
     * @param newFileMaxFrameSize the maximum frame size if this is a new file; an existing file keeps the size it was written with
     * @throws IOException if the existing file content cannot be indexed or its key cannot be derived
     */
    TranslogChunkManager(FileChannel delegate, KeyResolver keyResolver, Path filePath, int headerSize, int newFileMaxFrameSize)
        throws IOException {
        if (newFileMaxFrameSize <= 0 || newFileMaxFrameSize > ChunkCipher.CHUNK_SIZE) {
            throw new IllegalArgumentException("maximum frame size must be in (0, " + ChunkCipher.CHUNK_SIZE + "]: " + newFileMaxFrameSize);
        }
        this.delegate = delegate;
        this.keyResolver = keyResolver;
        this.filePath = filePath;
        this.headerSize = headerSize;
        this.newFileMaxFrameSize = newFileMaxFrameSize;
        synchronized (this) {
            indexNewFrames();
        }
    }

    /**
     * Returns the logical (plaintext) size of the file: the header plus every complete frame,
     * including frames appended by another channel since this one last looked.
     *
     * @return the logical size in bytes
     * @throws IOException if the file size cannot be read or new frames cannot be indexed
     */
    synchronized long logicalSize() throws IOException {
        if (delegate.size() != physicalEnd) {
            indexNewFrames();
        }
        return logicalEnd;
    }

    /** Returns the maximum frame size this file is read and written with. */
    synchronized int maxFrameSize() {
        return fileKey != null ? maxFrameSize : newFileMaxFrameSize;
    }

    /**
     * Indexes frames appended since the last scan (by this or another channel). Reads only the frame
     * length headers; nothing is decrypted. Bytes left after the last complete frame block appends.
     */
    private void indexNewFrames() throws IOException {
        long fileSize = delegate.size();
        scanFrames(fileSize);
        if (physicalEnd < fileSize) {
            appendsBlocked = true;
        }
    }

    private void scanFrames(long fileSize) throws IOException {
        if (fileKey == null) {
            if (fileSize < headerSize + FORMAT_HEADER_SIZE) {
                // Header only (or a header or format header torn by a crash): no frames yet.
                logicalEnd = physicalEnd = Math.min(fileSize, headerSize);
                return;
            }
            ByteBuffer format = readPhysical(headerSize, FORMAT_HEADER_SIZE);
            int magic = format.getInt();
            int version = format.getInt();
            int frameSize = format.getInt();
            if (magic != FORMAT_MAGIC || version != FORMAT_VERSION || frameSize <= 0 || frameSize > ChunkCipher.CHUNK_SIZE) {
                throw new IOException(
                    "Unsupported translog encryption format (magic=0x"
                        + Integer.toHexString(magic)
                        + ", version="
                        + version
                        + ", maxFrameSize="
                        + frameSize
                        + ") in file: "
                        + filePath
                );
            }
            byte[] messageId = new byte[MESSAGE_ID_LENGTH];
            format.get(messageId);
            fileKey = deriveFileKey(messageId);
            maxFrameSize = frameSize;
            logicalEnd = headerSize;
            physicalEnd = headerSize + FORMAT_HEADER_SIZE;
        }
        ByteBuffer lengthBuf = ByteBuffer.allocate(FRAME_HEADER_SIZE);
        while (physicalEnd + FRAME_OVERHEAD < fileSize) {
            lengthBuf.clear();
            if (readPhysicalInto(lengthBuf, physicalEnd) < FRAME_HEADER_SIZE) {
                return;
            }
            int length = lengthBuf.getInt(0);
            if (length <= 0 || length > maxFrameSize || physicalEnd + FRAME_OVERHEAD + length > fileSize) {
                // Incomplete or invalid trailing frame, beyond the last checkpoint: ignore it.
                return;
            }
            addFrame(length);
        }
    }

    /** Derives the file key, reporting a missing data key or a KDF failure as an IOException as core expects. */
    private Key deriveFileKey(byte[] messageId) throws IOException {
        try {
            byte[] dataKey = keyResolver.getDataKey().getEncoded();
            return new SecretKeySpec(KeyDerivation.deriveAesKey(dataKey, messageId, KEY_LABEL), "AES");
        } catch (RuntimeException e) {
            throw new IOException(
                "Failed to set up the cipher for translog file " + filePath + " (data key unavailable or key derivation failed)",
                e
            );
        }
    }

    private void addFrame(int length) throws IOException {
        if (frameCount == Integer.MAX_VALUE) {
            throw new IOException("Too many frames in translog file: " + filePath);
        }
        if (frameCount == lengths.length) {
            int newCapacity = (int) Math.min(Integer.MAX_VALUE, frameCount * 2L);
            logicalStarts = Arrays.copyOf(logicalStarts, newCapacity);
            physicalStarts = Arrays.copyOf(physicalStarts, newCapacity);
            lengths = Arrays.copyOf(lengths, newCapacity);
        }
        logicalStarts[frameCount] = logicalEnd;
        physicalStarts[frameCount] = physicalEnd;
        lengths[frameCount] = length;
        frameCount++;
        logicalEnd += length;
        physicalEnd += FRAME_OVERHEAD + length;
    }

    /** Returns the frame holding logical offset {@code position}, or null if it is past the last frame. */
    private synchronized Frame findFrame(long position) throws IOException {
        if (position >= logicalEnd) {
            indexNewFrames();
            if (position >= logicalEnd) {
                return null;
            }
        }
        int lo = 0;
        int hi = frameCount - 1;
        while (lo < hi) {
            int mid = (lo + hi + 1) >>> 1;
            if (logicalStarts[mid] <= position) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        return new Frame(lo, logicalStarts[lo], physicalStarts[lo], lengths[lo]);
    }

    /** Reads, authenticates and decrypts a frame. */
    private byte[] decryptFrame(Frame frame) throws IOException {
        DecryptedFrame cached = lastDecrypted;
        if (cached != null && cached.index() == frame.index()) {
            return cached.plaintext();
        }
        ByteBuffer sealed = readPhysical(frame.physicalStart() + FRAME_HEADER_SIZE, frame.length() + ChunkCipher.ENTRY_LENGTH);
        ByteBuffer ciphertext = sealed.slice(0, frame.length());
        ByteBuffer entry = sealed.slice(frame.length(), ChunkCipher.ENTRY_LENGTH);
        byte[] plaintext = new byte[frame.length()];
        try {
            ChunkCipher.open(fileKey, frame.index(), ciphertext, entry, ByteBuffer.wrap(plaintext));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IOException("Failed to authenticate translog frame " + frame.index() + " in file: " + filePath, e);
        }
        lastDecrypted = new DecryptedFrame(frame.index(), plaintext);
        return plaintext;
    }

    private ByteBuffer readPhysical(long position, int length) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(length);
        if (readPhysicalInto(buf, position) < length) {
            throw new IOException("Unexpected end of translog file: " + filePath + " at offset: " + position);
        }
        buf.flip();
        return buf;
    }

    private int readPhysicalInto(ByteBuffer buf, long position) throws IOException {
        int total = 0;
        while (buf.hasRemaining()) {
            int read = delegate.read(buf, position + total);
            if (read <= 0) {
                break;
            }
            total += read;
        }
        return total;
    }

    private void writePhysical(ByteBuffer buf, long position) throws IOException {
        long written = 0;
        while (buf.hasRemaining()) {
            written += delegate.write(buf, position + written);
        }
    }

    /**
     * Reads and decrypts bytes at logical offset {@code position}. Header bytes are returned as stored.
     * A read never crosses from the header into the data.
     *
     * @param dst the buffer to read data into
     * @param position the logical file position to read from
     * @return the number of bytes read, or -1 at end of file
     * @throws IOException if reading or authentication fails
     */
    int read(ByteBuffer dst, long position) throws IOException {
        if (dst.remaining() == 0) {
            return 0;
        }
        if (position < headerSize) {
            long headerEnd = Math.min(headerSize, logicalSize());
            if (position >= headerEnd) {
                return -1;
            }
            ByteBuffer headerPart = dst.duplicate();
            headerPart.limit(headerPart.position() + (int) Math.min(dst.remaining(), headerEnd - position));
            int read = delegate.read(headerPart, position);
            if (read > 0) {
                dst.position(dst.position() + read);
            }
            return read;
        }
        int total = 0;
        while (dst.hasRemaining()) {
            Frame frame = findFrame(position + total);
            if (frame == null) {
                break;
            }
            byte[] plaintext = decryptFrame(frame);
            int offsetInFrame = (int) (position + total - frame.logicalStart());
            int n = Math.min(dst.remaining(), frame.length() - offsetInFrame);
            dst.put(plaintext, offsetInFrame, n);
            total += n;
        }
        return total == 0 ? -1 : total;
    }

    /**
     * Writes all of {@code src} at logical offset {@code position}: header bytes as given, data bytes
     * sealed as one or more frames. Translog files are append-only, so data must be written at the
     * logical end of the file. Never modifies the caller's bytes.
     *
     * @param src the buffer containing data to write
     * @param position the logical file position to write to
     * @return the number of bytes written
     * @throws IOException if the write is not an append, or encryption or writing fails
     */
    synchronized int write(ByteBuffer src, long position) throws IOException {
        int total = src.remaining();
        if (total == 0) {
            return 0;
        }
        if (appendsBlocked) {
            throw new IOException(
                "Cannot append to translog file: "
                    + filePath
                    + ": it has an incomplete frame after logical offset "
                    + logicalEnd
                    + " (a torn or failed write); appending would write a second frame under that frame's index"
            );
        }
        long pos = position;
        if (pos < headerSize) {
            if (fileKey != null) {
                throw new IOException("Cannot rewrite the header of translog file: " + filePath);
            }
            ByteBuffer headerPart = src.duplicate();
            headerPart.limit(headerPart.position() + (int) Math.min(src.remaining(), headerSize - pos));
            int headerBytes = headerPart.remaining();
            writePhysical(headerPart, pos);
            src.position(src.position() + headerBytes);
            pos += headerBytes;
            logicalEnd = physicalEnd = Math.max(logicalEnd, pos);
            if (src.hasRemaining() == false) {
                return total;
            }
        }
        if (pos != logicalEnd || logicalEnd < headerSize) {
            throw new IOException(
                "Encrypted translog files are append-only: write at " + pos + ", logical end " + logicalEnd + " in file: " + filePath
            );
        }
        Key newFileKey = null;
        byte[] messageId = null;
        if (fileKey == null) {
            messageId = new byte[MESSAGE_ID_LENGTH];
            CryptoProviders.secureRandom().nextBytes(messageId);
            // Derive the key before writing anything, so a key failure leaves the file as it was.
            newFileKey = deriveFileKey(messageId);
        }
        boolean completed = false;
        try {
            if (fileKey == null) {
                ByteBuffer format = ByteBuffer.allocate(FORMAT_HEADER_SIZE);
                format.putInt(FORMAT_MAGIC).putInt(FORMAT_VERSION).putInt(newFileMaxFrameSize).put(messageId).flip();
                writePhysical(format, headerSize);
                maxFrameSize = newFileMaxFrameSize;
                physicalEnd = headerSize + FORMAT_HEADER_SIZE;
                fileKey = newFileKey;
            }
            Cipher cipher = SEAL_CIPHER.get();
            byte[] plaintext = new byte[Math.min(src.remaining(), maxFrameSize)];
            while (src.hasRemaining()) {
                int length = Math.min(src.remaining(), maxFrameSize);
                src.get(plaintext, 0, length);
                byte[] frame = new byte[FRAME_OVERHEAD + length];
                ByteBuffer.wrap(frame).putInt(length);
                byte[] sealed = new byte[length + ChunkCipher.ENTRY_LENGTH];
                ChunkCipher.seal(cipher, fileKey, frameCount, plaintext, 0, length, sealed);
                System.arraycopy(sealed, 0, frame, FRAME_HEADER_SIZE, sealed.length);
                writePhysical(ByteBuffer.wrap(frame), physicalEnd);
                addFrame(length);
            }
            completed = true;
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to seal translog frame " + frameCount + " in file: " + filePath, e);
        } finally {
            if (completed == false) {
                // Part of a frame or format header may be on disk; never write over it.
                appendsBlocked = true;
            }
        }
        return total;
    }

    /**
     * Truncating is only supported as a no-op ({@code size} at or past the logical end). Appending
     * after a real truncation would write a second frame under the index of a removed one.
     *
     * @param size the new logical size
     * @throws IOException if {@code size} is before the logical end of the file
     */
    synchronized void truncate(long size) throws IOException {
        if (size < logicalSize()) {
            throw new IOException(
                "Encrypted translog files cannot be truncated (size " + size + ", logical end " + logicalEnd + ") in file: " + filePath
            );
        }
    }
}
