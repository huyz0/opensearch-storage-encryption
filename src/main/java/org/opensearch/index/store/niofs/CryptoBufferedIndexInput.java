/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.opensearch.index.store.cipher.AesCipherFactory.ALGORITHM;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.BufferedIndexInput;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.KeyResolver;

/**
 * An IndexInput implementation that decrypts and authenticates data for reading.
 *
 * <p>Reads go through whole {@link ChunkCipher} chunks: each chunk is read with its tag from the
 * tag table, verified, and kept until a read moves to another chunk. A chunk that fails
 * verification raises {@link CorruptIndexException}.
 *
 * @opensearch.internal
 */
final class CryptoBufferedIndexInput extends BufferedIndexInput {
    private static final long CHUNK_MASK = ChunkCipher.CHUNK_SIZE - 1;

    private final FileChannel channel;
    /** Only the input that opened the channel closes it; clones and slices share it. */
    private boolean ownsChannel;
    /** Slice bounds, in plaintext offsets. */
    private final long off;
    private final long end;
    /** Plaintext length of the whole file; the tag table starts here. */
    private final long dataLength;
    private final SecretKeySpec keySpec;

    // Per-instance chunk state, allocated on first read. Clones get their own.
    private ByteBuffer ciphertext;
    private ByteBuffer tag;
    private ByteBuffer plaintext;
    private long cachedChunk = -1;

    public CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        IOContext context,
        KeyResolver keyResolver,
        Path filePath,
        EncryptionMetadataCache encryptionMetadataCache
    )
        throws IOException {
        super(resourceDesc, context);
        this.channel = fc;
        this.ownsChannel = true;
        String normalizedFilePath = EncryptionMetadataCache.normalizePath(filePath);
        byte[] masterKey = keyResolver.getDataKey().getEncoded();

        // Read footer and cache metadata atomically
        EncryptionFooter footer = EncryptionFooter.readViaFileChannel(normalizedFilePath, channel, masterKey, encryptionMetadataCache);
        var metadata = encryptionMetadataCache.getOrLoadMetadata(normalizedFilePath, footer, masterKey);
        this.dataLength = metadata.getFooter().getDataLength();
        // The footer may come from the cache, so check the size here too: truncation is corruption.
        long expectedSize = dataLength + metadata.getFooter().getTrailerLength();
        if (fc.size() != expectedSize) {
            throw new CorruptIndexException("encrypted file size " + fc.size() + " does not match its footer (" + expectedSize + ")", this);
        }
        this.keySpec = new SecretKeySpec(metadata.getFileKey(), ALGORITHM);
        this.off = 0L;
        this.end = dataLength;
    }

    private CryptoBufferedIndexInput(
        String resourceDesc,
        FileChannel fc,
        long off,
        long length,
        int bufferSize,
        long dataLength,
        SecretKeySpec keySpec
    ) {
        super(resourceDesc, bufferSize);
        this.channel = fc;
        this.ownsChannel = false;
        this.off = off;
        this.end = off + length;
        this.dataLength = dataLength;
        this.keySpec = keySpec;
    }

    @Override
    public void close() throws IOException {
        if (ownsChannel) {
            channel.close();
        }
    }

    @Override
    public CryptoBufferedIndexInput clone() {
        CryptoBufferedIndexInput clone = (CryptoBufferedIndexInput) super.clone();
        clone.ownsChannel = false;
        clone.ciphertext = null;
        clone.tag = null;
        clone.plaintext = null;
        clone.cachedChunk = -1;
        return clone;
    }

    @Override
    public IndexInput slice(String sliceDescription, long offset, long length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > this.length()) {
            throw new IllegalArgumentException(
                "slice() " + sliceDescription + " out of bounds: offset=" + offset + ", length=" + length + ", fileLength=" + this.length()
            );
        }
        return new CryptoBufferedIndexInput(
            getFullSliceDescription(sliceDescription),
            channel,
            off + offset,
            length,
            getBufferSize(),
            dataLength,
            keySpec
        );
    }

    @Override
    public long length() {
        return end - off;
    }

    @Override
    protected void readInternal(ByteBuffer b) throws IOException {
        long pos = getFilePointer() + off;
        if (pos + b.remaining() > end) {
            throw new EOFException("read past EOF: pos=" + pos + ", end=" + end + ": " + this);
        }

        while (b.hasRemaining()) {
            long chunk = pos >>> ChunkCipher.CHUNK_SIZE_POWER;
            loadChunk(chunk);
            int offsetInChunk = (int) (pos & CHUNK_MASK);
            int n = Math.min(b.remaining(), plaintext.limit() - offsetInChunk);
            b.put(b.position(), plaintext, offsetInChunk, n);
            b.position(b.position() + n);
            pos += n;
        }
    }

    /** Reads, verifies and decrypts {@code chunk} into {@link #plaintext}, unless it is already there. */
    private void loadChunk(long chunk) throws IOException {
        if (chunk == cachedChunk) {
            return;
        }
        if (plaintext == null) {
            ciphertext = ByteBuffer.allocate(ChunkCipher.CHUNK_SIZE);
            tag = ByteBuffer.allocate(ChunkCipher.TAG_LENGTH);
            plaintext = ByteBuffer.allocate(ChunkCipher.CHUNK_SIZE);
        }
        cachedChunk = -1;

        int length = ChunkCipher.chunkLength(chunk, dataLength);
        readFully(ciphertext.clear().limit(length), chunk << ChunkCipher.CHUNK_SIZE_POWER);
        readFully(tag.clear(), dataLength + chunk * ChunkCipher.TAG_LENGTH);

        try {
            ChunkCipher.open(keySpec, chunk, ciphertext.flip(), tag.flip(), plaintext.clear());
        } catch (AEADBadTagException e) {
            throw new CorruptIndexException("encrypted chunk " + chunk + " failed authentication", this, e);
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to decrypt chunk " + chunk + ": " + this, e);
        }
        plaintext.flip();
        cachedChunk = chunk;
    }

    @SuppressForbidden(reason = "FileChannel#read is efficient and used intentionally")
    private void readFully(ByteBuffer dst, long position) throws IOException {
        while (dst.hasRemaining()) {
            int n = channel.read(dst, position);
            if (n < 0) {
                throw new EOFException("Unexpected EOF at " + position + " while reading encrypted data: " + this);
            }
            position += n;
        }
    }

    @Override
    protected void seekInternal(long pos) throws IOException {
        if (pos > length()) {
            throw new EOFException("seek past EOF: pos=" + pos + ", length=" + length());
        }
    }
}
