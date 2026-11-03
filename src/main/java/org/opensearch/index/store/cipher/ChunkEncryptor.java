/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;

/**
 * Streams plaintext into {@link ChunkCipher} chunks. Ciphertext goes to the output as each chunk
 * fills; the chunks' tag-table entries (nonce and tag, 28 bytes per 8 KiB) are kept in memory and written as the tag table by
 * {@link #finish}. Not thread-safe: one instance per file being written.
 *
 * @opensearch.internal
 */
public final class ChunkEncryptor {

    private final Cipher cipher = ChunkCipher.newCipher();
    private final Key fileKey;
    private final byte[] chunk = new byte[ChunkCipher.CHUNK_SIZE];
    private final byte[] sealed = new byte[ChunkCipher.CHUNK_SIZE + ChunkCipher.ENTRY_LENGTH];
    private byte[] tags = new byte[64 * ChunkCipher.ENTRY_LENGTH];
    // Last LUCENE_FOOTER_COPY_SIZE plaintext bytes, right-aligned and zero-padded on the left
    private final byte[] tail = new byte[EncryptionMetadataTrailer.LUCENE_FOOTER_COPY_SIZE];
    private int tagBytes;
    private int chunkPosition;
    private long chunkIndex;
    private long dataLength;
    private boolean finished;

    public ChunkEncryptor(Key fileKey) {
        this.fileKey = fileKey;
    }

    /** Encrypts {@code length} bytes and writes any completed chunks to {@code out}. */
    public void write(OutputStream out, byte[] b, int offset, int length) throws IOException {
        if (finished) {
            throw new IOException("ChunkEncryptor is already finished");
        }
        updateTail(b, offset, length);
        while (length > 0) {
            if (chunkPosition == 0 && length >= ChunkCipher.CHUNK_SIZE) {
                // Whole chunk available in the caller's buffer: seal it without copying.
                sealChunk(out, b, offset, ChunkCipher.CHUNK_SIZE);
                offset += ChunkCipher.CHUNK_SIZE;
                length -= ChunkCipher.CHUNK_SIZE;
                continue;
            }
            int n = Math.min(length, ChunkCipher.CHUNK_SIZE - chunkPosition);
            System.arraycopy(b, offset, chunk, chunkPosition, n);
            chunkPosition += n;
            offset += n;
            length -= n;
            if (chunkPosition == ChunkCipher.CHUNK_SIZE) {
                sealChunk(out, chunk, 0, ChunkCipher.CHUNK_SIZE);
                chunkPosition = 0;
            }
        }
    }

    /**
     * Seals the last partial chunk, writes the tag table, and returns the plaintext length.
     * The caller writes the footer after this.
     */
    public long finish(OutputStream out) throws IOException {
        if (finished) {
            throw new IOException("ChunkEncryptor is already finished");
        }
        if (chunkPosition > 0) {
            sealChunk(out, chunk, 0, chunkPosition);
            chunkPosition = 0;
        }
        out.write(tags, 0, tagBytes);
        finished = true;
        return dataLength;
    }

    /**
     * The 16 bytes writers append after the footer so that the raw file ends with Lucene's codec footer, which
     * lets core code read the checksum without the key. It is the plaintext's last 16 bytes when they form a
     * codec footer (footer magic, algorithm 0, then the checksum), and all zeros otherwise, so files without
     * a codec footer expose nothing.
     */
    public byte[] luceneFooterCopy() {
        if (getInt(tail, 0) == CodecUtil.FOOTER_MAGIC && getInt(tail, 4) == 0 && getInt(tail, 8) == 0) {
            return tail.clone();
        }
        return new byte[tail.length];
    }

    private static int getInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24) | ((b[offset + 1] & 0xFF) << 16) | ((b[offset + 2] & 0xFF) << 8) | (b[offset + 3] & 0xFF);
    }

    private void updateTail(byte[] b, int offset, int length) {
        int n = tail.length;
        if (length >= n) {
            System.arraycopy(b, offset + length - n, tail, 0, n);
        } else if (length > 0) {
            System.arraycopy(tail, length, tail, 0, n - length);
            System.arraycopy(b, offset, tail, n - length, length);
        }
    }

    /** Plaintext bytes accepted so far. */
    public long dataLength() {
        return dataLength + chunkPosition;
    }

    private void sealChunk(OutputStream out, byte[] b, int offset, int length) throws IOException {
        if (chunkIndex >= ChunkCipher.MAX_CHUNKS) {
            throw new IOException("encrypted file is too large: more than " + ChunkCipher.MAX_CHUNKS + " chunks");
        }
        try {
            ChunkCipher.seal(cipher, fileKey, chunkIndex, b, offset, length, sealed);
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to encrypt chunk " + chunkIndex, e);
        }
        out.write(sealed, 0, length);
        if (tagBytes == tags.length) {
            // Doubling past 2^30 bytes would overflow an int before MAX_CHUNKS is reached, so cap the growth
            // there; the check above keeps tagBytes below this cap.
            long cap = ChunkCipher.MAX_CHUNKS * ChunkCipher.ENTRY_LENGTH;
            tags = Arrays.copyOf(tags, (int) Math.min(2L * tags.length, cap));
        }
        System.arraycopy(sealed, length, tags, tagBytes, ChunkCipher.ENTRY_LENGTH);
        tagBytes += ChunkCipher.ENTRY_LENGTH;
        chunkIndex++;
        dataLength += length;
    }
}
