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

/**
 * Streams plaintext into {@link ChunkCipher} chunks. Ciphertext goes to the output as each chunk
 * fills; the chunk tags are kept in memory (16 bytes per 8 KiB) and written as the tag table by
 * {@link #finish}. Not thread-safe: one instance per file being written.
 *
 * @opensearch.internal
 */
public final class ChunkEncryptor {

    private final Cipher cipher = ChunkCipher.newCipher();
    private final Key fileKey;
    private final byte[] chunk = new byte[ChunkCipher.CHUNK_SIZE];
    private final byte[] sealed = new byte[ChunkCipher.CHUNK_SIZE + ChunkCipher.TAG_LENGTH];
    private byte[] tags = new byte[64 * ChunkCipher.TAG_LENGTH];
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

    /** Plaintext bytes accepted so far. */
    public long dataLength() {
        return dataLength + chunkPosition;
    }

    private void sealChunk(OutputStream out, byte[] b, int offset, int length) throws IOException {
        try {
            ChunkCipher.seal(cipher, fileKey, chunkIndex, b, offset, length, sealed);
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to encrypt chunk " + chunkIndex, e);
        }
        out.write(sealed, 0, length);
        if (tagBytes == tags.length) {
            tags = Arrays.copyOf(tags, Math.addExact(tags.length, tags.length));
        }
        System.arraycopy(sealed, length, tags, tagBytes, ChunkCipher.TAG_LENGTH);
        tagBytes += ChunkCipher.TAG_LENGTH;
        chunkIndex++;
        dataLength += length;
    }
}
