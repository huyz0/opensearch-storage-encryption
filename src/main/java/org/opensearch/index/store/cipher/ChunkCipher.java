/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

import org.opensearch.index.store.CryptoDirectoryFactory;

/**
 * AES-256-GCM over fixed-size chunks of an encrypted index file.
 *
 * <p>The plaintext of a file is split into {@link #CHUNK_SIZE} chunks (the last one may be shorter).
 * Chunk {@code i} is sealed on its own with the file key, the 12-byte nonce
 * {@code 00000000 || i} (big-endian {@code long}) and no AAD. The ciphertext has the same length
 * as the plaintext, so a plaintext offset is also the ciphertext offset, and each chunk's 16-byte
 * tag is stored separately in the file's tag table. A reader decrypts and verifies one whole chunk
 * at a time, so any change to the ciphertext or the tags is detected before plaintext is returned.
 *
 * <p>The chunk index is part of the nonce, so moving a chunk to another position fails
 * authentication. Nonces are deterministic, so a key must seal exactly one file: callers must use
 * a fresh per-file key (HKDF over a random message ID), never the directory key. The footer auth
 * tag uses nonce {@code FF x 8 || 00 x 4}, which no chunk nonce can equal because chunk nonces
 * start with four zero bytes.
 *
 * @opensearch.internal
 */
public final class ChunkCipher {

    /** log2 of the chunk size. Equal to the block cache's block size, so one cache block is one chunk. */
    public static final int CHUNK_SIZE_POWER = 13;

    /** Plaintext bytes per chunk (8 KiB). */
    public static final int CHUNK_SIZE = 1 << CHUNK_SIZE_POWER;

    /** GCM tag length in bytes. */
    public static final int TAG_LENGTH = 16;

    /** GCM nonce length in bytes. */
    public static final int NONCE_LENGTH = 12;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private static final ThreadLocal<Cipher> DECRYPT_CIPHER = ThreadLocal.withInitial(ChunkCipher::newCipher);

    private ChunkCipher() {}

    /**
     * Returns a new AES/GCM cipher. Writers keep their own instance: the JCE refuses to encrypt twice
     * with the same key and nonce on one instance, which is the check we want for a writer.
     */
    public static Cipher newCipher() {
        try {
            return Cipher.getInstance(TRANSFORMATION, CryptoDirectoryFactory.DEFAULT_CRYPTO_PROVIDER);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/GCM is not available", e);
        }
    }

    /** The nonce for chunk {@code chunkIndex}: four zero bytes followed by the big-endian index. */
    public static byte[] nonce(long chunkIndex) {
        if (chunkIndex < 0) {
            throw new IllegalArgumentException("chunkIndex must not be negative: " + chunkIndex);
        }
        byte[] nonce = new byte[NONCE_LENGTH];
        for (int i = 0; i < Long.BYTES; i++) {
            nonce[NONCE_LENGTH - 1 - i] = (byte) (chunkIndex >>> (8 * i));
        }
        return nonce;
    }

    /** Number of chunks in a file with {@code dataLength} plaintext bytes. */
    public static long chunkCount(long dataLength) {
        return (dataLength + CHUNK_SIZE - 1) >>> CHUNK_SIZE_POWER;
    }

    /** Length in bytes of the tag table for a file with {@code dataLength} plaintext bytes. */
    public static long tagTableLength(long dataLength) {
        return chunkCount(dataLength) * TAG_LENGTH;
    }

    /** Plaintext length of chunk {@code chunkIndex} in a file with {@code dataLength} plaintext bytes. */
    public static int chunkLength(long chunkIndex, long dataLength) {
        long start = chunkIndex << CHUNK_SIZE_POWER;
        if (chunkIndex < 0 || start >= dataLength) {
            throw new IllegalArgumentException("chunk " + chunkIndex + " is outside data of length " + dataLength);
        }
        return (int) Math.min(CHUNK_SIZE, dataLength - start);
    }

    /**
     * Encrypts one chunk.
     *
     * @param cipher     the writer's cipher, from {@link #newCipher()}
     * @param key        the file key
     * @param chunkIndex index of the chunk in the file
     * @param in         plaintext
     * @param inOffset   offset of the chunk in {@code in}
     * @param length     chunk length, at most {@link #CHUNK_SIZE}
     * @param out        receives {@code length} ciphertext bytes followed by the {@link #TAG_LENGTH}-byte tag
     */
    public static void seal(Cipher cipher, Key key, long chunkIndex, byte[] in, int inOffset, int length, byte[] out)
        throws GeneralSecurityException {
        checkLength(length);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, nonce(chunkIndex)));
        int written = cipher.doFinal(in, inOffset, length, out, 0);
        assert written == length + TAG_LENGTH : written;
    }

    /**
     * Decrypts and authenticates one chunk. If authentication fails the contents of {@code out} are
     * unspecified and must be discarded.
     *
     * @param key        the file key
     * @param chunkIndex index of the chunk in the file
     * @param ciphertext the chunk's ciphertext, from position to limit; consumed
     * @param tag        the chunk's tag, from position to limit ({@link #TAG_LENGTH} bytes); consumed
     * @param out        receives the plaintext at its position
     * @throws AEADBadTagException if the ciphertext, tag or chunk position was altered
     */
    public static void open(Key key, long chunkIndex, ByteBuffer ciphertext, ByteBuffer tag, ByteBuffer out)
        throws GeneralSecurityException {
        checkLength(ciphertext.remaining());
        if (tag.remaining() != TAG_LENGTH) {
            throw new IllegalArgumentException("tag must be " + TAG_LENGTH + " bytes, got " + tag.remaining());
        }
        Cipher cipher = DECRYPT_CIPHER.get();
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, nonce(chunkIndex)));
        // GCM decryption buffers until doFinal and only releases plaintext once the tag verifies.
        cipher.update(ciphertext, out);
        cipher.doFinal(tag, out);
    }

    private static void checkLength(int length) {
        if (length <= 0 || length > CHUNK_SIZE) {
            throw new IllegalArgumentException("chunk length must be in (0, " + CHUNK_SIZE + "], got " + length);
        }
    }
}
