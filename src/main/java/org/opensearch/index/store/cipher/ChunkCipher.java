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

/**
 * AES-256-GCM over fixed-size chunks of an encrypted index file.
 *
 * <p>The plaintext of a file is split into {@link #CHUNK_SIZE} chunks (the last one may be shorter).
 * Chunk {@code i} is sealed on its own with the file key, a random 12-byte nonce that the JCE provider
 * generates inside the cryptographic module, and the AAD {@code i} (big-endian {@code long}). The
 * ciphertext has the same length as the plaintext, so a plaintext offset is also the ciphertext offset.
 * Each chunk's {@link #ENTRY_LENGTH}-byte entry, {@code nonce || tag}, is stored separately in the file's
 * tag table. A reader decrypts and verifies one whole chunk at a time, so any change to the ciphertext,
 * the nonces or the tags is detected before plaintext is returned.
 *
 * <p>The chunk index is authenticated as AAD, so moving a chunk to another position fails
 * authentication. Nonces come from the provider's approved DRBG (FIPS 140-3 IG C.H, random IV
 * generated inside the module), and each file has its own key (SP 800-108 KDF over a random message
 * ID), so one key never sees anywhere near the 2^32 random-nonce limit of SP 800-38D.
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

    /** Bytes per chunk in the tag table: the chunk's nonce followed by its tag. */
    public static final int ENTRY_LENGTH = NONCE_LENGTH + TAG_LENGTH;

    /** Bytes of chunk index authenticated as AAD. */
    private static final int AAD_LENGTH = Long.BYTES;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    /**
     * Per-thread decryption state. {@link #open} copies each chunk into {@code sealed} and decrypts
     * with one array {@code doFinal}: the JDK's AES-GCM intrinsics work on heap arrays, and calling
     * the cipher with native (direct) buffers, or with separate update and doFinal calls, takes
     * slower paths (about half the throughput for the block loader's native buffers). The copies
     * cost far less than the decryption.
     */
    private static final class OpenScratch {
        final Cipher cipher = newCipher();
        final byte[] sealed = new byte[CHUNK_SIZE + TAG_LENGTH];
        final byte[] nonce = new byte[NONCE_LENGTH];
        final byte[] aad = new byte[AAD_LENGTH];
        final byte[] plaintext = new byte[CHUNK_SIZE];
    }

    private static final ThreadLocal<OpenScratch> OPEN_SCRATCH = ThreadLocal.withInitial(OpenScratch::new);

    private ChunkCipher() {}

    /** Returns a new AES/GCM cipher from {@link CryptoProviders#provider()}. Writers keep their own instance. */
    public static Cipher newCipher() {
        try {
            return Cipher.getInstance(TRANSFORMATION, CryptoProviders.provider());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/GCM is not available", e);
        }
    }

    /** The AAD for chunk {@code chunkIndex}: the big-endian index. */
    static byte[] aad(long chunkIndex, byte[] into) {
        if (chunkIndex < 0) {
            throw new IllegalArgumentException("chunkIndex must not be negative: " + chunkIndex);
        }
        for (int i = 0; i < Long.BYTES; i++) {
            into[Long.BYTES - 1 - i] = (byte) (chunkIndex >>> (8 * i));
        }
        return into;
    }

    /** Number of chunks in a file with {@code dataLength} plaintext bytes. */
    public static long chunkCount(long dataLength) {
        return (dataLength + CHUNK_SIZE - 1) >>> CHUNK_SIZE_POWER;
    }

    /** Length in bytes of the tag table for a file with {@code dataLength} plaintext bytes. */
    public static long tagTableLength(long dataLength) {
        return chunkCount(dataLength) * ENTRY_LENGTH;
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
     * Encrypts one chunk under a nonce that the provider generates.
     *
     * @param cipher     the writer's cipher, from {@link #newCipher()}
     * @param key        the file key
     * @param chunkIndex index of the chunk in the file
     * @param in         plaintext
     * @param inOffset   offset of the chunk in {@code in}
     * @param length     chunk length, at most {@link #CHUNK_SIZE}
     * @param out        receives {@code length} ciphertext bytes followed by the chunk's
     *                   {@link #ENTRY_LENGTH}-byte tag-table entry ({@code nonce || tag})
     */
    public static void seal(Cipher cipher, Key key, long chunkIndex, byte[] in, int inOffset, int length, byte[] out)
        throws GeneralSecurityException {
        checkLength(length);
        // No IV given: the provider generates a random one with its approved DRBG.
        cipher.init(Cipher.ENCRYPT_MODE, key, CryptoProviders.secureRandom());
        sealInitialized(cipher, chunkIndex, in, inOffset, length, out);
    }

    /** {@link #seal} with a caller-chosen nonce, for known-answer tests only. */
    static void sealWithNonce(Cipher cipher, Key key, long chunkIndex, byte[] nonce, byte[] in, int inOffset, int length, byte[] out)
        throws GeneralSecurityException {
        checkLength(length);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, nonce));
        sealInitialized(cipher, chunkIndex, in, inOffset, length, out);
    }

    private static void sealInitialized(Cipher cipher, long chunkIndex, byte[] in, int inOffset, int length, byte[] out)
        throws GeneralSecurityException {
        byte[] nonce = cipher.getIV();
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalStateException("provider chose a GCM nonce of unexpected length");
        }
        cipher.updateAAD(aad(chunkIndex, new byte[AAD_LENGTH]));
        int written = cipher.doFinal(in, inOffset, length, out, 0);
        if (written != length + TAG_LENGTH) {
            throw new IllegalStateException("provider chose a GCM tag of unexpected length");
        }
        // ciphertext || tag -> ciphertext || nonce || tag
        System.arraycopy(out, length, out, length + NONCE_LENGTH, TAG_LENGTH);
        System.arraycopy(nonce, 0, out, length, NONCE_LENGTH);
    }

    /**
     * Decrypts and authenticates one chunk. Nothing is written to {@code out} unless the chunk
     * authenticates.
     *
     * @param key        the file key
     * @param chunkIndex index of the chunk in the file
     * @param ciphertext the chunk's ciphertext, from position to limit; consumed
     * @param entry      the chunk's tag-table entry ({@code nonce || tag}), from position to limit
     *                   ({@link #ENTRY_LENGTH} bytes); consumed
     * @param out        receives the plaintext at its position, only if authentication succeeds
     * @throws AEADBadTagException if the ciphertext, nonce, tag or chunk position was altered
     */
    public static void open(Key key, long chunkIndex, ByteBuffer ciphertext, ByteBuffer entry, ByteBuffer out)
        throws GeneralSecurityException {
        int length = ciphertext.remaining();
        checkLength(length);
        if (entry.remaining() != ENTRY_LENGTH) {
            throw new IllegalArgumentException("entry must be " + ENTRY_LENGTH + " bytes, got " + entry.remaining());
        }
        if (out.remaining() < length) {
            throw new IllegalArgumentException("out has " + out.remaining() + " bytes left, chunk needs " + length);
        }
        OpenScratch scratch = OPEN_SCRATCH.get();
        ciphertext.get(scratch.sealed, 0, length);
        entry.get(scratch.nonce);
        entry.get(scratch.sealed, length, TAG_LENGTH);
        Cipher cipher = scratch.cipher;
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, scratch.nonce));
        cipher.updateAAD(aad(chunkIndex, scratch.aad));
        // Keep this a single doFinal over ciphertext||tag. Besides being the fast path, splitting it
        // into update(ciphertext) + doFinal(tag) makes BC-FIPS 2.1.2's native x86_64 GCM reject
        // valid chunks for some lengths. Throws AEADBadTagException before anything reaches out.
        int n = cipher.doFinal(scratch.sealed, 0, length + TAG_LENGTH, scratch.plaintext, 0);
        assert n == length : n;
        out.put(scratch.plaintext, 0, length);
    }

    private static void checkLength(int length) {
        if (length <= 0 || length > CHUNK_SIZE) {
            throw new IllegalArgumentException("chunk length must be in (0, " + CHUNK_SIZE + "], got " + length);
        }
    }
}
