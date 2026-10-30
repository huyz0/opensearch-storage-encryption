/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Offset-keyed AES-CTR for the data region of one translog file.
 *
 * <p>The keystream for data offset {@code o} starts at counter block {@code nonce + o / 16}
 * (128-bit big-endian addition), so any byte range can be encrypted or decrypted on its own:
 * reads work while the file is still being written, and a crash leaves every written byte
 * decryptable. Each file gets its own random nonce, so no two files share keystream even when
 * they share a key, translog UUID and generation (for example a primary and its replicas).
 *
 * <p>CTR gives confidentiality only; integrity of translog operations relies on the per-operation
 * checksums core already writes.
 *
 * @opensearch.internal
 */
final class TranslogCipher {

    /** Length of the per-file random nonce, in bytes. */
    static final int NONCE_LENGTH = 16;

    private static final int AES_BLOCK = 16;
    private static final byte[] ZERO_BLOCK = new byte[AES_BLOCK];

    private static final ThreadLocal<Cipher> CTR = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance("AES/CTR/NoPadding");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/CTR/NoPadding is not available", e);
        }
    });

    private final SecretKeySpec key;
    private final byte[] nonce;

    TranslogCipher(Key key, byte[] nonce) {
        if (nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("nonce must be " + NONCE_LENGTH + " bytes");
        }
        this.key = new SecretKeySpec(key.getEncoded(), "AES");
        this.nonce = nonce.clone();
    }

    /**
     * Encrypts or decrypts {@code len} bytes of {@code buf} in place. CTR is symmetric, so the
     * same call does both.
     *
     * @param buf the bytes to transform
     * @param off start of the range in {@code buf}
     * @param len number of bytes
     * @param dataOffset offset of {@code buf[off]} within the file's data region
     */
    void apply(byte[] buf, int off, int len, long dataOffset) throws IOException {
        if (len == 0) {
            return;
        }
        Cipher cipher = CTR.get();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(counterBlock(nonce, dataOffset / AES_BLOCK)));
            int skip = (int) (dataOffset % AES_BLOCK);
            if (skip > 0) {
                cipher.update(ZERO_BLOCK, 0, skip);
            }
            int n = cipher.update(buf, off, len, buf, off);
            if (n != len) {
                throw new IOException("AES-CTR produced " + n + " bytes for " + len + " input bytes");
            }
        } catch (GeneralSecurityException e) {
            throw new IOException("Failed to apply translog cipher at data offset " + dataOffset, e);
        }
    }

    /** Returns {@code nonce + blocks} as a 128-bit big-endian counter block. */
    static byte[] counterBlock(byte[] nonce, long blocks) {
        byte[] iv = nonce.clone();
        long carry = blocks;
        for (int i = iv.length - 1; i >= 0 && carry != 0; i--) {
            long sum = (iv[i] & 0xFFL) + (carry & 0xFFL);
            iv[i] = (byte) sum;
            carry = (carry >>> 8) + (sum >>> 8);
        }
        return iv;
    }
}
