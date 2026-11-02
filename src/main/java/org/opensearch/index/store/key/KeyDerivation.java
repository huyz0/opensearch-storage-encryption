/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.cipher.CryptoProviders;

/**
 * Derives per-file keys from an index data key with the NIST SP 800-108r1 key-based KDF in counter
 * mode, HMAC-SHA-384 as the PRF and a 32-bit counter before the fixed input:
 *
 * <pre>
 * K(i)  = HMAC-SHA-384(KI, [i]_32 || Label || 0x00 || Context || [L]_32),  i = 1, 2, ...
 * KO    = the first L bits of K(1) || K(2) || ...
 * </pre>
 *
 * where {@code KI} is the 32-byte data key, {@code Label} the UTF-8 context string (for example
 * {@code "file-encryption"}), {@code Context} the 16-byte message ID and {@code L} the output length
 * in bits. SP 800-108 is the NIST-approved way to derive keys from a key (SP 800-133r2, 6.3).
 *
 * <p>In FIPS mode the derivation runs inside the validated module: the AWS-LC FIPS module's
 * {@code CounterKdfWithHmacSHA384} when the plugin runs on AWS-LC, otherwise Bouncy Castle FIPS's
 * {@code FipsKDF} counter mode; each is an approved service of its module. Outside FIPS mode it is
 * computed here with the JCE HMAC. All three give the same bytes.
 *
 * @opensearch.internal
 */
public final class KeyDerivation {

    private static final String HMAC_ALGORITHM = "HmacSHA384";
    private static final int HASH_LENGTH = 48; // SHA-384 output length

    private KeyDerivation() {}

    /**
     * Derives {@code keyLength} bytes from the master key, the message ID and a label.
     *
     * @param masterKey the master key (32 bytes)
     * @param messageId the unique file identifier (16 bytes)
     * @param label the SP 800-108 Label, which separates uses of the same master key and message ID
     * @param keyLength the desired output length in bytes
     * @return derived key bytes
     */
    public static byte[] deriveKey(byte[] masterKey, byte[] messageId, String label, int keyLength) {
        if (masterKey == null || masterKey.length != 32) {
            throw new IllegalArgumentException("Master key must be 32 bytes");
        }
        if (messageId == null || messageId.length != 16) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        if (keyLength <= 0 || keyLength > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("Invalid key length: " + keyLength);
        }
        byte[] fixedInput = fixedInput(label.getBytes(StandardCharsets.UTF_8), messageId, keyLength);
        if (CryptoProviders.isFipsMode()) {
            return CryptoProviders.isAwsLc()
                ? AwsLcKeyDerivation.counterModeHmacSha384(masterKey, fixedInput, keyLength)
                : FipsKeyDerivation.counterModeHmacSha384(masterKey, fixedInput, keyLength);
        }
        return counterModeHmacSha384(masterKey, fixedInput, keyLength);
    }

    /** Derives a 32-byte AES-256 key. */
    public static byte[] deriveAesKey(byte[] masterKey, byte[] messageId, String label) {
        return deriveKey(masterKey, messageId, label, 32);
    }

    /**
     * Derives the AES-256 key for one index file.
     *
     * @param masterKey the master key (32 bytes)
     * @param messageId the file's unique message ID (16 bytes)
     * @return derived 32-byte file key
     */
    public static byte[] deriveFileKey(byte[] masterKey, byte[] messageId) {
        return deriveKey(masterKey, messageId, "file-encryption", 32);
    }

    /** {@code Label || 0x00 || Context || [L]_32}, with {@code L} in bits. */
    static byte[] fixedInput(byte[] label, byte[] context, int keyLength) {
        return ByteBuffer
            .allocate(label.length + 1 + context.length + Integer.BYTES)
            .put(label)
            .put((byte) 0)
            .put(context)
            .putInt(keyLength * Byte.SIZE)
            .array();
    }

    /** SP 800-108 counter mode, counter first, computed with the JCE HMAC of the chosen provider. */
    static byte[] counterModeHmacSha384(byte[] key, byte[] fixedInput, int keyLength) {
        byte[] block = new byte[HASH_LENGTH];
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM, CryptoProviders.provider());
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] out = new byte[keyLength];
            for (int i = 1, offset = 0; offset < keyLength; i++, offset += HASH_LENGTH) {
                mac.update(ByteBuffer.allocate(Integer.BYTES).putInt(i).array());
                mac.update(fixedInput);
                mac.doFinal(block, 0);
                System.arraycopy(block, 0, out, offset, Math.min(HASH_LENGTH, keyLength - offset));
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("key derivation failed", e);
        } finally {
            // The last block may hold key bytes beyond keyLength.
            Arrays.fill(block, (byte) 0);
        }
    }
}
