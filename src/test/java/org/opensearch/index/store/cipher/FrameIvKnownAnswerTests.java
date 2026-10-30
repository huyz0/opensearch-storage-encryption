/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer tests for the frame IV derivation in {@link AesCipherFactory#computeFrameIV}.
 *
 * <p>Files are written with AES-256-GCM using the first 12 bytes of the HKDF frame base IV
 * as the nonce, and read back with AES-CTR starting at counter {@code offset / 16 + 2}.
 * These tests pin the derived IVs and prove that the CTR read path reproduces a standard
 * GCM encryption, independent of the OpenSSL writer. Expected values come from
 * src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py.
 */
public class FrameIvKnownAnswerTests extends OpenSearchTestCase {

    private static final byte[] MASTER_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] MESSAGE_ID = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    private static final byte[] FILE_KEY = hex("eed4d15a63606f1a006ffad12ad89b6a06afe4198584def8bccd8c3351e146fb");
    private static final String PATH = "/golden/_0.fdt";

    public void testFrameIvKnownAnswers() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        byte[] frame0 = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 0, PATH, cache);
        assertArrayEquals(hex("823f88e33400dda05516cc0400000002"), frame0);
        // offset 4097 is in AES block 256, so the counter is 256 + 2 = 0x102
        byte[] frame1 = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 1, 4097, PATH, cache);
        assertArrayEquals(hex("a9745fa91eb99fe25c7605ad00000102"), frame1);
    }

    public void testCounterLayout() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        byte[] base = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 0, PATH, cache);
        assertCounter(base, AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 15, PATH, cache), 2);
        assertCounter(base, AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 16, PATH, cache), 3);
        assertCounter(base, AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 16L * 0x01020304, PATH, cache), 0x01020306);
    }

    public void testCacheDoesNotChangeResult() {
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        byte[] first = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 3, 160, PATH, cache);
        byte[] cached = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 3, 160, PATH, cache);
        byte[] fresh = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 3, 160, PATH, new EncryptionMetadataCache());
        assertArrayEquals(first, cached);
        assertArrayEquals(first, fresh);
    }

    public void testGcmCiphertextKnownAnswer() throws Exception {
        byte[] sealed = gcmEncrypt(goldenPlaintext(1000));
        assertArrayEquals(hex("d7ff0d74e41fc8d67eaf9f451c77492ef6e3180eadc81b3964c93478f1843190"), Arrays.copyOf(sealed, 32));
        assertArrayEquals(hex("3880401a2f71e0835650343c4661b358"), Arrays.copyOfRange(sealed, sealed.length - 16, sealed.length));
    }

    /**
     * Decrypting any range of a GCM-encrypted frame with the CTR read-path IV must give the plaintext back.
     */
    public void testCtrReadPathMatchesGcmWritePath() throws Exception {
        byte[] plaintext = randomByteArrayOfLength(randomIntBetween(1, 5000));
        byte[] sealed = gcmEncrypt(plaintext);
        byte[] ciphertext = Arrays.copyOf(sealed, plaintext.length);
        EncryptionMetadataCache cache = new EncryptionMetadataCache();

        for (int i = 0; i < 50; i++) {
            int offset = randomIntBetween(0, plaintext.length - 1);
            int length = randomIntBetween(1, plaintext.length - offset);
            byte[] iv = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, offset, PATH, cache);
            Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
            ctr.init(Cipher.DECRYPT_MODE, new SecretKeySpec(FILE_KEY, "AES"), new IvParameterSpec(iv));
            ctr.update(new byte[offset & 15]); // skip into the AES block, as the readers do
            byte[] decrypted = ctr.doFinal(ciphertext, offset, length);
            assertArrayEquals(Arrays.copyOfRange(plaintext, offset, offset + length), decrypted);
        }
    }

    private static byte[] gcmEncrypt(byte[] plaintext) throws Exception {
        byte[] frameIv = AesCipherFactory.computeFrameIV(MASTER_KEY, MESSAGE_ID, 0, 0, PATH, new EncryptionMetadataCache());
        byte[] nonce = Arrays.copyOf(frameIv, 12);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(FILE_KEY, "AES"), new GCMParameterSpec(128, nonce));
        return gcm.doFinal(plaintext);
    }

    private static void assertCounter(byte[] base, byte[] iv, int expectedCounter) {
        assertArrayEquals(Arrays.copyOf(base, 12), Arrays.copyOf(iv, 12));
        int counter = ((iv[12] & 0xFF) << 24) | ((iv[13] & 0xFF) << 16) | ((iv[14] & 0xFF) << 8) | (iv[15] & 0xFF);
        assertEquals(expectedCounter, counter);
    }

    static byte[] goldenPlaintext(int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (i * 31 + 7);
        }
        return b;
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
