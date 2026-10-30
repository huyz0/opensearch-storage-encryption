/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer tests for {@link HkdfKeyDerivation}.
 *
 * <p>The expected values were produced by an independent HKDF implementation
 * (src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py).
 * Every file key and frame IV on disk depends on these derivations, so a change
 * to any expected value here means existing encrypted indices can no longer be read.
 */
public class HkdfKeyDerivationKnownAnswerTests extends OpenSearchTestCase {

    static final byte[] MASTER_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    static final byte[] MESSAGE_ID = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");

    static final byte[] EXPECTED_FILE_KEY = hex("eed4d15a63606f1a006ffad12ad89b6a06afe4198584def8bccd8c3351e146fb");

    public void testFileKeyKnownAnswer() {
        assertArrayEquals(EXPECTED_FILE_KEY, HkdfKeyDerivation.deriveFileKey(MASTER_KEY, MESSAGE_ID));
        assertArrayEquals(EXPECTED_FILE_KEY, HkdfKeyDerivation.deriveAesKey(MASTER_KEY, MESSAGE_ID, "file-encryption"));
    }

    public void testFrameBaseIvKnownAnswer() {
        byte[] frame0 = HkdfKeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "frame-0", 16);
        byte[] frame1 = HkdfKeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "frame-1", 16);
        assertArrayEquals(hex("823f88e33400dda05516cc045f0d6021"), frame0);
        assertArrayEquals(hex("a9745fa91eb99fe25c7605adcda90fdb"), frame1);
    }

    public void testMultiBlockExpandKnownAnswer() {
        // 49 bytes needs two HMAC-SHA384 blocks, the second one truncated to a single byte.
        byte[] expected = hex("b81af9278622dfdf9e0105ed094b9857a134f73a028606b3b300748eeb7ec8b0432a76011e2ec806662ec6935c68dda09c");
        assertArrayEquals(expected, HkdfKeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "known-answer-test", 49));
    }

    public void testTranslogBaseIvKnownAnswer() {
        // UUIDs shorter than 16 bytes are zero padded.
        byte[] shortUuidIv = HkdfKeyDerivation.deriveTranslogBaseIV(MASTER_KEY, "short-uuid");
        assertArrayEquals(hex("29c860c2799af4bb5392e66e31d0e20c"), shortUuidIv);
        // Only the first 16 UTF-8 bytes of the UUID contribute; the rest is ignored.
        byte[] longUuidIv = HkdfKeyDerivation.deriveTranslogBaseIV(MASTER_KEY, "8rKGBKWtR9S2bIZ_hXlTQw-trailing");
        assertArrayEquals(hex("156cef97ad4e9da015f631a5cc1ea740"), longUuidIv);
        assertArrayEquals(longUuidIv, HkdfKeyDerivation.deriveTranslogBaseIV(MASTER_KEY, "8rKGBKWtR9S2bIZ_"));
    }

    /**
     * Cross-checks against the JDK's RFC 5869 HKDF with the master key as salt and the
     * messageId as input keying material, for random inputs.
     */
    public void testMatchesJdkHkdf() throws Exception {
        KDF kdf = KDF.getInstance("HKDF-SHA384");
        for (int i = 0; i < 20; i++) {
            byte[] masterKey = randomByteArrayOfLength(32);
            byte[] messageId = randomByteArrayOfLength(16);
            String context = randomAlphaOfLengthBetween(1, 40);
            byte[] info = context.getBytes(StandardCharsets.UTF_8);
            int length = randomIntBetween(1, 200);
            byte[] expected = kdf.deriveData(HKDFParameterSpec.ofExtract().addSalt(masterKey).addIKM(messageId).thenExpand(info, length));
            assertArrayEquals(expected, HkdfKeyDerivation.deriveKey(masterKey, messageId, context, length));
        }
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
