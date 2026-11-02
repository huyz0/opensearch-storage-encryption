/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.util.HexFormat;

import org.opensearch.index.store.cipher.CryptoProviders;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer tests for {@link KeyDerivation}.
 *
 * <p>The expected values were produced by an independent SP 800-108 implementation
 * (src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py).
 * Every file key on disk depends on these derivations, so a change
 * to any expected value here means existing encrypted indices can no longer be read.
 */
public class KeyDerivationKnownAnswerTests extends OpenSearchTestCase {

    static final byte[] MASTER_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    static final byte[] MESSAGE_ID = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");

    static final byte[] EXPECTED_FILE_KEY = hex("7880842664260e88ad71ee04d9f889fe1d13efe0d86041d1dab05d7a02e8d786");

    public void testFileKeyKnownAnswer() {
        assertArrayEquals(EXPECTED_FILE_KEY, KeyDerivation.deriveFileKey(MASTER_KEY, MESSAGE_ID));
        assertArrayEquals(EXPECTED_FILE_KEY, KeyDerivation.deriveAesKey(MASTER_KEY, MESSAGE_ID, "file-encryption"));
    }

    public void testFrameBaseIvKnownAnswer() {
        byte[] frame0 = KeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "frame-0", 16);
        byte[] frame1 = KeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "frame-1", 16);
        assertArrayEquals(hex("15d84b74c799776c0aa832e7e144bb09"), frame0);
        assertArrayEquals(hex("a7d5aeac35ac3ced03734ae446aea2ea"), frame1);
    }

    public void testMultiBlockExpandKnownAnswer() {
        // 49 bytes needs two HMAC-SHA384 blocks, the second one truncated to a single byte.
        byte[] expected = hex("91781bce0e96bc5f00355359d969e875d030b4859fed6ec35b9745668a11b3885cc2d5a74254b8d1697f2391e0536be786");
        assertArrayEquals(expected, KeyDerivation.deriveKey(MASTER_KEY, MESSAGE_ID, "known-answer-test", 49));
    }

    public void testTranslogKeyKnownAnswer() {
        assertArrayEquals(
            hex("b0f404d31dd965f7ea719ad6ee16e9e9655cd821fe91f40636d1f5ece2d0f458"),
            KeyDerivation.deriveAesKey(MASTER_KEY, MESSAGE_ID, "translog-ctr")
        );
    }

    public void testFixedInputLayout() {
        // Label || 0x00 || Context || [L]_32 with L in bits (SP 800-108r1, section 4).
        byte[] fixed = KeyDerivation.fixedInput(new byte[] { 'a', 'b' }, new byte[] { 1, 2, 3 }, 32);
        assertArrayEquals(hex("6162" + "00" + "010203" + "00000100"), fixed);
    }

    /**
     * In FIPS mode the derivation comes from the Bouncy Castle FIPS module. Cross-checks it against
     * the HMAC construction used outside FIPS mode, for random inputs.
     */
    public void testFipsModuleKdfMatchesHmacConstruction() {
        assumeTrue("Bouncy Castle FIPS is only on the classpath in FIPS mode", CryptoProviders.isFipsMode());
        for (int i = 0; i < 20; i++) {
            byte[] key = randomByteArrayOfLength(32);
            byte[] fixedInput = randomByteArrayOfLength(randomIntBetween(1, 60));
            int length = randomIntBetween(1, 200);
            assertArrayEquals(
                KeyDerivation.counterModeHmacSha384(key, fixedInput, length),
                FipsKeyDerivation.counterModeHmacSha384(key, fixedInput, length)
            );
        }
    }

    public void testAwsLcKdfMatchesHmacConstruction() {
        assumeTrue("AWS-LC is only bundled in the FIPS build", CryptoProviders.isFipsMode() && CryptoProviders.isAwsLc());
        for (int i = 0; i < 20; i++) {
            byte[] key = randomByteArrayOfLength(32);
            byte[] fixedInput = randomByteArrayOfLength(randomIntBetween(1, 60));
            int length = randomFrom(16, 24, 32);
            assertArrayEquals(
                KeyDerivation.counterModeHmacSha384(key, fixedInput, length),
                AwsLcKeyDerivation.counterModeHmacSha384(key, fixedInput, length)
            );
        }
    }

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
