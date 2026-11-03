/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer and tamper tests for {@link ChunkCipher}. Expected values come from
 * src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py, which seals the
 * same plaintext with the {@code cryptography} package and no plugin code.
 */
public class ChunkCipherKnownAnswerTests extends OpenSearchTestCase {

    private static final byte[] FILE_KEY = hex("7880842664260e88ad71ee04d9f889fe1d13efe0d86041d1dab05d7a02e8d786");
    private static final SecretKeySpec KEY = new SecretKeySpec(FILE_KEY, "AES");

    /** Two chunks: one full chunk and a 100-byte tail. */
    private static final byte[] PLAINTEXT = plaintext(ChunkCipher.CHUNK_SIZE + 100);

    public void testConstants() {
        assertEquals(8192, ChunkCipher.CHUNK_SIZE);
        assertEquals(16, ChunkCipher.TAG_LENGTH);
        assertEquals(12, ChunkCipher.NONCE_LENGTH);
        assertEquals(28, ChunkCipher.ENTRY_LENGTH);
    }

    public void testAadKnownAnswer() {
        assertArrayEquals(hex("0000000000000000"), ChunkCipher.aad(0, new byte[8]));
        assertArrayEquals(hex("0000000000000001"), ChunkCipher.aad(1, new byte[8]));
        assertArrayEquals(hex("0102030405060708"), ChunkCipher.aad(0x0102030405060708L, new byte[8]));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.aad(-1, new byte[8]));
    }

    /** The provider generates a fresh nonce for every chunk; they are stored in the entry. */
    public void testSealUsesFreshProviderNonces() throws Exception {
        Cipher cipher = ChunkCipher.newCipher();
        Set<String> nonces = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            byte[] sealed = new byte[100 + ChunkCipher.ENTRY_LENGTH];
            ChunkCipher.seal(cipher, KEY, 1, PLAINTEXT, 0, 100, sealed);
            assertTrue(nonces.add(HexFormat.of().formatHex(sealed, 100, 100 + ChunkCipher.NONCE_LENGTH)));
            open(1, sealed, 100);
        }
    }

    public void testSizes() {
        assertEquals(0, ChunkCipher.chunkCount(0));
        assertEquals(1, ChunkCipher.chunkCount(1));
        assertEquals(1, ChunkCipher.chunkCount(8192));
        assertEquals(2, ChunkCipher.chunkCount(8193));
        assertEquals(56, ChunkCipher.tagTableLength(8193));
        assertEquals(8192, ChunkCipher.chunkLength(0, 8193));
        assertEquals(1, ChunkCipher.chunkLength(1, 8193));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.chunkLength(2, 8193));
    }

    public void testSealKnownAnswer() throws Exception {
        Cipher cipher = ChunkCipher.newCipher();
        byte[] nonce0 = hex("20aa6f79755b30a1ef39cbf5");
        byte[] chunk0 = new byte[ChunkCipher.CHUNK_SIZE + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.sealWithNonce(cipher, KEY, 0, nonce0, PLAINTEXT, 0, ChunkCipher.CHUNK_SIZE, chunk0);
        assertArrayEquals(hex("1567287cd0e5b18a3e41644bc041eae3"), Arrays.copyOf(chunk0, 16));
        assertArrayEquals(concat(nonce0, hex("ea343819d4aa9ce73c9e58851bf1947f")), entryOf(chunk0, ChunkCipher.CHUNK_SIZE));

        byte[] nonce1 = hex("c5d101d10b9c2b347767abad");
        byte[] chunk1 = new byte[100 + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.sealWithNonce(cipher, KEY, 1, nonce1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, chunk1);
        assertArrayEquals(hex("8efcb95ed49d1d86d058a2e50f7b8d70"), Arrays.copyOf(chunk1, 16));
        assertArrayEquals(concat(nonce1, hex("9e154486ac54dc11f441527e41e28276")), entryOf(chunk1, 100));
        open(1, chunk1, 100);
    }

    public void testRoundTripHeapAndDirect() throws Exception {
        int length = randomIntBetween(1, ChunkCipher.CHUNK_SIZE);
        long chunkIndex = randomLongBetween(0, Long.MAX_VALUE);
        byte[] plain = randomByteArrayOfLength(length);
        byte[] sealed = new byte[length + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, chunkIndex, plain, 0, length, sealed);

        for (boolean direct : new boolean[] { false, true }) {
            ByteBuffer ciphertext = buffer(direct, Arrays.copyOf(sealed, length));
            ByteBuffer tag = buffer(direct, entryOf(sealed, length));
            ByteBuffer out = direct ? ByteBuffer.allocateDirect(length) : ByteBuffer.allocate(length);
            ChunkCipher.open(KEY, chunkIndex, ciphertext, tag, out);
            assertEquals(length, out.position());
            byte[] actual = new byte[length];
            out.flip().get(actual);
            assertArrayEquals(plain, actual);
        }
    }

    public void testEveryCiphertextNonceAndTagBitIsAuthenticated() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, sealed);
        for (int i = 0; i < sealed.length; i++) {
            byte[] tampered = sealed.clone();
            tampered[i] ^= (byte) (1 << randomIntBetween(0, 7));
            expectThrows(AEADBadTagException.class, () -> open(1, tampered, 100));
        }
        // Untampered still opens.
        open(1, sealed, 100);
    }

    public void testFailedOpenWritesNothing() throws Exception {
        int length = randomIntBetween(1, ChunkCipher.CHUNK_SIZE);
        byte[] sealed = new byte[length + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 3, randomByteArrayOfLength(length), 0, length, sealed);
        sealed[randomIntBetween(0, sealed.length - 1)] ^= 1;
        for (boolean direct : new boolean[] { false, true }) {
            ByteBuffer ciphertext = buffer(direct, Arrays.copyOf(sealed, length));
            ByteBuffer tag = buffer(direct, entryOf(sealed, length));
            ByteBuffer out = direct ? ByteBuffer.allocateDirect(length) : ByteBuffer.allocate(length);
            expectThrows(AEADBadTagException.class, () -> ChunkCipher.open(KEY, 3, ciphertext, tag, out));
            assertEquals(0, out.position());
            for (int i = 0; i < length; i++) {
                assertEquals(0, out.get(i));
            }
        }
    }

    public void testChunkMovedToAnotherIndexIsRejected() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, sealed);
        expectThrows(AEADBadTagException.class, () -> open(0, sealed, 100));
        expectThrows(AEADBadTagException.class, () -> open(2, sealed, 100));
    }

    public void testWrongKeyIsRejected() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.ENTRY_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, sealed);
        byte[] otherKey = FILE_KEY.clone();
        otherKey[31] ^= 1;
        expectThrows(
            AEADBadTagException.class,
            () -> ChunkCipher
                .open(
                    new SecretKeySpec(otherKey, "AES"),
                    1,
                    ByteBuffer.wrap(sealed, 0, 100),
                    ByteBuffer.wrap(sealed, 100, ChunkCipher.ENTRY_LENGTH),
                    ByteBuffer.allocate(100)
                )
        );
    }

    public void testRejectsBadLengths() {
        byte[] out = new byte[ChunkCipher.CHUNK_SIZE + 1 + ChunkCipher.ENTRY_LENGTH];
        Cipher cipher = ChunkCipher.newCipher();
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.seal(cipher, KEY, 0, PLAINTEXT, 0, 0, out));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.seal(cipher, KEY, 0, PLAINTEXT, 0, ChunkCipher.CHUNK_SIZE + 1, out));
        expectThrows(
            IllegalArgumentException.class,
            () -> ChunkCipher.open(KEY, 0, ByteBuffer.allocate(10), ByteBuffer.allocate(ChunkCipher.TAG_LENGTH), ByteBuffer.allocate(10))
        );
        expectThrows(
            IllegalArgumentException.class,
            () -> ChunkCipher.open(KEY, 0, ByteBuffer.allocate(10), ByteBuffer.allocate(ChunkCipher.ENTRY_LENGTH), ByteBuffer.allocate(9))
        );
    }

    private static void open(long chunkIndex, byte[] sealed, int length) throws Exception {
        ChunkCipher
            .open(
                KEY,
                chunkIndex,
                ByteBuffer.wrap(sealed, 0, length),
                ByteBuffer.wrap(sealed, length, ChunkCipher.ENTRY_LENGTH),
                ByteBuffer.allocate(length)
            );
    }

    private static ByteBuffer buffer(boolean direct, byte[] bytes) {
        ByteBuffer b = direct ? ByteBuffer.allocateDirect(bytes.length) : ByteBuffer.allocate(bytes.length);
        return b.put(bytes).flip();
    }

    private static byte[] entryOf(byte[] sealed, int length) {
        return Arrays.copyOfRange(sealed, length, length + ChunkCipher.ENTRY_LENGTH);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private static byte[] plaintext(int length) {
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
