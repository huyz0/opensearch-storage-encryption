/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.HexFormat;

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

    private static final byte[] FILE_KEY = hex("eed4d15a63606f1a006ffad12ad89b6a06afe4198584def8bccd8c3351e146fb");
    private static final SecretKeySpec KEY = new SecretKeySpec(FILE_KEY, "AES");

    /** Two chunks: one full chunk and a 100-byte tail. */
    private static final byte[] PLAINTEXT = plaintext(ChunkCipher.CHUNK_SIZE + 100);

    public void testConstants() {
        assertEquals(8192, ChunkCipher.CHUNK_SIZE);
        assertEquals(16, ChunkCipher.TAG_LENGTH);
        assertEquals(12, ChunkCipher.NONCE_LENGTH);
    }

    public void testNonceKnownAnswer() {
        assertArrayEquals(hex("000000000000000000000000"), ChunkCipher.nonce(0));
        assertArrayEquals(hex("000000000000000000000001"), ChunkCipher.nonce(1));
        assertArrayEquals(hex("000000000102030405060708"), ChunkCipher.nonce(0x0102030405060708L));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.nonce(-1));
    }

    /** The footer auth nonce (FF x 8 || 00 x 4) must never equal a chunk nonce. */
    public void testChunkNoncesCannotCollideWithFooterNonce() {
        byte[] footerNonce = hex("ffffffffffffffff00000000");
        for (long index : new long[] {
            0,
            1,
            0xffffffffL,
            0xffffffff00000000L >>> 1,
            Long.MAX_VALUE,
            randomLongBetween(0, Long.MAX_VALUE) }) {
            byte[] nonce = ChunkCipher.nonce(index);
            assertArrayEquals(new byte[4], Arrays.copyOf(nonce, 4));
            assertFalse(Arrays.equals(footerNonce, nonce));
        }
    }

    public void testSizes() {
        assertEquals(0, ChunkCipher.chunkCount(0));
        assertEquals(1, ChunkCipher.chunkCount(1));
        assertEquals(1, ChunkCipher.chunkCount(8192));
        assertEquals(2, ChunkCipher.chunkCount(8193));
        assertEquals(32, ChunkCipher.tagTableLength(8193));
        assertEquals(8192, ChunkCipher.chunkLength(0, 8193));
        assertEquals(1, ChunkCipher.chunkLength(1, 8193));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.chunkLength(2, 8193));
    }

    public void testSealKnownAnswer() throws Exception {
        Cipher cipher = ChunkCipher.newCipher();
        byte[] chunk0 = new byte[ChunkCipher.CHUNK_SIZE + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(cipher, KEY, 0, PLAINTEXT, 0, ChunkCipher.CHUNK_SIZE, chunk0);
        assertArrayEquals(hex("08213356f8326c89cbc87df44a1a1236"), Arrays.copyOf(chunk0, 16));
        assertArrayEquals(hex("473cce9f2b0818086bf67a586a30061f"), tagOf(chunk0, ChunkCipher.CHUNK_SIZE));

        byte[] chunk1 = new byte[100 + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(cipher, KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, chunk1);
        assertArrayEquals(hex("e4c89a5c2a394939c7846e0a12a733d4"), Arrays.copyOf(chunk1, 16));
        assertArrayEquals(hex("1201019cde612ca6d0682c9ac2a25e39"), tagOf(chunk1, 100));
    }

    public void testRoundTripHeapAndDirect() throws Exception {
        int length = randomIntBetween(1, ChunkCipher.CHUNK_SIZE);
        long chunkIndex = randomLongBetween(0, Long.MAX_VALUE);
        byte[] plain = randomByteArrayOfLength(length);
        byte[] sealed = new byte[length + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, chunkIndex, plain, 0, length, sealed);

        for (boolean direct : new boolean[] { false, true }) {
            ByteBuffer ciphertext = buffer(direct, Arrays.copyOf(sealed, length));
            ByteBuffer tag = buffer(direct, tagOf(sealed, length));
            ByteBuffer out = direct ? ByteBuffer.allocateDirect(length) : ByteBuffer.allocate(length);
            ChunkCipher.open(KEY, chunkIndex, ciphertext, tag, out);
            assertEquals(length, out.position());
            byte[] actual = new byte[length];
            out.flip().get(actual);
            assertArrayEquals(plain, actual);
        }
    }

    public void testEveryCiphertextAndTagBitIsAuthenticated() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, sealed);
        for (int i = 0; i < sealed.length; i++) {
            byte[] tampered = sealed.clone();
            tampered[i] ^= (byte) (1 << randomIntBetween(0, 7));
            expectThrows(AEADBadTagException.class, () -> open(1, tampered, 100));
        }
        // Untampered still opens.
        open(1, sealed, 100);
    }

    public void testChunkMovedToAnotherIndexIsRejected() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(ChunkCipher.newCipher(), KEY, 1, PLAINTEXT, ChunkCipher.CHUNK_SIZE, 100, sealed);
        expectThrows(AEADBadTagException.class, () -> open(0, sealed, 100));
        expectThrows(AEADBadTagException.class, () -> open(2, sealed, 100));
    }

    public void testWrongKeyIsRejected() throws Exception {
        byte[] sealed = new byte[100 + ChunkCipher.TAG_LENGTH];
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
                    ByteBuffer.wrap(sealed, 100, ChunkCipher.TAG_LENGTH),
                    ByteBuffer.allocate(100)
                )
        );
    }

    public void testWriterCipherRefusesNonceReuse() throws Exception {
        Cipher cipher = ChunkCipher.newCipher();
        byte[] out = new byte[100 + ChunkCipher.TAG_LENGTH];
        ChunkCipher.seal(cipher, KEY, 7, PLAINTEXT, 0, 100, out);
        // SunJCE refuses key+IV reuse for GCM encryption ("Cannot reuse iv for GCM encryption").
        expectThrows(InvalidAlgorithmParameterException.class, () -> ChunkCipher.seal(cipher, KEY, 7, PLAINTEXT, 0, 100, out));
    }

    public void testRejectsBadLengths() {
        byte[] out = new byte[ChunkCipher.CHUNK_SIZE + 1 + ChunkCipher.TAG_LENGTH];
        Cipher cipher = ChunkCipher.newCipher();
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.seal(cipher, KEY, 0, PLAINTEXT, 0, 0, out));
        expectThrows(IllegalArgumentException.class, () -> ChunkCipher.seal(cipher, KEY, 0, PLAINTEXT, 0, ChunkCipher.CHUNK_SIZE + 1, out));
        expectThrows(
            IllegalArgumentException.class,
            () -> ChunkCipher.open(KEY, 0, ByteBuffer.allocate(10), ByteBuffer.allocate(15), ByteBuffer.allocate(10))
        );
    }

    private static void open(long chunkIndex, byte[] sealed, int length) throws Exception {
        ChunkCipher
            .open(
                KEY,
                chunkIndex,
                ByteBuffer.wrap(sealed, 0, length),
                ByteBuffer.wrap(sealed, length, ChunkCipher.TAG_LENGTH),
                ByteBuffer.allocate(length)
            );
    }

    private static ByteBuffer buffer(boolean direct, byte[] bytes) {
        ByteBuffer b = direct ? ByteBuffer.allocateDirect(bytes.length) : ByteBuffer.allocate(bytes.length);
        return b.put(bytes).flip();
    }

    private static byte[] tagOf(byte[] sealed, int length) {
        return Arrays.copyOfRange(sealed, length, length + ChunkCipher.TAG_LENGTH);
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
