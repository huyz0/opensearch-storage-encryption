/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the encrypted translog file format in {@link CryptoFileChannelWrapper}.
 */
public class CryptoFileChannelWrapperTests extends OpenSearchTestCase {

    private static final String UUID = "test-translog-uuid";
    private static final OpenOption[] WRITE = { StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, StandardOpenOption.READ };

    private KeyResolver keyResolver;
    private SecretKeySpec key;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        byte[] raw = new byte[32];
        random().nextBytes(raw);
        key = new SecretKeySpec(raw, "AES");
        keyResolver = mock(KeyResolver.class);
        when(keyResolver.getDataKey()).thenReturn(key);
    }

    private CryptoFileChannelWrapper open(Path path, OpenOption... options) throws IOException {
        return new CryptoFileChannelWrapper(FileChannel.open(path, options), keyResolver, path, Set.of(options), UUID);
    }

    /** Writes a core header followed by {@code data}, without closing anything gracefully. */
    private int writeTranslog(Path path, byte[] data) throws IOException {
        try (CryptoFileChannelWrapper channel = open(path, WRITE)) {
            TranslogHeader header = new TranslogHeader(UUID, 1L);
            header.write(channel, false);
            assertEquals(header.sizeInBytes(), channel.headerSize());
            channel.write(ByteBuffer.wrap(data));
            return header.sizeInBytes();
        }
    }

    private static byte[] readFully(FileChannel channel, long position, int length) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(length);
        while (buf.hasRemaining()) {
            int n = channel.read(buf, position + buf.position());
            assertTrue("unexpected EOF", n > 0);
        }
        return buf.array();
    }

    public void testRoundTripAndLayout() throws IOException {
        Path path = createTempDir().resolve("translog-1.tlog");
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 50_000));
        int headerSize = writeTranslog(path, data);

        assertEquals(
            "magic and nonce add a fixed prefix",
            headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH + data.length,
            Files.size(path)
        );
        byte[] raw = Files.readAllBytes(path);
        assertEquals(CryptoFileChannelWrapper.MAGIC, ByteBuffer.wrap(raw, headerSize, 4).getInt());
        assertFalse(
            "data must not be stored in plaintext",
            Arrays.equals(data, Arrays.copyOfRange(raw, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH, raw.length))
        );

        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            assertEquals("size() hides the prefix", headerSize + data.length, channel.size());
            assertArrayEquals(data, readFully(channel, headerSize, data.length));
            // The header itself is untouched, because core reads it through a plain FileChannel.
        }
        try (FileChannel plain = FileChannel.open(path, StandardOpenOption.READ)) {
            TranslogHeader.read(UUID, path, plain);
        }
    }

    public void testEveryFileGetsItsOwnNonce() throws IOException {
        // Same key, translog UUID, generation and plaintext: the situation of a primary and its replica.
        byte[] data = randomByteArrayOfLength(4096);
        Path a = createTempDir().resolve("translog-7.tlog");
        Path b = createTempDir().resolve("translog-7.tlog");
        int headerSize = writeTranslog(a, data);
        writeTranslog(b, data);

        byte[] rawA = Files.readAllBytes(a);
        byte[] rawB = Files.readAllBytes(b);
        int dataStart = headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH;
        assertFalse(
            Arrays.equals(Arrays.copyOfRange(rawA, headerSize + 4, dataStart), Arrays.copyOfRange(rawB, headerSize + 4, dataStart))
        );
        // With a shared nonce, ciphertext XOR would equal plaintext XOR (all zeros here).
        assertFalse(Arrays.equals(Arrays.copyOfRange(rawA, dataStart, rawA.length), Arrays.copyOfRange(rawB, dataStart, rawB.length)));
    }

    public void testDataIsReadableWhileStillOpenAndAfterCrash() throws IOException {
        Path path = createTempDir().resolve("translog-2.tlog");
        byte[] first = randomByteArrayOfLength(randomIntBetween(1, 10_000));
        byte[] second = randomByteArrayOfLength(randomIntBetween(1, 10_000));

        FileChannel raw = FileChannel.open(path, WRITE);
        CryptoFileChannelWrapper writer = new CryptoFileChannelWrapper(raw, keyResolver, path, Set.of(WRITE), UUID);
        TranslogHeader header = new TranslogHeader(UUID, 1L);
        header.write(writer, false);
        int headerSize = header.sizeInBytes();
        writer.write(ByteBuffer.wrap(first));

        // A second reader sees everything written so far, with the writer still open.
        try (CryptoFileChannelWrapper reader = open(path, StandardOpenOption.READ)) {
            assertEquals(headerSize + first.length, reader.size());
            assertArrayEquals(first, readFully(reader, headerSize, first.length));
        }

        writer.write(ByteBuffer.wrap(second));
        // Simulate kill -9: the raw file is left as is, nothing is finalized.
        raw.close();

        try (CryptoFileChannelWrapper reader = open(path, StandardOpenOption.READ)) {
            assertArrayEquals(first, readFully(reader, headerSize, first.length));
            assertArrayEquals(second, readFully(reader, headerSize + first.length, second.length));
        }
    }

    public void testRandomAccessReadsAndAppendOnlyWrites() throws IOException {
        Path path = createTempDir().resolve("translog-3.tlog");
        byte[] data = randomByteArrayOfLength(20_000);
        int headerSize = writeTranslog(path, data);

        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            for (int i = 0; i < 50; i++) {
                int off = randomIntBetween(0, data.length - 1);
                int len = randomIntBetween(1, data.length - off);
                assertArrayEquals(Arrays.copyOfRange(data, off, off + len), readFully(channel, headerSize + off, len));
            }

            // Overwriting data would reuse keystream, and writing past the end would leave a hole.
            int off = randomIntBetween(0, data.length - 1);
            expectThrows(IOException.class, () -> channel.write(ByteBuffer.wrap(new byte[] { 1 }), headerSize + off));
            expectThrows(IOException.class, () -> channel.write(ByteBuffer.wrap(new byte[] { 1 }), headerSize + data.length + 1));
            assertArrayEquals(data, readFully(channel, headerSize, data.length));

            // Appending at the end works, positional or relative.
            byte[] more = randomByteArrayOfLength(randomIntBetween(1, 100));
            channel.write(ByteBuffer.wrap(more), headerSize + data.length);
            channel.position(channel.size());
            byte[] evenMore = randomByteArrayOfLength(randomIntBetween(1, 100));
            channel.write(ByteBuffer.wrap(evenMore));
            assertArrayEquals(more, readFully(channel, headerSize + data.length, more.length));
            assertArrayEquals(evenMore, readFully(channel, headerSize + data.length + more.length, evenMore.length));
        }
    }

    public void testDataMatchesWholeStreamCtr() throws Exception {
        Path path = createTempDir().resolve("translog-4.tlog");
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 5000));
        int headerSize = writeTranslog(path, data);

        byte[] raw = Files.readAllBytes(path);
        byte[] nonce = Arrays.copyOfRange(raw, headerSize + 4, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH);
        Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
        // The CTR key is HKDF(data key, nonce, "translog-ctr"), not the data key itself. The context
        // string is spelled out to pin the on-disk format.
        SecretKeySpec fileKey = new SecretKeySpec(HkdfKeyDerivation.deriveAesKey(key.getEncoded(), nonce, "translog-ctr"), "AES");
        ctr.init(Cipher.DECRYPT_MODE, fileKey, new IvParameterSpec(nonce));
        byte[] plain = ctr.doFinal(raw, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH, data.length);
        assertArrayEquals("data is one AES-CTR stream starting at the nonce", data, plain);
    }

    public void testCounterBlockCarriesAcrossBytes() {
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, 12, 16, (byte) 0xFF);
        byte[] expected = new byte[16];
        expected[11] = 1;
        expected[15] = 0;
        assertArrayEquals(expected, TranslogCipher.counterBlock(nonce, 1));

        byte[] allOnes = new byte[16];
        Arrays.fill(allOnes, (byte) 0xFF);
        assertArrayEquals("wraps around like a 128-bit counter", new byte[16], TranslogCipher.counterBlock(allOnes, 1));

        byte[] zero = new byte[16];
        byte[] big = TranslogCipher.counterBlock(zero, 0x0102030405060708L);
        assertArrayEquals(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, Arrays.copyOfRange(big, 8, 16));
    }

    public void testReadStartingInHeaderStopsAtHeaderEnd() throws IOException {
        Path path = createTempDir().resolve("translog-5.tlog");
        byte[] data = randomByteArrayOfLength(1000);
        int headerSize = writeTranslog(path, data);

        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            ByteBuffer buf = ByteBuffer.allocate(8192);
            assertEquals(headerSize, channel.read(buf, 0));
            assertArrayEquals(Arrays.copyOf(Files.readAllBytes(path), headerSize), Arrays.copyOf(buf.array(), headerSize));

            // Relative reads continue into decrypted data.
            channel.position(0);
            ByteBuffer all = ByteBuffer.allocate(headerSize + data.length);
            while (all.hasRemaining() && channel.read(all) > 0) {
            }
            assertArrayEquals(data, Arrays.copyOfRange(all.array(), headerSize, all.capacity()));
            assertEquals(-1, channel.read(ByteBuffer.allocate(1)));
        }
    }

    public void testHeaderOnlyFileHasNoData() throws IOException {
        Path path = createTempDir().resolve("translog-6.tlog");
        int headerSize = writeTranslog(path, new byte[0]);
        assertEquals("no nonce until the first data byte", headerSize, Files.size(path));

        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            assertEquals(headerSize, channel.size());
            assertEquals(-1, channel.read(ByteBuffer.allocate(16), headerSize));
        }
    }

    public void testRejectsUnknownFormat() throws IOException {
        Path path = createTempDir().resolve("translog-8.tlog");
        int headerSize = writeTranslog(path, randomByteArrayOfLength(100));
        try (FileChannel raw = FileChannel.open(path, StandardOpenOption.WRITE)) {
            raw.write(ByteBuffer.wrap(new byte[] { 0, 0, 0, 0 }), headerSize);
        }
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            IOException e = expectThrows(IOException.class, () -> channel.read(ByteBuffer.allocate(16), headerSize));
            assertTrue(e.getMessage(), e.getMessage().contains("Unsupported translog encryption format"));
        }
    }

    public void testTruncatingDataIsRefused() throws IOException {
        Path path = createTempDir().resolve("translog-9.tlog");
        int headerSize = writeTranslog(path, randomByteArrayOfLength(100));
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            expectThrows(IOException.class, () -> channel.truncate(headerSize + 50));
            expectThrows(IOException.class, () -> channel.truncate(headerSize));
            channel.truncate(headerSize + 100); // no-op at the current size
            assertEquals(headerSize + 100, channel.size());
        }

        // A file with only its header can still be truncated.
        Path empty = createTempDir().resolve("translog-11.tlog");
        writeTranslog(empty, new byte[0]);
        try (CryptoFileChannelWrapper channel = open(empty, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            channel.truncate(0);
            assertEquals(0, channel.size());
        }
    }

    public void testScatteringReadFillsEachBufferBeforeTheNext() throws IOException {
        Path path = createTempDir().resolve("translog-10.tlog");
        byte[] data = randomByteArrayOfLength(10_000);
        int headerSize = writeTranslog(path, data);
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            channel.position(headerSize);
            ByteBuffer a = ByteBuffer.allocate(6000);
            ByteBuffer b = ByteBuffer.allocate(4000);
            assertEquals(10_000L, channel.read(new ByteBuffer[] { a, b }, 0, 2));
            assertArrayEquals(Arrays.copyOfRange(data, 0, 6000), a.array());
            assertArrayEquals(Arrays.copyOfRange(data, 6000, 10_000), b.array());
            assertEquals(-1L, channel.read(new ByteBuffer[] { ByteBuffer.allocate(1) }, 0, 1));
        }
    }

    public void testDataKeyIsNotUsedDirectly() throws Exception {
        Path path = createTempDir().resolve("translog-9.tlog");
        byte[] data = randomByteArrayOfLength(randomIntBetween(16, 5000));
        int headerSize = writeTranslog(path, data);

        byte[] raw = Files.readAllBytes(path);
        byte[] nonce = Arrays.copyOfRange(raw, headerSize + 4, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH);
        Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
        ctr.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
        byte[] plain = ctr.doFinal(raw, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH, data.length);
        assertFalse(Arrays.equals(data, plain));
    }

    public void testTruncatingAwayThePrefixStartsANewNonce() throws IOException {
        Path path = createTempDir().resolve("translog-5.tlog");
        TranslogHeader header = new TranslogHeader(UUID, 1L);
        int headerSize = header.sizeInBytes();
        // A header and a prefix with no data, as left by a write that failed after the prefix.
        try (FileChannel raw = FileChannel.open(path, WRITE)) {
            header.write(raw, false);
            byte[] nonce = randomByteArrayOfLength(TranslogCipher.NONCE_LENGTH);
            raw.write(ByteBuffer.allocate(CryptoFileChannelWrapper.PREFIX_LENGTH).putInt(CryptoFileChannelWrapper.MAGIC).put(nonce).flip());
        }
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 1000));
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            assertEquals(headerSize, channel.size());
            assertEquals(-1, channel.read(ByteBuffer.allocate(1), headerSize)); // caches the cipher
            channel.truncate(0);
            channel.position(0);
            header.write(channel, false);
            channel.write(ByteBuffer.wrap(data), headerSize);
        }
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            assertArrayEquals(data, readFully(channel, headerSize, data.length));
        }
    }

    public void testKeyFailureLeavesNoPrefix() throws IOException {
        Path path = createTempDir().resolve("translog-6.tlog");
        KeyResolver failing = mock(KeyResolver.class);
        when(failing.getDataKey()).thenThrow(new IllegalStateException("key unavailable"));
        int headerSize;
        try (
            CryptoFileChannelWrapper channel = new CryptoFileChannelWrapper(
                FileChannel.open(path, WRITE),
                failing,
                path,
                Set.of(WRITE),
                UUID
            )
        ) {
            TranslogHeader header = new TranslogHeader(UUID, 1L);
            header.write(channel, false);
            headerSize = header.sizeInBytes();
            IOException e = expectThrows(IOException.class, () -> channel.write(ByteBuffer.wrap(new byte[] { 1, 2, 3 })));
            assertTrue(e.getCause() instanceof IllegalStateException);
        }
        assertEquals(headerSize, Files.size(path));
    }

    public void testRecreatedFileGetsANewNonce() throws IOException {
        Path path = createTempDir().resolve("translog-7.tlog");
        int headerSize = writeTranslog(path, randomByteArrayOfLength(100));
        byte[] firstNonce = Arrays
            .copyOfRange(Files.readAllBytes(path), headerSize + 4, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH);
        Files.delete(path);

        byte[] data = randomByteArrayOfLength(100);
        writeTranslog(path, data);
        byte[] secondNonce = Arrays
            .copyOfRange(Files.readAllBytes(path), headerSize + 4, headerSize + CryptoFileChannelWrapper.PREFIX_LENGTH);
        assertFalse(Arrays.equals(firstNonce, secondNonce));
        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            assertArrayEquals(data, readFully(channel, headerSize, data.length));
        }
    }

    public void testAppendIsRejected() throws IOException {
        Path path = createTempDir().resolve("translog-8.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, UUID);
        expectThrows(IllegalArgumentException.class, () -> factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND));
        assertFalse(Files.exists(path));
    }
}
