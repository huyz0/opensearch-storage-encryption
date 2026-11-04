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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.key.KeyDerivation;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the encrypted translog file format in {@link CryptoFileChannelWrapper}. Frame behaviour
 * (torn frames, tampering, appends) is covered by {@link TranslogFrameEncryptionTests}.
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

    public void testAppendIsRejected() throws IOException {
        Path path = createTempDir().resolve("translog-8.tlog");
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, UUID);
        expectThrows(IllegalArgumentException.class, () -> factory.open(path, StandardOpenOption.CREATE, StandardOpenOption.APPEND));
        assertFalse(Files.exists(path));
    }

    public void testRoundTripAndLayout() throws IOException {
        Path path = createTempDir().resolve("translog-1.tlog");
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 50_000));
        int headerSize = writeTranslog(path, data);

        long frames = (data.length + TranslogChunkManager.DEFAULT_MAX_FRAME_SIZE - 1) / TranslogChunkManager.DEFAULT_MAX_FRAME_SIZE;
        assertEquals(
            "format header plus a fixed overhead per frame",
            headerSize + TranslogChunkManager.FORMAT_HEADER_SIZE + data.length + frames * TranslogChunkManager.FRAME_OVERHEAD,
            Files.size(path)
        );
        byte[] raw = Files.readAllBytes(path);
        ByteBuffer format = ByteBuffer.wrap(raw, headerSize, TranslogChunkManager.FORMAT_HEADER_SIZE);
        assertEquals(TranslogChunkManager.FORMAT_MAGIC, format.getInt());
        assertEquals(TranslogChunkManager.FORMAT_VERSION, format.getInt());
        assertEquals(TranslogChunkManager.DEFAULT_MAX_FRAME_SIZE, format.getInt());

        try (CryptoFileChannelWrapper channel = open(path, StandardOpenOption.READ)) {
            assertEquals("size() hides the format header and frame overhead", headerSize + data.length, channel.size());
            assertArrayEquals(data, readFully(channel, headerSize, data.length));
        }
        // The header itself is untouched, because core reads it through a plain FileChannel.
        try (FileChannel plain = FileChannel.open(path, StandardOpenOption.READ)) {
            TranslogHeader.read(UUID, path, plain);
        }
    }

    /**
     * Pins the on-disk format: decrypts every frame with plain JCE AES-GCM, the file key derived
     * from the data key and the message ID with the label spelled out, and the frame index as AAD.
     */
    public void testFramesDecryptWithPlainGcm() throws Exception {
        Path path = createTempDir().resolve("translog-4.tlog");
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 30_000));
        int headerSize = writeTranslog(path, data);

        ByteBuffer raw = ByteBuffer.wrap(Files.readAllBytes(path));
        raw.position(headerSize + 3 * Integer.BYTES);
        byte[] messageId = new byte[16];
        raw.get(messageId);
        SecretKeySpec fileKey = new SecretKeySpec(KeyDerivation.deriveAesKey(key.getEncoded(), messageId, "translog-gcm"), "AES");
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        ByteBuffer plain = ByteBuffer.allocate(data.length);
        for (long index = 0; raw.hasRemaining(); index++) {
            int length = raw.getInt();
            // ciphertext || tag in one doFinal: BC-FIPS rejects valid frames decrypted as update + doFinal(tag).
            byte[] sealed = new byte[length + 16];
            byte[] nonce = new byte[12];
            raw.get(sealed, 0, length).get(nonce).get(sealed, length, 16);
            gcm.init(Cipher.DECRYPT_MODE, fileKey, new GCMParameterSpec(128, nonce));
            gcm.updateAAD(ByteBuffer.allocate(Long.BYTES).putLong(index).array());
            plain.put(gcm.doFinal(sealed));
        }
        assertArrayEquals(data, plain.array());
    }

    public void testDataKeyIsNotUsedDirectly() throws Exception {
        Path path = createTempDir().resolve("translog-9.tlog");
        int headerSize = writeTranslog(path, randomByteArrayOfLength(randomIntBetween(16, 5000)));
        byte[] raw = Files.readAllBytes(path);
        int frame = headerSize + TranslogChunkManager.FORMAT_HEADER_SIZE;
        int length = ByteBuffer.wrap(raw, frame, 4).getInt();
        int nonceAt = frame + 4 + length;
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOfRange(raw, nonceAt, nonceAt + 12)));
        gcm.updateAAD(new byte[Long.BYTES]);
        byte[] sealed = new byte[length + 16];
        System.arraycopy(raw, frame + 4, sealed, 0, length);
        System.arraycopy(raw, nonceAt + 12, sealed, length, 16);
        expectThrows(javax.crypto.AEADBadTagException.class, () -> gcm.doFinal(sealed));
    }

    public void testEveryFileGetsItsOwnKey() throws IOException {
        // Same key, translog UUID, generation and plaintext, as for a file recreated under the same name.
        byte[] data = new byte[4096];
        Path a = createTempDir().resolve("translog-7.tlog");
        Path b = createTempDir().resolve("translog-7.tlog");
        int headerSize = writeTranslog(a, data);
        writeTranslog(b, data);

        byte[] rawA = Files.readAllBytes(a);
        byte[] rawB = Files.readAllBytes(b);
        int idStart = headerSize + 3 * Integer.BYTES;
        int dataStart = headerSize + TranslogChunkManager.FORMAT_HEADER_SIZE;
        assertFalse(Arrays.equals(Arrays.copyOfRange(rawA, idStart, dataStart), Arrays.copyOfRange(rawB, idStart, dataStart)));
        assertFalse(Arrays.equals(Arrays.copyOfRange(rawA, dataStart, rawA.length), Arrays.copyOfRange(rawB, dataStart, rawB.length)));
    }

    public void testRejectsOtherFormats() throws IOException {
        Path path = createTempDir().resolve("translog-10.tlog");
        int headerSize = writeTranslog(path, randomByteArrayOfLength(100));
        ByteBuffer patch = randomFrom(
            // upstream's version 1 (derived nonces, no message ID)
            ByteBuffer.allocate(8).putInt(TranslogChunkManager.FORMAT_MAGIC).putInt(1),
            // this fork's earlier AES-CTR format "OST3"
            ByteBuffer.allocate(4).putInt(0x4F535433),
            // a frame size larger than one GCM chunk
            ByteBuffer.allocate(12).putInt(TranslogChunkManager.FORMAT_MAGIC).putInt(TranslogChunkManager.FORMAT_VERSION).putInt(1 << 20)
        );
        try (FileChannel raw = FileChannel.open(path, StandardOpenOption.WRITE)) {
            raw.write(patch.flip(), headerSize);
        }
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, UUID);
        IOException e = expectThrows(IOException.class, () -> factory.open(path, StandardOpenOption.READ));
        assertTrue(e.getMessage(), e.getMessage().contains("Unsupported translog encryption format"));
    }

    public void testKeyFailureLeavesNoFormatHeader() throws IOException {
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

    public void testKeyFailureOnOpenIsAnIOException() throws IOException {
        Path path = createTempDir().resolve("translog-11.tlog");
        writeTranslog(path, randomByteArrayOfLength(100));
        KeyResolver failing = mock(KeyResolver.class);
        when(failing.getDataKey()).thenThrow(new IllegalStateException("key unavailable"));
        CryptoChannelFactory factory = new CryptoChannelFactory(failing, UUID);
        IOException e = expectThrows(IOException.class, () -> factory.open(path, StandardOpenOption.READ));
        assertTrue(e.getCause() instanceof IllegalStateException);
    }

    public void testDecryptingStreamClosesTheFileWhenSetupFails() throws IOException {
        Path path = createTempDir().resolve("translog-12.tlog");
        writeTranslog(path, randomByteArrayOfLength(100));
        KeyResolver failing = mock(KeyResolver.class);
        when(failing.getDataKey()).thenThrow(new IllegalStateException("key unavailable"));
        // The test framework's file system fails the test if the raw channel is left open.
        IOException e = expectThrows(IOException.class, () -> new CryptoDecryptingInputStream(path, failing, UUID));
        assertTrue(e.getCause() instanceof IllegalStateException);
    }

}
