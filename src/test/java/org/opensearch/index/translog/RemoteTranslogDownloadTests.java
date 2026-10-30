/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot.TranslogFileSnapshot;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Remote-store translog files are uploaded decrypted and downloaded byte for byte. A downloaded
 * file must read back through {@link CryptoChannelFactory} on a node with a different data key,
 * and must not stay plaintext on disk (H2).
 */
public class RemoteTranslogDownloadTests extends OpenSearchTestCase {

    private static final String UUID = "test-translog-uuid";

    private static KeyResolver newKeyResolver() {
        byte[] raw = new byte[32];
        random().nextBytes(raw);
        KeyResolver keyResolver = mock(KeyResolver.class);
        when(keyResolver.getDataKey()).thenReturn(new SecretKeySpec(raw, "AES"));
        return keyResolver;
    }

    private static int headerSize() {
        return new TranslogHeader(UUID, 1L).sizeInBytes();
    }

    /** Returns translog operations framed as core writes them: size, payload, CRC32 of payload. */
    private static byte[] randomOperations() {
        ByteBuffer out = ByteBuffer.allocate(64 * 1024);
        int count = randomIntBetween(1, 10);
        for (int i = 0; i < count; i++) {
            byte[] payload = randomByteArrayOfLength(randomIntBetween(0, 4_000));
            CRC32 crc = new CRC32();
            crc.update(payload);
            out.putInt(payload.length + Integer.BYTES).put(payload).putInt((int) crc.getValue());
        }
        return Arrays.copyOf(out.array(), out.position());
    }

    /** Writes an encrypted translog file and returns the operation bytes it holds. */
    private static byte[] writeTranslog(CryptoChannelFactory factory, Path path) throws IOException {
        byte[] data = randomOperations();
        try (FileChannel channel = factory.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            new TranslogHeader(UUID, 1L).write(channel, false);
            channel.write(ByteBuffer.wrap(data));
        }
        return data;
    }

    /** What the upload sends: the bytes from the snapshot core hands to the repository. */
    private static byte[] uploadedBytes(Path path, KeyResolver keyResolver) throws IOException {
        // Core closes the snapshot it built (the original) and the one it uploads (the wrapper).
        try (
            TranslogFileSnapshot original = new TranslogFileSnapshot(1L, 1L, path, null);
            DecryptingFileSnapshot snapshot = new DecryptingFileSnapshot(original, keyResolver, UUID);
            InputStream in = snapshot.inputStream()
        ) {
            return in.readAllBytes();
        }
    }

    private static byte[] readData(FileChannel channel, int length) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(length);
        while (buf.hasRemaining()) {
            assertTrue("unexpected EOF", channel.read(buf, headerSize() + buf.position()) > 0);
        }
        return buf.array();
    }

    public void testDownloadedFileReadsBackOnAnotherNodeAndIsEncrypted() throws IOException {
        KeyResolver primaryKey = newKeyResolver();
        Path primaryFile = createTempDir().resolve("translog-3.tlog");
        byte[] data = writeTranslog(new CryptoChannelFactory(primaryKey, UUID), primaryFile);

        byte[] uploaded = uploadedBytes(primaryFile, primaryKey);
        assertEquals(headerSize() + data.length, uploaded.length);
        assertArrayEquals(data, Arrays.copyOfRange(uploaded, headerSize(), uploaded.length));

        // Another node, with its own data key, downloads the blob as-is and opens it.
        Path downloaded = createTempDir().resolve("translog-3.tlog");
        Files.write(downloaded, uploaded);
        CryptoChannelFactory otherNode = new CryptoChannelFactory(newKeyResolver(), UUID);
        try (FileChannel channel = otherNode.open(downloaded, StandardOpenOption.READ)) {
            assertEquals(uploaded.length, channel.size());
            assertArrayEquals(data, readData(channel, data.length));
        }

        byte[] onDisk = Files.readAllBytes(downloaded);
        assertEquals("the file is in the encrypted format", uploaded.length + CryptoFileChannelWrapper.PREFIX_LENGTH, onDisk.length);
        assertArrayEquals("header stays plaintext", Arrays.copyOf(uploaded, headerSize()), Arrays.copyOf(onDisk, headerSize()));
        assertEquals(CryptoFileChannelWrapper.MAGIC, ByteBuffer.wrap(onDisk, headerSize(), Integer.BYTES).getInt());
        assertFalse(
            "data is no longer plaintext",
            Arrays.equals(data, Arrays.copyOfRange(onDisk, headerSize() + CryptoFileChannelWrapper.PREFIX_LENGTH, onDisk.length))
        );
        assertFalse(Files.exists(downloaded.resolveSibling("translog-3.tlog.encrypting")));

        // Opening it again reads the encrypted file without rewriting it.
        try (FileChannel channel = otherNode.open(downloaded, StandardOpenOption.READ)) {
            assertArrayEquals(data, readData(channel, data.length));
        }
        assertArrayEquals(onDisk, Files.readAllBytes(downloaded));
    }

    public void testEncryptedFileIsNotRewritten() throws IOException {
        KeyResolver keyResolver = newKeyResolver();
        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, UUID);
        Path path = createTempDir().resolve("translog-1.tlog");
        writeTranslog(factory, path);
        byte[] before = Files.readAllBytes(path);

        assertFalse(CryptoFileChannelWrapper.encryptIfPlaintext(path, keyResolver, UUID));
        factory.open(path, StandardOpenOption.READ).close();
        assertArrayEquals(before, Files.readAllBytes(path));
    }

    public void testHeaderOnlyFileIsNotRewritten() throws IOException {
        KeyResolver keyResolver = newKeyResolver();
        Path path = createTempDir().resolve("translog-1.tlog");
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            new TranslogHeader(UUID, 1L).write(channel, false);
        }
        byte[] before = Files.readAllBytes(path);

        assertFalse(CryptoFileChannelWrapper.encryptIfPlaintext(path, keyResolver, UUID));
        assertArrayEquals(before, Files.readAllBytes(path));
    }

    public void testLeftoverTemporaryFileIsReplaced() throws IOException {
        KeyResolver keyResolver = newKeyResolver();
        Path primaryFile = createTempDir().resolve("translog-2.tlog");
        byte[] data = writeTranslog(new CryptoChannelFactory(keyResolver, UUID), primaryFile);

        Path downloaded = createTempDir().resolve("translog-2.tlog");
        Files.write(downloaded, uploadedBytes(primaryFile, keyResolver));
        // A crash in the middle of an earlier conversion left a partial temporary file behind.
        Files.write(downloaded.resolveSibling("translog-2.tlog.encrypting"), randomByteArrayOfLength(100));

        assertTrue(CryptoFileChannelWrapper.encryptIfPlaintext(downloaded, keyResolver, UUID));
        try (FileChannel channel = new CryptoChannelFactory(keyResolver, UUID).open(downloaded, StandardOpenOption.READ)) {
            assertArrayEquals(data, readData(channel, data.length));
        }
        assertFalse(Files.exists(downloaded.resolveSibling("translog-2.tlog.encrypting")));
    }

    public void testDamagedFileIsNotRewritten() throws IOException {
        KeyResolver keyResolver = newKeyResolver();
        Path primaryFile = createTempDir().resolve("translog-2.tlog");
        writeTranslog(new CryptoChannelFactory(keyResolver, UUID), primaryFile);
        byte[] uploaded = uploadedBytes(primaryFile, keyResolver);

        // Flip one byte of the first operation's payload: its checksum no longer matches, so this
        // is not recognisable plaintext and must not be encrypted a second time.
        Path damaged = createTempDir().resolve("translog-2.tlog");
        int payloadStart = headerSize() + Integer.BYTES;
        assumeTrue("needs a non-empty first payload", ByteBuffer.wrap(uploaded, headerSize(), Integer.BYTES).getInt() > Integer.BYTES);
        uploaded[payloadStart] ^= 1;
        Files.write(damaged, uploaded);

        assertFalse(CryptoFileChannelWrapper.encryptIfPlaintext(damaged, keyResolver, UUID));
        assertArrayEquals(uploaded, Files.readAllBytes(damaged));
        try (FileChannel channel = new CryptoChannelFactory(keyResolver, UUID).open(damaged, StandardOpenOption.READ)) {
            IOException e = expectThrows(IOException.class, () -> channel.read(ByteBuffer.allocate(16), headerSize()));
            assertTrue(e.getMessage(), e.getMessage().contains("Unsupported translog encryption format"));
        }
        assertArrayEquals(uploaded, Files.readAllBytes(damaged));
    }
}
