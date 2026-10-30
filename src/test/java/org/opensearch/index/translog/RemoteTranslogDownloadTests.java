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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;
import java.util.zip.CRC32;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.translog.transfer.FileSnapshot.TranslogFileSnapshot;
import org.opensearch.test.IndexSettingsModule;
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
        return uploadedBytes(path, keyResolver, UUID);
    }

    private static byte[] uploadedBytes(Path path, KeyResolver keyResolver, String uuid) throws IOException {
        // Core closes the snapshot it built (the original) and the one it uploads (the wrapper).
        try (
            TranslogFileSnapshot original = new TranslogFileSnapshot(1L, 1L, path, null);
            DecryptingFileSnapshot snapshot = new DecryptingFileSnapshot(original, keyResolver, uuid);
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

    private static LocalTranslog openTranslog(Path dir, String uuid, KeyResolver keyResolver) throws IOException {
        ShardId shardId = new ShardId("index", "_na_", 0);
        TranslogConfig config = new TranslogConfig(
            shardId,
            dir,
            IndexSettingsModule.newIndexSettings("index", Settings.EMPTY),
            BigArrays.NON_RECYCLING_INSTANCE,
            "",
            false
        );
        return new LocalTranslog(
            config,
            uuid,
            TranslogDeletionPolicies.createTranslogDeletionPolicy(),
            () -> SequenceNumbers.NO_OPS_PERFORMED,
            () -> 1L,
            seqNo -> {},
            TranslogOperationHelper.DEFAULT,
            new CryptoChannelFactory(keyResolver, uuid)
        );
    }

    /**
     * End to end through core: a translog written on one node, "uploaded" decrypted and
     * "downloaded" byte for byte, recovers on a node with another key, over several generations.
     */
    public void testTranslogRecoversFromDownloadedFilesOnAnotherNode() throws IOException {
        String uuid = UUIDs.randomBase64UUID();
        KeyResolver primaryKey = newKeyResolver();
        Path primaryDir = createTempDir();
        ShardId shardId = new ShardId("index", "_na_", 0);
        Translog
            .createEmptyTranslog(
                primaryDir,
                shardId,
                SequenceNumbers.NO_OPS_PERFORMED,
                1L,
                uuid,
                new CryptoChannelFactory(primaryKey, uuid)
            );

        List<byte[]> sources = new ArrayList<>();
        try (LocalTranslog translog = openTranslog(primaryDir, uuid, primaryKey)) {
            int generations = randomIntBetween(1, 3);
            for (int g = 0; g < generations; g++) {
                for (int i = randomIntBetween(1, 20); i > 0; i--) {
                    byte[] source = randomByteArrayOfLength(randomIntBetween(1, 2_000));
                    translog.add(new Translog.Index(Integer.toString(sources.size()), sources.size(), 1L, source));
                    sources.add(source);
                }
                translog.rollGeneration();
            }
            translog.sync();
        }

        Path replicaDir = createTempDir();
        try (Stream<Path> files = Files.list(primaryDir)) {
            // Only regular files: Lucene's test filesystem may add an "extra0" directory.
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                String name = file.getFileName().toString();
                Files
                    .write(
                        replicaDir.resolve(name),
                        name.endsWith(".tlog") ? uploadedBytes(file, primaryKey, uuid) : Files.readAllBytes(file)
                    );
            }
        }

        try (
            LocalTranslog translog = openTranslog(replicaDir, uuid, newKeyResolver());
            Translog.Snapshot snapshot = translog.newSnapshot()
        ) {
            int count = 0;
            Translog.Operation op;
            while ((op = snapshot.next()) != null) {
                Translog.Index index = (Translog.Index) op;
                assertArrayEquals(sources.get(Integer.parseInt(index.id())), BytesReference.toBytes(index.source()));
                count++;
            }
            assertEquals(sources.size(), count);
        }

        int headerSize = new TranslogHeader(uuid, 1L).sizeInBytes();
        try (Stream<Path> files = Files.list(replicaDir)) {
            for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".tlog")).toList()) {
                byte[] onDisk = Files.readAllBytes(file);
                if (onDisk.length > headerSize) {
                    assertEquals(
                        file.toString(),
                        CryptoFileChannelWrapper.MAGIC,
                        ByteBuffer.wrap(onDisk, headerSize, Integer.BYTES).getInt()
                    );
                }
            }
        }
    }

    public void testConcurrentOpensConvertOnce() throws Exception {
        KeyResolver keyResolver = newKeyResolver();
        Path primaryFile = createTempDir().resolve("translog-4.tlog");
        byte[] data = writeTranslog(new CryptoChannelFactory(keyResolver, UUID), primaryFile);
        Path downloaded = createTempDir().resolve("translog-4.tlog");
        Files.write(downloaded, uploadedBytes(primaryFile, keyResolver));

        CryptoChannelFactory factory = new CryptoChannelFactory(keyResolver, UUID);
        int threads = randomIntBetween(2, 8);
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        List<Throwable> failures = java.util.Collections.synchronizedList(new ArrayList<>());
        for (int t = 0; t < threads; t++) {
            Thread worker = new Thread(() -> {
                try {
                    start.await();
                    try (FileChannel channel = factory.open(downloaded, StandardOpenOption.READ)) {
                        assertArrayEquals(data, readData(channel, data.length));
                    }
                } catch (Throwable e) {
                    failures.add(e);
                }
            });
            worker.start();
            workers.add(worker);
        }
        start.countDown();
        for (Thread worker : workers) {
            worker.join();
        }
        assertTrue(failures.toString(), failures.isEmpty());
        assertEquals(headerSize() + CryptoFileChannelWrapper.PREFIX_LENGTH + data.length, Files.size(downloaded));
        assertFalse(Files.exists(downloaded.resolveSibling("translog-4.tlog.encrypting")));
    }
}
