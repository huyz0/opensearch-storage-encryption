/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Reads through {@link CryptoNIOFSDirectory} are authenticated: any change to the ciphertext, the
 * chunk tags or the file length on disk is reported as corruption instead of returning altered data.
 */
public class CryptoNIOFSAuthenticatedReadTests extends OpenSearchTestCase {

    private static final String FILE = "_0.fdt";
    private static final int CHUNK = ChunkCipher.CHUNK_SIZE;

    private final byte[] masterKey = randomByteArrayOfLength(32);
    private Path dir;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        dir = createTempDir();
    }

    public void testRoundTripAtAnyLength() throws IOException {
        for (int length : new int[] { 0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + randomIntBetween(1, CHUNK - 1) }) {
            String name = "_" + length + ".fdt";
            byte[] data = randomByteArrayOfLength(length);
            write(name, data);

            Path file = dir.resolve(name);
            assertEquals(length + ChunkCipher.tagTableLength(length) + EncryptionMetadataTrailer.MIN_FOOTER_SIZE, Files.size(file));
            try (Directory d = openDirectory()) {
                assertEquals(length, d.fileLength(name));
                assertArrayEquals(data, readAll(d, name));
                if (length > 0) {
                    try (IndexInput in = d.openInput(name, IOContext.DEFAULT)) {
                        for (int i = 0; i < 20; i++) {
                            int offset = randomIntBetween(0, length - 1);
                            int len = randomIntBetween(0, length - offset);
                            IndexInput slice = in.slice("s", offset, len);
                            byte[] actual = new byte[len];
                            slice.readBytes(actual, 0, len);
                            assertArrayEquals(Arrays.copyOfRange(data, offset, offset + len), actual);
                        }
                    }
                }
            }
        }
    }

    public void testFlippedCiphertextBitIsDetected() throws IOException {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 100);
        write(FILE, data);
        int chunk = randomIntBetween(0, 3);
        long position = (long) chunk * CHUNK + randomIntBetween(0, ChunkCipher.chunkLength(chunk, data.length) - 1);
        flipBit(position);

        try (Directory d = openDirectory(); IndexInput in = d.openInput(FILE, IOContext.DEFAULT)) {
            in.seek((long) chunk * CHUNK);
            expectThrows(CorruptIndexException.class, () -> in.readByte());
            // Other chunks are unaffected.
            int other = (chunk + 1) % 4;
            in.seek((long) other * CHUNK);
            assertEquals(data[other * CHUNK], in.readByte());
        }
    }

    public void testFlippedTagBitIsDetected() throws IOException {
        byte[] data = randomByteArrayOfLength(2 * CHUNK + 10);
        write(FILE, data);
        int chunk = randomIntBetween(0, 2);
        flipBit(data.length + (long) chunk * ChunkCipher.TAG_LENGTH + randomIntBetween(0, ChunkCipher.TAG_LENGTH - 1));

        try (Directory d = openDirectory(); IndexInput in = d.openInput(FILE, IOContext.DEFAULT)) {
            in.seek((long) chunk * CHUNK);
            expectThrows(CorruptIndexException.class, () -> in.readByte());
        }
    }

    public void testSwappedChunksAreDetected() throws IOException {
        byte[] data = randomByteArrayOfLength(2 * CHUNK + 10);
        write(FILE, data);
        // Swap chunk 0 and chunk 1 together with their tags: each is still a valid sealed chunk.
        swap(0, CHUNK, CHUNK);
        swap(data.length, data.length + ChunkCipher.TAG_LENGTH, ChunkCipher.TAG_LENGTH);

        try (Directory d = openDirectory(); IndexInput in = d.openInput(FILE, IOContext.DEFAULT)) {
            expectThrows(CorruptIndexException.class, () -> in.readByte());
            in.seek(CHUNK);
            expectThrows(CorruptIndexException.class, () -> in.readByte());
        }
    }

    public void testRemovedChunkIsDetected() throws IOException {
        byte[] data = randomByteArrayOfLength(3 * CHUNK);
        write(FILE, data);
        // Drop the last chunk and its tag but keep the authenticated footer.
        byte[] file = Files.readAllBytes(dir.resolve(FILE));
        byte[] cut = new byte[file.length - CHUNK - ChunkCipher.TAG_LENGTH];
        System.arraycopy(file, 0, cut, 0, 2 * CHUNK);
        System.arraycopy(file, data.length, cut, 2 * CHUNK, 2 * ChunkCipher.TAG_LENGTH);
        int footerStart = file.length - EncryptionMetadataTrailer.MIN_FOOTER_SIZE;
        System
            .arraycopy(
                file,
                footerStart,
                cut,
                cut.length - EncryptionMetadataTrailer.MIN_FOOTER_SIZE,
                EncryptionMetadataTrailer.MIN_FOOTER_SIZE
            );
        Files.write(dir.resolve(FILE), cut);

        try (Directory d = openDirectory()) {
            IOException e = expectThrows(IOException.class, () -> d.openInput(FILE, IOContext.DEFAULT));
            assertTrue(e.getMessage(), e.getMessage().contains("does not match its footer"));
        }
    }

    public void testWrongMasterKeyIsRejected() throws IOException {
        write(FILE, randomByteArrayOfLength(100));
        byte[] otherKey = masterKey.clone();
        otherKey[0] ^= 1;
        try (Directory d = openDirectory(otherKey)) {
            IOException e = expectThrows(IOException.class, () -> d.openInput(FILE, IOContext.DEFAULT));
            assertEquals("Footer authentication failed", e.getMessage());
        }
    }

    private void write(String name, byte[] data) throws IOException {
        try (Directory d = openDirectory(); IndexOutput out = d.createOutput(name, IOContext.DEFAULT)) {
            // Mix small and large writes so both the copy and the whole-chunk paths are used.
            int pos = 0;
            while (pos < data.length) {
                int n = Math.min(data.length - pos, randomBoolean() ? randomIntBetween(1, 100) : randomIntBetween(1, 3 * CHUNK));
                out.writeBytes(data, pos, n);
                pos += n;
            }
        }
    }

    private static byte[] readAll(Directory d, String name) throws IOException {
        try (IndexInput in = d.openInput(name, IOContext.DEFAULT)) {
            byte[] actual = new byte[(int) in.length()];
            in.readBytes(actual, 0, actual.length);
            return actual;
        }
    }

    private void flipBit(long position) throws IOException {
        try (FileChannel ch = FileChannel.open(dir.resolve(FILE), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            ByteBuffer b = ByteBuffer.allocate(1);
            ch.read(b, position);
            b.put(0, (byte) (b.get(0) ^ (1 << randomIntBetween(0, 7))));
            ch.write(b.rewind(), position);
        }
    }

    private void swap(long a, long b, int length) throws IOException {
        try (FileChannel ch = FileChannel.open(dir.resolve(FILE), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            ByteBuffer x = ByteBuffer.allocate(length);
            ByteBuffer y = ByteBuffer.allocate(length);
            ch.read(x, a);
            ch.read(y, b);
            ch.write(y.flip(), a);
            ch.write(x.flip(), b);
        }
    }

    /** A fresh directory with an empty metadata cache, so footers are read from disk again. */
    private Directory openDirectory() throws IOException {
        return openDirectory(masterKey);
    }

    private Directory openDirectory(byte[] key) throws IOException {
        KeyResolver resolver = new KeyResolver() {
            @Override
            public Key getDataKey() {
                return new SecretKeySpec(key, "AES");
            }
        };
        return new CryptoNIOFSDirectory(
            FSLockFactory.getDefault(),
            dir,
            Security.getProvider("SunJCE"),
            resolver,
            new EncryptionMetadataCache()
        );
    }
}
