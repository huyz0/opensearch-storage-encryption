/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.CryptoDirectoryFactory.DEFAULT_CRYPTO_PROVIDER;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.junit.After;
import org.junit.Before;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.CryptoDirectoryFactory;
import org.opensearch.index.store.DummyKeyProvider;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.block_loader.ChunkTagCache;
import org.opensearch.index.store.block_loader.CryptoDirectIOBlockLoader;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

/**
 * Reads through {@link BufferPoolDirectory} (Direct I/O, block cache) are authenticated: a block
 * whose ciphertext or tag changed on disk fails with {@link CorruptIndexException}.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BufferPoolAuthenticatedReadTests extends OpenSearchTestCase {

    private static final int CHUNK = ChunkCipher.CHUNK_SIZE;

    private Path path;
    private Provider provider;
    private KeyResolver keyResolver;
    private EncryptionMetadataCache encryptionMetadataCache;
    private BufferPoolDirectory directory;
    private BlockLoader<RefCountedMemorySegment> loader;
    private ChunkTagCache tagCache;
    private PoolBuilder.PoolResources poolResources;
    private boolean originalWriteCacheEnabled;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        originalWriteCacheEnabled = CryptoDirectoryFactory.isWriteCacheEnabled();
        // Reads must come from disk, not from blocks cached while writing.
        CryptoDirectoryFactory.setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", false).build());

        path = createTempDir();
        provider = Security.getProvider(DEFAULT_CRYPTO_PROVIDER);
        MasterKeyProvider keyProvider = DummyKeyProvider.create();

        Settings nodeSettings = Settings
            .builder()
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .build();
        poolResources = PoolBuilder.build(nodeSettings);
        Pool<RefCountedMemorySegment> segmentPool = poolResources.getSegmentPool();

        String indexUuid = randomAlphaOfLength(10);
        String indexName = randomAlphaOfLength(10);
        keyResolver = new TestKeyResolver(indexUuid, indexName, FSDirectory.open(path), provider, keyProvider, 0);
        encryptionMetadataCache = EncryptionMetadataCacheRegistry.getOrCreateCache(indexUuid, 0, indexName);

        tagCache = new ChunkTagCache(ChunkTagCache.DEFAULT_MAX_BYTES);
        loader = new CryptoDirectIOBlockLoader(
            segmentPool,
            keyResolver,
            encryptionMetadataCache,
            poolResources.getFileChannelCache(),
            tagCache
        );
        @SuppressWarnings("unchecked")
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> sharedCache =
            (CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment>) poolResources.getBlockCache();
        BlockCache<RefCountedMemorySegment> directoryCache = new CaffeineBlockCache<>(
            sharedCache.getCache(),
            loader,
            poolResources.getMaxCacheBlocks()
        );

        directory = new BufferPoolDirectory(
            path,
            FSLockFactory.getDefault(),
            provider,
            keyResolver,
            segmentPool,
            directoryCache,
            loader,
            poolResources.getSharedReadaheadWorker(),
            encryptionMetadataCache,
            poolResources.getFileChannelCache()
        );
    }

    @After
    public void tearDown() throws Exception {
        CryptoDirectoryFactory
            .setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", originalWriteCacheEnabled).build());
        directory.close();
        poolResources.close();
        super.tearDown();
    }

    public void testRoundTrip() throws IOException {
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 5 * CHUNK));
        write("_0.tim", data);
        try (IndexInput in = directory.openInput("_0.tim", IOContext.DEFAULT)) {
            assertEquals(data.length, in.length());
            for (int i = 0; i < 20; i++) {
                int offset = randomIntBetween(0, data.length - 1);
                int len = randomIntBetween(0, data.length - offset);
                in.seek(offset);
                byte[] actual = new byte[len];
                in.readBytes(actual, 0, len);
                assertArrayEquals(Arrays.copyOfRange(data, offset, offset + len), actual);
            }
        }
    }

    /** NIOFS and the buffer pool write the same format (temp files are written by NIOFS and read here). */
    public void testReadsFileWrittenByNioDirectory() throws IOException {
        byte[] data = randomByteArrayOfLength(randomIntBetween(1, 3 * CHUNK));
        try (
            CryptoNIOFSDirectory nio = new CryptoNIOFSDirectory(
                FSLockFactory.getDefault(),
                path,
                provider,
                keyResolver,
                new EncryptionMetadataCache()
            );
            IndexOutput out = nio.createOutput("_1.tim", IOContext.DEFAULT)
        ) {
            out.writeBytes(data, data.length);
        }
        try (IndexInput in = directory.openInput("_1.tim", IOContext.DEFAULT)) {
            byte[] actual = new byte[data.length];
            in.readBytes(actual, 0, actual.length);
            assertArrayEquals(data, actual);
        }
    }

    public void testFlippedCiphertextBitIsDetected() throws Exception {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 100);
        write("_2.tim", data);
        int chunk = randomIntBetween(0, 3);
        flipBit("_2.tim", (long) chunk * CHUNK + randomIntBetween(0, ChunkCipher.chunkLength(chunk, data.length) - 1));
        assertChunkCorrupt("_2.tim", chunk, data);
    }

    public void testFlippedTagBitIsDetected() throws Exception {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 100);
        write("_3.tim", data);
        int chunk = randomIntBetween(0, 3);
        flipBit("_3.tim", data.length + (long) chunk * ChunkCipher.TAG_LENGTH + randomIntBetween(0, ChunkCipher.TAG_LENGTH - 1));
        assertChunkCorrupt("_3.tim", chunk, data);
    }

    public void testZeroLengthFile() throws IOException {
        write("_4.tim", new byte[0]);
        try (IndexInput in = directory.openInput("_4.tim", IOContext.DEFAULT)) {
            assertEquals(0, in.length());
            expectThrows(java.io.EOFException.class, in::readByte);
        }
    }

    public void testSwappedChunksAreDetected() throws Exception {
        byte[] data = randomByteArrayOfLength(2 * CHUNK + 10);
        write("_5.tim", data);
        // Swap chunks 0 and 1 together with their tags: each is still a validly sealed chunk.
        swap("_5.tim", 0, CHUNK, CHUNK);
        swap("_5.tim", data.length, data.length + ChunkCipher.TAG_LENGTH, ChunkCipher.TAG_LENGTH);
        Path file = path.resolve("_5.tim");
        expectThrows(CorruptIndexException.class, () -> loader.load(file, 0, 1, 1000));
        expectThrows(CorruptIndexException.class, () -> loader.load(file, CHUNK, 1, 1000));
    }

    public void testTruncationIsDetected() throws Exception {
        write("_6.tim", randomByteArrayOfLength(2 * CHUNK + 10));
        // The writer cached the footer; the size check must still catch the cut.
        try (FileChannel ch = FileChannel.open(path.resolve("_6.tim"), StandardOpenOption.WRITE)) {
            ch.truncate(ch.size() - randomIntBetween(1, 100));
        }
        expectThrows(CorruptIndexException.class, () -> loader.load(path.resolve("_6.tim"), 0, 1, 1000));
    }

    public void testTamperedFooterIsDetected() throws Exception {
        write("_7.tim", randomByteArrayOfLength(CHUNK + 10));
        Path file = path.resolve("_7.tim");
        long size = java.nio.file.Files.size(file);
        // Flip a bit in the authenticated part of the footer (DataLength..Magic, after the auth tag).
        flipBit("_7.tim", size - randomIntBetween(1, 40));
        encryptionMetadataCache.invalidateFile(EncryptionMetadataCache.normalizePath(file));
        expectThrows(IOException.class, () -> loader.load(file, 0, 1, 1000));
    }

    public void testMissesInOneFileShareTagPages() throws Exception {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 10);
        write("_8.tim", data);
        Path file = path.resolve("_8.tim");
        for (int chunk : new int[] { 0, 3, 1 }) {
            RefCountedMemorySegment[] blocks = loader.load(file, (long) chunk * CHUNK, 1, 1000);
            try {
                assertEquals(data[chunk * CHUNK], blocks[0].segment().get(ValueLayout.JAVA_BYTE, 0));
            } finally {
                blocks[0].close();
            }
            assertEquals("all of this file's tags fit in one page", 1, tagCache.estimatedSize());
        }
    }

    public void testTruncationIsDetectedAfterTagsAreCached() throws Exception {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 10);
        write("_9.tim", data);
        Path file = path.resolve("_9.tim");
        loadAndCheck(file, 0, 1, data);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            // Either cut into the footer, or cut the ciphertext of the last chunk.
            ch.truncate(randomBoolean() ? ch.size() - randomIntBetween(1, 100) : 2L * CHUNK + 5);
        }
        expectThrows(CorruptIndexException.class, () -> loader.load(file, 0, 1, 1000));
        expectThrows(CorruptIndexException.class, () -> loader.load(file, 2L * CHUNK, 1, 1000));
    }

    public void testLoadsAcrossTagPageBoundaries() throws Exception {
        int page = ChunkTagCache.TAGS_PER_PAGE;
        int chunks = randomFrom(page, page + 1, 2 * page);
        int length = chunks * CHUNK - (randomBoolean() ? 0 : CHUNK - randomIntBetween(1, CHUNK - 1));
        byte[] data = randomByteArrayOfLength(length);
        write("_10.tim", data);
        Path file = path.resolve("_10.tim");
        long n = ChunkCipher.chunkCount(length);
        loadAndCheck(file, page - 2, 4, data); // spans a page boundary
        loadAndCheck(file, n - 1, 1, data); // last chunk
        loadAndCheck(file, Math.max(0, n - 3), 8, data); // runs past the end
        loadAndCheck(file, 0, 1, data);
    }

    public void testRewriteUnderSameNameUsesNewTags() throws Exception {
        byte[] a = randomByteArrayOfLength(2 * CHUNK + 3);
        write("_11.tim", a);
        Path file = path.resolve("_11.tim");
        loadAndCheck(file, 0, 2, a);
        directory.deleteFile("_11.tim");
        byte[] b = randomByteArrayOfLength(2 * CHUNK + 3);
        write("_11.tim", b);
        loadAndCheck(file, 0, 2, b);
    }

    public void testConcurrentLoadsShareTagPages() throws Exception {
        int page = ChunkTagCache.TAGS_PER_PAGE;
        byte[] data = randomByteArrayOfLength(3 * page * CHUNK + 77);
        write("_12.tim", data);
        Path file = path.resolve("_12.tim");
        long n = ChunkCipher.chunkCount(data.length);
        int threads = 8;
        CyclicBarrier barrier = new CyclicBarrier(threads);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            Random random = new Random(random().nextLong());
            workers[t] = new Thread(() -> {
                try {
                    barrier.await();
                    for (int i = 0; i < 300; i++) {
                        loadAndCheck(file, (long) (random.nextDouble() * n), 1 + random.nextInt(4), data);
                    }
                } catch (Throwable e) {
                    failure.compareAndSet(null, e);
                }
            });
            workers[t].start();
        }
        for (Thread worker : workers) {
            worker.join();
        }
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
        assertTrue(tagCache.estimatedSize() <= 4);
    }

    public void testFailedTagPageIsNotRemembered() throws Exception {
        byte[] data = randomByteArrayOfLength(3 * CHUNK + 100);
        write("_13.tim", data);
        Path file = path.resolve("_13.tim");
        long tagPosition = data.length + ChunkCipher.TAG_LENGTH; // chunk 1's tag
        ByteBuffer original = ByteBuffer.allocate(1);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            ch.read(original, tagPosition);
        }
        flipBit("_13.tim", tagPosition);
        expectThrows(CorruptIndexException.class, () -> loader.load(file, CHUNK, 1, 1000));
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.write(original.flip(), tagPosition);
            ch.force(true);
        }
        // Once the disk is good again, the chunk loads: the bad page was not kept.
        loadAndCheck(file, 1, 1, data);
    }

    private void loadAndCheck(Path file, long chunk, int count, byte[] data) throws Exception {
        RefCountedMemorySegment[] blocks = loader.load(file, chunk * CHUNK, count, 1000);
        try {
            for (int i = 0; i < count; i++) {
                if (blocks[i] == null) {
                    continue;
                }
                int length = ChunkCipher.chunkLength(chunk + i, data.length);
                byte[] actual = new byte[length];
                MemorySegment.copy(blocks[i].segment(), ValueLayout.JAVA_BYTE, 0, actual, 0, length);
                int offset = (int) ((chunk + i) * CHUNK);
                assertArrayEquals(Arrays.copyOfRange(data, offset, offset + length), actual);
            }
        } finally {
            for (RefCountedMemorySegment block : blocks) {
                if (block != null) {
                    block.close();
                }
            }
        }
    }

    private void assertChunkCorrupt(String name, int chunk, byte[] data) throws Exception {
        try (IndexInput in = directory.openInput(name, IOContext.DEFAULT)) {
            in.seek((long) chunk * CHUNK);
            expectThrows(CorruptIndexException.class, in::readByte);
        }
        // The loader authenticates block by block: the tampered one fails, the others still load.
        Path file = path.resolve(name);
        expectThrows(CorruptIndexException.class, () -> loader.load(file, (long) chunk * CHUNK, 1, 1000));
        int other = (chunk + 2) % 4;
        RefCountedMemorySegment[] blocks = loader.load(file, (long) other * CHUNK, 1, 1000);
        try {
            assertEquals(data[other * CHUNK], blocks[0].segment().get(ValueLayout.JAVA_BYTE, 0));
        } finally {
            blocks[0].close();
        }
    }

    private void write(String name, byte[] data) throws IOException {
        try (IndexOutput out = directory.createOutput(name, IOContext.DEFAULT)) {
            int pos = 0;
            while (pos < data.length) {
                int n = Math.min(data.length - pos, randomBoolean() ? randomIntBetween(1, 100) : randomIntBetween(1, 3 * CHUNK));
                out.writeBytes(data, pos, n);
                pos += n;
            }
        }
    }

    private void swap(String name, long a, long b, int length) throws IOException {
        try (FileChannel ch = FileChannel.open(path.resolve(name), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            ByteBuffer x = ByteBuffer.allocate(length);
            ByteBuffer y = ByteBuffer.allocate(length);
            ch.read(x, a);
            ch.read(y, b);
            ch.write(y.flip(), a);
            ch.write(x.flip(), b);
        }
    }

    private void flipBit(String name, long position) throws IOException {
        try (FileChannel ch = FileChannel.open(path.resolve(name), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
            ByteBuffer b = ByteBuffer.allocate(1);
            ch.read(b, position);
            b.put(0, (byte) (b.get(0) ^ (1 << randomIntBetween(0, 7))));
            ch.write(b.rewind(), position);
            ch.force(true);
        }
    }
}
