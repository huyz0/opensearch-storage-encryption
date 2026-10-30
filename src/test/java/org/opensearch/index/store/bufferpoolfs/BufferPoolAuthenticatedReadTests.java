/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import static org.opensearch.index.store.CryptoDirectoryFactory.DEFAULT_CRYPTO_PROVIDER;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

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

        loader = new CryptoDirectIOBlockLoader(segmentPool, keyResolver, encryptionMetadataCache, poolResources.getFileChannelCache());
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
