/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.bufferpoolfs;

import java.nio.file.Path;
import java.security.Provider;

import org.apache.lucene.store.AlreadyClosedException;
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
import org.opensearch.index.store.block_cache.FileBlockCacheKey;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.block_loader.CryptoDirectIOBlockLoader;
import org.opensearch.index.store.cipher.CryptoProviders;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.pool.Pool;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.index.store.read_ahead.Worker;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

/**
 * Unit tests for {@link BufferPoolDirectory}.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class BufferPoolDirectoryTests extends OpenSearchTestCase {

    private BufferPoolDirectory directory;
    private PoolBuilder.PoolResources poolResources;
    private boolean originalWriteCacheEnabled;
    private BlockCache<RefCountedMemorySegment> blockCache;
    private EncryptionMetadataCache metadataCache;
    private Path path;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        originalWriteCacheEnabled = CryptoDirectoryFactory.isWriteCacheEnabled();
        CryptoDirectoryFactory.setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", false).build());

        this.path = createTempDir();
        Provider provider = CryptoProviders.provider();
        MasterKeyProvider keyProvider = DummyKeyProvider.create();

        Settings nodeSettings = Settings
            .builder()
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .build();

        this.poolResources = PoolBuilder.build(nodeSettings);
        Pool<RefCountedMemorySegment> segmentPool = poolResources.getSegmentPool();

        String indexUuid = randomAlphaOfLength(10);
        String indexName = randomAlphaOfLength(10);
        FSDirectory fsDirectory = FSDirectory.open(path);
        int shardId = 0;

        KeyResolver keyResolver = new TestKeyResolver(indexUuid, indexName, fsDirectory, provider, keyProvider, shardId);
        EncryptionMetadataCache encryptionMetadataCache = EncryptionMetadataCacheRegistry.getOrCreateCache(indexUuid, shardId, indexName);
        this.metadataCache = encryptionMetadataCache;

        BlockLoader<RefCountedMemorySegment> loader = new CryptoDirectIOBlockLoader(
            segmentPool,
            keyResolver,
            encryptionMetadataCache,
            poolResources.getFileChannelCache()
        );

        Worker worker = poolResources.getSharedReadaheadWorker();

        @SuppressWarnings("unchecked")
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> sharedCache =
            (CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment>) poolResources.getBlockCache();

        BlockCache<RefCountedMemorySegment> directoryCache = new CaffeineBlockCache<>(
            sharedCache.getCache(),
            loader,
            poolResources.getMaxCacheBlocks()
        );
        this.blockCache = directoryCache;

        this.directory = new BufferPoolDirectory(
            path,
            FSLockFactory.getDefault(),
            provider,
            keyResolver,
            segmentPool,
            directoryCache,
            loader,
            worker,
            encryptionMetadataCache,
            poolResources.getFileChannelCache()
        );
    }

    @After
    public void tearDown() throws Exception {
        CryptoDirectoryFactory
            .setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", originalWriteCacheEnabled).build());
        // directory may already be closed by the test
        try {
            this.directory.close();
        } catch (AlreadyClosedException e) {
            // expected if test already closed it
        }
        this.poolResources.close();
        super.tearDown();
    }

    /**
     * The read-ahead worker is shared by every directory on the node, so closing one
     * directory (shard close, relocation, deletion) must not stop it for the others.
     */
    public void testCloseDoesNotStopSharedReadaheadWorker() throws Exception {
        Worker worker = poolResources.getSharedReadaheadWorker();
        assertTrue(worker.isRunning());

        directory.close();

        assertTrue("Shared read-ahead worker must survive a directory close", worker.isRunning());
    }

    /**
     * Verifies that close() calls super.close() so that ensureOpen() throws
     * AlreadyClosedException on subsequent operations. Without super.close(),
     * the directory appears open and operations silently proceed on stale state.
     *
     * We test via createTempOutput since its ensureOpen() call is not wrapped in
     * a catch block that calls CryptoMetricsService (which isn't initialized in
     * unit tests).
     */
    public void testCloseMarksDirectoryAsClosed() throws Exception {
        // Close the directory
        directory.close();

        // After close, createTempOutput should throw AlreadyClosedException from ensureOpen()
        expectThrows(AlreadyClosedException.class, () -> directory.createTempOutput("test", "tmp", IOContext.DEFAULT));
    }

    /**
     * Recovery and replication write files under a temporary name and rename them. A rename must drop
     * the blocks, footer and key cached under the temporary name, and reads under the new name must
     * load the file again.
     */
    public void testRenameDropsEntriesCachedUnderTheOldName() throws Exception {
        String temp = "recovery.abc._0.tim";
        byte[] data = randomByteArrayOfLength(3 * StaticConfigs.CACHE_BLOCK_SIZE + 17);
        try (IndexOutput out = directory.createOutput(temp, IOContext.DEFAULT)) {
            out.writeBytes(data, data.length);
        }
        Path tempFile = directory.getDirectory().resolve(temp);
        try (IndexInput in = directory.openInput(temp, IOContext.DEFAULT)) {
            in.readBytes(new byte[data.length], 0, data.length);
        }
        FileBlockCacheKey tempKey = new FileBlockCacheKey(tempFile, 0);
        assertNotNull("reading caches the first block", blockCache.peek(tempKey));
        assertNotNull(metadataCache.getFooter(EncryptionMetadataCache.normalizePath(tempFile)));

        directory.rename(temp, "_0.tim");

        assertNull(blockCache.peek(tempKey));
        assertNull(metadataCache.getFooter(EncryptionMetadataCache.normalizePath(tempFile)));
        byte[] read = new byte[data.length];
        try (IndexInput in = directory.openInput("_0.tim", IOContext.DEFAULT)) {
            assertEquals(data.length, in.length());
            in.readBytes(read, 0, read.length);
        }
        assertArrayEquals(data, read);
    }
}
