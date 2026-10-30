/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import static org.opensearch.index.store.CryptoDirectoryFactory.DEFAULT_CRYPTO_PROVIDER;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;

import java.io.IOException;
import java.lang.foreign.ValueLayout;
import java.nio.channels.ClosedByInterruptException;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
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
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.bufferpoolfs.TestKeyResolver;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

/**
 * Regression tests for H6: an interrupted reader closes the node-wide cached FileChannel
 * (FileChannel is interruptible), which used to break every later block load for that file
 * until the channel happened to be evicted.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class CryptoDirectIOBlockLoaderInterruptTests extends OpenSearchTestCase {

    private static final String FILE_NAME = "interrupt_test";
    private static final int FILE_SIZE = 4 * CACHE_BLOCK_SIZE;

    private PoolBuilder.PoolResources poolResources;
    private BufferPoolDirectory directory;
    private KeyResolver keyResolver;
    private EncryptionMetadataCache encryptionMetadataCache;
    private Path dirPath;
    private byte[] expected;
    private boolean originalWriteCacheEnabled;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Disable the write-through cache so reads go through the block loader.
        originalWriteCacheEnabled = CryptoDirectoryFactory.isWriteCacheEnabled();
        CryptoDirectoryFactory.setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", false).build());
        dirPath = createTempDir();
        Provider provider = Security.getProvider(DEFAULT_CRYPTO_PROVIDER);
        MasterKeyProvider keyProvider = DummyKeyProvider.create();

        Settings nodeSettings = Settings
            .builder()
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .build();
        poolResources = PoolBuilder.build(nodeSettings);

        String indexUuid = randomAlphaOfLength(10);
        String indexName = randomAlphaOfLength(10);
        keyResolver = new TestKeyResolver(indexUuid, indexName, FSDirectory.open(dirPath), provider, keyProvider, 0);
        encryptionMetadataCache = EncryptionMetadataCacheRegistry.getOrCreateCache(indexUuid, 0, indexName);

        BlockLoader<RefCountedMemorySegment> loader = newLoader(poolResources.getFileChannelCache());
        @SuppressWarnings("unchecked")
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> sharedCache =
            (CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment>) poolResources.getBlockCache();
        BlockCache<RefCountedMemorySegment> directoryCache = new CaffeineBlockCache<>(
            sharedCache.getCache(),
            loader,
            poolResources.getMaxCacheBlocks()
        );
        directory = new BufferPoolDirectory(
            dirPath,
            FSLockFactory.getDefault(),
            provider,
            keyResolver,
            poolResources.getSegmentPool(),
            directoryCache,
            loader,
            poolResources.getSharedReadaheadWorker(),
            encryptionMetadataCache,
            poolResources.getFileChannelCache()
        );

        expected = new byte[FILE_SIZE];
        for (int i = 0; i < FILE_SIZE; i++) {
            expected[i] = (byte) (i * 31 + (i >>> 8));
        }
        try (IndexOutput out = directory.createOutput(FILE_NAME, IOContext.DEFAULT)) {
            out.writeBytes(expected, expected.length);
        }
    }

    @After
    public void tearDown() throws Exception {
        CryptoDirectoryFactory
            .setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", originalWriteCacheEnabled).build());
        directory.close();
        poolResources.close();
        super.tearDown();
    }

    private CryptoDirectIOBlockLoader newLoader(FileChannelCache fileChannelCache) {
        return new CryptoDirectIOBlockLoader(poolResources.getSegmentPool(), keyResolver, encryptionMetadataCache, fileChannelCache);
    }

    private void assertLoadsBlock(BlockLoader<RefCountedMemorySegment> loader, long offset) throws Exception {
        RefCountedMemorySegment[] blocks = loader.load(dirPath.resolve(FILE_NAME), offset, 1);
        try {
            for (int i = 0; i < CACHE_BLOCK_SIZE; i++) {
                assertEquals("byte " + (offset + i), expected[(int) offset + i], blocks[0].segment().get(ValueLayout.JAVA_BYTE, i));
            }
        } finally {
            blocks[0].close();
        }
    }

    /**
     * The interrupted reader fails, as it should, but the next reader of the same file must get a
     * fresh channel instead of the one the interrupt closed.
     */
    public void testLoadAfterInterruptedLoadOpensFreshChannel() throws Exception {
        CryptoDirectIOBlockLoader loader = newLoader(poolResources.getFileChannelCache());
        assertLoadsBlock(loader, 0); // caches the shared channel

        Thread.currentThread().interrupt();
        try {
            expectThrows(ClosedByInterruptException.class, () -> loader.load(dirPath.resolve(FILE_NAME), CACHE_BLOCK_SIZE, 1));
        } finally {
            assertTrue("interrupt flag should be preserved", Thread.interrupted());
        }

        assertLoadsBlock(loader, CACHE_BLOCK_SIZE);
        assertLoadsBlock(loader, 2L * CACHE_BLOCK_SIZE);
    }

    /**
     * Another thread's interrupt can close the shared channel after this reader acquired it. This
     * reader was not interrupted, so it must retry on a fresh channel instead of failing, even if it
     * happens more than once.
     */
    public void testLoadRetriesWhenSharedChannelClosedByAnotherThread() throws Exception {
        AtomicInteger closesLeft = new AtomicInteger(2); // two interrupted neighbours in a row
        FileChannelCache sabotaging = new FileChannelCache(16, null) {
            @Override
            public RefCountedChannel acquire(String normalizedPath) throws IOException {
                RefCountedChannel ref = super.acquire(normalizedPath);
                if (closesLeft.getAndDecrement() > 0) {
                    ref.channel().close(); // simulates a concurrent interrupted reader of the same channel
                }
                return ref;
            }
        };
        try {
            assertLoadsBlock(newLoader(sabotaging), 0);
            assertTrue("the channel should have been closed twice", closesLeft.get() < 0);
        } finally {
            sabotaging.close();
        }
    }
}
