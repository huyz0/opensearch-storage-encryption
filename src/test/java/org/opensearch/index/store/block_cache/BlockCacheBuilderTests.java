/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import static org.mockito.Mockito.mock;

import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import com.github.benmanes.caffeine.cache.Cache;

/**
 * The shared block cache must hand an evicted block's segment back to the pool before the eviction
 * call returns. When removals were queued on an executor, an eviction made to relieve pool pressure
 * freed nothing until that queue drained, so the waiting miss could still time out.
 */
@SuppressWarnings("preview")
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class BlockCacheBuilderTests extends OpenSearchTestCase {

    private static final int SEGMENT_SIZE = 4096;
    private static final int POOL_SEGMENTS = 8;

    private MemorySegmentPool pool;
    private Cache<BlockCacheKey, BlockCacheValue<RefCountedMemorySegment>> cache;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        pool = new MemorySegmentPool((long) POOL_SEGMENTS * SEGMENT_SIZE, SEGMENT_SIZE);
        BlockCacheBuilder.CacheWithExecutor<RefCountedMemorySegment, RefCountedMemorySegment> built = BlockCacheBuilder
            .build(16, POOL_SEGMENTS / 2);
        assertNull("removals are synchronous, so there is no executor to shut down", built.getExecutor());
        cache = built.getCache().getCache();
    }

    @Override
    public void tearDown() throws Exception {
        cache.invalidateAll();
        pool.close();
        super.tearDown();
    }

    private static BlockCacheKey key(int block) {
        return new FileBlockCacheKey(Paths.get("/test/backlog.dat"), (long) block * SEGMENT_SIZE);
    }

    private void fill(int blocks) throws Exception {
        for (int i = 0; i < blocks; i++) {
            cache.put(key(i), pool.tryAcquire(10, TimeUnit.MILLISECONDS));
        }
    }

    public void testInvalidateReturnsSegmentToPoolBeforeReturning() throws Exception {
        fill(POOL_SEGMENTS / 2);
        long before = pool.availableMemoryAccurate();

        cache.invalidate(key(0));

        assertEquals("the segment must be back in the pool when invalidate() returns", before + SEGMENT_SIZE, pool.availableMemoryAccurate());
    }

    public void testSizeEvictionReturnsSegmentToPoolBeforeReturning() throws Exception {
        fill(POOL_SEGMENTS / 2);
        long before = pool.availableMemoryAccurate();

        cache.put(key(POOL_SEGMENTS), pool.tryAcquire(10, TimeUnit.MILLISECONDS)); // one over the limit
        cache.cleanUp();

        assertEquals("one segment taken, one evicted and returned", before, pool.availableMemoryAccurate());
        assertEquals(POOL_SEGMENTS / 2, cache.estimatedSize());
    }

    public void testPinnedSegmentReturnsWhenReaderUnpins() throws Exception {
        fill(1);
        BlockCacheValue<RefCountedMemorySegment> value = cache.getIfPresent(key(0));
        assertTrue(value.tryPin());
        long before = pool.availableMemoryAccurate();

        cache.invalidate(key(0));
        assertEquals("a pinned segment stays out of the pool", before, pool.availableMemoryAccurate());

        value.unpin();
        assertEquals(before + SEGMENT_SIZE, pool.availableMemoryAccurate());
    }
}
