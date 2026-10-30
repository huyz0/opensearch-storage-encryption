/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.pool.MemorySegmentPool;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Regression tests for H5: a cache miss with an exhausted segment pool used to wait up to 5 s for a
 * segment while holding the cache's map lock, and nothing evicted entries to free one, because the
 * cache's entry limit does not track the pool.
 */
@SuppressWarnings("preview")
@ThreadLeakFilters(filters = CaffeineThreadLeakFilter.class)
public class CaffeineBlockCachePoolPressureTests extends OpenSearchTestCase {

    private static final int SEGMENT_SIZE = 4096;
    private static final int POOL_SEGMENTS = 8;
    private static final Path FILE = Paths.get("/test/pool-pressure.dat");

    private MemorySegmentPool pool;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
        pool = new MemorySegmentPool((long) POOL_SEGMENTS * SEGMENT_SIZE, SEGMENT_SIZE);
    }

    @Override
    public void tearDown() throws Exception {
        pool.close();
        super.tearDown();
    }

    /** Acquires from the real pool and reports a timeout the way CryptoDirectIOBlockLoader does. */
    private static final class PoolBackedLoader implements BlockLoader<RefCountedMemorySegment> {
        private final MemorySegmentPool pool;
        final List<Long> timeoutsMs = new CopyOnWriteArrayList<>();
        final java.util.concurrent.atomic.AtomicInteger reservations = new java.util.concurrent.atomic.AtomicInteger();

        PoolBackedLoader(MemorySegmentPool pool) {
            this.pool = pool;
        }

        @Override
        public RefCountedMemorySegment[] load(Path filePath, long startOffset, long blockCount, long poolTimeoutMs) throws Exception {
            timeoutsMs.add(poolTimeoutMs);
            RefCountedMemorySegment[] result = new RefCountedMemorySegment[(int) blockCount];
            for (int i = 0; i < blockCount; i++) {
                try {
                    result[i] = pool.tryAcquire(poolTimeoutMs, TimeUnit.MILLISECONDS);
                } catch (IOException e) {
                    throw new PoolAcquireFailedException(e.getMessage(), e);
                }
            }
            return result;
        }

        @Override
        public boolean reservePoolSegment(long timeoutMs) throws InterruptedException {
            reservations.incrementAndGet();
            return pool.reserve(timeoutMs, TimeUnit.MILLISECONDS);
        }

        @Override
        public void releasePoolReservation() {
            pool.releaseReservation();
        }

        @Override
        public boolean poolExhausted() {
            return pool.availableMemoryAccurate() < SEGMENT_SIZE;
        }
    }

    private static BlockCacheKey key(int block) {
        return new FileBlockCacheKey(FILE, (long) block * SEGMENT_SIZE);
    }

    /**
     * The cache's entry limit is far above what the pool can back, as happens when readers pin
     * segments or removals lag. Once every segment is held by a cache entry, a miss must evict cold
     * entries and succeed quickly instead of stalling for the full timeout and failing.
     */
    public void testMissOnExhaustedPoolEvictsColdEntriesInsteadOfStalling() throws Exception {
        Cache<BlockCacheKey, BlockCacheValue<RefCountedMemorySegment>> caffeine = Caffeine
            .newBuilder()
            .maximumSize(1000)
            .executor(Runnable::run)
            .removalListener(
                (BlockCacheKey k, BlockCacheValue<RefCountedMemorySegment> v, com.github.benmanes.caffeine.cache.RemovalCause c) -> {
                    if (v != null) {
                        v.close();
                    }
                }
            )
            .build();
        PoolBackedLoader loader = new PoolBackedLoader(pool);
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache = new CaffeineBlockCache<>(caffeine, loader, 1000);

        for (int i = 0; i < POOL_SEGMENTS; i++) {
            assertNotNull(cache.getOrLoad(key(i)));
        }
        assertEquals("every pool segment is now held by the cache", 0, pool.availableMemoryAccurate());

        long start = System.nanoTime();
        BlockCacheValue<RefCountedMemorySegment> value = cache.getOrLoad(key(POOL_SEGMENTS));
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertNotNull(value);
        assertTrue("miss took " + elapsedMs + " ms; it should not sit out the 5 s pool timeout", elapsedMs < 2000);
        assertNull("the coldest entry should have been evicted to free a segment", caffeine.getIfPresent(key(0)));
        assertNotNull(caffeine.getIfPresent(key(POOL_SEGMENTS)));
        // the fills took one load each; the miss failed once under the map lock without waiting, reserved a
        // segment outside the lock, and loaded again
        assertEquals(POOL_SEGMENTS + 2, loader.timeoutsMs.size());
        assertEquals(1, loader.reservations.get());
        for (long timeout : loader.timeoutsMs) {
            assertEquals("loads under the map lock must not wait for the pool", BlockLoader.CACHE_LOAD_POOL_TIMEOUT_MS, timeout);
        }
        caffeine.invalidateAll();
    }

    /**
     * When nothing can be freed (every segment is pinned outside the cache), the miss still fails
     * once the wait budget is spent, with the pool-acquire failure as the cause.
     */
    public void testMissFailsAfterBudgetWhenNothingCanBeFreed() throws Exception {
        Cache<BlockCacheKey, BlockCacheValue<RefCountedMemorySegment>> caffeine = Caffeine.newBuilder().maximumSize(1000).build();
        PoolBackedLoader loader = new PoolBackedLoader(pool);
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache = new CaffeineBlockCache<>(caffeine, loader, 1000, 200);

        RefCountedMemorySegment[] held = new RefCountedMemorySegment[POOL_SEGMENTS];
        for (int i = 0; i < POOL_SEGMENTS; i++) {
            held[i] = pool.tryAcquire(10, TimeUnit.MILLISECONDS);
        }
        try {
            expectThrows(BlockLoader.PoolAcquireFailedException.class, () -> cache.getOrLoad(key(0)));
            assertEquals("one attempt under the lock", 1, loader.timeoutsMs.size());
            assertEquals("then one wait outside it", 1, loader.reservations.get());
        } finally {
            for (RefCountedMemorySegment segment : held) {
                segment.decRef();
            }
        }
    }

    /**
     * Misses waiting for pool space are served in arrival order. The first miss to start waiting gets
     * the first freed segment, even though a later miss is also waiting for it.
     */
    public void testWaitingMissesAreServedInArrivalOrder() throws Exception {
        Cache<BlockCacheKey, BlockCacheValue<RefCountedMemorySegment>> caffeine = Caffeine.newBuilder().maximumSize(1000).build();
        PoolBackedLoader loader = new PoolBackedLoader(pool);
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache = new CaffeineBlockCache<>(
            caffeine,
            loader,
            1000,
            10_000
        );

        RefCountedMemorySegment[] held = new RefCountedMemorySegment[POOL_SEGMENTS];
        for (int i = 0; i < POOL_SEGMENTS; i++) {
            held[i] = pool.tryAcquire(10, TimeUnit.MILLISECONDS);
        }
        CompletableFuture<BlockCacheValue<RefCountedMemorySegment>> first = new CompletableFuture<>();
        CompletableFuture<BlockCacheValue<RefCountedMemorySegment>> second = new CompletableFuture<>();
        Thread firstThread = missInBackground(cache, key(100), first);
        // wait until the first miss is queued in its wait outside the lock
        assertBusy(() -> {
            assertEquals(1, loader.reservations.get());
            assertEquals(1, pool.waiterCount());
        });
        Thread secondThread = missInBackground(cache, key(200), second);
        assertBusy(() -> {
            assertEquals(2, loader.reservations.get());
            assertEquals(2, pool.waiterCount());
        });

        held[0].decRef();
        assertNotNull(first.get(10, TimeUnit.SECONDS));
        // the second miss is still queued; it must not have taken the first miss's segment
        assertFalse(second.isDone());
        assertEquals(1, pool.waiterCount());

        held[1].decRef();
        assertNotNull(second.get(10, TimeUnit.SECONDS));
        firstThread.join();
        secondThread.join();

        for (int i = 2; i < POOL_SEGMENTS; i++) {
            held[i].decRef();
        }
        caffeine.asMap().values().forEach(BlockCacheValue::close);
        caffeine.asMap().clear();
    }

    /**
     * A miss that waited for a segment, only to find that another thread cached the block meanwhile,
     * returns the cached block and gives its reserved segment back to the pool.
     */
    public void testReservedSegmentIsReturnedWhenAnotherThreadCachedTheBlock() throws Exception {
        Cache<BlockCacheKey, BlockCacheValue<RefCountedMemorySegment>> caffeine = Caffeine.newBuilder().maximumSize(1000).build();
        PoolBackedLoader loader = new PoolBackedLoader(pool);
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache = new CaffeineBlockCache<>(
            caffeine,
            loader,
            1000,
            10_000
        );

        RefCountedMemorySegment[] held = new RefCountedMemorySegment[POOL_SEGMENTS];
        for (int i = 0; i < POOL_SEGMENTS; i++) {
            held[i] = pool.tryAcquire(10, TimeUnit.MILLISECONDS);
        }
        CompletableFuture<BlockCacheValue<RefCountedMemorySegment>> miss = new CompletableFuture<>();
        Thread t = missInBackground(cache, key(7), miss);
        assertBusy(() -> {
            assertEquals(1, loader.reservations.get());
            assertEquals(1, pool.waiterCount());
        });

        // another thread caches the block with a segment it already had
        caffeine.put(key(7), held[POOL_SEGMENTS - 1]);
        held[0].decRef(); // frees a segment for the waiting miss

        assertSame(held[POOL_SEGMENTS - 1], miss.get(10, TimeUnit.SECONDS));
        t.join();
        assertEquals("the reserved segment went back to the pool unused", SEGMENT_SIZE, pool.availableMemoryAccurate());

        for (int i = 1; i < POOL_SEGMENTS - 1; i++) {
            held[i].decRef();
        }
        caffeine.asMap().values().forEach(BlockCacheValue::close);
        caffeine.asMap().clear();
    }

    private static Thread missInBackground(
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache,
        BlockCacheKey key,
        CompletableFuture<BlockCacheValue<RefCountedMemorySegment>> result
    ) {
        Thread t = new Thread(() -> {
            try {
                result.complete(cache.getOrLoad(key));
            } catch (Throwable e) {
                result.completeExceptionally(e);
            }
        }, "miss-" + key.offset());
        t.start();
        return t;
    }
}
