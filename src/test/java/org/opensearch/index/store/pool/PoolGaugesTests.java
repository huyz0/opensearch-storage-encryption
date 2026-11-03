/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.Closeable;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.opensearch.index.store.CaffeineThreadLeakFilter;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCacheBuilder;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.FileChannelCache;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakFilters;

@ThreadLeakFilters(filters = { CaffeineThreadLeakFilter.class })
public class PoolGaugesTests extends OpenSearchTestCase {

    @Override
    public void tearDown() throws Exception {
        resetMetrics();
        super.tearDown();
    }

    private static void resetMetrics() throws Exception {
        Field instance = CryptoMetricsService.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    @SuppressWarnings("unchecked")
    public void testRegistersOneSeriesPerGaugeAndReadsCurrentValues() throws Exception {
        resetMetrics();
        Map<String, Supplier<Double>> gauges = new ConcurrentHashMap<>();
        Map<String, Closeable> handles = new ConcurrentHashMap<>();
        MetricsRegistry registry = mock(MetricsRegistry.class);
        when(registry.createGauge(anyString(), anyString(), anyString(), any(Supplier.class), any())).thenAnswer(inv -> {
            String name = inv.getArgument(0);
            gauges.put(name, inv.getArgument(3));
            Closeable handle = () -> gauges.remove(name);
            handles.put(name, handle);
            return handle;
        });
        CryptoMetricsService.initialize(registry);

        MemorySegmentPool pool = new MemorySegmentPool(16L * 8192, 8192);
        CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> cache = BlockCacheBuilder.build(16, 16);
        FileChannelCache channels = new FileChannelCache(4, 60, null);
        try {
            Closeable registered = PoolGauges.register(pool, cache, channels);
            assertEquals(
                java.util.Set
                    .of(
                        "crypto.pool.segments.max",
                        "crypto.pool.segments.allocated",
                        "crypto.pool.segments.free",
                        "crypto.cache.blocks",
                        "crypto.cache.hits",
                        "crypto.cache.misses",
                        "crypto.cache.evictions",
                        "crypto.fd_cache.open",
                        "crypto.fd_cache.hits",
                        "crypto.fd_cache.misses",
                        "crypto.fd_cache.evictions"
                    ),
                gauges.keySet()
            );
            assertEquals(16.0, gauges.get("crypto.pool.segments.max").get(), 0.0);
            assertEquals(0.0, gauges.get("crypto.pool.segments.allocated").get(), 0.0);
            pool.release(pool.acquire());
            assertEquals(1.0, gauges.get("crypto.pool.segments.allocated").get(), 0.0);
            assertEquals(1.0, gauges.get("crypto.pool.segments.free").get(), 0.0);

            registered.close();
            assertTrue("closing unregisters every gauge", gauges.isEmpty());
        } finally {
            channels.close();
            pool.close();
        }
    }

    public void testNoOpWhenMetricsNotInitialized() throws Exception {
        resetMetrics();
        MemorySegmentPool pool = new MemorySegmentPool(4L * 8192, 8192);
        try {
            PoolGauges.register(pool, BlockCacheBuilder.build(4, 4), null).close();
        } finally {
            pool.close();
        }
    }
}
