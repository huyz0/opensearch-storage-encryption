/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.FileChannelCache;
import org.opensearch.index.store.metrics.CryptoMetricsService;

/**
 * Node-level gauges for the shared segment pool, block cache and file channel cache. The exporter
 * reads them when it collects, so they are always current and need no polling thread. None carries
 * a tag, so each is one series per node.
 *
 * <p>Hit, miss, load and eviction gauges report running totals since the node started; graph their
 * rate.
 */
final class PoolGauges implements Closeable {

    private static final Logger LOGGER = LogManager.getLogger(PoolGauges.class);
    private static final String COUNT = "count";

    private final List<Closeable> handles = new ArrayList<>();

    private PoolGauges() {}

    /**
     * Registers the gauges, or returns a no-op handle if metrics are not initialized.
     */
    static Closeable register(MemorySegmentPool pool, BlockCache<?> blockCache, FileChannelCache fileChannelCache) {
        CryptoMetricsService metrics;
        try {
            metrics = CryptoMetricsService.getInstance();
        } catch (IllegalStateException e) {
            return () -> {};
        }
        PoolGauges gauges = new PoolGauges();
        gauges.add(metrics, "crypto.pool.segments.max", "Segments the shared pool can allocate", () -> pool.maxSegments());
        gauges
            .add(
                metrics,
                "crypto.pool.segments.allocated",
                "Segments the shared pool has allocated, in use or free",
                () -> pool.allocatedSegmentCount()
            );
        gauges.add(metrics, "crypto.pool.segments.free", "Allocated segments on the free list", () -> pool.freeSegmentCount());

        gauges.add(metrics, "crypto.cache.blocks", "Blocks in the shared block cache", blockCache::getCacheSize);
        gauges.add(metrics, "crypto.cache.hits", "Block cache hits since the node started", blockCache::hitCount);
        gauges.add(metrics, "crypto.cache.misses", "Block cache misses since the node started", blockCache::missCount);
        if (blockCache instanceof CaffeineBlockCache<?, ?> caffeine) {
            gauges
                .add(
                    metrics,
                    "crypto.cache.evictions",
                    "Block cache evictions since the node started",
                    () -> caffeine.getCache().stats().evictionCount()
                );
        }

        if (fileChannelCache != null) {
            gauges.add(metrics, "crypto.fd_cache.open", "Open file channels in the shared cache", fileChannelCache::estimatedSize);
            gauges
                .add(
                    metrics,
                    "crypto.fd_cache.hits",
                    "File channel cache hits since the node started",
                    () -> fileChannelCache.stats().hitCount()
                );
            gauges
                .add(
                    metrics,
                    "crypto.fd_cache.misses",
                    "File channel cache misses since the node started",
                    () -> fileChannelCache.stats().missCount()
                );
            gauges
                .add(
                    metrics,
                    "crypto.fd_cache.evictions",
                    "File channel cache evictions since the node started",
                    () -> fileChannelCache.stats().evictionCount()
                );
        }
        return gauges;
    }

    private void add(CryptoMetricsService metrics, String name, String description, Supplier<? extends Number> value) {
        handles.add(metrics.registerGauge(name, description, COUNT, () -> value.get().doubleValue()));
    }

    @Override
    public void close() {
        for (Closeable handle : handles) {
            try {
                handle.close();
            } catch (Exception e) {
                LOGGER.debug("Failed to unregister a pool gauge", e);
            }
        }
        handles.clear();
    }
}
