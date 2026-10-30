/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;

/**
 * Builder for creating block caches with proper lifecycle management.
 */
public final class BlockCacheBuilder {

    private static final Logger LOGGER = LogManager.getLogger(BlockCacheBuilder.class);

    private BlockCacheBuilder() {}

    /**
     * Creates a block cache with the specified capacity and removal handling.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     * @param initialCapacity initial capacity hint for the cache
     * @param maxBlocks maximum number of blocks to cache
     * @return the configured cache
     */
    public static <T extends AutoCloseable, V> CaffeineBlockCache<T, V> build(int initialCapacity, long maxBlocks) {
        // Removal notifications run on the thread that removed the entry (Runnable::run), and the value is
        // closed right there. Handing them to an executor delayed the segment's return to the pool behind a
        // queue, so under memory pressure an eviction made to free a segment did not free it in time and the
        // miss that triggered it still timed out. Closing is a CAS plus a short pool lock, cheap enough inline.
        // The same executor setting makes Caffeine's other maintenance (draining buffers, size eviction) run on
        // the reading and writing threads instead of ForkJoinPool.commonPool; it is amortized and short.
        Cache<BlockCacheKey, BlockCacheValue<T>> cache = Caffeine
            .newBuilder()
            .initialCapacity(initialCapacity)
            .recordStats()
            .maximumSize(maxBlocks)
            .executor(Runnable::run)
            .removalListener((BlockCacheKey key, BlockCacheValue<T> value, RemovalCause cause) -> {
                if (value != null) {
                    try {
                        value.close();
                    } catch (Throwable t) {
                        LOGGER.warn("Failed to close cached value during removal {}", key, t);
                    }
                }
            })
            .build();

        // Loader is null here because this creates a shared cache instance.
        // Per-directory caches will wrap this cache with their own loaders
        // that provide directory-specific decryption keys.
        return new CaffeineBlockCache<>(cache, null, maxBlocks);
    }
}
