/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_cache;

import java.util.concurrent.ThreadPoolExecutor;

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
     * Result containing both the cache and the executor that must be shut down
     * on node closure.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     */
    public static class CacheWithExecutor<T extends AutoCloseable, V> {
        private final CaffeineBlockCache<T, V> cache;
        private final ThreadPoolExecutor executor;

        CacheWithExecutor(CaffeineBlockCache<T, V> cache, ThreadPoolExecutor executor) {
            this.cache = cache;
            this.executor = executor;
        }

        /**
         * Returns the configured block cache.
         *
         * @return the block cache instance
         */
        public CaffeineBlockCache<T, V> getCache() {
            return cache;
        }

        /**
         * Returns the executor for asynchronous cache removal, or {@code null}: removals are now
         * processed synchronously, so {@link BlockCacheBuilder#build} no longer creates one.
         *
         * @return the thread pool executor, or {@code null}
         */
        public ThreadPoolExecutor getExecutor() {
            return executor;
        }
    }

    /**
     * Creates a block cache with the specified capacity and removal handling.
     *
     * @param <T> the type of cached block values
     * @param <V> the type returned by the block loader
     * @param initialCapacity initial capacity hint for the cache
     * @param maxBlocks maximum number of blocks to cache
     * @return CacheWithExecutor containing the configured cache and its executor
     */
    public static <T extends AutoCloseable, V> CacheWithExecutor<T, V> build(int initialCapacity, long maxBlocks) {
        // Removal notifications run on the thread that removed the entry (Runnable::run), and the value is
        // closed right there. Handing them to an executor delayed the segment's return to the pool behind a
        // queue, so under memory pressure an eviction made to free a segment did not free it in time and the
        // miss that triggered it still timed out. Closing is a CAS plus a short pool lock, cheap enough inline.
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
        CaffeineBlockCache<T, V> caffeineBlockCache = new CaffeineBlockCache<>(cache, null, maxBlocks);
        return new CacheWithExecutor<>(caffeineBlockCache, null);
    }
}
