/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.util.concurrent.TimeUnit;

/**
 * Generic pool interface for managing reusable resources.
 * 
 * <p>This pool provides resource management with support for acquisition timeouts,
 * memory tracking, pressure monitoring, and warm-up operations. Implementations
 * should be thread-safe for concurrent access.
 *
 * @param <T> the type of pooled resource
 * @opensearch.internal
 */
public interface Pool<T> {
    /**
     * Acquires a resource from the pool, blocking until one becomes available.
     *
     * @return a pooled resource ready for use
     * @throws Exception if acquisition fails due to pool closure, allocation errors, or other issues
     */
    T acquire() throws Exception;

    /**
     * Attempts to acquire a resource from the pool within the specified timeout.
     *
     * @param timeout maximum time to wait for a resource
     * @param unit time unit for the timeout
     * @return a pooled resource if available within timeout
     * @throws InterruptedException if the thread is interrupted while waiting
     * @throws Exception if acquisition fails due to timeout, pool closure, or allocation errors
     */
    T tryAcquire(long timeout, TimeUnit unit) throws Exception;

    /**
     * Waits in turn for a resource and holds it for the calling thread: that thread's next
     * {@link #tryAcquire} returns it without waiting. Lets a caller wait without holding locks and
     * then acquire under a lock. Pair every successful call with {@link #releaseReservation()}.
     *
     * @param timeout maximum time to wait
     * @param unit time unit for the timeout
     * @return true if a resource is now held for this thread, false on timeout
     * @throws InterruptedException if the thread is interrupted while waiting
     */
    default boolean reserve(long timeout, TimeUnit unit) throws InterruptedException {
        return false;
    }

    /**
     * Returns the resource held for the calling thread by {@link #reserve}, if it was not used.
     */
    default void releaseReservation() {}

    /**
     * Returns a resource to the pool for reuse.
     *
     * @param pooled the resource to return to the pool
     */
    void release(T pooled);

    /**
     * Returns the total memory capacity of the pool in bytes.
     *
     * @return total memory capacity in bytes
     */
    long totalMemory();

    /**
     * Returns the available memory in the pool in bytes.
     *
     * @return available memory in bytes
     */
    long availableMemory();

    /**
     * Returns the size of each pooled segment in bytes.
     *
     * @return segment size in bytes
     */
    int pooledSegmentSize();

    /**
     * Checks if the pool is under memory pressure.
     *
     * @return true if the pool is under pressure, false otherwise
     */
    boolean isUnderPressure();

    /**
     * Pre-allocates resources to warm up the pool.
     *
     * @param numBlocks number of blocks to pre-allocate
     */
    void warmUp(long numBlocks);

    /**
     * Returns pool statistics as a formatted string.
     *
     * @return string representation of pool statistics
     */
    String poolStats();

    /**
     * Closes the pool and releases all resources.
     */
    void close();

    /**
     * Checks if the pool has been closed.
     *
     * @return true if the pool is closed, false otherwise
     */
    boolean isClosed();

    void recordStats();
}
