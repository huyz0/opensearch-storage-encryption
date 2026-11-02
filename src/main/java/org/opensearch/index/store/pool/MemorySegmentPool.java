/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.pool;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.PanamaNativeAccess;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.metrics.CryptoMetricsService;

/**
 * High-performance primary memory pool for off-heap memory segment allocation using
 * pure Panama FFM API (malloc/free) without arenas.
 *
 * <p>This pool manages fixed-size native segments, allocated on-demand
 * via libc malloc() and released via free(). Segments are recycled
 * through a freelist for performance. Optionally, memory is zeroed on release
 * for security.
 *
 * <p>Thread-safe via an internal {@link ReentrantLock}.
 * Cached stats minimize lock contention during monitoring.
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
@SuppressForbidden(reason = "Uses Panama FFI for native memory allocation")
public class MemorySegmentPool implements Pool<RefCountedMemorySegment>, AutoCloseable {

    private static final Logger LOGGER = LogManager.getLogger(MemorySegmentPool.class);

    private final ReentrantLock lock = new ReentrantLock();
    // One condition per queued caller, in arrival order; see acquireInOrder
    private final Deque<Condition> waiters = new ArrayDeque<>();
    // Segment taken in turn by reserve() and held for its thread's next acquire
    private final ThreadLocal<RefCountedMemorySegment> reserved = new ThreadLocal<>();
    private final Deque<RefCountedMemorySegment> freeList = new ArrayDeque<>();

    private final int segmentSize;
    private final int maxSegments;
    private final long totalMemory;
    private final boolean requiresZeroing;

    private volatile boolean closed = false;
    private int allocatedSegments = 0;
    private volatile int cachedFreeListSize = 0;

    /**
     * Creates a pool with lazy allocation and memory zeroing enabled for security.
     *
     * @param totalMemory total memory in bytes (must be a multiple of segmentSize)
     * @param segmentSize size of each memory segment in bytes
     */
    public MemorySegmentPool(long totalMemory, int segmentSize) {
        this(totalMemory, segmentSize, true);
    }

    /**
     * Creates a pool with configurable allocation strategy and zeroing behavior.
     *
     * @param totalMemory total memory in bytes (must be a multiple of segmentSize)
     * @param segmentSize size of each memory segment in bytes
     * @param requiresZeroing if true, memory is zeroed on release for security
     */
    public MemorySegmentPool(long totalMemory, int segmentSize, boolean requiresZeroing) {
        if (totalMemory % segmentSize != 0) {
            throw new IllegalArgumentException("Total memory must be a multiple of segment size");
        }
        this.totalMemory = totalMemory;
        this.segmentSize = segmentSize;
        this.maxSegments = (int) (totalMemory / segmentSize);
        this.requiresZeroing = requiresZeroing;
    }

    @Override
    public RefCountedMemorySegment acquire() throws InterruptedException {
        return acquireInOrder(false, 0L);
    }

    @Override
    public RefCountedMemorySegment tryAcquire(long timeout, TimeUnit unit) throws Exception {
        RefCountedMemorySegment refSeg = acquireInOrder(true, unit.toNanos(timeout));
        if (refSeg != null) {
            return refSeg;
        }
        // debug, not warn: short timeouts are expected under pressure, and the block cache logs if it gives up
        LOGGER
            .debug("Pool acquisition timed out after {}ms (allocated={}, max={})", unit.toMillis(timeout), allocatedSegments, maxSegments);
        throw new IOException(
            "Pool acquisition timed out after "
                + timeout
                + " "
                + unit.toString().toLowerCase()
                + " (allocated="
                + allocatedSegments
                + ", max="
                + maxSegments
                + ")"
        );
    }

    /**
     * Hands out segments in arrival order once the pool runs dry. A caller that finds other callers
     * already waiting queues behind them instead of taking the next released segment, and each
     * released segment goes to the longest waiter. Without this, a segment freed for one waiter could
     * be taken by a newcomer, and a waiter could be passed over until it timed out.
     *
     * @return a segment, or {@code null} if {@code timed} and the timeout elapsed
     */
    private RefCountedMemorySegment acquireInOrder(boolean timed, long timeoutNanos) throws InterruptedException {
        RefCountedMemorySegment held = reserved.get();
        if (held != null) {
            reserved.remove();
            return held;
        }
        lock.lock();
        try {
            ensureOpen();
            if (waiters.isEmpty()) {
                RefCountedMemorySegment refSeg = takeLocked();
                if (refSeg != null) {
                    return refSeg;
                }
            }

            LOGGER
                .debug(
                    "Pool exhausted (allocated={}, max={}, waiting={}), queueing for release",
                    allocatedSegments,
                    maxSegments,
                    waiters.size()
                );
            Condition turn = lock.newCondition();
            waiters.addLast(turn);
            long remainingNanos = timeoutNanos;
            try {
                while (true) {
                    ensureOpen();
                    if (waiters.peekFirst() == turn) {
                        RefCountedMemorySegment refSeg = takeLocked();
                        if (refSeg != null) {
                            return refSeg;
                        }
                    }
                    if (!timed) {
                        turn.await();
                    } else if (remainingNanos <= 0) {
                        return null;
                    } else {
                        remainingNanos = turn.awaitNanos(remainingNanos);
                    }
                }
            } finally {
                waiters.remove(turn);
                // Pass the turn on, whether this waiter got a segment, timed out or was interrupted
                signalHeadIfAvailable();
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean reserve(long timeout, TimeUnit unit) throws InterruptedException {
        if (reserved.get() != null) {
            return true;
        }
        RefCountedMemorySegment refSeg = acquireInOrder(true, unit.toNanos(timeout));
        if (refSeg == null) {
            return false;
        }
        reserved.set(refSeg);
        return true;
    }

    @Override
    public void releaseReservation() {
        RefCountedMemorySegment held = reserved.get();
        if (held != null) {
            reserved.remove();
            held.decRef(); // back to the pool, to the next waiter in line
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("Pool is closed");
        }
    }

    /** Takes a free or newly allocated segment, or returns null when the pool is exhausted. Lock must be held. */
    private RefCountedMemorySegment takeLocked() {
        if (!freeList.isEmpty()) {
            RefCountedMemorySegment refSeg = freeList.removeFirst();
            cachedFreeListSize = freeList.size();
            refSeg.reset();
            return refSeg;
        }
        if (allocatedSegments < maxSegments) {
            MemorySegment seg = PanamaNativeAccess.malloc(segmentSize);
            RefCountedMemorySegment refSeg = new RefCountedMemorySegment(seg, segmentSize, this::release);
            allocatedSegments++;
            LOGGER.trace("Allocated new native segment, total allocated={}", allocatedSegments);
            return refSeg;
        }
        return null;
    }

    /** Wakes the longest waiter if a segment can be handed out. Lock must be held. */
    private void signalHeadIfAvailable() {
        Condition head = waiters.peekFirst();
        if (head != null && (!freeList.isEmpty() || allocatedSegments < maxSegments)) {
            head.signal();
        }
    }

    /**
     * Returns the number of callers queued for a segment.
     *
     * @return queued caller count
     */
    public int waiterCount() {
        lock.lock();
        try {
            return waiters.size();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void release(RefCountedMemorySegment refSegment) {
        lock.lock();
        try {
            if (closed) {
                // Free directly if pool is closed
                PanamaNativeAccess.free(refSegment.segment());
                return;
            }

            if (requiresZeroing) {
                refSegment.segment().fill((byte) 0);
            }

            freeList.addLast(refSegment);
            cachedFreeListSize = freeList.size();
            signalHeadIfAvailable();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Release multiple segments efficiently in one lock operation.
     *
     * @param segments the segments to release
     */
    public void releaseAll(RefCountedMemorySegment... segments) {
        if (segments.length == 0)
            return;
        lock.lock();
        try {
            if (closed) {
                for (RefCountedMemorySegment s : segments) {
                    PanamaNativeAccess.free(s.segment());
                }
                return;
            }

            for (RefCountedMemorySegment s : segments) {
                if (requiresZeroing) {
                    s.segment().fill((byte) 0);
                }
                freeList.addLast(s);
            }
            cachedFreeListSize = freeList.size();
            // Each waiter that takes one passes the turn on while segments remain
            signalHeadIfAvailable();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public long totalMemory() {
        return totalMemory;
    }

    @Override
    public long availableMemory() {
        int free = cachedFreeListSize;
        int allocated = allocatedSegments;
        int canAllocate = Math.max(0, maxSegments - allocated);
        return (long) (free + canAllocate) * segmentSize;
    }

    /**
     * Returns the accurate available memory by acquiring the lock.
     * This is more accurate than {@link #availableMemory()} but requires locking.
     *
     * @return available memory in bytes
     */
    public long availableMemoryAccurate() {
        lock.lock();
        try {
            int free = freeList.size();
            int canAlloc = Math.max(0, maxSegments - allocatedSegments);
            return (long) (free + canAlloc) * segmentSize;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int pooledSegmentSize() {
        return segmentSize;
    }

    /**
     * Returns current pool statistics.
     *
     * @return pool statistics snapshot
     */
    public PoolStats getStats() {
        return new PoolStats(maxSegments, allocatedSegments, freeList.size(), maxSegments - allocatedSegments);
    }

    @Override
    public boolean isUnderPressure() {
        int free = cachedFreeListSize;
        int unallocated = maxSegments - allocatedSegments;
        return (free + unallocated) < (maxSegments * 0.1);
    }

    @Override
    public void warmUp(long targetSegments) {
        targetSegments = Math.min(targetSegments, maxSegments);
        lock.lock();
        try {
            while (allocatedSegments < targetSegments) {
                MemorySegment seg = PanamaNativeAccess.malloc(segmentSize);
                RefCountedMemorySegment refSeg = new RefCountedMemorySegment(seg, segmentSize, this::release);
                freeList.addLast(refSeg);
                allocatedSegments++;
            }
            cachedFreeListSize = freeList.size();
            signalHeadIfAvailable();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void close() {
        lock.lock();
        try {
            if (closed)
                return;
            closed = true;
            while (!freeList.isEmpty()) {
                RefCountedMemorySegment seg = freeList.removeFirst();
                PanamaNativeAccess.free(seg.segment());
            }
            cachedFreeListSize = 0;
            // Wake every waiter so it sees the pool is closed
            waiters.forEach(Condition::signal);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public String poolStats() {
        int free = cachedFreeListSize;
        int allocated = allocatedSegments;
        int unalloc = maxSegments - allocated;
        double utilization = (double) (allocated - free) / maxSegments;
        double allocation = (double) allocated / maxSegments;
        return String
            .format(
                "PoolStats[max=%d, allocated=%d, free=%d, unallocated=%d, utilization=%.1f%%, allocation=%.1f%%]",
                maxSegments,
                allocated,
                free,
                unalloc,
                utilization * 100,
                allocation * 100
            );
    }

    /**
     * Monitoring snapshot of pool metrics.
     */
    @SuppressForbidden(reason = "custom string builder")
    public static class PoolStats {
        /** Maximum number of segments the pool can allocate. */
        public final int maxSegments;
        /** Number of segments currently allocated. */
        public final int allocatedSegments;
        /** Number of segments in the free list. */
        public final int freeSegments;
        /** Number of segments that can still be allocated. */
        public final int unallocatedSegments;
        /** Ratio of segments in use (allocated - free) / max. */
        public final double utilizationRatio;
        /** Ratio of allocated segments to max segments. */
        public final double allocationRatio;

        PoolStats(int maxSegments, int allocatedSegments, int freeSegments, int unallocatedSegments) {
            this.maxSegments = maxSegments;
            this.allocatedSegments = allocatedSegments;
            this.freeSegments = freeSegments;
            this.unallocatedSegments = unallocatedSegments;
            this.utilizationRatio = (double) (allocatedSegments - freeSegments) / maxSegments;
            this.allocationRatio = (double) allocatedSegments / maxSegments;
        }

        @Override
        public String toString() {
            return String
                .format(
                    "PoolStats[max=%d, allocated=%d, free=%d, unallocated=%d, utilization=%.1f%%, allocation=%.1f%%]",
                    maxSegments,
                    allocatedSegments,
                    freeSegments,
                    unallocatedSegments,
                    utilizationRatio * 100,
                    allocationRatio * 100
                );
        }
    }

    @Override
    public void recordStats() {
        double utilization = (double) (allocatedSegments - cachedFreeListSize) / maxSegments;
        double allocation = (double) allocatedSegments / maxSegments;
        CryptoMetricsService
            .getInstance()
            .recordPoolStats(SegmentType.PRIMARY, maxSegments, allocatedSegments, cachedFreeListSize, utilization, allocation);
    }
}
