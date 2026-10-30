/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import static org.opensearch.index.store.block_loader.DirectIOReaderUtil.directIOReadAligned;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_MASK;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE;
import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.CACHE_BLOCK_SIZE_POWER;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.MemorySegmentDecryptor;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.footer.EncryptionMetadataTrailer;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.pool.Pool;

/**
 * A {@link BlockLoader} implementation that loads encrypted file blocks using Direct I/O
 * and automatically decrypts them in-place.
 *
 * <p>This loader combines high-performance Direct I/O with transparent decryption to provide
 * efficient access to encrypted file data. It reads blocks directly from storage, bypassing
 * the OS buffer cache, then decrypts the data in memory using the configured key and IV resolver.
 *
 * <p>Key features:
 * <ul>
 * <li>Direct I/O for high performance and reduced memory pressure</li>
 * <li>Automatic in-place decryption of loaded blocks</li>
 * <li>Memory pool integration for efficient buffer management</li>
 * <li>Block-aligned operations for optimal storage performance</li>
 * <li>Cached FileChannels via {@link FileChannelCache} to avoid per-load open/close overhead</li>
 * </ul>
 *
 * @opensearch.internal
 */
@SuppressWarnings("preview")
public class CryptoDirectIOBlockLoader implements BlockLoader<RefCountedMemorySegment> {
    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectIOBlockLoader.class);
    private static final int MAX_READ_ATTEMPTS = 3;

    private final KeyResolver keyResolver;
    private final Pool<RefCountedMemorySegment> segmentPool;
    private final EncryptionMetadataCache encryptionMetadataCache;
    private final FileChannelCache fileChannelCache;

    /**
     * Constructs a new CryptoDirectIOBlockLoader with the specified memory pool and key resolver.
     *
     * @param segmentPool the memory segment pool for acquiring buffer space
     * @param keyResolver the resolver for obtaining encryption keys and initialization vectors
     * @param encryptionMetadataCache cache for encryption metadata
     * @param fileChannelCache node-level cache of FileChannels bounded by max open FDs
     */
    public CryptoDirectIOBlockLoader(
        Pool<RefCountedMemorySegment> segmentPool,
        KeyResolver keyResolver,
        EncryptionMetadataCache encryptionMetadataCache,
        FileChannelCache fileChannelCache
    ) {
        this.segmentPool = segmentPool;
        this.keyResolver = keyResolver;
        this.encryptionMetadataCache = encryptionMetadataCache;
        this.fileChannelCache = fileChannelCache;
    }

    @Override
    public RefCountedMemorySegment[] load(Path filePath, long startOffset, long blockCount, long poolTimeoutMs) throws Exception {
        if (!Files.exists(filePath)) {
            throw new NoSuchFileException(filePath.toString());
        }

        if ((startOffset & CACHE_BLOCK_MASK) != 0) {
            throw new IllegalArgumentException("startOffset must be block-aligned: " + startOffset);
        }

        if (blockCount <= 0) {
            throw new IllegalArgumentException("blockCount must be positive: " + blockCount);
        }

        RefCountedMemorySegment[] result = new RefCountedMemorySegment[(int) blockCount];
        long readLength = blockCount << CACHE_BLOCK_SIZE_POWER;
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();

        // Take the pool segments before any I/O. Under pool pressure the block cache retries this load,
        // and failing here keeps each retry from re-reading and re-decrypting the block.
        acquireSegments(result, poolTimeoutMs);
        boolean success = false;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment readBytes = readAligned(normalizedPath, filePath, startOffset, readLength, arena);
            long bytesRead = readBytes.byteSize();

            byte[] masterKey = keyResolver.getDataKey().getEncoded();

            // Get footer from disk and load metadata (footer + derived key) atomically into cache
            EncryptionFooter footer = readFooterFromDisk(normalizedPath, filePath, masterKey);

            // Get or create metadata atomically - ensures footer and key are always consistent
            var metadata = encryptionMetadataCache.getOrLoadMetadata(normalizedPath, footer, masterKey);
            byte[] messageId = metadata.getFooter().getMessageId();
            byte[] fileKey = metadata.getFileKey();

            // Use frame-based decryption with derived file key
            MemorySegmentDecryptor
                .decryptInPlaceFrameBased(
                    readBytes.address(),
                    readBytes.byteSize(),
                    fileKey,
                    masterKey,
                    messageId,
                    EncryptionMetadataTrailer.DEFAULT_FRAME_SIZE,
                    startOffset,
                    normalizedPath,
                    encryptionMetadataCache
                );

            if (bytesRead == 0) {
                throw new java.io.EOFException("Unexpected EOF or empty read at offset " + startOffset + " for file " + filePath);
            }

            int blockIndex = 0;
            long bytesCopied = 0;
            while (blockIndex < blockCount && bytesCopied < bytesRead) {
                int toCopy = (int) Math.min(CACHE_BLOCK_SIZE, bytesRead - bytesCopied);
                MemorySegment.copy(readBytes, bytesCopied, result[blockIndex].segment(), 0, toCopy);
                blockIndex++;
                bytesCopied += toCopy;
            }
            // Short read at EOF: hand back the segments that got no data
            releaseHandles(result, blockIndex, result.length);

            success = true;
            return result;
        } catch (NoSuchFileException e) {
            throw e;
        } catch (ClosedByInterruptException e) {
            // Cancellation (e.g. recovery or shutdownNow), not a storage failure
            LOGGER.debug("Bulk read interrupted: path={} offset={}", filePath, startOffset);
            throw e;
        } catch (Exception e) {
            LOGGER.error("Bulk read failed: path={} offset={} length={} err={}", filePath, startOffset, readLength, e.toString());
            throw e;
        } finally {
            if (!success) {
                releaseHandles(result, 0, result.length);
            }
        }
    }

    /**
     * Reads through the shared cached channel. Another thread that is interrupted while reading the
     * same file closes the channel for everyone (FileChannel is interruptible), which surfaces here as
     * {@link java.nio.channels.AsynchronousCloseException}. That is not this reader's failure, so retry
     * on a fresh channel. If this thread was the one interrupted, propagate the exception. Nothing else
     * closes the channel mid-read: the ref held here keeps cache eviction from closing it.
     */
    private MemorySegment readAligned(String normalizedPath, Path filePath, long startOffset, long readLength, Arena arena)
        throws IOException {
        if (Thread.currentThread().isInterrupted()) {
            // An already-cancelled thread would close the shared channel on its first read, and keep
            // closing each replacement on every later load. Fail before touching it.
            throw new ClosedByInterruptException();
        }
        for (int attempt = 1;; attempt++) {
            // acquire() drops a closed channel from the cache and opens a new one
            try (RefCountedChannel ref = fileChannelCache.acquire(normalizedPath)) {
                return directIOReadAligned(ref.channel(), filePath, startOffset, readLength, arena);
            } catch (ClosedChannelException e) {
                if (e instanceof ClosedByInterruptException || Thread.currentThread().isInterrupted() || attempt >= MAX_READ_ATTEMPTS) {
                    throw e;
                }
            }
        }
    }

    /**
     * Fills {@code into} from the pool, or releases what it took and throws. A pool timeout is reported as
     * {@link PoolAcquireFailedException} so the block cache can free space and retry.
     */
    private void acquireSegments(RefCountedMemorySegment[] into, long poolTimeoutMs) throws Exception {
        int acquired = 0;
        try {
            for (; acquired < into.length; acquired++) {
                into[acquired] = segmentPool.tryAcquire(poolTimeoutMs, TimeUnit.MILLISECONDS);
            }
        } catch (InterruptedException e) {
            releaseHandles(into, 0, acquired);
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while acquiring pool segment", e);
        } catch (IOException e) {
            releaseHandles(into, 0, acquired);
            // The pool reports a timeout as a plain IOException
            throw new PoolAcquireFailedException(e.getMessage(), e);
        } catch (Exception e) {
            releaseHandles(into, 0, acquired);
            throw e;
        }
    }

    private void releaseHandles(RefCountedMemorySegment[] handles, int from, int to) {
        for (int i = from; i < to; i++) {
            if (handles[i] != null) {
                handles[i].close();
                handles[i] = null;
            }
        }
    }

    private EncryptionFooter readFooterFromDisk(String normalizedPath, Path filePath, byte[] masterKey) throws IOException {
        // Check cache first for fast path
        EncryptionFooter cachedFooter = encryptionMetadataCache.getFooter(normalizedPath);
        if (cachedFooter != null) {
            return cachedFooter;
        }

        // Cache miss - read from disk using a buffered channel (footer reads are small, no O_DIRECT needed)
        try (FileChannel channel = FileChannel.open(filePath, StandardOpenOption.READ)) {
            long fileSize = channel.size();
            if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
                throw new IOException("File too small to contain footer: " + filePath);
            }

            // Read minimum footer to check OSEF magic bytes
            ByteBuffer minBuffer = ByteBuffer.allocate(EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            channel.read(minBuffer, fileSize - EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
            byte[] minFooterBytes = minBuffer.array();

            // Check if this is an OSEF file
            if (!isValidOSEFFile(minFooterBytes)) {
                throw new IOException("Not an OSEF file -" + filePath);
            }

            return EncryptionFooter.readViaFileChannel(normalizedPath, channel, masterKey, encryptionMetadataCache);
        }
    }

    /**
     * Check if file has valid OSEF magic bytes
     */
    private boolean isValidOSEFFile(byte[] minFooterBytes) {
        int magicOffset = minFooterBytes.length - EncryptionMetadataTrailer.MAGIC.length;
        for (int i = 0; i < EncryptionMetadataTrailer.MAGIC.length; i++) {
            if (minFooterBytes[magicOffset + i] != EncryptionMetadataTrailer.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }
}
