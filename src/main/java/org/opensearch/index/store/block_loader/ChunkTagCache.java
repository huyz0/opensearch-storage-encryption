/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;

import org.opensearch.index.store.cipher.ChunkCipher;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Node-level cache of pages of encrypted files' chunk tag tables.
 *
 * <p>A buffer-pool miss needs each chunk's 16-byte tag as well as its ciphertext. Without this cache
 * every miss does a second Direct I/O read for a few tags. A page holds {@link #TAGS_PER_PAGE} tags
 * (the tags for 2 MiB of data), so neighbouring misses in the same file share one read.
 *
 * <p>Entries are keyed by the file's random message ID and plaintext length, not its path, so a file
 * written again under the same name never sees the old file's tags. Pages of deleted files age out by
 * size. Cached tags are only ever used to verify chunks: a wrong tag fails authentication, it cannot
 * produce plaintext. The caller drops a page with {@link #invalidate} when a chunk fails, so a bad read
 * is not remembered.
 *
 * @opensearch.internal
 */
public final class ChunkTagCache {

    /** Tags per cached page: 4 KiB of tags, covering 2 MiB of data. */
    public static final int TAGS_PER_PAGE = 256;
    static final int PAGE_BYTES = TAGS_PER_PAGE * ChunkCipher.TAG_LENGTH;

    /** Default heap budget, including per-entry overhead: tags for up to about 16 GiB of data. */
    public static final long DEFAULT_MAX_BYTES = 32L * 1024 * 1024;

    /**
     * Approximate heap cost of one entry beyond its tag bytes: the key, the array header and the
     * cache's node. Small files have pages of a few bytes, so without this the bound would mostly
     * count overhead it cannot see.
     */
    static final int ENTRY_OVERHEAD_BYTES = 200;

    private record PageKey(long messageIdHigh, long messageIdLow, long dataLength, long page) {
    }

    /** Reads tag-table bytes for a page that is not cached. */
    @FunctionalInterface
    public interface PageReader {
        /**
         * Reads part of the file's tag table.
         *
         * @param offset offset into the tag table (not into the file)
         * @param length number of bytes to read
         * @return the bytes read
         * @throws IOException if the read fails
         */
        byte[] read(long offset, int length) throws IOException;
    }

    private final Cache<PageKey, byte[]> pages;

    /**
     * Creates a cache bounded to about {@code maxBytes} of heap.
     *
     * @param maxBytes heap budget for cached pages, including per-entry overhead
     */
    public ChunkTagCache(long maxBytes) {
        this.pages = Caffeine
            .newBuilder()
            .maximumWeight(maxBytes)
            .weigher((PageKey k, byte[] v) -> v.length + ENTRY_OVERHEAD_BYTES)
            .build();
    }

    /**
     * Returns the tags of {@code chunks} chunks starting at {@code firstChunk}, as one buffer of
     * {@code chunks * TAG_LENGTH} bytes, loading missing pages with {@code reader}.
     *
     * @param messageId the file's message ID from its footer
     * @param dataLength the file's plaintext length, which fixes the size of its tag table
     * @param firstChunk index of the first chunk
     * @param chunks number of chunks
     * @param reader reads tag-table bytes for pages that are not cached
     * @return the tags, positioned at 0
     * @throws IOException if a page has to be read and the read fails or is short
     */
    public ByteBuffer getTags(byte[] messageId, long dataLength, long firstChunk, int chunks, PageReader reader) throws IOException {
        long tableLength = ChunkCipher.tagTableLength(dataLength);
        ByteBuffer tags = ByteBuffer.allocate(chunks * ChunkCipher.TAG_LENGTH);
        long chunk = firstChunk;
        long end = firstChunk + chunks;
        while (chunk < end) {
            long page = chunk / TAGS_PER_PAGE;
            byte[] pageBytes = getPage(key(messageId, dataLength, page), tableLength, reader);
            int from = (int) (chunk - page * TAGS_PER_PAGE);
            int n = (int) Math.min(end - chunk, TAGS_PER_PAGE - from);
            tags.put(pageBytes, from * ChunkCipher.TAG_LENGTH, n * ChunkCipher.TAG_LENGTH);
            chunk += n;
        }
        return tags.flip();
    }

    /**
     * Drops the cached page holding {@code chunk}'s tag, so the next load reads it from disk again.
     *
     * @param messageId the file's message ID from its footer
     * @param dataLength the file's plaintext length
     * @param chunk index of the chunk whose page to drop
     */
    public void invalidate(byte[] messageId, long dataLength, long chunk) {
        pages.invalidate(key(messageId, dataLength, chunk / TAGS_PER_PAGE));
    }

    private static PageKey key(byte[] messageId, long dataLength, long page) {
        ByteBuffer id = ByteBuffer.wrap(messageId);
        return new PageKey(id.getLong(0), id.getLong(8), dataLength, page);
    }

    private byte[] getPage(PageKey key, long tableLength, PageReader reader) throws IOException {
        byte[] bytes = pages.getIfPresent(key);
        if (bytes != null) {
            return bytes;
        }
        // Read outside the cache's locks; two threads missing the same page both read it, which is harmless.
        long offset = key.page() * PAGE_BYTES;
        int length = (int) Math.min(PAGE_BYTES, tableLength - offset);
        bytes = reader.read(offset, length);
        if (bytes.length != length) {
            throw new EOFException("short read of tag table: " + bytes.length + " of " + length + " bytes");
        }
        pages.put(key, bytes);
        return bytes;
    }

    /**
     * Number of cached pages, for tests and stats.
     *
     * @return the approximate number of cached pages
     */
    public long estimatedSize() {
        pages.cleanUp();
        return pages.estimatedSize();
    }

    /** Drops every cached page. */
    public void clear() {
        pages.invalidateAll();
    }
}
