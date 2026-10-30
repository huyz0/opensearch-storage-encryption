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
 * <p>Entries are keyed by the file's random message ID, not its path, so a file written again under
 * the same name never sees the old file's tags. Pages of deleted files age out by size. Cached tags
 * are only ever used to verify chunks; a wrong tag fails authentication, it cannot produce plaintext.
 *
 * @opensearch.internal
 */
public final class ChunkTagCache {

    /** Tags per cached page: 4 KiB of tags, covering 2 MiB of data. */
    public static final int TAGS_PER_PAGE = 256;
    static final int PAGE_BYTES = TAGS_PER_PAGE * ChunkCipher.TAG_LENGTH;

    /** Default heap budget: tags for 16 GiB of data. */
    public static final long DEFAULT_MAX_BYTES = 32L * 1024 * 1024;

    private record PageKey(long messageIdHigh, long messageIdLow, long page) {
    }

    /** Reads {@code length} tag-table bytes starting {@code offset} bytes into the tag table. */
    @FunctionalInterface
    public interface PageReader {
        byte[] read(long offset, int length) throws IOException;
    }

    private final Cache<PageKey, byte[]> pages;

    public ChunkTagCache(long maxBytes) {
        this.pages = Caffeine.newBuilder().maximumWeight(maxBytes).weigher((PageKey k, byte[] v) -> v.length).build();
    }

    /**
     * Returns the tags of {@code chunks} chunks starting at {@code firstChunk}, as one buffer of
     * {@code chunks * TAG_LENGTH} bytes, loading missing pages with {@code reader}.
     *
     * @param messageId the file's message ID from its footer
     * @param dataLength the file's plaintext length, which fixes the size of its tag table
     */
    public ByteBuffer getTags(byte[] messageId, long dataLength, long firstChunk, int chunks, PageReader reader) throws IOException {
        ByteBuffer messageIdBuffer = ByteBuffer.wrap(messageId);
        long high = messageIdBuffer.getLong(0);
        long low = messageIdBuffer.getLong(8);
        long tableLength = ChunkCipher.tagTableLength(dataLength);

        ByteBuffer tags = ByteBuffer.allocate(chunks * ChunkCipher.TAG_LENGTH);
        long chunk = firstChunk;
        long end = firstChunk + chunks;
        while (chunk < end) {
            long page = chunk / TAGS_PER_PAGE;
            byte[] pageBytes = getPage(new PageKey(high, low, page), tableLength, reader);
            int from = (int) (chunk - page * TAGS_PER_PAGE);
            int n = (int) Math.min(end - chunk, TAGS_PER_PAGE - from);
            tags.put(pageBytes, from * ChunkCipher.TAG_LENGTH, n * ChunkCipher.TAG_LENGTH);
            chunk += n;
        }
        return tags.flip();
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

    /** Number of cached pages, for tests and stats. */
    public long estimatedSize() {
        pages.cleanUp();
        return pages.estimatedSize();
    }

    public void clear() {
        pages.invalidateAll();
    }
}
