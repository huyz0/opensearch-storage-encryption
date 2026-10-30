/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.test.OpenSearchTestCase;

public class ChunkTagCacheTests extends OpenSearchTestCase {

    private static final int TAG = ChunkCipher.TAG_LENGTH;
    private static final int PAGE = ChunkTagCache.TAGS_PER_PAGE;

    /** A tag table where every byte encodes its own offset, so misplaced bytes are visible. */
    private static byte[] table(long chunks) {
        byte[] table = new byte[(int) (chunks * TAG)];
        for (int i = 0; i < table.length; i++) {
            table[i] = (byte) (i * 7 + (i >>> 8));
        }
        return table;
    }

    private static final class CountingReader implements ChunkTagCache.PageReader {
        final byte[] table;
        final List<long[]> reads = new ArrayList<>();

        CountingReader(byte[] table) {
            this.table = table;
        }

        @Override
        public byte[] read(long offset, int length) {
            reads.add(new long[] { offset, length });
            return Arrays.copyOfRange(table, (int) offset, (int) offset + length);
        }
    }

    public void testReturnsTagsAcrossPagesAndCachesPages() throws IOException {
        long chunks = 3L * PAGE + 17;
        long dataLength = (chunks - 1) * ChunkCipher.CHUNK_SIZE + 5;
        byte[] table = table(chunks);
        CountingReader reader = new CountingReader(table);
        ChunkTagCache cache = new ChunkTagCache(ChunkTagCache.DEFAULT_MAX_BYTES);
        byte[] messageId = randomByteArrayOfLength(16);

        for (int i = 0; i < 50; i++) {
            long first = randomLongBetween(0, chunks - 1);
            int n = (int) randomLongBetween(1, Math.min(2L * PAGE + 3, chunks - first));
            ByteBuffer tags = cache.getTags(messageId, dataLength, first, n, reader);
            assertEquals(n * TAG, tags.remaining());
            byte[] actual = new byte[n * TAG];
            tags.get(actual);
            assertArrayEquals(Arrays.copyOfRange(table, (int) first * TAG, (int) (first + n) * TAG), actual);
        }
        // Each page is read at most once, and the last page is only as long as the table.
        assertTrue(reader.reads.size() <= 4);
        for (long[] read : reader.reads) {
            assertEquals(0, read[0] % ((long) PAGE * TAG));
            assertEquals(Math.min((long) PAGE * TAG, table.length - read[0]), read[1]);
        }
    }

    public void testPagesAreKeyedByMessageId() throws IOException {
        long dataLength = 10L * ChunkCipher.CHUNK_SIZE;
        ChunkTagCache cache = new ChunkTagCache(ChunkTagCache.DEFAULT_MAX_BYTES);
        byte[] a = table(10);
        byte[] b = table(10);
        b[0] ^= 1;
        byte[] idA = randomByteArrayOfLength(16);
        byte[] idB = idA.clone();
        idB[15] ^= 1;

        assertEquals(a[0], cache.getTags(idA, dataLength, 0, 1, new CountingReader(a)).get(0));
        // Same path, rewritten file: a new message ID must not see the old tags.
        assertEquals(b[0], cache.getTags(idB, dataLength, 0, 1, new CountingReader(b)).get(0));
        assertEquals(2, cache.estimatedSize());
    }

    public void testShortReadIsAnErrorAndNotCached() throws IOException {
        long dataLength = 4L * ChunkCipher.CHUNK_SIZE;
        ChunkTagCache cache = new ChunkTagCache(ChunkTagCache.DEFAULT_MAX_BYTES);
        byte[] id = randomByteArrayOfLength(16);
        expectThrows(EOFException.class, () -> cache.getTags(id, dataLength, 0, 1, (offset, length) -> new byte[length - 1]));
        assertEquals(0, cache.estimatedSize());
        expectThrows(IOException.class, () -> cache.getTags(id, dataLength, 0, 1, (offset, length) -> { throw new IOException("boom"); }));
        assertEquals(0, cache.estimatedSize());
    }

    public void testSizeIsBounded() throws IOException {
        long chunks = 40L * PAGE;
        long dataLength = chunks * ChunkCipher.CHUNK_SIZE;
        ChunkTagCache cache = new ChunkTagCache(4L * PAGE * TAG);
        CountingReader reader = new CountingReader(table(chunks));
        byte[] id = randomByteArrayOfLength(16);
        for (long page = 0; page < 40; page++) {
            cache.getTags(id, dataLength, page * PAGE, 1, reader);
        }
        assertTrue("cached pages: " + cache.estimatedSize(), cache.estimatedSize() <= 4);
    }
}
