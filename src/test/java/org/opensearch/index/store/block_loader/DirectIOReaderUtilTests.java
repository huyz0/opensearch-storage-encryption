/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import static org.opensearch.index.store.bufferpoolfs.StaticConfigs.getDirectIOAlignment;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.test.OpenSearchTestCase;

/**
 * {@link DirectIOReaderUtil#directIOReadAligned} returns every requested byte even when the channel
 * returns short reads, as pread may.
 */
@SuppressForbidden(reason = "test channel wraps a FileChannel")
public class DirectIOReaderUtilTests extends OpenSearchTestCase {

    public void testShortReadsAreRetried() throws IOException {
        Path file = createTempDir().resolve("data");
        int alignment = getDirectIOAlignment(file.getParent());
        byte[] data = randomByteArrayOfLength(5 * alignment + 123);
        Files.write(file, data);

        try (FileChannel real = FileChannel.open(file, StandardOpenOption.READ); Arena arena = Arena.ofConfined()) {
            // Each read returns at most one aligned unit, as a short pread would
            FileChannel shortReads = new ShortReadChannel(real, alignment);
            for (int i = 0; i < 20; i++) {
                long offset = randomIntBetween(0, data.length - 1);
                long length = randomIntBetween(1, (int) (data.length - offset));
                MemorySegment read = DirectIOReaderUtil.directIOReadAligned(shortReads, file, offset, length, arena);
                assertEquals(length, read.byteSize());
                assertArrayEquals(Arrays.copyOfRange(data, (int) offset, (int) (offset + length)), read.toArray(ValueLayout.JAVA_BYTE));
            }
            // Past the end of the file: only what exists
            MemorySegment tail = DirectIOReaderUtil.directIOReadAligned(shortReads, file, data.length - 10, 1000, arena);
            assertEquals(10, tail.byteSize());
        }
    }

    /** Reads at most {@code max} bytes per call; nothing else is used by the code under test. */
    private static final class ShortReadChannel extends FileChannel {
        private final FileChannel delegate;
        private final int max;

        ShortReadChannel(FileChannel delegate, int max) {
            this.delegate = delegate;
            this.max = max;
        }

        @Override
        public int read(ByteBuffer dst, long position) throws IOException {
            ByteBuffer limited = dst.slice(dst.position(), Math.min(dst.remaining(), max));
            int n = delegate.read(limited, position);
            if (n > 0) {
                dst.position(dst.position() + n);
            }
            return n;
        }

        @Override
        public int read(ByteBuffer dst) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long read(ByteBuffer[] dsts, int offset, int length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int write(ByteBuffer src) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long write(ByteBuffer[] srcs, int offset, int length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long position() {
            throw new UnsupportedOperationException();
        }

        @Override
        public FileChannel position(long newPosition) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public FileChannel truncate(long size) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void force(boolean metaData) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long transferTo(long position, long count, WritableByteChannel target) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long transferFrom(ReadableByteChannel src, long position, long count) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int write(ByteBuffer src, long position) {
            throw new UnsupportedOperationException();
        }

        @Override
        public MappedByteBuffer map(MapMode mode, long position, long size) {
            throw new UnsupportedOperationException();
        }

        @Override
        public FileLock lock(long position, long size, boolean shared) {
            throw new UnsupportedOperationException();
        }

        @Override
        public FileLock tryLock(long position, long size, boolean shared) {
            throw new UnsupportedOperationException();
        }

        @Override
        protected void implCloseChannel() {}
    }
}
