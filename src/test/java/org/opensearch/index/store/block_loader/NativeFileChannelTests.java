/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.block_loader;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.NonWritableChannelException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.Before;
import org.opensearch.test.OpenSearchTestCase;

public class NativeFileChannelTests extends OpenSearchTestCase {

    private static final int FILE_SIZE = 3 * 4096 + 123;

    private Path file;
    private byte[] content;

    @Before
    public void setUpFile() throws IOException {
        assumeTrue("native reads unavailable on this platform", NativeFileChannel.isAvailable());
        content = new byte[FILE_SIZE];
        for (int i = 0; i < FILE_SIZE; i++) {
            content[i] = (byte) (i * 7 + (i >>> 8));
        }
        file = createTempDir().resolve("native");
        Files.write(file, content);
    }

    private FileChannel open() throws IOException {
        FileChannel fc = NativeFileChannel.open(file, false, null);
        assertTrue(fc instanceof NativeFileChannel);
        return fc;
    }

    private void assertContent(ByteBuffer buf, long offset, int n) {
        for (int i = 0; i < n; i++) {
            assertEquals("byte " + (offset + i), content[(int) offset + i], buf.get(i));
        }
    }

    public void testPositionalReadIntoDirectAndHeapBuffers() throws IOException {
        try (FileChannel fc = open()) {
            for (ByteBuffer buf : new ByteBuffer[] { ByteBuffer.allocateDirect(1000), ByteBuffer.allocate(1000) }) {
                buf.position(10);
                int n = fc.read(buf, 4100);
                assertEquals(990, n);
                assertEquals(1000, buf.position());
                assertContent(buf.flip().position(10).slice(), 4100, n);
            }
        }
    }

    public void testShortReadAtEndAndEof() throws IOException {
        try (FileChannel fc = open()) {
            ByteBuffer buf = ByteBuffer.allocateDirect(4096);
            assertEquals(123, fc.read(buf, 3 * 4096));
            assertContent(buf.flip(), 3 * 4096, 123);
            assertEquals(-1, fc.read(ByteBuffer.allocate(16), FILE_SIZE));
            assertEquals(0, fc.read(ByteBuffer.allocate(0), 0));
        }
    }

    public void testRelativeReadsSizeAndPosition() throws IOException {
        try (FileChannel fc = open()) {
            assertEquals(FILE_SIZE, fc.size());
            fc.position(50);
            ByteBuffer a = ByteBuffer.allocate(100);
            ByteBuffer b = ByteBuffer.allocateDirect(100);
            assertEquals(200, fc.read(new ByteBuffer[] { a, b }));
            assertEquals(250, fc.position());
            assertContent(a.flip(), 50, 100);
            assertContent(b.flip(), 150, 100);
        }
    }

    public void testMissingFile() {
        expectThrows(NoSuchFileException.class, () -> NativeFileChannel.open(file.resolveSibling("missing"), false, null));
    }

    public void testIsReadOnly() throws IOException {
        try (FileChannel fc = open()) {
            expectThrows(NonWritableChannelException.class, () -> fc.write(ByteBuffer.allocate(1), 0));
            expectThrows(NonWritableChannelException.class, () -> fc.truncate(0));
        }
    }

    public void testReadAfterCloseFails() throws IOException {
        FileChannel fc = open();
        fc.close();
        assertFalse(fc.isOpen());
        expectThrows(ClosedChannelException.class, () -> fc.read(ByteBuffer.allocate(8), 0));
        expectThrows(ClosedChannelException.class, fc::size);
        fc.close(); // idempotent
    }

    /** The JDK FileChannel closes itself here (ClosedByInterruptException); this one must not. */
    public void testInterruptDoesNotCloseChannel() throws Exception {
        try (FileChannel fc = open()) {
            Thread.currentThread().interrupt();
            try {
                ByteBuffer buf = ByteBuffer.allocateDirect(64);
                assertEquals(64, fc.read(buf, 0));
                assertContent(buf.flip(), 0, 64);
            } finally {
                assertTrue("interrupt flag should be preserved", Thread.interrupted());
            }
            assertTrue(fc.isOpen());

            // Interrupt other readers of the same channel while they read
            int threads = 4;
            CountDownLatch done = new CountDownLatch(threads);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread[] readers = new Thread[threads];
            for (int t = 0; t < threads; t++) {
                readers[t] = new Thread(() -> {
                    try {
                        ByteBuffer buf = ByteBuffer.allocateDirect(4096);
                        for (int i = 0; i < 2000; i++) {
                            buf.clear();
                            fc.read(buf, 0);
                        }
                    } catch (Throwable e) {
                        failure.compareAndSet(null, e);
                    } finally {
                        done.countDown();
                    }
                });
                readers[t].start();
            }
            while (done.getCount() > 0) {
                for (Thread r : readers) {
                    r.interrupt();
                }
                Thread.onSpinWait();
            }
            for (Thread r : readers) {
                r.join();
            }
            assertNull(failure.get());
            assertTrue("interrupted readers must not close the shared channel", fc.isOpen());
        }
    }

    public void testDirectRead() throws IOException {
        FileChannel fc;
        try {
            fc = NativeFileChannel.open(file, true, DirectIOReaderUtil.getDirectOpenOption());
        } catch (IOException e) {
            assumeNoException("filesystem does not support O_DIRECT", e);
            return;
        }
        try (fc; Arena arena = Arena.ofConfined()) {
            MemorySegment aligned = arena.allocate(8192, 4096);
            ByteBuffer buf = aligned.asByteBuffer();
            assertEquals(8192, fc.read(buf, 4096));
            assertContent(buf.flip(), 4096, 8192);
        }
    }

    public void testAccessDenied() throws IOException {
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"));
        assumeFalse("running with root privileges", Files.isReadable(file));
        expectThrows(AccessDeniedException.class, () -> NativeFileChannel.open(file, false, null));
    }

    public void testReadOfDirectoryReportsErrno() throws IOException {
        try (FileChannel fc = NativeFileChannel.open(file.getParent(), false, null)) {
            IOException e = expectThrows(IOException.class, () -> fc.read(ByteBuffer.allocateDirect(8), 0));
            assertTrue(e.getMessage(), e.getMessage().contains("errno 21")); // EISDIR
        }
    }

    public void testReadOnlyBufferRejected() throws IOException {
        try (FileChannel fc = open()) {
            expectThrows(IllegalArgumentException.class, () -> fc.read(ByteBuffer.allocateDirect(16).asReadOnlyBuffer(), 0));
            expectThrows(IllegalArgumentException.class, () -> fc.read(ByteBuffer.allocate(16).asReadOnlyBuffer(), 0));
        }
    }

    /** close() waits for a read in flight; later reads fail with ClosedChannelException. */
    public void testCloseWaitsForInFlightRead() throws Exception {
        Path big = file.resolveSibling("big");
        int size = 16 << 20;
        Files.write(big, new byte[size]);
        FileChannel fc = NativeFileChannel.open(big, false, null);
        AtomicReference<Object> result = new AtomicReference<>();
        Thread reader = new Thread(() -> {
            try {
                result.set(fc.read(ByteBuffer.allocateDirect(size), 0));
            } catch (Throwable e) {
                result.set(e);
            }
        });
        reader.start();
        fc.close();
        reader.join();
        Object res = result.get();
        assertTrue(
            "read completes fully or sees the close: " + res,
            Integer.valueOf(size).equals(res) || res instanceof ClosedChannelException
        );
        expectThrows(ClosedChannelException.class, () -> fc.read(ByteBuffer.allocateDirect(8), 0));
    }

    /**
     * Closing while readers are in flight must never let a read reach another file that reused the
     * freed fd number.
     */
    public void testCloseDuringReadsNeverReadsAnotherFile() throws Exception {
        byte[] a = new byte[1 << 20];
        byte[] b = new byte[1 << 20];
        Arrays.fill(a, (byte) 'A');
        Arrays.fill(b, (byte) 'B');
        Path fileA = Files.write(file.resolveSibling("a"), a);
        Path fileB = Files.write(file.resolveSibling("b"), b);
        for (int round = 0; round < 20; round++) {
            FileChannel fc = NativeFileChannel.open(fileA, false, null);
            int readers = 4;
            CountDownLatch started = new CountDownLatch(readers);
            AtomicBoolean stop = new AtomicBoolean();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            List<Thread> threads = new ArrayList<>();
            for (int t = 0; t < readers; t++) {
                Thread th = new Thread(() -> {
                    ByteBuffer buf = ByteBuffer.allocateDirect(1 << 20);
                    started.countDown();
                    while (!stop.get()) {
                        buf.clear();
                        try {
                            int n = fc.read(buf, 0);
                            for (int i = 0; i < n; i++) {
                                if (buf.get(i) != 'A') {
                                    failure.compareAndSet(null, new AssertionError("read another file's byte " + (char) buf.get(i)));
                                    return;
                                }
                            }
                        } catch (ClosedChannelException e) {
                            return;
                        } catch (Throwable e) {
                            failure.compareAndSet(null, e);
                            return;
                        }
                    }
                });
                threads.add(th);
                th.start();
            }
            started.await();
            Thread.sleep(2);
            fc.close();
            // Grab the freed fd number while readers are still running
            List<FileChannel> others = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                others.add(NativeFileChannel.open(fileB, false, null));
            }
            Thread.sleep(2);
            stop.set(true);
            for (Thread th : threads) {
                th.join();
            }
            for (FileChannel o : others) {
                o.close();
            }
            assertNull("round " + round, failure.get());
        }
    }
}
