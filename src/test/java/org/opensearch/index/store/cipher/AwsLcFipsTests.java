/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.BeforeClass;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests the AWS-LC FIPS binding against the JCE provider the plugin uses. Runs only when
 * {@value AwsLcFips#LIBRARY_PROPERTY} names an AWS-LC FIPS build (the FIPS build's tests set it).
 */
public class AwsLcFipsTests extends OpenSearchTestCase {

    private static AwsLcFips fips;

    @BeforeClass
    public static void loadLibrary() {
        String path = System.getProperty(AwsLcFips.LIBRARY_PROPERTY);
        assumeTrue(AwsLcFips.LIBRARY_PROPERTY + " is not set", path != null && path.isEmpty() == false);
        fips = AwsLcFips.load(Path.of(path));
    }

    private static Key randomKey() {
        return new SecretKeySpec(randomByteArrayOfLength(32), "AES");
    }

    public void testLoadsTheValidatedFipsModule() {
        assertEquals(AwsLcFips.EXPECTED_VERSION, fips.version());
    }

    public void testSealThenOpenRoundTripsAndMatchesJce() throws Exception {
        Key key = randomKey();
        for (int i = 0; i < 50; i++) {
            byte[] plain = randomByteArrayOfLength(randomIntBetween(0, 3 * ChunkCipher.CHUNK_SIZE));
            byte[] aad = randomByteArrayOfLength(8);
            byte[] ct = new byte[plain.length];
            byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
            fips.seal(key, seg(aad), seg(plain), seg(ct), seg(entry));

            byte[] out = new byte[plain.length];
            fips.open(key, seg(aad), seg(ct), seg(entry), seg(out));
            assertArrayEquals(plain, out);

            // The JCE provider opens what AWS-LC sealed: ciphertext || tag under the stored nonce.
            Cipher jce = Cipher.getInstance("AES/GCM/NoPadding", CryptoProviders.provider());
            jce.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Arrays.copyOf(entry, 12)));
            jce.updateAAD(aad);
            byte[] withTag = new byte[ct.length + 16];
            System.arraycopy(ct, 0, withTag, 0, ct.length);
            System.arraycopy(entry, 12, withTag, ct.length, 16);
            assertArrayEquals(plain, jce.doFinal(withTag));
        }
    }

    public void testOpensWhatJceSealed() throws Exception {
        Key key = randomKey();
        byte[] nonce = randomByteArrayOfLength(12);
        byte[] aad = randomByteArrayOfLength(8);
        byte[] plain = randomByteArrayOfLength(ChunkCipher.CHUNK_SIZE);
        Cipher jce = Cipher.getInstance("AES/GCM/NoPadding", CryptoProviders.provider());
        jce.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        jce.updateAAD(aad);
        byte[] sealed = jce.doFinal(plain);
        byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
        System.arraycopy(nonce, 0, entry, 0, 12);
        System.arraycopy(sealed, plain.length, entry, 12, 16);
        byte[] out = new byte[plain.length];
        fips.open(key, seg(aad), MemorySegment.ofArray(sealed).asSlice(0, plain.length), seg(entry), seg(out));
        assertArrayEquals(plain, out);
    }

    public void testSealsInPlaceAndFromNativeMemory() throws Exception {
        Key key = randomKey();
        byte[] plain = randomByteArrayOfLength(ChunkCipher.CHUNK_SIZE);
        byte[] aad = new byte[8];
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buf = arena.allocate(plain.length);
            MemorySegment.copy(plain, 0, buf, ValueLayout.JAVA_BYTE, 0, plain.length);
            MemorySegment entry = arena.allocate(AwsLcFips.ENTRY_LENGTH);
            fips.seal(key, seg(aad), buf, buf, entry);
            assertFalse(Arrays.equals(plain, buf.toArray(ValueLayout.JAVA_BYTE)));
            ByteBuffer direct = ByteBuffer.allocateDirect(plain.length);
            fips.open(key, seg(aad), buf, entry, MemorySegment.ofBuffer(direct));
            byte[] out = new byte[plain.length];
            direct.get(out);
            assertArrayEquals(plain, out);
        }
    }

    public void testNoncesAreFreshPerSeal() throws Exception {
        Key key = randomKey();
        Set<String> nonces = new HashSet<>();
        byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
        for (int i = 0; i < 1000; i++) {
            fips.seal(key, seg(new byte[8]), seg(new byte[16]), seg(new byte[16]), seg(entry));
            assertTrue(nonces.add(HexFormat.of().formatHex(entry, 0, 12)));
        }
    }

    public void testTamperedInputFailsToOpen() throws Exception {
        Key key = randomKey();
        byte[] plain = randomByteArrayOfLength(64);
        byte[] aad = randomByteArrayOfLength(8);
        byte[] ct = new byte[64];
        byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
        fips.seal(key, seg(aad), seg(plain), seg(ct), seg(entry));

        byte[] badCt = ct.clone();
        badCt[randomInt(63)] ^= 1;
        expectThrows(AEADBadTagException.class, () -> fips.open(key, seg(aad), seg(badCt), seg(entry), seg(new byte[64])));
        byte[] badAad = aad.clone();
        badAad[7] ^= 1;
        expectThrows(AEADBadTagException.class, () -> fips.open(key, seg(badAad), seg(ct), seg(entry), seg(new byte[64])));
        byte[] badEntry = entry.clone();
        badEntry[randomInt(AwsLcFips.ENTRY_LENGTH - 1)] ^= 1;
        expectThrows(AEADBadTagException.class, () -> fips.open(key, seg(aad), seg(ct), seg(badEntry), seg(new byte[64])));
        expectThrows(AEADBadTagException.class, () -> fips.open(randomKey(), seg(aad), seg(ct), seg(entry), seg(new byte[64])));
        // A failure leaves no state behind: the right inputs still open.
        byte[] out = new byte[64];
        fips.open(key, seg(aad), seg(ct), seg(entry), seg(out));
        assertArrayEquals(plain, out);
    }

    public void testSwitchingKeysOnOneThread() throws Exception {
        Key a = randomKey();
        Key b = new SecretKeySpec(a.getEncoded().clone(), "AES"); // same bytes, other object
        Key c = randomKey();
        byte[] ct = new byte[32];
        byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
        fips.seal(a, seg(new byte[8]), seg(new byte[32]), seg(ct), seg(entry));
        fips.seal(c, seg(new byte[8]), seg(new byte[32]), seg(new byte[32]), seg(new byte[AwsLcFips.ENTRY_LENGTH]));
        byte[] out = new byte[32];
        fips.open(b, seg(new byte[8]), seg(ct), seg(entry), seg(out));
        assertArrayEquals(new byte[32], out);
        expectThrows(AEADBadTagException.class, () -> fips.open(c, seg(new byte[8]), seg(ct), seg(entry), seg(new byte[32])));
    }

    public void testCtrMatchesJceAtAnyOffset() throws Exception {
        Key key = randomKey();
        byte[] iv = randomByteArrayOfLength(16);
        iv[15] = (byte) 0xfe; // cross a counter-byte carry
        byte[] plain = randomByteArrayOfLength(4096);
        Cipher jce = Cipher.getInstance("AES/CTR/NoPadding", CryptoProviders.ctrProvider());
        jce.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] expected = jce.doFinal(plain);
        for (int i = 0; i < 100; i++) {
            int start = randomInt(plain.length - 1);
            int len = randomIntBetween(0, plain.length - start);
            byte[] counter = TranslogCipherTestAccess.counterBlock(iv, start / 16);
            byte[] buf = Arrays.copyOfRange(plain, start, start + len);
            fips.ctr(key, counter, start % 16, seg(buf));
            assertArrayEquals(Arrays.copyOfRange(expected, start, start + len), buf);
        }
    }

    public void testKdfMatchesHmacDefinition() throws Exception {
        byte[] secret = randomByteArrayOfLength(32);
        byte[] fixedInput = randomByteArrayOfLength(randomIntBetween(0, 64));
        int length = randomIntBetween(1, 200);
        Mac mac = Mac.getInstance("HmacSHA384", CryptoProviders.provider());
        mac.init(new SecretKeySpec(secret, "HmacSHA384"));
        byte[] expected = new byte[length];
        for (int i = 1, off = 0; off < length; i++, off += 48) {
            mac.update(ByteBuffer.allocate(4).putInt(i).array());
            mac.update(fixedInput);
            byte[] block = mac.doFinal();
            System.arraycopy(block, 0, expected, off, Math.min(48, length - off));
        }
        assertArrayEquals(expected, fips.kbkdfHmacSha384(secret, fixedInput, length));
    }

    public void testRandomBytes() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        fips.randomBytes(a);
        fips.randomBytes(b);
        assertFalse(Arrays.equals(a, b));
        assertFalse(Arrays.equals(new byte[32], a));
        fips.randomBytes(new byte[0]);
    }

    public void testConcurrentThreadsUseTheirOwnContexts() throws Exception {
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread[] workers = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            workers[t] = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 200; i++) {
                        Key key = new SecretKeySpec(randomByteArrayOfLength(32), "AES");
                        byte[] plain = randomByteArrayOfLength(1024);
                        byte[] ct = new byte[1024];
                        byte[] entry = new byte[AwsLcFips.ENTRY_LENGTH];
                        byte[] aad = new byte[8];
                        fips.seal(key, seg(aad), seg(plain), seg(ct), seg(entry));
                        byte[] out = new byte[1024];
                        fips.open(key, seg(aad), seg(ct), seg(entry), seg(out));
                        if (Arrays.equals(plain, out) == false) {
                            throw new AssertionError("round trip mismatch");
                        }
                    }
                } catch (Throwable e) {
                    failure.compareAndSet(null, e);
                }
            });
            workers[t].start();
        }
        start.countDown();
        for (Thread w : workers) {
            w.join();
        }
        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
    }

    /**
     * Another libcrypto loaded into the process with global scope (an OpenSSL another plugin or an {@code LD_PRELOAD}
     * brought in) must not capture AWS-LC's own calls. Without {@code RTLD_DEEPBIND} the module's integrity check
     * aborts the JVM here. Loads a copy of the library under another name, so it is a fresh load.
     */
    public void testLoadsAfterAGlobalOpenSsl() throws Throwable {
        Linker linker = Linker.nativeLinker();
        MethodHandle dlopen = linker
            .downcallHandle(
                linker.defaultLookup().find("dlopen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
            );
        MemorySegment openSsl = MemorySegment.NULL;
        try (Arena arena = Arena.ofConfined()) {
            for (String name : new String[] { "libcrypto.so.3", "libcrypto.so.1.1" }) {
                openSsl = (MemorySegment) dlopen.invokeExact(arena.allocateFrom(name), 0x2 | 0x100); // RTLD_NOW | RTLD_GLOBAL
                if (openSsl.equals(MemorySegment.NULL) == false) {
                    break;
                }
            }
        }
        assumeFalse("no system OpenSSL libcrypto to load", openSsl.equals(MemorySegment.NULL));
        Path copy = createTempDir().resolve("libawslc-fips-copy.so");
        Files.copy(fips.library(), copy);
        AwsLcFips second = AwsLcFips.load(copy);
        assertEquals(AwsLcFips.EXPECTED_VERSION, second.version());
        second.selfTest();
    }

    public void testRejectsAMissingLibrary() {
        IllegalStateException e = expectThrows(IllegalStateException.class, () -> AwsLcFips.load(createTempDir().resolve("nope.so")));
        assertTrue(e.getMessage(), e.getMessage().contains("does not exist"));
    }

    private static MemorySegment seg(byte[] array) {
        return MemorySegment.ofArray(array);
    }

    /** The translog's counter-block arithmetic, without depending on the translog package. */
    private static final class TranslogCipherTestAccess {
        static byte[] counterBlock(byte[] iv, long blocks) {
            byte[] counter = iv.clone();
            long carry = blocks;
            for (int i = 15; i >= 0 && carry != 0; i--) {
                long sum = (counter[i] & 0xff) + (carry & 0xff);
                counter[i] = (byte) sum;
                carry = (carry >>> 8) + (sum >>> 8);
            }
            return counter;
        }
    }
}
