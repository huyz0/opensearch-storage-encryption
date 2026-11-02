/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.benchmark;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.opensearch.index.store.cipher.ChunkCipher;

/**
 * Raw cipher cost of the encryption hot paths, without any I/O: sealing and opening one
 * {@link ChunkCipher} chunk (index files) and AES-CTR over a translog write.
 *
 * <p>Each benchmark processes {@code size} bytes, so JMH's {@code ops/s} times {@code size} is the
 * cipher's throughput. The open benchmarks compare ways to decrypt a chunk. {@link ChunkCipher#open}
 * stages ciphertext and tag through a heap array and makes one {@code doFinal}
 * ({@code gcmOpenDirectViaHeap} for the block loader's native {@link MemorySegment} buffers).
 * {@code gcmOpenDirect} and {@code gcmOpenHeap} call {@code update} with the ciphertext and then
 * {@code doFinal} with the tag on native and heap buffers, which is how {@code open} worked before;
 * {@code gcmOpenArrayContiguous} is one {@code doFinal} with no copies, the lower bound.
 *
 * <p>{@code provider} selects the JCE provider. Besides the JDK's SunJCE, the benchmark can load
 * Amazon Corretto Crypto Provider ({@code AmazonCorrettoCryptoProvider}, regular or FIPS build) and
 * Bouncy Castle FIPS ({@code BCFIPS}) when their jars are on the class path; see
 * {@code scripts/benchmark-cipher.sh}.
 *
 * <p>To see what hardware acceleration is worth for SunJCE on a machine, run it with the intrinsics
 * turned off:
 * <pre>
 *   java -jar storage-encryption-jmh.jar CipherBenchmarks \
 *     -jvmArgsAppend "-XX:+UnlockDiagnosticVMOptions -XX:-UseAESIntrinsics -XX:-UseAESCTRIntrinsics -XX:-UseGHASHIntrinsics"
 * </pre>
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@Fork(value = 1, jvmArgsAppend = { "--enable-native-access=ALL-UNNAMED" })
@State(Scope.Thread)
public class CipherBenchmarks {

    /** Bytes per operation. 8192 is one full chunk; 1024 is a typical translog write. */
    @Param({ "8192" })
    public int size;

    /** JCE provider name. */
    @Param({ "SunJCE" })
    public String provider;

    private Key key;
    private Cipher sealCipher;
    private Cipher openCipher;
    private Cipher ctrCipher;
    private long sealIndex;
    private byte[] plaintext;
    private byte[] sealed;

    // Heap copies of one sealed chunk.
    private ByteBuffer heapCiphertext;
    private ByteBuffer heapTag;
    private ByteBuffer heapOut;
    private byte[] heapSealed;
    private byte[] heapPlain;

    // Native copies, as the block loader sees them.
    private Arena arena;
    private ByteBuffer directCiphertext;
    private ByteBuffer directTag;
    private ByteBuffer directOut;

    private byte[] translogBuffer;
    private byte[] ctrIv;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        if (size > ChunkCipher.CHUNK_SIZE) {
            throw new IllegalArgumentException("size must be at most " + ChunkCipher.CHUNK_SIZE);
        }
        Provider p = loadProvider(provider);
        Random random = new Random(BenchmarkConfig.RANGE_SEED);
        byte[] keyBytes = new byte[32];
        random.nextBytes(keyBytes);
        key = new SecretKeySpec(keyBytes, "AES");
        sealCipher = Cipher.getInstance("AES/GCM/NoPadding", p);
        openCipher = Cipher.getInstance("AES/GCM/NoPadding", p);
        try {
            ctrCipher = Cipher.getInstance("AES/CTR/NoPadding", p);
        } catch (NoSuchAlgorithmException e) {
            ctrCipher = null; // e.g. Amazon Corretto Crypto Provider has no AES-CTR; ctrApply fails if run
        }

        plaintext = new byte[size];
        random.nextBytes(plaintext);
        sealed = new byte[size + ChunkCipher.TAG_LENGTH];
        seal(0);

        heapSealed = sealed.clone();
        heapPlain = new byte[size];
        byte[] heapCopy = sealed.clone();
        heapCiphertext = ByteBuffer.wrap(heapCopy, 0, size).slice();
        heapTag = ByteBuffer.wrap(heapCopy, size, ChunkCipher.TAG_LENGTH).slice();
        heapOut = ByteBuffer.allocate(size);

        arena = Arena.ofShared();
        MemorySegment ct = arena.allocate(size, 4096);
        MemorySegment.copy(MemorySegment.ofArray(sealed), 0, ct, 0, size);
        MemorySegment tag = arena.allocate(ChunkCipher.TAG_LENGTH);
        MemorySegment.copy(MemorySegment.ofArray(sealed), size, tag, 0, ChunkCipher.TAG_LENGTH);
        directCiphertext = ct.asByteBuffer();
        directTag = tag.asByteBuffer();
        directOut = arena.allocate(size, 4096).asByteBuffer();

        translogBuffer = plaintext.clone();
        ctrIv = new byte[16];
        random.nextBytes(ctrIv);

        // Fail the trial early if a variant does not round-trip with this provider.
        ByteBuffer expected = ByteBuffer.wrap(plaintext);
        gcmOpenDirect();
        check(directOut.clear(), expected, "gcmOpenDirect");
        gcmOpenHeap();
        check(heapOut.clear(), expected, "gcmOpenHeap");
        gcmOpenArrayContiguous();
        check(ByteBuffer.wrap(heapPlain), expected, "gcmOpenArrayContiguous");
        Arrays.fill(heapPlain, (byte) 0);
        directOut.clear().put(new byte[size]);
        gcmOpenDirectViaHeap();
        check(directOut.clear(), expected, "gcmOpenDirectViaHeap");
    }

    private void check(ByteBuffer actual, ByteBuffer expected, String variant) {
        if (!actual.equals(expected)) {
            throw new IllegalStateException(variant + " did not round-trip with " + provider);
        }
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        arena.close();
    }

    private static Provider loadProvider(String name) throws Exception {
        Provider p = Security.getProvider(name);
        if (p != null) {
            return p;
        }
        String className = switch (name) {
            case "AmazonCorrettoCryptoProvider" -> "com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider";
            case "BCFIPS" -> "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
            default -> throw new IllegalArgumentException("unknown provider " + name);
        };
        p = (Provider) Class.forName(className).getConstructor().newInstance();
        if (name.equals("AmazonCorrettoCryptoProvider")) {
            // Throws if the native library failed to load, instead of quietly benchmarking a fallback.
            p.getClass().getMethod("assertHealthy").invoke(p);
        }
        Security.addProvider(p);
        return p;
    }

    private void seal(long chunkIndex) throws Exception {
        sealCipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(ChunkCipher.TAG_LENGTH * Byte.SIZE, ChunkCipher.nonce(chunkIndex)));
        sealCipher.doFinal(plaintext, 0, size, sealed, 0);
    }

    private void initOpen() throws Exception {
        openCipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(ChunkCipher.TAG_LENGTH * Byte.SIZE, ChunkCipher.nonce(0)));
    }

    /**
     * Writer path: seal one chunk from a heap array, as ChunkEncryptor does. The chunk index
     * advances every call because the JCE refuses to reuse a GCM nonce.
     */
    @Benchmark
    public byte[] gcmSeal() throws Exception {
        seal(++sealIndex);
        return sealed;
    }

    /** Native memory in and out, update then doFinal(tag): the block loader before staging. */
    @Benchmark
    public ByteBuffer gcmOpenDirect() throws Exception {
        initOpen();
        openCipher.update(directCiphertext.clear(), directOut.clear());
        openCipher.doFinal(directTag.clear(), directOut);
        return directOut;
    }

    /** Heap ByteBuffers, update then doFinal(tag): the NIO path before staging. */
    @Benchmark
    public ByteBuffer gcmOpenHeap() throws Exception {
        initOpen();
        openCipher.update(heapCiphertext.clear(), heapOut.clear());
        openCipher.doFinal(heapTag.clear(), heapOut);
        return heapOut;
    }

    /** One doFinal over a heap array holding ciphertext then tag. */
    @Benchmark
    public byte[] gcmOpenArrayContiguous() throws Exception {
        initOpen();
        openCipher.doFinal(heapSealed, 0, size + ChunkCipher.TAG_LENGTH, heapPlain, 0);
        return heapPlain;
    }

    /**
     * What {@link ChunkCipher#open} does for native buffers: copy ciphertext and tag into one heap
     * array, one doFinal, copy the plaintext back.
     */
    @Benchmark
    public ByteBuffer gcmOpenDirectViaHeap() throws Exception {
        directCiphertext.get(0, heapSealed, 0, size);
        directTag.get(0, heapSealed, size, ChunkCipher.TAG_LENGTH);
        initOpen();
        openCipher.doFinal(heapSealed, 0, size + ChunkCipher.TAG_LENGTH, heapPlain, 0);
        directOut.put(0, heapPlain, 0, size);
        return directOut;
    }

    /** Translog path: AES-CTR in place on a heap array, with a fresh init per call as TranslogCipher does. */
    @Benchmark
    public byte[] ctrApply() throws Exception {
        if (ctrCipher == null) {
            throw new UnsupportedOperationException(provider + " has no AES/CTR/NoPadding");
        }
        ctrCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ctrIv));
        ctrCipher.update(translogBuffer, 0, size, translogBuffer, 0);
        return translogBuffer;
    }
}
