/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Chooses the cryptographic implementation for every cipher, MAC and random number the plugin uses.
 *
 * <p>JCE algorithms come from the JVM's provider order, as in OpenSearch core: no provider is named, so the
 * node's {@code java.security} configuration decides. Outside FIPS mode that is normally the JDK's SunJCE. In
 * FIPS mode (Bouncy Castle FIPS in approved-only mode, which OpenSearch's {@code OPENSEARCH_FIPS_MODE=true} turns
 * on) OpenSearch puts {@value #FIPS_PROVIDER} first and removes SunJCE. The provider the order picks for each
 * algorithm is pinned the first time it is needed (AES-GCM, AES-CTR, HmacSHA384 and SecureRandom at startup), so a
 * provider added to the JVM later cannot change what the plugin uses. The startup log names each one.
 *
 * <p>Two builds:
 * <ul>
 *   <li>The default build uses only JCE and loads no native code. It runs in either mode.</li>
 *   <li>The FIPS build ({@code -Pcrypto.standard=FIPS-140-3}) bundles the AWS-LC FIPS module ({@link AwsLcFips})
 *       and uses it directly for AES-GCM, AES-CTR, key derivation and random numbers; JCE only for the rest. It refuses to start
 *       on a node that is not in FIPS mode, or if AWS-LC cannot be loaded.</li>
 * </ul>
 *
 * @opensearch.internal
 */
public final class CryptoProviders {

    private static final Logger LOGGER = LogManager.getLogger(CryptoProviders.class);

    /** The Bouncy Castle FIPS provider, first in the JVM's order in OpenSearch's FIPS mode. */
    public static final String FIPS_PROVIDER = "BCFIPS";

    /** Value of {@code crypto.standard} for a FIPS build, matching OpenSearch's own build parameter. */
    public static final String FIPS_140_3 = "FIPS-140-3";

    /** Classpath resource written by the build; holds {@code crypto.standard}. */
    static final String BUILD_INFO_RESOURCE = "crypto-standard.properties";

    private static volatile Resolved resolved;

    private CryptoProviders() {}

    /** What was chosen for this JVM. */
    private record Resolved(
        Provider provider,
        SecureRandom random,
        String randomAlgorithm,
        Provider randomProvider,
        AwsLcFips awsLc,
        boolean fips,
        Map<String, Provider> pinned
    ) {
    }

    static final String GCM = "AES/GCM/NoPadding";
    static final String CTR = "AES/CTR/NoPadding";
    static final String HMAC = "HmacSHA384";

    /**
     * Nonce source for JCE sealing: one per thread, so parallel writers do not contend on a shared generator. Each
     * is an instance of the pinned SecureRandom algorithm and provider.
     */
    private static final ThreadLocal<SecureRandom> NONCE_RANDOM = ThreadLocal.withInitial(() -> {
        Resolved r = resolve();
        try {
            return SecureRandom.getInstance(r.randomAlgorithm, r.randomProvider);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("cannot create a [" + r.randomAlgorithm + "] SecureRandom from [" + r.randomProvider + "]", e);
        }
    });

    /** Looks up the provider the JVM's order picks for an algorithm. */
    @FunctionalInterface
    private interface Lookup {
        Provider provider() throws GeneralSecurityException;
    }

    /**
     * Returns a JCE cipher for {@code transformation} from the provider the JVM's order picked for it, like
     * OpenSearch core: the plugin names no provider, so the node's {@code java.security} configuration decides (in
     * FIPS mode OpenSearch puts {@value #FIPS_PROVIDER} first and removes SunJCE). The choice is pinned the first
     * time, and every later call uses the same provider.
     */
    public static Cipher cipher(String transformation) throws GeneralSecurityException {
        return Cipher.getInstance(transformation, pinned(resolve(), "Cipher." + transformation, () -> Cipher.getInstance(transformation).getProvider()));
    }

    /** Returns a JCE MAC for {@code algorithm} from the provider pinned for it; see {@link #cipher}. */
    public static Mac mac(String algorithm) throws GeneralSecurityException {
        return Mac.getInstance(algorithm, pinned(resolve(), "Mac." + algorithm, () -> Mac.getInstance(algorithm).getProvider()));
    }

    private static Provider pinned(Resolved r, String key, Lookup lookup) throws GeneralSecurityException {
        Provider p = r.pinned.get(key);
        if (p == null) {
            synchronized (r.pinned) {
                p = r.pinned.get(key);
                if (p == null) {
                    p = lookup.provider();
                    r.pinned.put(key, p);
                }
            }
        }
        return p;
    }

    /**
     * The provider pinned for AES-GCM, for logging and for components that only record it. Other
     * algorithms may come from another provider; get them with {@link #cipher} and {@link #mac}.
     *
     * @throws IllegalStateException if this is a FIPS build and the node is not in FIPS mode, or no provider
     *     offers AES-GCM
     */
    public static Provider provider() {
        return resolve().provider;
    }

    /**
     * The AWS-LC FIPS module in the FIPS build (which refuses to start without it); null in the default build,
     * which uses JCE ({@link #cipher}, {@link #mac}) for everything.
     */
    public static AwsLcFips awsLc() {
        return resolve().awsLc;
    }

    /**
     * Random source to pass when initializing a JCE seal cipher without an IV: a per-thread {@link SecureRandom}
     * of the algorithm and provider the JVM's default order picked at startup. In FIPS mode that is {@value #FIPS_PROVIDER}'s approved DRBG, and the cipher
     * generates the IV inside its module from it. Not used when {@link #awsLc()} seals.
     */
    public static SecureRandom nonceRandom() {
        resolve();
        return NONCE_RANDOM.get();
    }

    /**
     * Returns a shared random source for message IDs and translog nonces: the AWS-LC FIPS module's DRBG when
     * {@link #awsLc()} is loaded (with no JCE fallback), otherwise one from the JVM's default order.
     */
    public static SecureRandom secureRandom() {
        return resolve().random;
    }

    /** Whether the node runs in FIPS approved-only mode. */
    public static boolean isFipsMode() {
        return resolve().fips;
    }

    /** Whether this plugin was built with {@code -Pcrypto.standard=FIPS-140-3}. */
    public static boolean isFipsBuild() {
        return FIPS_140_3.equals(buildCryptoStandard());
    }

    /**
     * Resolves the configuration, then runs AES-256-GCM, AES-256-CTR and nonce-generation self-tests on what was
     * picked. Call at node startup so a misconfigured node fails there instead of on the first encrypted write.
     * Logs which provider the JVM's order picked for each algorithm.
     *
     * @throws IllegalStateException if no usable provider is available or a self-test fails
     */
    public static void checkAtStartup() {
        Resolved r = resolve();
        String gcm = selfTest();
        String ctr = selfTestCtr();
        selfTestSealNonce(nonceRandom());
        String hmac;
        try {
            hmac = mac(HMAC).getProvider().getName();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HMAC + " is not available", e);
        }
        if (r.awsLc != null) {
            r.awsLc.selfTest();
        }
        LOGGER
            .info(
                "storage encryption uses [{}] for AES-GCM, AES-CTR, key derivation and random numbers; JCE providers from the JVM's order: "
                    + "AES-GCM [{}], AES-CTR [{}], HmacSHA384 [{}], SecureRandom [{}/{}] (FIPS mode: {}, crypto.standard: {})",
                r.awsLc != null ? r.awsLc.version() + " (" + r.awsLc.library() + ")" : "JCE",
                gcm,
                ctr,
                hmac,
                r.randomAlgorithm,
                r.randomProvider.getName(),
                r.fips,
                isFipsBuild() ? FIPS_140_3 : "any-supported"
            );
    }

    private static Resolved resolve() {
        Resolved r = resolved;
        if (r == null) {
            synchronized (CryptoProviders.class) {
                r = resolved;
                if (r == null) {
                    boolean fips = isApprovedOnlyMode();
                    requireFipsModeForFipsBuild(isFipsBuild(), fips);
                    // Pin what the JVM's order picks now, so a provider added later cannot change it.
                    Map<String, Provider> pinned = new HashMap<>();
                    pinned.put("Cipher." + GCM, lookup(GCM, () -> Cipher.getInstance(GCM).getProvider()));
                    pinned.put("Cipher." + CTR, lookup(CTR, () -> Cipher.getInstance(CTR).getProvider()));
                    pinned.put("Mac." + HMAC, lookup(HMAC, () -> Mac.getInstance(HMAC).getProvider()));
                    SecureRandom jceRandom = new SecureRandom();
                    AwsLcFips awsLc = isFipsBuild() ? loadAwsLc() : null;
                    // With AWS-LC loaded, message IDs and translog nonces come from its DRBG, with no JCE fallback.
                    SecureRandom random = awsLc != null ? awsLc.secureRandom() : jceRandom;
                    r = new Resolved(
                        pinned.get("Cipher." + GCM),
                        random,
                        jceRandom.getAlgorithm(),
                        jceRandom.getProvider(),
                        awsLc,
                        fips,
                        pinned
                    );
                    resolved = r;
                }
            }
        }
        return r;
    }

    private static Provider lookup(String algorithm, Lookup lookup) {
        try {
            return lookup.provider();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no installed JCE provider offers " + algorithm, e);
        }
    }

    /**
     * Loads the AWS-LC FIPS module bundled with the FIPS build. There is no fallback: a FIPS build that cannot
     * load it refuses to start.
     *
     * @throws IllegalStateException with the reason if the module cannot be loaded or fails its self-tests
     */
    static AwsLcFips loadAwsLc() {
        try {
            return AwsLcFips.load(AwsLcFips.defaultLibrary());
        } catch (RuntimeException | LinkageError e) {
            throw new IllegalStateException(
                "this storage-encryption plugin was built for "
                    + FIPS_140_3
                    + " with the AWS-LC FIPS module, which cannot be used: "
                    + e.getMessage(),
                e
            );
        }
    }

    /**
     * A FIPS build runs only on a node in FIPS approved-only mode. A default build runs in either mode.
     *
     * @param fipsBuild     the plugin was built for FIPS 140-3
     * @param approvedOnly  Bouncy Castle FIPS runs in approved-only mode in this JVM
     */
    static void requireFipsModeForFipsBuild(boolean fipsBuild, boolean approvedOnly) {
        if (fipsBuild && approvedOnly == false) {
            throw new IllegalStateException(
                "this storage-encryption plugin was built for "
                    + FIPS_140_3
                    + " but the node is not in FIPS mode; start OpenSearch with OPENSEARCH_FIPS_MODE=true "
                    + "(Bouncy Castle FIPS with -Dorg.bouncycastle.fips.approved_only=true), or install the non-FIPS build"
            );
        }
    }

    /**
     * Whether Bouncy Castle FIPS runs in approved-only mode. Uses reflection, like OpenSearch core,
     * because the FIPS jars are only on the classpath of a FIPS distribution.
     */
    static boolean isApprovedOnlyMode() {
        try {
            Class<?> registrar = Class.forName("org.bouncycastle.crypto.CryptoServicesRegistrar");
            return (Boolean) registrar.getMethod("isInApprovedOnlyMode").invoke(null);
        } catch (ClassNotFoundException e) {
            return false;
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new IllegalStateException("cannot determine whether Bouncy Castle FIPS is in approved-only mode", e);
        }
    }

    static String buildCryptoStandard() {
        try (InputStream in = CryptoProviders.class.getResourceAsStream(BUILD_INFO_RESOURCE)) {
            if (in == null) {
                return "any-supported";
            }
            Properties properties = new Properties();
            properties.load(in);
            return properties.getProperty("crypto.standard", "any-supported");
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + BUILD_INFO_RESOURCE, e);
        }
    }

    // AES-256-GCM, test case 14 of McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)":
    // zero key, zero 96-bit IV, one zero block of plaintext, no AAD.
    private static final byte[] KAT_EXPECTED = HexFormat
        .of()
        .parseHex("cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919");

    // AES-256-CTR, NIST SP 800-38A F.5.5, first block.
    private static final byte[] CTR_KAT_KEY = HexFormat
        .of()
        .parseHex("603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4");
    private static final byte[] CTR_KAT_IV = HexFormat.of().parseHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    private static final byte[] CTR_KAT_PLAINTEXT = HexFormat.of().parseHex("6bc1bee22e409f96e93d7e117393172a");
    private static final byte[] CTR_KAT_EXPECTED = HexFormat.of().parseHex("601ec313775789a5b7a7f504bbf3d228");

    /** AES-256-CTR known-answer test on the cipher the JVM's order picks; returns its provider's name. */
    static String selfTestCtr() {
        String name = "?";
        try {
            Cipher cipher = cipher(CTR);
            name = cipher.getProvider().getName();
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CTR_KAT_KEY, "AES"), new IvParameterSpec(CTR_KAT_IV));
            if (MessageDigest.isEqual(CTR_KAT_EXPECTED, cipher.doFinal(CTR_KAT_PLAINTEXT)) == false) {
                throw new IllegalStateException("AES-256-CTR known-answer test failed for provider [" + name + "]");
            }
            return name;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CTR self-test failed for provider [" + name + "]", e);
        }
    }

    /**
     * Seals with a nonce the cipher generates itself (FIPS 140-3 IG C.H wants it generated inside the module)
     * and opens the result.
     */
    static void selfTestSealNonce(SecureRandom random) {
        String name = "?";
        try {
            SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
            Cipher seal = cipher(GCM);
            name = seal.getProvider().getName();
            seal.init(Cipher.ENCRYPT_MODE, key, random);
            byte[] nonce = seal.getIV();
            if (nonce == null || nonce.length != 12) {
                throw new IllegalStateException("provider [" + name + "] did not generate a 12-byte GCM nonce");
            }
            seal.updateAAD(new byte[8]);
            byte[] sealed = seal.doFinal(new byte[16]);
            Cipher open = cipher(GCM);
            open.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            open.updateAAD(new byte[8]);
            if (MessageDigest.isEqual(new byte[16], open.doFinal(sealed)) == false) {
                throw new IllegalStateException("AES-256-GCM nonce round trip failed");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM nonce self-test failed for provider [" + name + "]", e);
        }
    }

    /** AES-256-GCM known-answer test on the cipher the JVM's order picks; returns its provider's name. */
    static String selfTest() {
        String name = "?";
        try {
            Cipher cipher = cipher(GCM);
            name = cipher.getProvider().getName();
            SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
            byte[] out = cipher.doFinal(new byte[16]);
            if (MessageDigest.isEqual(KAT_EXPECTED, out) == false) {
                throw new IllegalStateException("AES-256-GCM known-answer test failed for provider [" + name + "]");
            }
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
            if (MessageDigest.isEqual(new byte[16], cipher.doFinal(out)) == false) {
                throw new IllegalStateException("AES-256-GCM decryption self-test failed for provider [" + name + "]");
            }
            return name;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM self-test failed for provider [" + name + "]", e);
        }
    }
}
