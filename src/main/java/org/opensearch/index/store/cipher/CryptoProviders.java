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
import java.security.Security;
import java.util.HexFormat;
import java.util.Properties;
import java.util.function.Function;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Chooses the cryptographic implementation for every cipher, MAC and random number the plugin uses.
 *
 * <p>On a node running in FIPS 140-3 mode (Bouncy Castle FIPS in approved-only mode, which is what
 * OpenSearch's {@code OPENSEARCH_FIPS_MODE=true} turns on) the plugin uses only validated modules: the
 * AWS-LC FIPS module bundled with the FIPS build ({@link AwsLcFips}) for AES-GCM, AES-CTR and key
 * derivation, and {@value #FIPS_PROVIDER} for everything else. A FIPS build that cannot load AWS-LC refuses to
 * start; the default build uses {@value #FIPS_PROVIDER} for everything in FIPS mode. OpenSearch removes {@code SunJCE} in that mode. Otherwise the plugin uses the JDK's
 * {@value #DEFAULT_PROVIDER}.
 *
 * <p>A plugin built with {@code -Pcrypto.standard=FIPS-140-3} requires FIPS mode: it refuses to pick
 * a provider, and so refuses to start, on a node that is not in approved-only mode. A default build
 * runs in either mode and never loads native crypto.
 *
 * @opensearch.internal
 */
public final class CryptoProviders {

    private static final Logger LOGGER = LogManager.getLogger(CryptoProviders.class);

    /** Provider used outside FIPS mode. */
    public static final String DEFAULT_PROVIDER = "SunJCE";

    /** The Bouncy Castle FIPS provider, used in FIPS mode. */
    public static final String FIPS_PROVIDER = "BCFIPS";

    /** Value of {@code crypto.standard} for a FIPS build, matching OpenSearch's own build parameter. */
    public static final String FIPS_140_3 = "FIPS-140-3";

    /** Classpath resource written by the build; holds {@code crypto.standard}. */
    static final String BUILD_INFO_RESOURCE = "crypto-standard.properties";

    private static volatile Resolved resolved;

    private CryptoProviders() {}

    /** The provider, random sources and native module chosen for this JVM. */
    private record Resolved(Provider provider, SecureRandom random, SecureRandom fipsNonceRandom, AwsLcFips awsLc, boolean fips) {
    }

    /** Non-FIPS nonce source: one per thread, so parallel writers do not contend on a shared generator. */
    private static final ThreadLocal<SecureRandom> NONCE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    /**
     * Returns the JCE provider: Bouncy Castle FIPS in FIPS mode, otherwise SunJCE. In FIPS mode AES-GCM,
     * AES-CTR and key derivation go to {@link #awsLc()} instead when it is loaded.
     *
     * @throws IllegalStateException if this is a FIPS build and the node is not in FIPS mode, or the
     *     required provider is not installed
     */
    public static Provider provider() {
        return resolve().provider;
    }

    /**
     * The AWS-LC FIPS module in the FIPS build (which refuses to start without it); null in the default build,
     * where callers use {@link #provider()}.
     */
    public static AwsLcFips awsLc() {
        return resolve().awsLc;
    }

    /**
     * Random source to pass when initializing a JCE seal cipher without an IV: Bouncy Castle FIPS's approved
     * DRBG in FIPS mode (where the cipher generates the IV inside the module from it), otherwise a per-thread
     * {@link SecureRandom}. Not used when {@link #awsLc()} seals.
     */
    public static SecureRandom nonceRandom() {
        Resolved r = resolve();
        return r.fips ? r.fipsNonceRandom : NONCE_RANDOM.get();
    }

    /**
     * Returns a shared random source for message IDs and translog nonces: the AWS-LC FIPS module's DRBG when
     * {@link #awsLc()} is loaded, otherwise one from the chosen provider.
     */
    public static SecureRandom secureRandom() {
        return resolve().random;
    }

    /** Whether the plugin runs on the FIPS provider. */
    public static boolean isFipsMode() {
        return resolve().fips;
    }

    /** Whether this plugin was built with {@code -Pcrypto.standard=FIPS-140-3}. */
    public static boolean isFipsBuild() {
        return FIPS_140_3.equals(buildCryptoStandard());
    }

    /**
     * Picks the providers, then runs AES-256-GCM and AES-256-CTR known-answer tests with them. Call at node startup so
     * a misconfigured node fails there instead of on the first encrypted write.
     *
     * @throws IllegalStateException if no usable provider is available or the self-test fails
     */
    public static void checkAtStartup() {
        Resolved r = resolve();
        selfTest(r.provider);
        selfTestCtr(r.provider);
        selfTestSealNonce(r.provider, r.provider, nonceRandom());
        if (r.awsLc != null) {
            r.awsLc.selfTest();
        }
        LOGGER
            .info(
                "storage encryption uses [{}] for AES-GCM, AES-CTR, key derivation and random numbers, JCE provider [{}] (FIPS mode: {}, crypto.standard: {})",
                r.awsLc != null ? r.awsLc.version() + " (" + r.awsLc.library() + ")" : r.provider.getName(),
                r.provider.getName(),
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
                    Provider provider = choose(isFipsBuild(), fips, Security::getProvider);
                    // choose() has already refused a FIPS build on a node that is not in FIPS mode.
                    AwsLcFips awsLc = isFipsBuild() ? loadAwsLc() : null;
                    // With AWS-LC loaded, message IDs and translog nonces come from its DRBG, with no JCE fallback.
                    SecureRandom random = awsLc != null ? awsLc.secureRandom() : newSecureRandom(provider, fips);
                    r = new Resolved(provider, random, fips ? newSecureRandom(provider, true) : null, awsLc, fips);
                    resolved = r;
                }
            }
        }
        return r;
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
     * Chooses the provider. Kept free of global state so the rules can be tested.
     *
     * @param fipsBuild     the plugin was built for FIPS 140-3
     * @param approvedOnly  Bouncy Castle FIPS runs in approved-only mode in this JVM
     * @param lookup        finds an installed provider by name, or returns null
     */
    static Provider choose(boolean fipsBuild, boolean approvedOnly, Function<String, Provider> lookup) {
        if (approvedOnly) {
            return require(lookup, FIPS_PROVIDER, "the JVM is in FIPS approved-only mode");
        }
        if (fipsBuild) {
            throw new IllegalStateException(
                "this storage-encryption plugin was built for "
                    + FIPS_140_3
                    + " but the node is not in FIPS mode; start OpenSearch with OPENSEARCH_FIPS_MODE=true "
                    + "(Bouncy Castle FIPS with -Dorg.bouncycastle.fips.approved_only=true), or install the non-FIPS build"
            );
        }
        Provider provider = lookup.apply(DEFAULT_PROVIDER);
        if (provider != null) {
            return provider;
        }
        // OpenSearch also removes SunJCE when OPENSEARCH_CRYPTO_STANDARD=FIPS-140-3 is set without approved-only mode.
        return require(lookup, FIPS_PROVIDER, DEFAULT_PROVIDER + " is not installed");
    }

    private static Provider require(Function<String, Provider> lookup, String name, String reason) {
        Provider provider = lookup.apply(name);
        if (provider == null) {
            throw new IllegalStateException("JCE provider [" + name + "] is required because " + reason + ", but it is not installed");
        }
        return provider;
    }

    private static SecureRandom newSecureRandom(Provider provider, boolean fips) {
        if (fips == false) {
            return new SecureRandom();
        }
        try {
            // The FIPS module's SP 800-90A DRBG.
            return SecureRandom.getInstance("DEFAULT", provider);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no approved SecureRandom in provider [" + provider.getName() + "]", e);
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

    static void selfTestCtr(Provider provider) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", provider);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(CTR_KAT_KEY, "AES"), new IvParameterSpec(CTR_KAT_IV));
            if (MessageDigest.isEqual(CTR_KAT_EXPECTED, cipher.doFinal(CTR_KAT_PLAINTEXT)) == false) {
                throw new IllegalStateException("AES-256-CTR known-answer test failed for provider [" + provider.getName() + "]");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CTR self-test failed for provider [" + provider.getName() + "]", e);
        }
    }

    /** Seals with a provider-generated nonce and opens the result with the read provider. */
    static void selfTestSealNonce(Provider sealProvider, Provider openProvider, SecureRandom random) {
        try {
            SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
            Cipher seal = Cipher.getInstance("AES/GCM/NoPadding", sealProvider);
            seal.init(Cipher.ENCRYPT_MODE, key, random);
            byte[] nonce = seal.getIV();
            if (nonce == null || nonce.length != 12) {
                throw new IllegalStateException("provider [" + sealProvider.getName() + "] did not generate a 12-byte GCM nonce");
            }
            seal.updateAAD(new byte[8]);
            byte[] sealed = seal.doFinal(new byte[16]);
            Cipher open = Cipher.getInstance("AES/GCM/NoPadding", openProvider);
            open.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            open.updateAAD(new byte[8]);
            if (MessageDigest.isEqual(new byte[16], open.doFinal(sealed)) == false) {
                throw new IllegalStateException("AES-256-GCM nonce round trip failed");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                "AES-256-GCM nonce self-test failed for providers [" + sealProvider.getName() + ", " + openProvider.getName() + "]",
                e
            );
        }
    }

    static void selfTest(Provider provider) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
            SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
            byte[] out = cipher.doFinal(new byte[16]);
            if (MessageDigest.isEqual(KAT_EXPECTED, out) == false) {
                throw new IllegalStateException("AES-256-GCM known-answer test failed for provider [" + provider.getName() + "]");
            }
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, new byte[12]));
            if (MessageDigest.isEqual(new byte[16], cipher.doFinal(out)) == false) {
                throw new IllegalStateException("AES-256-GCM decryption self-test failed for provider [" + provider.getName() + "]");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM self-test failed for provider [" + provider.getName() + "]", e);
        }
    }
}
