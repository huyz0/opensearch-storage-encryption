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
 * Chooses the JCE provider for every cipher, MAC and random number the plugin uses.
 *
 * <p>On a node running in FIPS 140-3 mode (Bouncy Castle FIPS in approved-only mode, which is what
 * OpenSearch's {@code OPENSEARCH_FIPS_MODE=true} turns on) the plugin uses only validated modules: the
 * AWS-LC FIPS module ({@value #AWS_LC_PROVIDER}, bundled in the FIPS build) when it loads, and
 * {@value #FIPS_PROVIDER} for AES-CTR, which AWS-LC's provider lacks, and as the fallback. OpenSearch
 * removes {@code SunJCE} in that mode. Otherwise the plugin uses the JDK's {@value #DEFAULT_PROVIDER}.
 *
 * <p>A plugin built with {@code -Pcrypto.standard=FIPS-140-3} requires FIPS mode: it refuses to pick
 * a provider, and so refuses to start, on a node that is not in approved-only mode. A default build
 * runs in either mode.
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

    /** Name of the Amazon Corretto Crypto Provider (AWS-LC), preferred in FIPS mode. */
    public static final String AWS_LC_PROVIDER = "AmazonCorrettoCryptoProvider";

    private static final String AWS_LC_CLASS = "com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider";

    /** The providers and random source chosen for this JVM. */
    private record Resolved(Provider provider, Provider ctrProvider, SecureRandom random, boolean fips) {
    }

    /**
     * Returns the provider for AES-GCM, HMAC and key derivation. In FIPS mode this is the AWS-LC FIPS
     * module (Amazon Corretto Crypto Provider) when it is bundled and loads, otherwise Bouncy Castle FIPS.
     *
     * @throws IllegalStateException if this is a FIPS build and the node is not in FIPS mode, or the
     *     required provider is not installed
     */
    public static Provider provider() {
        return resolve().provider;
    }

    /**
     * Returns the provider for AES-CTR (translog). The AWS-LC provider has no CTR mode, so in FIPS mode
     * this is always Bouncy Castle FIPS.
     */
    public static Provider ctrProvider() {
        return resolve().ctrProvider;
    }

    /** Whether {@link #provider()} is the AWS-LC FIPS module. */
    public static boolean isAwsLc() {
        return AWS_LC_PROVIDER.equals(provider().getName());
    }

    /** Returns a shared random source from the chosen provider, for nonces and message IDs. */
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
        selfTestCtr(r.ctrProvider);
        LOGGER
            .info(
                "storage encryption uses JCE provider [{}], AES-CTR provider [{}] (FIPS mode: {}, crypto.standard: {})",
                r.provider.getName(),
                r.ctrProvider.getName(),
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
                    Provider ctrProvider = choose(isFipsBuild(), fips, Security::getProvider);
                    Provider provider = fips ? preferAwsLc(ctrProvider, loadAwsLc()) : ctrProvider;
                    r = new Resolved(provider, ctrProvider, newSecureRandom(provider, fips), fips);
                    resolved = r;
                }
            }
        }
        return r;
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

    /**
     * In FIPS mode, uses the AWS-LC FIPS module when it loaded and passed its self-tests; it is several
     * times faster than Bouncy Castle FIPS and has native code for x86_64 and aarch64.
     */
    static Provider preferAwsLc(Provider bcFips, Provider awsLc) {
        return awsLc != null ? awsLc : bcFips;
    }

    /**
     * Returns the AWS-LC FIPS provider if it is on the classpath, built against the FIPS module, loaded
     * its native library and passed its power-on self-tests; otherwise null (with a warning if it is
     * present but unusable). The FIPS build of this plugin bundles it.
     */
    static Provider loadAwsLc() {
        Class<?> type;
        try {
            type = Class.forName(AWS_LC_CLASS);
        } catch (ClassNotFoundException e) {
            return null;
        }
        try {
            Provider provider = (Provider) type.getField("INSTANCE").get(null);
            Object loadingError = type.getMethod("getLoadingError").invoke(provider);
            if (loadingError != null) {
                LOGGER.warn("AWS-LC provider did not load, using Bouncy Castle FIPS", (Throwable) loadingError);
                return null;
            }
            if (Boolean.TRUE.equals(type.getMethod("isFips").invoke(provider)) == false) {
                LOGGER.warn("AWS-LC provider on the classpath is not the FIPS build, using Bouncy Castle FIPS");
                return null;
            }
            if (Boolean.TRUE.equals(type.getMethod("isExperimentalFips").invoke(provider))) {
                LOGGER
                    .warn(
                        "AWS-LC provider on the classpath is an experimental FIPS build, not the validated module, using Bouncy Castle FIPS"
                    );
                return null;
            }
            Object selfTests = type.getMethod("runSelfTests").invoke(provider);
            if ("PASSED".equals(String.valueOf(selfTests)) == false) {
                LOGGER.warn("AWS-LC provider self-tests returned [{}], using Bouncy Castle FIPS", selfTests);
                return null;
            }
            type.getMethod("assertHealthy").invoke(provider);
            return provider;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            // includes assertHealthy() failing (InvocationTargetException)
            LOGGER.warn("AWS-LC provider is unusable, using Bouncy Castle FIPS", e);
            return null;
        }
    }

    private static SecureRandom newSecureRandom(Provider provider, boolean fips) {
        if (fips == false) {
            return new SecureRandom();
        }
        try {
            // The FIPS module's SP 800-90A DRBG.
            return SecureRandom.getInstance(AWS_LC_PROVIDER.equals(provider.getName()) ? "LibCryptoRng" : "DEFAULT", provider);
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
