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
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Chooses the JCE provider for every cipher, MAC and random number the plugin uses.
 *
 * <p>On a node running in FIPS 140-3 mode (Bouncy Castle FIPS in approved-only mode, which is what
 * OpenSearch's {@code OPENSEARCH_FIPS_MODE=true} turns on) the plugin uses the validated
 * {@value #FIPS_PROVIDER} provider. OpenSearch removes {@code SunJCE} in that mode, so nothing else
 * would work anyway. Otherwise the plugin uses {@value #DEFAULT_PROVIDER}, whose AES intrinsics are
 * much faster.
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

    /** The provider and random source chosen for this JVM. */
    private record Resolved(Provider provider, SecureRandom random, boolean fips) {
    }

    /**
     * Returns the provider for all cipher and MAC operations.
     *
     * @throws IllegalStateException if this is a FIPS build and the node is not in FIPS mode, or the
     *     required provider is not installed
     */
    public static Provider provider() {
        return resolve().provider;
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
     * Picks the provider, then runs an AES-256-GCM known-answer test with it. Call at node startup so
     * a misconfigured node fails there instead of on the first encrypted write.
     *
     * @throws IllegalStateException if no usable provider is available or the self-test fails
     */
    public static void checkAtStartup() {
        Resolved r = resolve();
        selfTest(r.provider);
        LOGGER
            .info(
                "storage encryption uses JCE provider [{}] (FIPS mode: {}, crypto.standard: {})",
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
                    r = new Resolved(provider, newSecureRandom(provider, fips), fips);
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

    private static SecureRandom newSecureRandom(Provider provider, boolean fips) {
        if (fips == false) {
            return new SecureRandom();
        }
        try {
            // The FIPS provider's default DRBG (SP 800-90A).
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
