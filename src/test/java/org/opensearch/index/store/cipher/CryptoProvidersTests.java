/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.security.SecureRandom;
import java.security.Provider;
import java.util.Map;

import org.opensearch.test.OpenSearchTestCase;

public class CryptoProvidersTests extends OpenSearchTestCase {

    private static final Provider SUN = new Provider(CryptoProviders.DEFAULT_PROVIDER, "1", "stub") {
    };
    private static final Provider BC = new Provider(CryptoProviders.FIPS_PROVIDER, "1", "stub") {
    };

    public void testDefaultBuildOutsideFipsModeUsesSunJce() {
        assertSame(SUN, CryptoProviders.choose(false, false, Map.of("SunJCE", SUN, "BCFIPS", BC)::get));
    }

    public void testApprovedOnlyModeUsesBcFipsEvenWhenSunJceIsInstalled() {
        assertSame(BC, CryptoProviders.choose(false, true, Map.of("SunJCE", SUN, "BCFIPS", BC)::get));
        assertSame(BC, CryptoProviders.choose(true, true, Map.of("SunJCE", SUN, "BCFIPS", BC)::get));
    }

    public void testFipsBuildRefusesNonFipsNode() {
        IllegalStateException e = expectThrows(
            IllegalStateException.class,
            () -> CryptoProviders.choose(true, false, Map.of("SunJCE", SUN, "BCFIPS", BC)::get)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("OPENSEARCH_FIPS_MODE=true"));
    }

    public void testApprovedOnlyModeWithoutBcFipsFails() {
        IllegalStateException e = expectThrows(
            IllegalStateException.class,
            () -> CryptoProviders.choose(false, true, Map.of("SunJCE", SUN)::get)
        );
        assertTrue(e.getMessage(), e.getMessage().contains("BCFIPS"));
    }

    public void testFallsBackToBcFipsWhenSunJceWasRemoved() {
        // OpenSearch removes SunJCE when OPENSEARCH_CRYPTO_STANDARD=FIPS-140-3 even without approved-only mode.
        assertSame(BC, CryptoProviders.choose(false, false, Map.of("BCFIPS", BC)::get));
        expectThrows(IllegalStateException.class, () -> CryptoProviders.choose(false, false, Map.<String, Provider>of()::get));
    }

    public void testSelfTestPassesWithChosenProvider() {
        CryptoProviders.selfTest(CryptoProviders.provider());
        CryptoProviders.checkAtStartup();
    }

    public void testSelfTestFailsWithProviderWithoutAesGcm() {
        expectThrows(IllegalStateException.class, () -> CryptoProviders.selfTest(SUN));
    }

    public void testSealNonceSelfTestPasses() {
        CryptoProviders.selfTestSealNonce(CryptoProviders.provider(), CryptoProviders.provider(), CryptoProviders.nonceRandom());
    }

    public void testCtrSelfTestPassesWithChosenProvider() {
        CryptoProviders.selfTestCtr(CryptoProviders.provider());
        expectThrows(IllegalStateException.class, () -> CryptoProviders.selfTestCtr(SUN));
    }

    /** In a FIPS build every test JVM runs approved-only, so this checks the build wiring end to end. */
    public void testFipsBuildRunsOnFipsProvider() {
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isApprovedOnlyMode());
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isFipsMode());
        if (CryptoProviders.isFipsBuild()) {
            // The FIPS build bundles the AWS-LC FIPS module for AES-GCM, AES-CTR, the KDF and the DRBG.
            assertNotNull("the bundled AWS-LC FIPS module did not load", CryptoProviders.awsLc());
            assertEquals(AwsLcFips.EXPECTED_VERSION, CryptoProviders.awsLc().version());
            assertEquals(CryptoProviders.FIPS_PROVIDER, CryptoProviders.provider().getName());
            SecureRandom random = CryptoProviders.secureRandom();
            assertEquals("AWS-LC-FIPS", random.getProvider().getName());
            assertEquals("AWS-LC-FIPS-DRBG", random.getAlgorithm());
            byte[] a = new byte[16];
            byte[] b = new byte[16];
            random.nextBytes(a);
            random.nextBytes(b);
            assertFalse(java.util.Arrays.equals(a, b));
        } else {
            assertEquals(CryptoProviders.DEFAULT_PROVIDER, CryptoProviders.provider().getName());
            assertNull(CryptoProviders.awsLc());
        }
    }

    public void testUnusableAwsLcLibraryRefusesToStart() {
        String saved = System.getProperty(AwsLcFips.LIBRARY_PROPERTY);
        try {
            System.setProperty(AwsLcFips.LIBRARY_PROPERTY, createTempDir().resolve("missing.so").toString());
            IllegalStateException e = expectThrows(IllegalStateException.class, CryptoProviders::loadAwsLc);
            assertTrue(e.getMessage(), e.getMessage().contains("missing.so"));
        } finally {
            if (saved == null) {
                System.clearProperty(AwsLcFips.LIBRARY_PROPERTY);
            } else {
                System.setProperty(AwsLcFips.LIBRARY_PROPERTY, saved);
            }
        }
    }
}
