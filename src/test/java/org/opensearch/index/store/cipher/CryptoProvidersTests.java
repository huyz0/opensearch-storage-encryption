/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

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
        CryptoProviders.selfTestSealNonce(CryptoProviders.sealProvider(), CryptoProviders.provider(), CryptoProviders.nonceRandom());
    }

    public void testCtrSelfTestPassesWithChosenCtrProvider() {
        CryptoProviders.selfTestCtr(CryptoProviders.ctrProvider());
        expectThrows(IllegalStateException.class, () -> CryptoProviders.selfTestCtr(SUN));
    }

    public void testFipsModePrefersAwsLcWhenItLoads() {
        Provider awsLc = new Provider(CryptoProviders.AWS_LC_PROVIDER, "1", "stub") {
        };
        assertSame(awsLc, CryptoProviders.preferAwsLc(BC, awsLc));
        assertSame(BC, CryptoProviders.preferAwsLc(BC, null));
    }

    /** In a FIPS build every test JVM runs approved-only, so this checks the build wiring end to end. */
    public void testFipsBuildRunsOnFipsProvider() {
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isApprovedOnlyMode());
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isFipsMode());
        if (CryptoProviders.isFipsBuild()) {
            // The FIPS build bundles AWS-LC; AES-CTR (translog) stays on Bouncy Castle FIPS.
            assertEquals(CryptoProviders.AWS_LC_PROVIDER, CryptoProviders.provider().getName());
            assertTrue(CryptoProviders.isAwsLc());
            assertEquals(CryptoProviders.FIPS_PROVIDER, CryptoProviders.ctrProvider().getName());
            assertEquals(CryptoProviders.AWS_LC_PROVIDER, CryptoProviders.secureRandom().getProvider().getName());
        } else {
            assertEquals(CryptoProviders.DEFAULT_PROVIDER, CryptoProviders.provider().getName());
            assertEquals(CryptoProviders.DEFAULT_PROVIDER, CryptoProviders.ctrProvider().getName());
            assertFalse(CryptoProviders.isAwsLc());
        }
        // Sealing generates the GCM nonce inside the module: Bouncy Castle FIPS in FIPS mode (see sealProvider).
        String sealProvider = CryptoProviders.isFipsBuild() ? CryptoProviders.FIPS_PROVIDER : CryptoProviders.DEFAULT_PROVIDER;
        assertEquals(sealProvider, CryptoProviders.sealProvider().getName());
        assertEquals(sealProvider, ChunkCipher.newCipher().getProvider().getName());
    }
}
