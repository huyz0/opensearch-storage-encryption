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

    /** In a FIPS build every test JVM runs approved-only, so this checks the build wiring end to end. */
    public void testFipsBuildRunsOnFipsProvider() {
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isApprovedOnlyMode());
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isFipsMode());
        String expected = CryptoProviders.isFipsBuild() ? CryptoProviders.FIPS_PROVIDER : CryptoProviders.DEFAULT_PROVIDER;
        assertEquals(expected, CryptoProviders.provider().getName());
        assertEquals(expected, ChunkCipher.newCipher().getProvider().getName());
        if (CryptoProviders.isFipsBuild()) {
            assertEquals(CryptoProviders.FIPS_PROVIDER, CryptoProviders.secureRandom().getProvider().getName());
        }
    }
}
