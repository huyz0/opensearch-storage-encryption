/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.opensearch.test.OpenSearchTestCase;

public class CryptoProvidersTests extends OpenSearchTestCase {

    public void testDefaultBuildRunsInEitherMode() {
        CryptoProviders.requireFipsModeForFipsBuild(false, false);
        CryptoProviders.requireFipsModeForFipsBuild(false, true);
        CryptoProviders.requireFipsModeForFipsBuild(true, true);
    }

    public void testFipsBuildRefusesNonFipsNode() {
        IllegalStateException e = expectThrows(IllegalStateException.class, () -> CryptoProviders.requireFipsModeForFipsBuild(true, false));
        assertTrue(e.getMessage(), e.getMessage().contains("OPENSEARCH_FIPS_MODE=true"));
    }

    public void testSelfTestsPassWithTheJvmOrder() {
        CryptoProviders.selfTest();
        CryptoProviders.selfTestCtr();
        CryptoProviders.selfTestSealNonce(CryptoProviders.nonceRandom());
        CryptoProviders.checkAtStartup();
    }

    /** No provider is named: the plugin gets what the JVM's order gives for each algorithm, like OpenSearch core. */
    public void testUsesTheJvmProviderOrder() throws Exception {
        assertEquals(Cipher.getInstance("AES/GCM/NoPadding").getProvider(), CryptoProviders.cipher("AES/GCM/NoPadding").getProvider());
        assertEquals(Cipher.getInstance("AES/CTR/NoPadding").getProvider(), CryptoProviders.cipher("AES/CTR/NoPadding").getProvider());
        assertEquals(Cipher.getInstance("AES/GCM/NoPadding").getProvider(), CryptoProviders.provider());
        assertEquals(Security.getProviders()[0].getName().equals(CryptoProviders.FIPS_PROVIDER), CryptoProviders.isFipsMode());
    }

    /** In a FIPS build every test JVM runs approved-only, so this checks the build wiring end to end. */
    public void testFipsBuildRunsOnFipsProvider() {
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isApprovedOnlyMode());
        assertEquals(CryptoProviders.isFipsBuild(), CryptoProviders.isFipsMode());
        if (CryptoProviders.isFipsBuild()) {
            // The FIPS build bundles the AWS-LC FIPS module for AES-GCM, AES-CTR, the KDF and the DRBG; JCE (BCFIPS first)
            // does the rest.
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
            assertFalse(Arrays.equals(a, b));
        } else {
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
