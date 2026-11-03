/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.MacSpi;

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

    /** A provider added to the front of the JVM's order after startup does not change what the plugin uses. */
    public void testProvidersArePinnedAtStartup() throws Exception {
        Provider before = CryptoProviders.mac(CryptoProviders.HMAC).getProvider();
        Provider beforeRandom = CryptoProviders.nonceRandom().getProvider();
        String randomAlgorithm = CryptoProviders.nonceRandom().getAlgorithm();
        Provider shadow = new Provider("ShadowForTest", "1.0", "test provider") {
            {
                put("Mac." + CryptoProviders.HMAC, ShadowMac.class.getName());
                // SecureRandom needs no signed provider on any JDK, so this part runs everywhere.
                put("SecureRandom." + randomAlgorithm, ShadowRandom.class.getName());
            }
        };
        assertEquals(1, Security.insertProviderAt(shadow, 1));
        try {
            assertSame(shadow, new SecureRandom().getProvider());
            // A new thread gets a fresh nonce source, which must still come from the pinned provider.
            AtomicReference<Provider> fromNewThread = new AtomicReference<>();
            Thread thread = new Thread(() -> fromNewThread.set(CryptoProviders.nonceRandom().getProvider()));
            thread.start();
            thread.join();
            assertSame(beforeRandom, fromNewThread.get());
            assertSame(beforeRandom, CryptoProviders.nonceRandom().getProvider());

            // Oracle's JDK only picks signed JCE providers, so the shadow MAC is first in the order only on other JDKs
            // (such as Temurin in CI); either way the plugin must still get the pinned provider.
            assertSame(before, CryptoProviders.mac(CryptoProviders.HMAC).getProvider());
        } finally {
            Security.removeProvider(shadow.getName());
        }
    }

    /** A random source that only exists to sit first in the provider order. */
    public static final class ShadowRandom extends SecureRandomSpi {
        @Override
        protected void engineSetSeed(byte[] seed) {}

        @Override
        protected void engineNextBytes(byte[] bytes) {}

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            return new byte[numBytes];
        }
    }

    /** A MAC that only exists to sit first in the provider order. */
    public static final class ShadowMac extends MacSpi {
        @Override
        protected int engineGetMacLength() {
            return 48;
        }

        @Override
        protected void engineInit(Key key, AlgorithmParameterSpec params) {}

        @Override
        protected void engineUpdate(byte input) {}

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {}

        @Override
        protected byte[] engineDoFinal() {
            return new byte[48];
        }

        @Override
        protected void engineReset() {}
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
