/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;

import org.opensearch.index.store.cipher.CryptoProviders;

/**
 * SP 800-108 counter-mode KDF from the AWS-LC FIPS module (Amazon Corretto Crypto Provider's
 * {@code CounterKdfWithHmacSHA384}). AWS-LC computes {@code HMAC(KI, [i]_32 || info)}, so passing the
 * SP 800-108 fixed input as {@code info} gives the same bytes as {@link KeyDerivation}. The provider
 * is only bundled in the FIPS build, so its key spec class is reached by reflection.
 *
 * @opensearch.internal
 */
final class AwsLcKeyDerivation {

    private static final String SPEC_CLASS = "com.amazon.corretto.crypto.provider.CounterKdfSpec";

    private static volatile Constructor<?> specConstructor;

    private AwsLcKeyDerivation() {}

    static byte[] counterModeHmacSha384(byte[] key, byte[] fixedInput, int keyLength) {
        try {
            KeySpec spec = (KeySpec) constructor().newInstance(key, fixedInput, keyLength, "AES");
            return SecretKeyFactory.getInstance("CounterKdfWithHmacSHA384", CryptoProviders.provider()).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException | ReflectiveOperationException e) {
            throw new IllegalStateException("AWS-LC key derivation failed", e);
        }
    }

    private static Constructor<?> constructor() throws ReflectiveOperationException {
        Constructor<?> c = specConstructor;
        if (c == null) {
            Class<?> type = Class.forName(SPEC_CLASS, true, CryptoProviders.provider().getClass().getClassLoader());
            c = type.getConstructor(byte[].class, byte[].class, int.class, String.class);
            specConstructor = c;
        }
        return c;
    }
}
