/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.lang.reflect.Constructor;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    private static final Logger LOGGER = LogManager.getLogger(AwsLcKeyDerivation.class);

    private static final String ALGORITHM = "CounterKdfWithHmacSHA384";

    private static volatile Constructor<?> specConstructor;

    private static volatile boolean localeWarningLogged;

    private AwsLcKeyDerivation() {}

    static byte[] counterModeHmacSha384(byte[] key, byte[] fixedInput, int keyLength) {
        SecretKeyFactory factory;
        try {
            factory = SecretKeyFactory.getInstance(ALGORITHM, CryptoProviders.provider());
        } catch (NoSuchAlgorithmException e) {
            // ACCP 2.5.0 upper-cases KDF names with the default locale both when it registers them and when it
            // looks them up, so the lookup misses if the default locale changed in between (e.g. to Turkish or
            // Azerbaijani, where 'i' upper-cases to a dotted capital I). Bouncy Castle FIPS, the other validated
            // module on a FIPS node, computes the same KDF.
            if (localeWarningLogged == false) {
                localeWarningLogged = true;
                LOGGER.warn("AWS-LC counter-mode KDF lookup failed ({}), using Bouncy Castle FIPS's KDF instead", e.getMessage());
            }
            return FipsKeyDerivation.counterModeHmacSha384(key, fixedInput, keyLength);
        }
        try {
            KeySpec spec = (KeySpec) constructor().newInstance(key, fixedInput, keyLength, "AES");
            return factory.generateSecret(spec).getEncoded();
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
