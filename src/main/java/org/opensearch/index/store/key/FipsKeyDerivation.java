/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;

/**
 * SP 800-108 counter-mode KDF from the Bouncy Castle FIPS module. Only loaded in FIPS mode: the
 * Bouncy Castle FIPS jars are on the classpath of an OpenSearch FIPS distribution, not bundled with
 * the plugin.
 *
 * @opensearch.internal
 */
final class FipsKeyDerivation {

    private static final FipsKDF.CounterModeFactory FACTORY = new FipsKDF.CounterModeFactory();
    private static final byte[] NO_PREFIX = new byte[0];

    private FipsKeyDerivation() {}

    /** Counter mode with HMAC-SHA-384 and a 32-bit counter placed before {@code fixedInput}. */
    static byte[] counterModeHmacSha384(byte[] key, byte[] fixedInput, int keyLength) {
        KDFCalculator<FipsKDF.CounterModeParameters> kdf = FACTORY
            .createKDFCalculator(FipsKDF.COUNTER_MODE.withPRFAndR(FipsKDF.PRF.SHA384_HMAC, 32).using(key, NO_PREFIX, fixedInput));
        byte[] out = new byte[keyLength];
        kdf.generateBytes(out);
        return out;
    }
}
