/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import org.opensearch.common.SuppressForbidden;

import com.carrotsearch.randomizedtesting.ThreadFilter;

/**
 * Thread leak filter for Bouncy Castle FIPS's "BC Disposal Daemon", a JVM-wide daemon thread that BC-FIPS starts
 * the first time it is used and never stops. In FIPS mode whichever suite touches BC-FIPS first would otherwise be
 * reported as leaking it.
 */
@SuppressForbidden(reason = "Thread matching for test leak filtering")
public class BouncyCastleThreadLeakFilter implements ThreadFilter {
    @Override
    public boolean reject(Thread t) {
        return t.getName().equals("BC Disposal Daemon");
    }
}
