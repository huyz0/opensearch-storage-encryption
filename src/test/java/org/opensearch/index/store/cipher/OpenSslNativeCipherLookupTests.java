/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.file.Path;
import java.util.List;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Tests for the libcrypto lookup order in {@link OpenSslNativeCipher}.
 */
public class OpenSslNativeCipherLookupTests extends OpenSearchTestCase {

    public void testRhelPathsComeFirst() {
        List<Path> paths = OpenSslNativeCipher.linuxLibcryptoPaths("amd64");
        assertEquals(Path.of("/lib64/libcrypto.so.3"), paths.get(0));
        assertTrue(paths.indexOf(Path.of("/lib64/libcrypto.so.1.1")) < paths.indexOf(Path.of("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")));
    }

    public void testDebianMultiarchPathsOnX86() {
        for (String arch : new String[] { "amd64", "x86_64" }) {
            List<Path> paths = OpenSslNativeCipher.linuxLibcryptoPaths(arch);
            assertTrue(paths.contains(Path.of("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")));
            assertTrue(paths.contains(Path.of("/lib/x86_64-linux-gnu/libcrypto.so.3")));
            assertTrue(paths.contains(Path.of("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")));
        }
    }

    public void testDebianMultiarchPathsOnArm() {
        List<Path> paths = OpenSslNativeCipher.linuxLibcryptoPaths("aarch64");
        assertTrue(paths.contains(Path.of("/usr/lib/aarch64-linux-gnu/libcrypto.so.3")));
        assertFalse(paths.contains(Path.of("/usr/lib/x86_64-linux-gnu/libcrypto.so.3")));
    }

    public void testMultiarchBeforePlainLib() {
        List<Path> paths = OpenSslNativeCipher.linuxLibcryptoPaths("amd64");
        assertTrue(paths.indexOf(Path.of("/usr/lib/x86_64-linux-gnu/libcrypto.so")) < paths.indexOf(Path.of("/lib/libcrypto.so.3")));
    }

    public void testUnknownArchStillHasGenericPaths() {
        List<Path> paths = OpenSslNativeCipher.linuxLibcryptoPaths("riscv64");
        assertTrue(paths.contains(Path.of("/lib64/libcrypto.so.3")));
        assertTrue(paths.contains(Path.of("/usr/lib/libcrypto.so.3")));
        assertNull(OpenSslNativeCipher.multiarchTriplet("riscv64"));
        assertNull(OpenSslNativeCipher.multiarchTriplet(null));
    }
}
