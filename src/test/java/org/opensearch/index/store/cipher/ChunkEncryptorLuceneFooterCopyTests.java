/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.codecs.CodecUtil;
import org.opensearch.test.OpenSearchTestCase;

/**
 * {@link ChunkEncryptor#luceneFooterCopy()} returns the plaintext's codec footer, whatever the write sizes, and
 * nothing for files that do not end with one.
 */
public class ChunkEncryptorLuceneFooterCopyTests extends OpenSearchTestCase {

    public void testCopiesCodecFooterAcrossAnyWriteSizes() throws IOException {
        byte[] footer = codecFooter(randomLongBetween(0, 0xFFFFFFFFL));
        for (int bodyLength : new int[] { 0, 1, 15, 16, 17, ChunkCipher.CHUNK_SIZE, 3 * ChunkCipher.CHUNK_SIZE + 5 }) {
            byte[] data = new byte[bodyLength + footer.length];
            random().nextBytes(data);
            System.arraycopy(footer, 0, data, bodyLength, footer.length);
            assertArrayEquals("body " + bodyLength, footer, encrypt(data));
        }
    }

    public void testZerosWhenThereIsNoCodecFooter() throws IOException {
        byte[] zeros = new byte[16];
        assertArrayEquals(zeros, encrypt(new byte[0]));
        assertArrayEquals(zeros, encrypt(randomByteArrayOfLength(randomIntBetween(1, 3 * ChunkCipher.CHUNK_SIZE))));
        // Footer magic but a non-zero algorithm id, or a checksum wider than 32 bits: not a codec footer.
        byte[] badAlgorithm = codecFooter(1);
        badAlgorithm[7] = 1;
        assertArrayEquals(zeros, encrypt(badAlgorithm));
        byte[] wideChecksum = codecFooter(1);
        wideChecksum[8] = 1;
        assertArrayEquals(zeros, encrypt(wideChecksum));
        // A footer that is not at the very end.
        byte[] notLast = Arrays.copyOf(codecFooter(1), 17);
        assertArrayEquals(zeros, encrypt(notLast));
    }

    private static byte[] codecFooter(long checksum) throws IOException {
        // Codec footers are big-endian, unlike DataOutput.writeInt
        return ByteBuffer.allocate(CodecUtil.footerLength()).putInt(CodecUtil.FOOTER_MAGIC).putInt(0).putLong(checksum).array();
    }

    /** Encrypts {@code data} in randomly sized writes and returns the encryptor's footer copy. */
    private byte[] encrypt(byte[] data) throws IOException {
        ChunkEncryptor encryptor = new ChunkEncryptor(new SecretKeySpec(randomByteArrayOfLength(32), "AES"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pos = 0;
        while (pos < data.length) {
            int n = Math
                .min(data.length - pos, randomBoolean() ? randomIntBetween(1, 20) : randomIntBetween(1, 2 * ChunkCipher.CHUNK_SIZE));
            encryptor.write(out, data, pos, n);
            pos += n;
        }
        encryptor.finish(out);
        return encryptor.luceneFooterCopy();
    }
}
