/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.footer;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer tests for the OSEF footer and a committed golden encrypted file.
 *
 * <p>{@code golden-v1.osef} and every expected value here were produced by
 * src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py, which
 * implements the format without any plugin code. If one of these tests fails, the on-disk
 * format has changed: files written by earlier builds will not be readable by this one.
 */
public class EncryptionFooterKnownAnswerTests extends OpenSearchTestCase {

    private static final byte[] MASTER_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] MESSAGE_ID = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    private static final byte[] FILE_KEY = hex("eed4d15a63606f1a006ffad12ad89b6a06afe4198584def8bccd8c3351e146fb");
    private static final String GOLDEN_FILE = "/org/opensearch/index/store/golden/golden-v2.osef";
    /** Two full 8 KiB chunks and a 3616-byte tail. */
    private static final int GOLDEN_PLAINTEXT_LENGTH = 20000;
    private static final String GOLDEN_TAG_TABLE_HEX = "473cce9f2b0818086bf67a586a30061f"
        + "b1f68af5d8293235634b20e7c0fe6e33"
        + "2f472d32a61d2169cbb07cba8934ee62";

    /**
     * Footer of the golden file, no key metadata. Big-endian fields, in order:
     * <pre>
     * FooterAuthTag      8ef061dddcfe40529873d7cab3d6e95c  GCM tag over the rest of the footer (as AAD)
     * DataLength         0000000000004e20                  20000
     * ChunkSize          00002000                          8192
     * MessageId          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
     * KeyMetadataLength  0000                              KeyMetadata itself is empty
     * AlgorithmId        0001                              AES_256_GCM_CTR
     * FooterLength       00000038                          56, including the auth tag
     * Magic              4f534546                          "OSEF"
     * </pre>
     */
    private static final byte[] GOLDEN_FOOTER = hex(
        "8ef061dddcfe40529873d7cab3d6e95c"
            + "0000000000004e20"
            + "00002000"
            + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            + "0000"
            + "0001"
            + "00000038"
            + "4f534546"
    );

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
    }

    public void testFooterLayoutConstants() {
        assertEquals(56, EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        assertEquals(56, EncryptionMetadataTrailer.calculateFooterSize(0));
        assertArrayEquals(new byte[] { 'O', 'S', 'E', 'F' }, EncryptionMetadataTrailer.MAGIC);
    }

    public void testSerializeKnownAnswer() throws IOException {
        assertArrayEquals(GOLDEN_FOOTER, goldenFooter().serialize(FILE_KEY));
    }

    public void testDeserializeKnownAnswer() throws IOException {
        EncryptionFooter footer = EncryptionFooter.deserialize(GOLDEN_FOOTER, FILE_KEY);
        assertArrayEquals(MESSAGE_ID, footer.getMessageId());
        assertEquals(GOLDEN_PLAINTEXT_LENGTH, footer.getDataLength());
        assertEquals(3 * 16 + GOLDEN_FOOTER.length, footer.getTrailerLength());
        assertEquals(1, footer.getAlgorithmId());
        assertEquals(GOLDEN_FOOTER.length, footer.getFooterLength());
        assertEquals(0, footer.getKeyMetadata().length);
        // Round trip is byte-identical.
        assertArrayEquals(GOLDEN_FOOTER, footer.serialize(FILE_KEY));
    }

    public void testEveryFooterBitIsProtected() {
        for (int i = 0; i < GOLDEN_FOOTER.length; i++) {
            byte[] tampered = GOLDEN_FOOTER.clone();
            tampered[i] ^= (byte) (1 << randomIntBetween(0, 7));
            expectThrows(IOException.class, () -> EncryptionFooter.deserialize(tampered, FILE_KEY));
        }
    }

    public void testWrongKeyRejected() {
        byte[] wrongKey = FILE_KEY.clone();
        wrongKey[0] ^= 1;
        CorruptIndexException e = expectThrows(CorruptIndexException.class, () -> EncryptionFooter.deserialize(GOLDEN_FOOTER, wrongKey));
        assertEquals("Footer authentication failed", e.getOriginalMessage());
    }

    public void testGoldenFileLayout() throws Exception {
        byte[] file = Files.readAllBytes(getDataPath(GOLDEN_FILE));
        byte[] tagTable = hex(GOLDEN_TAG_TABLE_HEX);
        assertEquals(GOLDEN_PLAINTEXT_LENGTH + tagTable.length + GOLDEN_FOOTER.length, file.length);
        assertArrayEquals(tagTable, Arrays.copyOfRange(file, GOLDEN_PLAINTEXT_LENGTH, GOLDEN_PLAINTEXT_LENGTH + tagTable.length));
        assertArrayEquals(GOLDEN_FOOTER, Arrays.copyOfRange(file, file.length - GOLDEN_FOOTER.length, file.length));
        int trailerStart = file.length - EncryptionMetadataTrailer.MIN_FOOTER_SIZE;
        assertEquals(GOLDEN_FOOTER.length, EncryptionFooter.calculateFooterLength(file, trailerStart));
    }

    /**
     * Reads the committed golden file through {@link CryptoNIOFSDirectory}. This is the
     * format check: today's reader must decrypt and authenticate a file in the v2 format.
     */
    public void testReadGoldenFileThroughDirectory() throws Exception {
        Path dir = createTempDir();
        Files.copy(getDataPath(GOLDEN_FILE), dir.resolve("_0.fdt"));
        byte[] expected = goldenPlaintext(GOLDEN_PLAINTEXT_LENGTH);

        Provider provider = Security.getProvider("SunJCE");
        KeyResolver keyResolver = new FixedKeyResolver();
        EncryptionMetadataCache cache = new EncryptionMetadataCache();
        try (CryptoNIOFSDirectory directory = new CryptoNIOFSDirectory(FSLockFactory.getDefault(), dir, provider, keyResolver, cache)) {
            assertEquals(GOLDEN_PLAINTEXT_LENGTH, directory.fileLength("_0.fdt"));
            try (IndexInput in = directory.openInput("_0.fdt", IOContext.DEFAULT)) {
                assertEquals(GOLDEN_PLAINTEXT_LENGTH, in.length());
                byte[] actual = new byte[GOLDEN_PLAINTEXT_LENGTH];
                in.readBytes(actual, 0, actual.length);
                assertArrayEquals(expected, actual);

                for (int i = 0; i < 20; i++) {
                    int offset = randomIntBetween(0, GOLDEN_PLAINTEXT_LENGTH - 1);
                    int length = randomIntBetween(1, GOLDEN_PLAINTEXT_LENGTH - offset);
                    in.seek(offset);
                    byte[] range = new byte[length];
                    in.readBytes(range, 0, length);
                    assertArrayEquals(Arrays.copyOfRange(expected, offset, offset + length), range);
                }
            }
        }
    }

    private static EncryptionFooter goldenFooter() throws IOException {
        EncryptionFooter footer = new EncryptionFooter(MESSAGE_ID, (short) 1);
        footer.setDataLength(GOLDEN_PLAINTEXT_LENGTH);
        return footer;
    }

    private static byte[] goldenPlaintext(int length) {
        byte[] b = new byte[length];
        for (int i = 0; i < length; i++) {
            b[i] = (byte) (i * 31 + 7);
        }
        return b;
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }

    private static final class FixedKeyResolver implements KeyResolver {
        @Override
        public Key getDataKey() {
            return new SecretKeySpec(MASTER_KEY, "AES");
        }
    }
}
