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
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.index.store.cipher.CryptoProviders;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Known-answer tests for the OSEF footer and a committed golden encrypted file.
 *
 * <p>{@code golden-v4.osef} and every expected value here were produced by
 * src/test/resources/org/opensearch/index/store/golden/generate_golden_vectors.py, which
 * implements the format without any plugin code. If one of these tests fails, the on-disk
 * format has changed: files written by earlier builds will not be readable by this one.
 */
public class EncryptionFooterKnownAnswerTests extends OpenSearchTestCase {

    private static final byte[] MASTER_KEY = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] MESSAGE_ID = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    private static final byte[] FILE_KEY = hex("7880842664260e88ad71ee04d9f889fe1d13efe0d86041d1dab05d7a02e8d786");
    private static final String GOLDEN_FILE = "/org/opensearch/index/store/golden/golden-v4.osef";
    /** Two full 8 KiB chunks and a 3616-byte tail. */
    private static final int GOLDEN_PLAINTEXT_LENGTH = 20000;
    /** One {@code nonce || tag} entry per chunk. */
    private static final String GOLDEN_TAG_TABLE_HEX = "77abc86d5c37fe261ce8496620bfef2ac071cc75736748bf2c5a080d"
        + "2442ffeede6ab0781f47fb14858194a230ac00856299dd401798d7f3"
        + "7fc3c2c1eb9394af89bee45c22df0f122ea650c17ddb67e4faaef4e4";

    /**
     * Footer of the golden file, no key metadata. Big-endian fields, in order:
     * <pre>
     * FooterAuthTag      4d638b7bc985e5fc1003c4f493f51fde  GCM tag, AAD = the footer after the nonce
     * FooterNonce        139921a957eb2c01734a97b6          GCM nonce of the auth tag (random when written)
     * DataLength         0000000000004e20                  20000
     * ChunkSize          00002000                          8192
     * MessageId          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
     * KeyMetadataLength  0000                              KeyMetadata itself is empty
     * AlgorithmId        0001                              AES_256_GCM_CTR
     * FooterLength       00000044                          68, including the auth tag
     * Magic              4f534546                          "OSEF"
     * </pre>
     */
    private static final byte[] GOLDEN_FOOTER = hex(
        "4d638b7bc985e5fc1003c4f493f51fde"
            + "139921a957eb2c01734a97b6"
            + "0000000000004e20"
            + "00002000"
            + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            + "0000"
            + "0001"
            + "00000044"
            + "4f534546"
    );

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
    }

    public void testFooterLayoutConstants() {
        assertEquals(68, EncryptionMetadataTrailer.MIN_FOOTER_SIZE);
        assertEquals(68, EncryptionMetadataTrailer.calculateFooterSize(0));
        assertArrayEquals(new byte[] { 'O', 'S', 'E', 'F' }, EncryptionMetadataTrailer.MAGIC);
    }

    /** Serialize uses a fresh provider nonce each time; everything after the nonce is fixed. */
    public void testSerializeKnownAnswer() throws IOException {
        int fixedFrom = EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE + EncryptionMetadataTrailer.FOOTER_NONCE_SIZE;
        byte[] first = goldenFooter().serialize(FILE_KEY);
        byte[] second = goldenFooter().serialize(FILE_KEY);
        assertEquals(GOLDEN_FOOTER.length, first.length);
        assertArrayEquals(
            Arrays.copyOfRange(GOLDEN_FOOTER, fixedFrom, GOLDEN_FOOTER.length),
            Arrays.copyOfRange(first, fixedFrom, first.length)
        );
        assertFalse(
            "nonces must differ",
            Arrays.equals(Arrays.copyOfRange(first, 16, fixedFrom), Arrays.copyOfRange(second, 16, fixedFrom))
        );
        for (byte[] footer : new byte[][] { first, second }) {
            EncryptionFooter parsed = EncryptionFooter.deserialize(footer, FILE_KEY);
            assertArrayEquals(MESSAGE_ID, parsed.getMessageId());
            assertEquals(GOLDEN_PLAINTEXT_LENGTH, parsed.getDataLength());
        }
    }

    public void testDeserializeKnownAnswer() throws IOException {
        EncryptionFooter footer = EncryptionFooter.deserialize(GOLDEN_FOOTER, FILE_KEY);
        assertArrayEquals(MESSAGE_ID, footer.getMessageId());
        assertEquals(GOLDEN_PLAINTEXT_LENGTH, footer.getDataLength());
        assertEquals(3 * 28 + GOLDEN_FOOTER.length + 16, footer.getTrailerLength());
        assertEquals(1, footer.getAlgorithmId());
        assertEquals(GOLDEN_FOOTER.length, footer.getFooterLength());
        assertEquals(0, footer.getKeyMetadata().length);
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
        int copy = EncryptionMetadataTrailer.LUCENE_FOOTER_COPY_SIZE;
        assertEquals(16, copy);
        assertEquals(GOLDEN_PLAINTEXT_LENGTH + tagTable.length + GOLDEN_FOOTER.length + copy, file.length);
        assertArrayEquals(tagTable, Arrays.copyOfRange(file, GOLDEN_PLAINTEXT_LENGTH, GOLDEN_PLAINTEXT_LENGTH + tagTable.length));
        int footerEnd = file.length - copy;
        assertArrayEquals(GOLDEN_FOOTER, Arrays.copyOfRange(file, footerEnd - GOLDEN_FOOTER.length, footerEnd));
        // The golden plaintext does not end with a Lucene codec footer, so the copy is all zeros.
        assertArrayEquals(new byte[copy], Arrays.copyOfRange(file, footerEnd, file.length));
        byte[] upToFooterEnd = Arrays.copyOf(file, footerEnd);
        int trailerStart = footerEnd - EncryptionMetadataTrailer.MIN_FOOTER_SIZE;
        assertEquals(GOLDEN_FOOTER.length, EncryptionFooter.calculateFooterLength(upToFooterEnd, trailerStart));
    }

    /**
     * Reads the committed golden file through {@link CryptoNIOFSDirectory}. This is the
     * format check: today's reader must decrypt and authenticate a file in the v4 format.
     */
    public void testReadGoldenFileThroughDirectory() throws Exception {
        Path dir = createTempDir();
        Files.copy(getDataPath(GOLDEN_FILE), dir.resolve("_0.fdt"));
        byte[] expected = goldenPlaintext(GOLDEN_PLAINTEXT_LENGTH);

        Provider provider = CryptoProviders.provider();
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
