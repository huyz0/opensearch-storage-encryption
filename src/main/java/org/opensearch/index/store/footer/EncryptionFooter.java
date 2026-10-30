/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.footer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.index.CorruptIndexException;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.key.HkdfKeyDerivation;

/**
 * Footer of an encrypted index file.
 *
 * <p>File layout: {@code [Ciphertext(DataLength)][ChunkTags(16 * chunkCount)][Footer]}. The data is
 * sealed in {@link ChunkCipher} chunks; the tag table holds one GCM tag per chunk, in order.
 *
 * Footer format: [FooterAuthTag(16)][DataLength(8)][ChunkSize(4)][MessageId(16)][KeyMetadata(0)]
 * [KeyMetadataLength(2)][AlgorithmId(2)][FooterLength(4)][Magic(4)]
 *
 * Field Name   Size in Bytes
 * ------------  -------------
 * FooterAuthTag      16    GCM tag over the rest of the footer (as AAD)
 * DataLength         8     plaintext length; authenticated, so truncation is detected
 * ChunkSize          4     must be ChunkCipher.CHUNK_SIZE
 * MessageId          16
 * KeyMetadata        Variable // currently empty
 * KeyMetadataLength  2
 * AlgorithmId        2
 * FooterLength       4     footer length including the auth tag, excluding the tag table
 * MagicBytes         4
 *
 */
public class EncryptionFooter {

    private static final Logger LOGGER = LogManager.getLogger(EncryptionFooter.class);

    private final byte[] messageId;
    private final short algorithmId;
    private final byte[] keyMetadata; // Currently empty - key data retrieved from keyfile
    private byte[] footerAuthTag; // 16-byte GCM auth tag for footer authentication
    private long dataLength;
    private int footerLength;

    public EncryptionFooter(byte[] messageId, short algorithmId) {
        if (messageId.length != EncryptionMetadataTrailer.MESSAGE_ID_SIZE) {
            throw new IllegalArgumentException("MessageId must be 16 bytes");
        }
        this.messageId = Arrays.copyOf(messageId, EncryptionMetadataTrailer.MESSAGE_ID_SIZE);
        this.algorithmId = algorithmId;
        this.keyMetadata = new byte[0]; // Empty - currently using keyfile for key data
        this.dataLength = 0;
        this.footerLength = 0;
    }

    public static EncryptionFooter generateNew(short algorithmId) {
        byte[] messageId = new byte[EncryptionMetadataTrailer.MESSAGE_ID_SIZE];
        new SecureRandom().nextBytes(messageId);
        return new EncryptionFooter(messageId, algorithmId);
    }

    public void setFooterLength(int footerLength) {
        this.footerLength = footerLength;
    }

    /** Length of the footer itself, excluding the chunk tag table that precedes it. */
    public int getFooterLength() {
        return footerLength;
    }

    /** Bytes after the data: the chunk tag table plus the footer. */
    public long getTrailerLength() {
        return ChunkCipher.tagTableLength(dataLength) + footerLength;
    }

    public byte[] serialize(byte[] fileKey) throws IOException {

        // Build footer data without auth tag
        byte[] footerData = buildFooterDataWithoutAuthTag();

        // Set footer length (includes auth tag)
        this.setFooterLength(footerData.length + EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE);

        // Generate auth tag
        this.footerAuthTag = generateFooterAuthTag(fileKey, footerData);

        // Prepend auth tag to footer: [AuthTag(16)][FooterData...]
        ByteBuffer buffer = ByteBuffer.allocate(footerData.length + EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE);
        buffer.put(footerAuthTag);
        buffer.put(footerData);
        return buffer.array();
    }

    private byte[] buildFooterDataWithoutAuthTag() {
        int footerSize = EncryptionMetadataTrailer.calculateFooterSize(keyMetadata.length) - EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE;
        ByteBuffer buffer = ByteBuffer.allocate(footerSize);

        buffer.putLong(dataLength);
        buffer.putInt(ChunkCipher.CHUNK_SIZE);

        // Write MessageId
        buffer.put(messageId);

        // Write KeyMetadata (empty - using keyfile)
        buffer.put(keyMetadata);

        // Write KeyMetadataLength
        buffer.putShort((short) keyMetadata.length);

        // Write algorithm ID
        buffer.putShort(algorithmId);

        // Write footer length
        buffer.putInt(footerSize + EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE);

        // Write magic
        buffer.put(EncryptionMetadataTrailer.MAGIC);

        return buffer.array();
    }

    public static EncryptionFooter deserialize(byte[] fileBytes, byte[] fileKey) throws IOException {
        if (fileBytes.length < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException("Invalid footer size: " + fileBytes.length);
        }

        // Extract auth tag from beginning
        byte[] authTag = Arrays.copyOfRange(fileBytes, 0, EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE);
        byte[] footerData = Arrays.copyOfRange(fileBytes, EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE, fileBytes.length);

        // Verify auth tag
        if (!verifyFooterAuthTag(fileKey, footerData, authTag)) {
            throw new CorruptIndexException("Footer authentication failed", "encryption footer");
        }

        int pos = footerData.length;

        // Read magic
        pos -= EncryptionMetadataTrailer.MAGIC.length;
        byte[] magic = Arrays.copyOfRange(footerData, pos, pos + EncryptionMetadataTrailer.MAGIC.length);
        if (!Arrays.equals(magic, EncryptionMetadataTrailer.MAGIC)) {
            throw new IOException("Invalid footer magic");
        }

        // Read footer length
        pos -= EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE;
        int footerLength = ByteBuffer.wrap(footerData, pos, EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE).getInt();

        // Read algorithm ID
        pos -= EncryptionMetadataTrailer.ALGORITHM_ID_SIZE;
        short algorithmId = ByteBuffer.wrap(footerData, pos, EncryptionMetadataTrailer.ALGORITHM_ID_SIZE).getShort();

        // Read KeyMetadataLength
        pos -= EncryptionMetadataTrailer.KEY_METADATA_LENGTH_SIZE;
        short keyMetadataLength = ByteBuffer.wrap(footerData, pos, EncryptionMetadataTrailer.KEY_METADATA_LENGTH_SIZE).getShort();
        checkKeyMetadataLength(keyMetadataLength, fileBytes.length);

        // Read KeyMetadata (currently empty)
        pos -= keyMetadataLength;
        byte[] keyMetadata = Arrays.copyOfRange(footerData, pos, pos + keyMetadataLength);

        // Read MessageId
        pos -= EncryptionMetadataTrailer.MESSAGE_ID_SIZE;
        byte[] messageId = Arrays.copyOfRange(footerData, pos, pos + EncryptionMetadataTrailer.MESSAGE_ID_SIZE);

        // Read chunk size
        pos -= EncryptionMetadataTrailer.CHUNK_SIZE_SIZE;
        int chunkSize = ByteBuffer.wrap(footerData, pos, EncryptionMetadataTrailer.CHUNK_SIZE_SIZE).getInt();
        if (chunkSize != ChunkCipher.CHUNK_SIZE) {
            throw new IOException("Unsupported chunk size " + chunkSize + ", expected " + ChunkCipher.CHUNK_SIZE);
        }

        // Read data length
        pos -= EncryptionMetadataTrailer.DATA_LENGTH_SIZE;
        long dataLength = ByteBuffer.wrap(footerData, pos, EncryptionMetadataTrailer.DATA_LENGTH_SIZE).getLong();
        if (dataLength < 0) {
            throw new IOException("Invalid data length " + dataLength);
        }

        // Validate footer length
        int expectedLength = EncryptionMetadataTrailer.calculateFooterSize(keyMetadataLength);
        if (footerLength != expectedLength || fileBytes.length != expectedLength) {
            throw new IOException("Footer length mismatch: expected " + expectedLength + ", got " + footerLength);
        }

        EncryptionFooter footer = new EncryptionFooter(messageId, algorithmId);
        footer.dataLength = dataLength;
        footer.footerAuthTag = authTag;
        footer.setFooterLength(footerLength);
        return footer;
    }

    /**
     * Calculate footer length from byte array starting at offset
     * 
     * @param footerBytes byte array containing footer data
     * @param offset starting position in the array
     * @return footer length in bytes
     * @throws IOException if buffer is too small
     */
    public static int calculateFooterLength(byte[] footerBytes, int offset) throws IOException {
        int availableBytes = footerBytes.length - offset;
        if (availableBytes < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException(
                "Footer too small: " + availableBytes + " bytes available, need " + EncryptionMetadataTrailer.MIN_FOOTER_SIZE
            );
        }

        // Read footer length from end: [FooterLength(4)][Magic(4)]
        int pos = footerBytes.length - EncryptionMetadataTrailer.MAGIC.length - EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE;
        return ByteBuffer.wrap(footerBytes, pos, EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE).getInt();
    }

    public byte[] getMessageId() {
        return Arrays.copyOf(messageId, EncryptionMetadataTrailer.MESSAGE_ID_SIZE);
    }

    /** Plaintext length of the file; also the offset of the chunk tag table. */
    public long getDataLength() {
        return dataLength;
    }

    public void setDataLength(long dataLength) {
        if (dataLength < 0) {
            throw new IllegalArgumentException("dataLength must not be negative: " + dataLength);
        }
        this.dataLength = dataLength;
    }

    public short getAlgorithmId() {
        return algorithmId;
    }

    public byte[] getKeyMetadata() {
        return Arrays.copyOf(keyMetadata, keyMetadata.length);
    }

    private static byte[] generateFooterAuthTag(byte[] fileKey, byte[] footerData) throws IOException {
        try {
            byte[] footerIV = new byte[12];  // GCM uses 12-byte IV
            Arrays.fill(footerIV, 0, 8, (byte) 0xFF);  // 0xFFFFFFFFFFFFFFFF0000

            // Use default provider instead of null
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, footerIV);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"), spec);

            // Encrypt empty data to generate auth tag for footerData as AAD
            cipher.updateAAD(footerData);
            byte[] result = cipher.doFinal();  // Empty ciphertext + 16-byte tag

            // Extract the 16-byte GCM tag from the end
            return Arrays.copyOfRange(result, result.length - 16, result.length);
        } catch (Exception e) {
            throw new IOException("Failed to generate footer auth tag", e);
        }
    }

    private static boolean verifyFooterAuthTag(byte[] fileKey, byte[] footerData, byte[] expectedTag) throws IOException {
        try {
            byte[] computedTag = generateFooterAuthTag(fileKey, footerData);
            return Arrays.equals(computedTag, expectedTag);
        } catch (IOException e) {
            LOGGER.error("Encountered error while verify footer auth tag", e);
            throw e;
        }
    }

    /**
     * Maximum footer size to read in single I/O operation. The footer has a fixed size plus
     * key metadata; chunk tags live in the tag table before it.
     */
    private static final int MAX_FOOTER_READ_SIZE = 8192; // 8KB

    /**
     * Read and deserialize footer from a FileChannel
     *
     * @param normalizedFilePath normalized file path string
     * @param channel FileChannel to read from
     * @param masterKey Master key for file key derivation and footer authentication
     * @param encryptionMetadataCache cache for encryption metadata
     * @return Deserialized EncryptionFooter
     * @throws IOException If reading or deserialization fails
     * @throws NotOSEFFileException If file is not a valid OSEF format
     */
    public static EncryptionFooter readViaFileChannel(
        String normalizedFilePath,
        java.nio.channels.FileChannel channel,
        byte[] masterKey,
        EncryptionMetadataCache encryptionMetadataCache
    ) throws IOException {

        EncryptionFooter cachedFooter = encryptionMetadataCache.getFooter(normalizedFilePath);
        if (cachedFooter != null) {
            return cachedFooter;
        }

        long fileSize = channel.size();
        if (fileSize < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new NotOSEFFileException("File too small to contain encryption footer: " + normalizedFilePath);
        }

        // Read MAX_FOOTER_READ_SIZE or entire file if smaller
        int readSize = (int) Math.min(MAX_FOOTER_READ_SIZE, fileSize);
        long readPosition = fileSize - readSize;

        ByteBuffer buffer = ByteBuffer.allocate(readSize);
        int bytesRead = channel.read(buffer, readPosition);

        if (bytesRead != readSize) {
            throw new IOException("Failed to read footer: expected " + readSize + " bytes, got " + bytesRead);
        }

        // Reset position for reading
        buffer.flip();

        // Extract bytes for validation - read from end of buffer
        byte[] bufferArray = buffer.array();
        int minFooterStart = bufferArray.length - EncryptionMetadataTrailer.MIN_FOOTER_SIZE;

        // Validate OSEF magic bytes from the last MIN_FOOTER_SIZE bytes
        if (!isValidOSEFFile(bufferArray, minFooterStart)) {
            throw new NotOSEFFileException("File does not contain valid OSEF magic bytes: " + normalizedFilePath);
        }

        // Calculate actual footer length from the buffer
        int footerLength = calculateFooterLength(bufferArray, minFooterStart);

        // Validate we read enough data
        if (footerLength < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException("Invalid footer length " + footerLength + " in " + normalizedFilePath);
        }
        if (footerLength > readSize) {
            throw new IOException(
                "Footer length "
                    + footerLength
                    + " exceeds max read size "
                    + MAX_FOOTER_READ_SIZE
                    + ". File may have an unusually large footer."
            );
        }

        // Extract actual footer bytes from buffer
        int footerStart = bufferArray.length - footerLength;
        byte[] footerBytes = Arrays.copyOfRange(bufferArray, footerStart, bufferArray.length);

        // Extract messageId to derive file key for authentication
        byte[] messageId = extractMessageId(footerBytes);
        byte[] fileKey = HkdfKeyDerivation.deriveFileKey(masterKey, messageId);

        // Deserialize footer with file key for authentication
        EncryptionFooter footer = deserialize(footerBytes, fileKey);

        // DataLength is authenticated, so this catches truncated or extended files
        long expectedFileSize = footer.getDataLength() + footer.getTrailerLength();
        if (fileSize != expectedFileSize) {
            throw new CorruptIndexException(
                "Encrypted file size " + fileSize + " does not match its footer (expected " + expectedFileSize + ")",
                normalizedFilePath
            );
        }
        encryptionMetadataCache.getOrLoadMetadata(normalizedFilePath, footer, masterKey);
        return footer;
    }

    /**
     * Extract messageId from footer bytes without full deserialization or authentication.
     * This is needed to derive the file key before we can verify the footer's auth tag.
     *
     * @param footerBytes complete footer bytes including auth tag
     * @return 16-byte messageId
     * @throws IOException if footer format is invalid
     */
    private static byte[] extractMessageId(byte[] footerBytes) throws IOException {
        if (footerBytes.length < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            throw new IOException("Footer too small: " + footerBytes.length);
        }

        // Skip auth tag at beginning
        byte[] footerData = Arrays.copyOfRange(footerBytes, EncryptionMetadataTrailer.FOOTER_AUTH_TAG_SIZE, footerBytes.length);

        // Read KeyMetadataLength to know how much to skip
        int keyMetadataLengthPos = footerData.length - EncryptionMetadataTrailer.MAGIC.length - EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE
            - EncryptionMetadataTrailer.ALGORITHM_ID_SIZE - EncryptionMetadataTrailer.KEY_METADATA_LENGTH_SIZE;
        short keyMetadataLength = ByteBuffer
            .wrap(footerData, keyMetadataLengthPos, EncryptionMetadataTrailer.KEY_METADATA_LENGTH_SIZE)
            .getShort();
        checkKeyMetadataLength(keyMetadataLength, footerBytes.length);

        // MessageId is before KeyMetadata
        int messageIdPos = footerData.length - EncryptionMetadataTrailer.MAGIC.length - EncryptionMetadataTrailer.FOOTER_LENGTH_SIZE
            - EncryptionMetadataTrailer.ALGORITHM_ID_SIZE - EncryptionMetadataTrailer.KEY_METADATA_LENGTH_SIZE - keyMetadataLength
            - EncryptionMetadataTrailer.MESSAGE_ID_SIZE;

        return Arrays.copyOfRange(footerData, messageIdPos, messageIdPos + EncryptionMetadataTrailer.MESSAGE_ID_SIZE);
    }

    /** Rejects a KeyMetadataLength that doesn't fit the footer, before it is used as an offset. */
    private static void checkKeyMetadataLength(short keyMetadataLength, int footerLength) throws CorruptIndexException {
        if (keyMetadataLength < 0 || EncryptionMetadataTrailer.calculateFooterSize(keyMetadataLength) != footerLength) {
            throw new CorruptIndexException(
                "Invalid key metadata length " + keyMetadataLength + " for footer of length " + footerLength,
                "encryption footer"
            );
        }
    }

    /**
     * Check if file has valid OSEF magic bytes starting at offset
     * 
     * @param footerBytes byte array containing footer data
     * @param offset starting position in the array
     * @return true if valid OSEF magic bytes are present
     */
    private static boolean isValidOSEFFile(byte[] footerBytes, int offset) {
        int availableBytes = footerBytes.length - offset;
        if (availableBytes < EncryptionMetadataTrailer.MIN_FOOTER_SIZE) {
            return false;
        }

        int magicOffset = footerBytes.length - EncryptionMetadataTrailer.MAGIC.length;
        for (int i = 0; i < EncryptionMetadataTrailer.MAGIC.length; i++) {
            if (footerBytes[magicOffset + i] != EncryptionMetadataTrailer.MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    public static class NotOSEFFileException extends IOException {

        public NotOSEFFileException(String message) {
            super(message);
        }

        public NotOSEFFileException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
