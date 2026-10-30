/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.footer;

import java.nio.charset.StandardCharsets;

/**
 * Constants and utilities for encryption metadata footer format.
 *
 * File layout: [Ciphertext (DataLength bytes)][ChunkTags (16 per chunk)][Footer]
 *
 * Footer format (read backwards from end of file):
 * [FooterAuthTag][DataLength][ChunkSize][MessageId][KeyMetadata][KeyMetadataLength][AlgorithmId][FooterLength][MagicBytes]
 *
 * Features:
 * - Data sealed in independent AES-GCM chunks (see ChunkCipher), so every read is authenticated
 * - HKDF key derivation using MessageId
 * - Footer authentication to prevent tampering, including truncation (DataLength is authenticated)
 * - Algorithm agility for future evolution
 * - Variable KeyMetadata for different key providers
 *
 * @opensearch.internal
 */
public class EncryptionMetadataTrailer {

    // Magic bytes at the very end for reliable footer detection
    public static final String ENCRYPTION_MAGIC_STRING = "OSEF"; // OpenSearch Encrypted File
    public static final byte[] MAGIC = ENCRYPTION_MAGIC_STRING.getBytes(StandardCharsets.UTF_8);

    // Field sizes in bytes
    public static final int MESSAGE_ID_SIZE = 16;
    public static final int DATA_LENGTH_SIZE = 8;
    public static final int CHUNK_SIZE_SIZE = 4;
    public static final int KEY_METADATA_LENGTH_SIZE = 2;
    public static final int ALGORITHM_ID_SIZE = 2;
    public static final int FOOTER_LENGTH_SIZE = 4;
    public static final int FOOTER_AUTH_TAG_SIZE = 16;

    // Calculated sizes
    public static final int FIXED_FOOTER_SIZE = MESSAGE_ID_SIZE + KEY_METADATA_LENGTH_SIZE + ALGORITHM_ID_SIZE + FOOTER_LENGTH_SIZE
        + MAGIC.length;
    public static final int MIN_FOOTER_SIZE = FIXED_FOOTER_SIZE + DATA_LENGTH_SIZE + CHUNK_SIZE_SIZE + FOOTER_AUTH_TAG_SIZE;

    // Algorithm IDs for future extensibility
    public static final int ALGORITHM_AES_256_GCM = 1;

    /**
     * Calculate total footer size including variable parts. The chunk tag table sits before the
     * footer and is not counted here.
     * @param keyMetadataLength length of key metadata
     * @return total footer size in bytes
     */
    public static int calculateFooterSize(int keyMetadataLength) {
        return MIN_FOOTER_SIZE + keyMetadataLength;
    }
}
