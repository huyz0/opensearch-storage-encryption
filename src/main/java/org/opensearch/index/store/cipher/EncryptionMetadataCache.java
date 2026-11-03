/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.cipher;

import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.KeyDerivation;

/**
 * Cache for encryption metadata (footers and derived file keys) for a directory.
 * Shared across all shards of the same index.
 * Lucene segment merging provides natural cleanup via deleteFile() calls.
 */
public class EncryptionMetadataCache {

    /**
     * Immutable container for file encryption metadata.
     * Thread-safe and ensures atomicity between footer and derived file key.
     */
    public static final class FileEncryptionMetadata {
        private final EncryptionFooter footer;
        private final byte[] fileKey;
        private final SecretKeySpec fileKeySpec;

        FileEncryptionMetadata(EncryptionFooter footer, byte[] masterKey) {
            this.footer = footer;
            this.fileKey = KeyDerivation.deriveFileKey(masterKey, footer.getMessageId());
            this.fileKeySpec = new SecretKeySpec(fileKey, "AES");
        }

        public EncryptionFooter getFooter() {
            return footer;
        }

        public byte[] getFileKey() {
            return fileKey;
        }

        /**
         * The file key as one shared key object. The AWS-LC binding keeps each thread's AES-GCM context
         * for the last key object it saw, so reusing this object across block loads of the file keeps
         * that context instead of rebuilding it on every load.
         */
        public SecretKeySpec getFileKeySpec() {
            return fileKeySpec;
        }
    }

    private final ConcurrentHashMap<String, FileEncryptionMetadata> fileMetadataCache;

    public EncryptionMetadataCache() {
        this.fileMetadataCache = new ConcurrentHashMap<>(128, 0.75f, 4);
    }

    public static String normalizePath(Path filePath) {
        return filePath.toAbsolutePath().normalize().toString();
    }

    /**
     * Get or create file encryption metadata atomically.
     * If metadata doesn't exist, creates it from the provided footer and derives the file key.
     * Only one thread will perform the expensive key derivation per file.
     *
     * @param normalizedPath normalized file path
     * @param footer the footer containing messageId for derivation
     * @param masterKey master key for deriving file key
     * @return file encryption metadata (cached or newly created)
     */
    public FileEncryptionMetadata getOrLoadMetadata(String normalizedPath, EncryptionFooter footer, byte[] masterKey) {
        return fileMetadataCache.computeIfAbsent(normalizedPath, k -> new FileEncryptionMetadata(footer, masterKey));
    }

    /**
     * Get cached footer, or null if not cached.
     */
    public EncryptionFooter getFooter(String normalizedPath) {
        FileEncryptionMetadata metadata = fileMetadataCache.get(normalizedPath);
        return metadata != null ? metadata.getFooter() : null;
    }

    /**
     * Get cached file key, or null if not cached.
     */
    public byte[] getFileKey(String normalizedPath) {
        FileEncryptionMetadata metadata = fileMetadataCache.get(normalizedPath);
        return metadata != null ? metadata.getFileKey() : null;
    }

    public void invalidateFile(String normalizedPath) {
        fileMetadataCache.remove(normalizedPath);
    }

    public void invalidateDirectory() {
        fileMetadataCache.clear();
    }
}
