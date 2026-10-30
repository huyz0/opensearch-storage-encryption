/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.key;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.Provider;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.index.CorruptIndexException;
import org.apache.lucene.index.IndexFileNames;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.apache.lucene.util.IOUtils;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.metrics.ErrorType;

/**
 * Default implementation of {@link KeyResolver} responsible for managing
 * the encryption key used in encrypting and decrypting Lucene index files.
 *
 * Uses node-level cache for TTL-based key management with automatic refresh.
 * Always returns the last known key if Master Key Provider is unavailable to ensure operations can continue.
 *
 * Metadata files:
 * - "keyfile" stores the encrypted data key
 * - IVs are derived using HKDF
 *
 * @opensearch.internal
 */
public class DefaultKeyResolver implements KeyResolver {

    private final String indexUuid;
    private final String indexName;
    private final Directory directory;
    private final MasterKeyProvider keyProvider;
    private final int shardId;

    private static final String KEY_FILE = "keyfile";
    private static final String KEY_FILE_TEMP_SUFFIX = "tmp";

    /**
     * Constructs a new {@link DefaultKeyResolver} and ensures the key is initialized.
     *
     * @param indexUuid   the unique identifier for the index
     * @param indexName   the index name
     * @param directory   the Lucene directory to read/write metadata files
     * @param provider    the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @param shardId     the shard ID
     * @throws KeyCacheException if an I/O error occurs while reading or writing key metadata
     */
    public DefaultKeyResolver(
        String indexUuid,
        String indexName,
        Directory directory,
        Provider provider,
        MasterKeyProvider keyProvider,
        int shardId
    )
        throws KeyCacheException {
        this.indexUuid = indexUuid;
        this.indexName = indexName;
        this.directory = directory;
        this.keyProvider = keyProvider;
        this.shardId = shardId;
        initialize(shardId);
    }

    /**
     * Gets the index name for this resolver.
     * 
     * @return the index name
     */
    public String getIndexName() {
        return indexName;
    }

    /**
     * Attempts to load the encrypted key from the directory.
     * If not present, it generates and persists new values, unless shard data already exists
     * for this index: that data was encrypted with a key that is now lost, so generating a
     * fresh key would silently make it undecryptable.
     */
    private void initialize(int shardId) throws KeyCacheException {
        try {
            keyProvider.decryptKey(readByteArrayFile(KEY_FILE));
        } catch (java.nio.file.NoSuchFileException e) {
            // Key file doesn't exist, generate new one
            try {
                ensureNoExistingShardData();
                initNewKey(shardId);
            } catch (Exception ex) {
                CryptoMetricsService.getInstance().recordError(ErrorType.KMS_KEY_ERROR, getMetricKey(ex));
                String rootCause = KeyCacheException.extractRootCauseMessage(ex);
                throw new KeyCacheException(
                    "Error encountered for index '" + indexName + "' (UUID: " + indexUuid + "): " + rootCause,
                    ex,
                    true  // suppress stack trace
                );
            }
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.KMS_KEY_ERROR, getMetricKey(e));
            String rootCause = KeyCacheException.extractRootCauseMessage(e);
            throw new KeyCacheException("Error encountered for index '" + indexName + "' (UUID: " + indexUuid + "): " + rootCause, e, true);
        }
    }

    private void initNewKey(int shardId) throws IOException {
        DataKeyPair pair = keyProvider.generateDataPair();
        writeByteArrayFile(KEY_FILE, pair.getEncryptedKey());
    }

    /**
     * Refuses to generate a new key when this index already has shard data in the directory.
     * Only applies to filesystem directories, where the index-level directory holds the shard
     * subdirectories ({@code <shardId>/index}).
     */
    private void ensureNoExistingShardData() throws IOException {
        if (directory instanceof FSDirectory == false) {
            return;
        }
        Path existing = findExistingShardData(((FSDirectory) directory).getDirectory());
        if (existing != null) {
            throw new IOException(
                "encryption keyfile is missing but shard data already exists at ["
                    + existing
                    + "]; refusing to generate a new key because the existing data could no longer be decrypted. "
                    + "Restore the keyfile, or delete the shard data so it can be recovered from another copy"
            );
        }
    }

    /**
     * Returns the first Lucene commit point ({@code segments_N}) found under the shard subdirectories
     * of {@code indexDirectory}, or {@code null} if there is none. A new shard's directories may already
     * exist when the key is created, but its first commit is only written after the key exists.
     */
    static Path findExistingShardData(Path indexDirectory) throws IOException {
        if (Files.isDirectory(indexDirectory) == false) {
            return null;
        }
        try (DirectoryStream<Path> shards = Files.newDirectoryStream(indexDirectory, Files::isDirectory)) {
            for (Path shard : shards) {
                Path found = findCommitPoint(shard.resolve("index"));
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static Path findCommitPoint(Path dir) throws IOException {
        if (Files.isDirectory(dir) == false) {
            return null;
        }
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir)) {
            for (Path file : files) {
                String name = file.getFileName().toString();
                if (name.startsWith(IndexFileNames.SEGMENTS + "_")) {
                    return file;
                }
            }
        }
        return null;
    }

    /**
     * Reads a byte array from the specified file in the directory.
     * The file must contain exactly a 4-byte length followed by that many bytes, so a truncated
     * or padded keyfile is reported as corrupt instead of being handed to the key provider.
     */
    private byte[] readByteArrayFile(String fileName) throws IOException {
        try (IndexInput in = directory.openInput(fileName, IOContext.READONCE)) {
            if (in.length() < Integer.BYTES) {
                throw new CorruptIndexException("keyfile is too short: " + in.length() + " bytes", in);
            }
            int size = in.readInt();
            if (size < 0 || size != in.length() - Integer.BYTES) {
                throw new CorruptIndexException(
                    "keyfile length mismatch: header says " + size + " bytes, file has " + (in.length() - Integer.BYTES),
                    in
                );
            }
            byte[] bytes = new byte[size];
            in.readBytes(bytes, 0, size);
            return bytes;
        }
    }

    /**
     * Durably and atomically writes a byte array to the specified file in the directory:
     * the data goes to a temp file which is fsynced, then renamed over the target, and the
     * directory metadata is fsynced so the rename survives a crash.
     */
    private void writeByteArrayFile(String fileName, byte[] data) throws IOException {
        String tempName = null;
        boolean success = false;
        try {
            try (IndexOutput out = directory.createTempOutput(fileName, KEY_FILE_TEMP_SUFFIX, IOContext.DEFAULT)) {
                tempName = out.getName();
                out.writeInt(data.length);
                out.writeBytes(data, 0, data.length);
            }
            directory.sync(List.of(tempName));
            directory.rename(tempName, fileName);
            directory.syncMetaData();
            success = true;
        } finally {
            if (success == false && tempName != null) {
                IOUtils.deleteFilesIgnoringExceptions(directory, tempName);
            }
        }
    }

    /**
     * Loads master key from Master Key provider by decrypting the stored encrypted key.
     * This method is called by the node-level cache.
     * Exceptions are allowed to bubble up - the cache will handle fallback to old value.
     */
    Key loadKeyFromMasterKeyProvider() throws Exception {
        // Attempt decryption
        try {
            byte[] encryptedKey = readByteArrayFile(KEY_FILE);
            byte[] masterKey = keyProvider.decryptKey(encryptedKey);
            return new SecretKeySpec(masterKey, "AES");
        } catch (Exception e) {
            CryptoMetricsService.getInstance().recordError(ErrorType.KMS_KEY_ERROR, getMetricKey(e));
            throw e;
        }

    }

    /**
     * {@inheritDoc}
     * Returns the master key. File-specific keys are derived on-demand from master key + messageId.
     * The cache handles MasterKey Provider failures by returning the last known key.
     */
    @Override
    public Key getDataKey() {
        try {
            return NodeLevelKeyCache.getInstance().get(indexUuid, shardId, indexName);
        } catch (Exception e) {
            // If it's already a KeyCacheException with clean message, just rethrow
            if (e instanceof KeyCacheException) {
                throw (KeyCacheException) e;
            }
            // Only wrap unexpected exceptions
            throw new KeyCacheException("Failed to get encryption key for index: " + indexName, e, true);
        }
    }

    private String getMetricKey(Exception e) {
        String kmsKey = extractKmsKey(e);
        return this.indexName + ":" + kmsKey;
    }

    private String extractKmsKey(Exception e) {
        String message = e.getMessage();
        if (message != null) {
            Pattern pattern = Pattern.compile("arn:aws:kms:[^:]+:[^:]+:key/([^\\s]+)");
            Matcher matcher = pattern.matcher(message);
            if (matcher.find()) {
                return matcher.group(1); // Just the key ID, not full ARN
            }
        }
        return "unknown";
    }

}
