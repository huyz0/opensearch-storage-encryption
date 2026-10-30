/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.niofs;

import java.io.BufferedOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Objects;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.store.OutputStreamIndexOutput;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.index.store.cipher.ChunkCipher;
import org.opensearch.index.store.cipher.ChunkEncryptor;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.footer.EncryptionFooter;
import org.opensearch.index.store.key.HkdfKeyDerivation;
import org.opensearch.index.store.key.KeyResolver;

/**
 * An IndexOutput implementation that encrypts data in authenticated AES-GCM chunks
 * (see {@link ChunkCipher}) and appends the chunk tag table and footer on close.
 *
 * @opensearch.internal
 */
@SuppressForbidden(reason = "temporary bypass")
@SuppressWarnings("preview")
public final class CryptoOutputStreamIndexOutput extends OutputStreamIndexOutput {

    private static final int CHUNK_SIZE = 8_192;
    private static final int BUFFER_SIZE = 65_536;

    /**
     * Creates a new CryptoIndexOutput with per-file key derivation
     *
     * @param name        The name of the output
     * @param path        The path to write to
     * @param os          The output stream
     * @param keyResolver The key resolver for directory keys
     * @param provider    The JCE provider to use
     */
    public CryptoOutputStreamIndexOutput(
        String name,
        Path path,
        OutputStream os,
        KeyResolver keyResolver,
        java.security.Provider provider,
        int algorithmId,
        Path filePath,
        EncryptionMetadataCache encryptionMetadataCache
    ) {
        super(
            "FSIndexOutput(path=\"" + path + "\")",
            name,
            new EncryptedOutputStream(os, keyResolver, algorithmId, filePath, encryptionMetadataCache),
            CHUNK_SIZE
        );
    }

    private static class EncryptedOutputStream extends FilterOutputStream {

        private final byte[] masterKey;
        private final byte[] fileKey;
        private final EncryptionFooter footer;
        private final ChunkEncryptor encryptor;
        private boolean isClosed = false;

        private final String normalizedFilePath;
        private final EncryptionMetadataCache encryptionMetadataCache;

        EncryptedOutputStream(
            OutputStream os,
            KeyResolver keyResolver,
            int algorithmId,
            Path filePath,
            EncryptionMetadataCache encryptionMetadataCache
        ) {
            super(new BufferedOutputStream(os, BUFFER_SIZE));

            // Generate MessageId and derive file-specific key
            this.footer = EncryptionFooter.generateNew((short) algorithmId);
            this.masterKey = keyResolver.getDataKey().getEncoded();
            this.fileKey = HkdfKeyDerivation.deriveFileKey(masterKey, footer.getMessageId());
            this.encryptor = new ChunkEncryptor(new SecretKeySpec(fileKey, "AES"));

            this.normalizedFilePath = EncryptionMetadataCache.normalizePath(filePath);
            this.encryptionMetadataCache = encryptionMetadataCache;
        }

        @Override
        public void write(byte[] b, int offset, int length) throws IOException {
            checkClosed();
            Objects.checkFromIndexSize(offset, length, b.length);
            encryptor.write(out, b, offset, length);
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override
        public void close() throws IOException {
            checkClosed();
            isClosed = true;
            // Lucene's own footer has already been written through write().
            // Closing the buffered stream flushes it and closes the file, also on failure.
            try (OutputStream o = out) {
                footer.setDataLength(encryptor.finish(o));
                o.write(footer.serialize(fileKey));
            }

            if (normalizedFilePath != null) {
                encryptionMetadataCache.getOrLoadMetadata(normalizedFilePath, footer, this.masterKey);
            }
        }

        private void checkClosed() throws IOException {
            if (isClosed) {
                throw new IOException("Output stream is already closed, this is unusual");
            }
        }
    }
}
