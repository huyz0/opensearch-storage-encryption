/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.IOUtils;
import org.opensearch.index.store.key.KeyResolver;

/**
 * A ChannelFactory implementation that creates FileChannels with transparent
 * encryption/decryption for translog files.
 *
 * This factory determines whether to apply encryption based on the file extension:
 * - .tlog files: Encrypted by {@link CryptoFileChannelWrapper} (offset-keyed AES-CTR, random nonce per file)
 * - .ckp files: Not encrypted (checkpoint metadata)
 *
 * Updated to use unified KeyResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoChannelFactory implements ChannelFactory {

    private static final Logger logger = LogManager.getLogger(CryptoChannelFactory.class);

    private final KeyResolver keyResolver;
    private final String translogUUID;

    /**
     * Creates a new CryptoChannelFactory.
     *
     * @param keyResolver the key and IV resolver for encryption keys (unified with index files)
     * @param translogUUID the translog UUID for exact header size calculation
     */
    public CryptoChannelFactory(KeyResolver keyResolver, String translogUUID) {
        if (translogUUID == null) {
            throw new IllegalArgumentException("translogUUID is required for exact header size calculation");
        }
        this.keyResolver = Objects.requireNonNull(keyResolver, "keyResolver");
        this.translogUUID = translogUUID;
    }

    @Override
    public FileChannel open(Path path, OpenOption... options) throws IOException {
        if (!path.getFileName().toString().endsWith(".tlog")) {
            return FileChannel.open(path, options);
        }

        Set<OpenOption> optionSet = Set.of(options);
        if (optionSet.contains(StandardOpenOption.APPEND)) {
            // The wrapper writes at explicit physical offsets past the hidden magic and nonce.
            throw new IllegalArgumentException("APPEND is not supported for encrypted translog files: " + path);
        }
        // A file opened read-only already exists; if it was downloaded from the remote store it is
        // plaintext and gets encrypted under this node's key before it is read.
        if (optionSet.contains(StandardOpenOption.WRITE) == false
            && CryptoFileChannelWrapper.encryptIfPlaintext(path, keyResolver, translogUUID)) {
            logger.info("Encrypted plaintext translog file {} (downloaded from the remote store)", path.getFileName());
        }

        FileChannel baseChannel = FileChannel.open(path, options);
        try {
            return new CryptoFileChannelWrapper(baseChannel, keyResolver, path, optionSet, translogUUID);
        } catch (IOException | RuntimeException e) {
            IOUtils.closeWhileHandlingException(baseChannel);
            throw e;
        }
    }
}
