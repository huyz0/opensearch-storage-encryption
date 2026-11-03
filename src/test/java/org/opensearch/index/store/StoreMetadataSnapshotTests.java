/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.Provider;
import java.util.Arrays;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.apache.lucene.codecs.CodecUtil;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.FSLockFactory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.store.block.RefCountedMemorySegment;
import org.opensearch.index.store.block_cache.BlockCache;
import org.opensearch.index.store.block_cache.CaffeineBlockCache;
import org.opensearch.index.store.block_loader.BlockLoader;
import org.opensearch.index.store.block_loader.CryptoDirectIOBlockLoader;
import org.opensearch.index.store.bufferpoolfs.BufferPoolDirectory;
import org.opensearch.index.store.bufferpoolfs.TestKeyResolver;
import org.opensearch.index.store.cipher.CryptoProviders;
import org.opensearch.index.store.cipher.EncryptionMetadataCache;
import org.opensearch.index.store.cipher.EncryptionMetadataCacheRegistry;
import org.opensearch.index.store.hybrid.HybridCryptoDirectory;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.index.store.metrics.CryptoMetricsService;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.store.pool.PoolBuilder;
import org.opensearch.telemetry.metrics.MetricsRegistry;
import org.opensearch.test.DummyShardLock;
import org.opensearch.test.OpenSearchTestCase;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

/**
 * Core reads the store metadata of a closed shard with a plain {@code NIOFSDirectory}, for example to tell the
 * replica allocator which nodes hold a copy after a restart. That read takes the checksum from the last 16 bytes of
 * each file, so every encrypted file must end with a copy of Lucene's codec footer.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class StoreMetadataSnapshotTests extends OpenSearchTestCase {

    private static final ShardId SHARD_ID = new ShardId("index", "_na_", 0);

    @Override
    public void setUp() throws Exception {
        super.setUp();
        CryptoMetricsService.initialize(mock(MetricsRegistry.class));
    }

    public void testReadMetadataSnapshotOfCryptoNIOFSIndex() throws IOException {
        Path path = createTempDir();
        byte[] masterKey = randomByteArrayOfLength(32);
        KeyResolver resolver = new KeyResolver() {
            @Override
            public Key getDataKey() {
                return new SecretKeySpec(masterKey, "AES");
            }
        };
        try (
            Directory dir = new CryptoNIOFSDirectory(
                FSLockFactory.getDefault(),
                path,
                CryptoProviders.provider(),
                resolver,
                new EncryptionMetadataCache()
            )
        ) {
            writeIndex(dir);
            assertSnapshotMatches(path, dir);
        }
    }

    public void testReadMetadataSnapshotOfHybridIndex() throws Exception {
        boolean originalWriteCacheEnabled = CryptoDirectoryFactory.isWriteCacheEnabled();
        CryptoDirectoryFactory.setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", false).build());
        Settings nodeSettings = Settings
            .builder()
            .put("plugins.crypto.enabled", true)
            .put("node.store.crypto.pool_size_percentage", 0.05)
            .put("node.store.crypto.warmup_percentage", 0.0)
            .put("node.store.crypto.cache_to_pool_ratio", 0.8)
            .build();
        Path path = createTempDir();
        try (PoolBuilder.PoolResources pool = PoolBuilder.build(nodeSettings)) {
            Provider provider = CryptoProviders.provider();
            MasterKeyProvider keyProvider = DummyKeyProvider.create();
            String indexUuid = randomAlphaOfLength(10);
            String indexName = randomAlphaOfLength(10);
            KeyResolver keyResolver = new TestKeyResolver(indexUuid, indexName, FSDirectory.open(path), provider, keyProvider, 0);
            EncryptionMetadataCache metadataCache = EncryptionMetadataCacheRegistry.getOrCreateCache(indexUuid, 0, indexName);
            BlockLoader<RefCountedMemorySegment> loader = new CryptoDirectIOBlockLoader(
                pool.getSegmentPool(),
                keyResolver,
                metadataCache,
                pool.getFileChannelCache()
            );
            @SuppressWarnings("unchecked")
            CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment> sharedCache =
                (CaffeineBlockCache<RefCountedMemorySegment, RefCountedMemorySegment>) pool.getBlockCache();
            BlockCache<RefCountedMemorySegment> directoryCache = new CaffeineBlockCache<>(
                sharedCache.getCache(),
                loader,
                pool.getMaxCacheBlocks()
            );
            BufferPoolDirectory bufferPool = new BufferPoolDirectory(
                path,
                FSLockFactory.getDefault(),
                provider,
                keyResolver,
                pool.getSegmentPool(),
                directoryCache,
                loader,
                pool.getSharedReadaheadWorker(),
                metadataCache,
                pool.getFileChannelCache()
            );
            // As in production: small and metadata files go through NIO, the rest through the buffer pool.
            try (
                Directory dir = new HybridCryptoDirectory(
                    FSLockFactory.getDefault(),
                    bufferPool,
                    provider,
                    keyResolver,
                    metadataCache,
                    Set.of("si", "cfe", "fnm", "fdx", "fdt", "pos", "pay", "nvm", "dvm", "tvx", "tvd", "liv", "dii", "vem")
                )
            ) {
                writeIndex(dir);
                assertSnapshotMatches(path, dir);
            }
        } finally {
            CryptoDirectoryFactory
                .setNodeSettings(Settings.builder().put("node.store.crypto.write_cache_enabled", originalWriteCacheEnabled).build());
        }
    }

    private void writeIndex(Directory dir) throws IOException {
        IndexWriterConfig config = new IndexWriterConfig().setUseCompoundFile(randomBoolean());
        try (IndexWriter writer = new IndexWriter(dir, config)) {
            int docs = randomIntBetween(10, 200);
            for (int i = 0; i < docs; i++) {
                Document doc = new Document();
                doc.add(new StringField("id", Integer.toString(i), Field.Store.YES));
                doc.add(new TextField("body", randomAlphaOfLengthBetween(10, 500), Field.Store.YES));
                writer.addDocument(doc);
            }
            writer.commit();
        }
    }

    /** Reads the snapshot the way core does for a closed shard, and checks every checksum against the decrypted file. */
    private void assertSnapshotMatches(Path path, Directory encrypted) throws IOException {
        Store.MetadataSnapshot snapshot = Store
            .readMetadataSnapshot(path, SHARD_ID, (id, details, timeout) -> new DummyShardLock(id), logger);
        assertTrue("snapshot lists the committed files", snapshot.size() > 1);
        for (StoreFileMetadata file : snapshot) {
            try (IndexInput in = encrypted.openInput(file.name(), IOContext.READONCE)) {
                assertEquals(file.name(), Store.digestToString(CodecUtil.retrieveChecksum(in)), file.checksum());
            }
            if (file.name().startsWith("segments_") == false && file.name().endsWith(".si") == false) {
                // The raw file ends with the decrypted file's codec footer.
                byte[] raw = Files.readAllBytes(path.resolve(file.name()));
                byte[] footer = new byte[CodecUtil.footerLength()];
                try (IndexInput in = encrypted.openInput(file.name(), IOContext.READONCE)) {
                    in.seek(in.length() - footer.length);
                    in.readBytes(footer, 0, footer.length);
                }
                assertArrayEquals(file.name(), footer, Arrays.copyOfRange(raw, raw.length - footer.length, raw.length));
            }
        }
    }
}
