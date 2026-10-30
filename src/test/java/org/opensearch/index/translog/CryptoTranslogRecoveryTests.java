/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.common.UUIDs;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.BigArrays;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.seqno.SequenceNumbers;
import org.opensearch.index.store.key.KeyResolver;
import org.opensearch.test.IndexSettingsModule;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Encrypted translog files through core's own writer, reader and recovery: roll generations,
 * close, reopen and recover every operation, then keep writing after recovery.
 */
public class CryptoTranslogRecoveryTests extends OpenSearchTestCase {

    private final ShardId shardId = new ShardId("index", "_na_", 0);
    private KeyResolver keyResolver;
    private String uuid;
    private Path dir;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        byte[] raw = new byte[32];
        random().nextBytes(raw);
        keyResolver = mock(KeyResolver.class);
        when(keyResolver.getDataKey()).thenReturn(new SecretKeySpec(raw, "AES"));
        uuid = UUIDs.randomBase64UUID();
        dir = createTempDir();
        Translog.createEmptyTranslog(dir, shardId, SequenceNumbers.NO_OPS_PERFORMED, 1L, uuid, new CryptoChannelFactory(keyResolver, uuid));
    }

    private LocalTranslog open() throws IOException {
        TranslogConfig config = new TranslogConfig(
            shardId,
            dir,
            IndexSettingsModule.newIndexSettings("index", Settings.EMPTY),
            BigArrays.NON_RECYCLING_INSTANCE,
            "",
            false
        );
        return new LocalTranslog(
            config,
            uuid,
            TranslogDeletionPolicies.createTranslogDeletionPolicy(),
            () -> SequenceNumbers.NO_OPS_PERFORMED,
            () -> 1L,
            seqNo -> {},
            TranslogOperationHelper.DEFAULT,
            new CryptoChannelFactory(keyResolver, uuid)
        );
    }

    private static void addOps(Translog translog, List<byte[]> sources) throws IOException {
        for (int i = randomIntBetween(1, 20); i > 0; i--) {
            byte[] source = randomByteArrayOfLength(randomIntBetween(1, 2_000));
            translog.add(new Translog.Index(Integer.toString(sources.size()), sources.size(), 1L, source));
            sources.add(source);
        }
    }

    private static void assertOps(Translog translog, List<byte[]> sources) throws IOException {
        try (Translog.Snapshot snapshot = translog.newSnapshot()) {
            int count = 0;
            Translog.Operation op;
            while ((op = snapshot.next()) != null) {
                Translog.Index index = (Translog.Index) op;
                assertArrayEquals(sources.get(Integer.parseInt(index.id())), BytesReference.toBytes(index.source()));
                count++;
            }
            assertEquals(sources.size(), count);
        }
    }

    public void testRollReopenAndRecover() throws IOException {
        List<byte[]> sources = new ArrayList<>();
        try (LocalTranslog translog = open()) {
            for (int g = randomIntBetween(1, 3); g > 0; g--) {
                addOps(translog, sources);
                translog.rollGeneration();
            }
            addOps(translog, sources); // left in the current generation
            translog.sync();
            assertOps(translog, sources);
        }

        try (LocalTranslog translog = open()) {
            assertOps(translog, sources);
            addOps(translog, sources);
            translog.sync();
        }

        try (LocalTranslog translog = open()) {
            assertOps(translog, sources);
        }

        // On disk: every generation with data is in the OST2 format and holds no operation source.
        int headerSize = new TranslogHeader(uuid, 1L).sizeInBytes();
        try (Stream<Path> files = Files.list(dir)) {
            for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".tlog")).toList()) {
                byte[] onDisk = Files.readAllBytes(file);
                if (onDisk.length > headerSize) {
                    assertEquals(
                        file.toString(),
                        CryptoFileChannelWrapper.MAGIC,
                        ByteBuffer.wrap(onDisk, headerSize, Integer.BYTES).getInt()
                    );
                    for (byte[] source : sources) {
                        if (source.length >= 16) {
                            assertEquals(file + " contains plaintext", -1, indexOf(onDisk, Arrays.copyOf(source, 16)));
                        }
                    }
                }
            }
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
