# Opensearch Storage Encryption

A high-performance OpenSearch plugin that provides transparent, on-the-fly encryption and decryption of index data at rest. This plugin implements encryption at the Lucene Directory level, offering a seamless integration that requires no changes to application code. Currently only supporting AWS KMS as master key provider but will allow other key providers as well in future versions.

## Features

The plugin provides transparent on-the-fly encryption and decryption at the Lucene Directory level. It offers two encrypted directory implementations: an NIO-based directory (`CryptoNIOFSDirectory`) and a buffer-pool directory (`BufferPoolDirectory`) that reads with O_DIRECT and keeps decrypted blocks in an off-heap cache. `HybridCryptoDirectory` routes each file to one of the two by extension. Both encrypt every file they write except `segments_N`, `pending_segments_N` and `.si`, which stay plaintext (see [What is not encrypted](#what-is-not-encrypted)).

Performance is optimized through a Caffeine-based block cache, read-ahead prefetching for sequential access patterns, and pooled off-heap memory segments. Index files are sealed with AES-256-GCM in 8 KiB chunks, and every read verifies the chunk's tag before returning data.

Key management uses an envelope scheme: a data key per index is wrapped by a master key in the key provider (AWS KMS), each file gets its own key derived with the NIST SP 800-108 KDF, data keys are cached per node, and master key health is monitored. Translog files are also encrypted, with the known issues listed under [Limitations and known issues](#limitations-and-known-issues).

Built-in monitoring and comprehensive metrics provide visibility into plugin operations and performance characteristics.

## Architecture

```
┌──────────────┐
│  Tenant A    │
│ (plain text) │────────┐
└──────────────┘        │
                        │
┌──────────────┐        │         ┌─────────────────────────────────────────┐
│  Tenant B    │        │         │       OpenSearch Node                   │
│ (encrypted)  │────────┼────────►│                                         │
└──────────────┘        │         │  ┌────────────────────────────────┐     │
                        │         │  │   Query Processing Layer       │     │
                        └────────►│  │   (Lucene Directory API)       │     │
                                  │  └─────────────┬──────────────────┘     │
                                  │                │                        │
                                  │    ┌───────────┴──────────┐             │
                                  │    │                      │             │
                                  │    ▼                      ▼             │
                                  │  ┌──────────────┐   ┌──────────────┐    │
                                  │  │   Standard   │   │    Crypto    │    │
                                  │  │  Directory   │   │  Directory   │    │
                                  │  │              │   │      🔐      │    │
                                  │  └──────┬───────┘   └──────┬───────┘    │
                                  │         │                  │            │
                                  └─────────┼──────────────────┼────────────┘
                                            │                  │
                                            │                  │ Encrypt/Decrypt
                                            │                  │ ┌─────────────┐
                                            ▼                  ├─┤ Block Cache │
                                     ┌─────────────┐           │ └─────────────┘
                                     │   Disk      │           │
                                     │             │           ▼
                                     │ Plain Text  │    ┌─────────────┐
                                     │   Shards    │    │   Disk      │
                                     │  (Tenant A) │    │             │
                                     └─────────────┘    │ 🔒 Encrypted│
                                                        │   Shards    │
                                                        │  (Tenant B) │
                                                        └──────┬──────┘
                                                               │
                                                               │ Key Operations
                                                               ▼
                                                        ┌─────────────────────────┐
                                                        │   Master Key Provider   │
                                                        │        🔑 Master        │
                                                        │           Keys          │
                                                        └─────────────────────────┘

Legend:  🔐 Encryption Point    🔒 Encrypted Storage    🔑 Key Management
```

**Multi-Tenant Encryption:**
- **Tenant A**: Uses standard directory → data stored in plain text
- **Tenant B**: Uses crypto directory → data encrypted at rest
- Both tenants query using plain text → encryption is transparent

### Key Components

#### CryptoDirectory Layer
The plugin implements custom Lucene Directory implementations that intercept all file I/O operations. `CryptoNIOFSDirectory` provides NIO-based encrypted file access. `BufferPoolDirectory` reads with O_DIRECT, decrypts into pooled off-heap blocks and serves them from the block cache. `HybridCryptoDirectory` sends the extensions listed in `index.store.hybrid.nio.extensions` to `CryptoNIOFSDirectory` and everything else to `BufferPoolDirectory`; files on both sides are encrypted. The io_uring code under `experimentals/` is not used by any directory.

#### Block Cache
A node-wide cache built on Caffeine holds decrypted 8 KB blocks for `BufferPoolDirectory`, with a small per-file L1 cache in front of it. Its size is a fraction of the memory pool (see `node.store.crypto.cache_to_pool_ratio`). Cached blocks are plaintext in off-heap memory.

#### Key Management
`DefaultKeyResolver` loads or creates the index data key: a 256-bit key generated by the key provider, stored wrapped by the master key in `indices/<index-uuid>/keyfile` on each node. Each node generates its own data key for its copy of the index. `NodeLevelKeyCache` caches unwrapped data keys on the node and refreshes them from the key provider, `ShardKeyResolverRegistry` shares one resolver per index and shard, and `MasterKeyHealthMonitor` watches master key availability and applies index blocks when it is lost. Per-file keys are derived from the data key with the SP 800-108 counter-mode KDF (HMAC-SHA-384) and a random 16-byte message ID stored in the file footer.

#### Encryption Engine
Index files are sealed with AES-256-GCM by `ChunkCipher` in independent 8 KiB chunks, one chunk per block-cache block. A file is laid out as `[ciphertext][one 28-byte nonce + tag entry per chunk][footer][16-byte Lucene footer copy]`; the ciphertext is the same length as the plaintext, so offsets don't move. Each chunk's 12-byte GCM nonce is generated at random by the JCE provider that seals it (inside the FIPS module in FIPS mode, as FIPS 140-3 IG C.H requires), and the chunk index is authenticated as AAD, so a chunk moved to another position fails authentication. The footer holds the message ID and the plaintext length and is itself authenticated, so truncation is detected. The last 16 bytes repeat the plaintext's Lucene codec footer (zeros if it has none), so core code that reads a closed shard with a plain `NIOFSDirectory`, such as the store metadata listing the replica allocator uses after a restart, can read each file's checksum; the plugin's readers ignore these bytes. Both read paths (`CryptoBufferedIndexInput` for NIOFS and `CryptoDirectIOBlockLoader` for the buffer pool) read whole chunks with their tags and verify them before any plaintext is used; a chunk that fails is reported as `CorruptIndexException`.

Translog files keep core's header in plaintext, followed by a 4-byte magic, a random 16-byte nonce per file, and the operation data encrypted with offset-keyed AES-256-CTR under a per-file key derived with the SP 800-108 KDF from the index data key and that nonce (`CryptoFileChannelWrapper`, `TranslogCipher`). The magic is `OST3`; files in any other format are rejected. Any byte range can be decrypted on its own, so reads work while a generation is still being written and everything written before a crash stays readable. Each node has its own data key, so translog files are uploaded to the remote store decrypted; a downloaded file is encrypted under the local key the first time it is opened, so it sits on local disk in plaintext between the download and that open (normally the shard recovery that follows straight after).

#### Memory Management
Efficient memory management is achieved through `MemorySegmentPool`, which provides pooling of off-heap memory segments. `RefCountedMemorySegment` ensures safe concurrent access through reference counting. The system supports configurable pool sizes and warmup strategies to optimize resource utilization.

#### I/O Optimization
`ReadaheadManager` prefetches blocks for sequential reads. `CryptoDirectIOBlockLoader` loads and decrypts blocks on a cache miss, taking chunk tags from a node-wide cache of tag-table pages (`ChunkTagCache`, bounded to about 32 MiB of heap including per-entry overhead), so a miss whose tag page is cached needs one data read instead of two, and `DirectIOReaderUtil` opens files with O_DIRECT so reads bypass the OS page cache. Because of that, data that is not in the block cache is read from disk, not from the page cache.

## Requirements

- **JDK**: 25
- **OpenSearch**: 3.6.0 (the build targets `3.6.0-SNAPSHOT` by default)
- **Master Key Provider**: a key provider plugin, such as OpenSearch's `crypto-kms` plugin for AWS KMS
- **Operating System**: Linux on x86_64 or aarch64. Encryption uses the JDK's own AES-GCM, so no native crypto library is needed. CI runs on x86_64 only; aarch64 is not tested in CI. Other operating systems are not supported.

## Installation

### Build from Source

```bash
# Clone the repository
git clone https://github.com/opensearch-project/opensearch-storage-encryption.git
cd opensearch-storage-encryption

# Build the plugin
./gradlew clean assemble

# The plugin zip will be located at:
# build/distributions/storage-encryption.zip
```

### Install Plugin

```bash
# Install using opensearch-plugin command
cd /path/to/opensearch
bin/opensearch-plugin install file:///path/to/storage-encryption.zip
```

### Configure KMS

Add KMS configuration to `opensearch.yml`:

```yaml
kms.region: us-east-1
kms.key_arn: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012
```

Add AWS credentials to the keystore:

```bash
bin/opensearch-keystore create
echo "your-access-key" | bin/opensearch-keystore add -x kms.access_key
echo "your-secret-key" | bin/opensearch-keystore add -x kms.secret_key
echo "your-session-token" | bin/opensearch-keystore add -x kms.session_token
```

### FIPS 140-3 Mode

On an OpenSearch node running in FIPS mode (`OPENSEARCH_FIPS_MODE=true` on a FIPS distribution, which runs
Bouncy Castle FIPS in approved-only mode), the plugin uses only FIPS 140-3 validated modules. The FIPS build
bundles the AWS-LC FIPS 3.0.0 module (`libcrypto` built from AWS-LC's validated `AWS-LC-FIPS-3.0.0` release by
`scripts/build-aws-lc-fips.sh`) and calls it directly through Java's Foreign Function and Memory API for AES-GCM,
AES-CTR (translog), key derivation and random numbers (message IDs and translog nonces come from the module's
DRBG, with no JCE fallback). It has native code for both x86_64 and aarch64. Only the JCE self-tests use `BCFIPS`. If AWS-LC fails to load or fails its self-tests, the plugin refuses to
start; the default build, which bundles no native code, uses `BCFIPS` for everything in FIPS mode. The default build bundles no native code
and gets every algorithm from the JVM's provider order, as OpenSearch core does: no provider is named, so the
node's `java.security` decides. That is normally the JDK's `SunJCE`, and `BCFIPS` in FIPS mode, where OpenSearch
puts it first and removes `SunJCE`. If core or an operator changes the order, the plugin follows at the next node start: the choice for each
algorithm is pinned at startup, so a provider added while the node runs changes nothing. The node log says
what is in use:

```
storage encryption uses [AWS-LC FIPS 3.0.0 (.../plugins/storage-encryption/native/linux-x86_64/libawslc-fips-crypto.so)] for AES-GCM, AES-CTR, key derivation and random numbers; JCE providers from the JVM's order: AES-GCM [BCFIPS], AES-CTR [BCFIPS], HmacSHA384 [BCFIPS], SecureRandom [DEFAULT/BCFIPS] (FIPS mode: true, crypto.standard: FIPS-140-3)
```

In FIPS mode the default build relies on the first provider generating GCM nonces inside its own module, as
`BCFIPS` does (FIPS 140-3 IG C.H); the startup self-test checks that the cipher generated the nonce.

To get a plugin that only runs in FIPS mode, build it with OpenSearch's own FIPS build parameter:

```bash
./gradlew assemble -Pcrypto.standard=FIPS-140-3   # builds AWS-LC FIPS for the build host (needs cmake, ninja, Go, Perl, a C compiler)
./gradlew assemble -Pcrypto.standard=FIPS-140-3 -Paws_lc.libraries=<dir>   # <dir>/linux-<arch>/libawslc-fips-crypto.so, prebuilt
```

The first gives `storage-encryption-fips-linux-<arch>.zip` for the build host's architecture. The second bundles
every architecture found under `<dir>` into one `storage-encryption-fips.zip`; CI builds the libraries in
`almalinux:8` (glibc 2.28) so they load on any current Linux distribution. The library is loaded from the plugin's
own `native/` directory and kept private to the plugin (`RTLD_DEEPBIND`), so other plugins that bring their own
OpenSSL or AWS-LC do not interfere with it, and it registers no JCE provider.

That plugin refuses to start (when `plugins.crypto.enabled` is true) on a node that is not in approved-only
mode, instead of silently falling back to a non-validated provider. The same flag runs the unit, internal
cluster and YAML REST tests in FIPS mode. Run FIPS builds on an OpenJDK build such as Temurin: Oracle JDK
checks JCE provider signatures with an algorithm the FIPS provider list does not offer.

Per-file keys come from the NIST SP 800-108 counter-mode KDF with HMAC-SHA-384. In FIPS mode it runs inside the
validated module (AWS-LC, or Bouncy Castle FIPS as the fallback). AES-GCM nonces for index chunks and footers
are generated at random inside the module (AWS-LC's `EVP_aead_aes_256_gcm_randnonce`) and stored next to each tag
(FIPS 140-3 IG C.H). Not covered: the `dummy` key provider (test only) and key provider plugins such as
`crypto-kms` are outside this plugin's control.

## Usage

### Creating an Encrypted Index

```json
PUT /encrypted-index
{
  "settings": {
    "index.store.type": "cryptofs",
    "index.store.crypto.key_provider": "aws-kms",
    "index.store.crypto.kms.key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
}
```

### Index Template Example

```json
PUT /_index_template/encrypted_template
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "index.store.type": "cryptofs",
      "index.store.crypto.key_provider": "aws-kms",
      "index.store.crypto.kms.key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    }
  }
}
```

## Configuration Reference

### Index-Level Settings

Configure these when creating an index. Setting `index.store.type` to `"cryptofs"` enables encryption.

| Setting | Description | Type | Options/Range |
|---------|-------------|------|---------------|
| `index.store.type` | **Set to `"cryptofs"` to enable encryption** | String | `cryptofs` (for encryption) or standard types (`niofs`, `hybridfs`, `mmapfs`, `simplefs`) |
| `index.store.crypto.key_provider` | Key management provider type **(required when using cryptofs)** | String | `aws-kms`, or `dummy` for tests only. `dummy` stores the data key unencrypted next to the index and is rejected unless the node sets `node.store.crypto.allow_dummy_key_provider: true`; never use it for real data. |
| `index.store.crypto.kms.key_arn` | AWS KMS key ARN (master key) **(required when `key_provider` is `aws-kms`)** | String | Valid AWS KMS ARN format |
| `index.store.crypto.kms.encryption_context` | AWS KMS encryption context (optional) | String | Comma-separated `key=value` pairs, merged with any default context taken from the cluster's repository settings |

There is no setting for the JCE provider: the plugin uses the JVM's provider order (see FIPS 140-3 Mode above).

**How Encryption Works:**
- When you set `index.store.type: "cryptofs"`, the plugin automatically wraps the node's default store type with encryption
- The actual encrypted directory implementation used depends on the node's configuration:
  - `HYBRIDFS` (the default on 64-bit Linux) → `HybridCryptoDirectory` (`BufferPoolDirectory` plus `CryptoNIOFSDirectory` for the NIO extensions)
  - `MMAPFS` → `BufferPoolDirectory` (mmap of encrypted data is not supported)
  - `NIOFS`, `SIMPLEFS` → `CryptoNIOFSDirectory`
  - With `node.store.allow_mmap: false` the node default is `NIOFS`, so every encrypted index uses `CryptoNIOFSDirectory`

**Example:**
```json
{
  "settings": {
    "index.store.type": "cryptofs",
    "index.store.crypto.key_provider": "aws-kms",
    "index.store.crypto.kms.key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
    "index.store.crypto.kms.encryption_context": "project=myapp"
  }
}
```

### Node-Level Settings

Configure in `opensearch.yml`:

| Setting | Description | Type | Range |
|---------|-------------|------|-------|
| `node.store.crypto.pool_size_percentage` | Memory pool size as percentage of off-heap memory| Double | `0.0` - `1.0` |
| `node.store.crypto.cache_to_pool_ratio` | Cache size as ratio of pool size (cache = pool × ratio) | Double | `0.1` - `1.0` |
| `node.store.crypto.warmup_percentage` | Percentage of cache blocks to warmup at initialization | Double | `0.0` - `1.0` |
| `node.store.crypto.key_refresh_interval` | Interval for refreshing data keys from KMS | TimeValue | default `1h`, minimum `1s` |
| `node.store.crypto.key_expiry_interval` | Expiration time for keys after refresh failures | TimeValue | default `24h`; `-1` (never) or positive duration |
| `node.store.crypto.allow_dummy_key_provider` | Allow indices to use the `dummy` key provider, which stores the data key in plaintext. **For tests only** | Boolean | `false` (default) or `true` |
| `node.store.crypto.write_cache_enabled` | Cache blocks in the block cache as they are written (dynamic) | Boolean | default `true` |
| `node.store.crypto.max_file_channels` | Maximum open file channels in the node-wide channel cache | Integer | default `256`, minimum `1` |
| `node.store.crypto.fd_cache_expire_after_access_seconds` | Close cached file channels not used for this long; `0` disables | Long | default `300` |

**Time Value Format:**
- Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- Examples: `30s`, `5m`, `1h`, `24h`
- Special value: `-1` disables key expiry (`key_expiry_interval` only)

**Memory Configuration Notes:**
- Pool size is calculated as: `max(256 MB, (Total Physical Memory - Max Heap) × pool_size_percentage)`, default percentage `0.3`
- The pool is allocated outside the JVM's direct-memory accounting, so it does not show up in `MaxDirectMemorySize` or circuit breakers, and it does not shrink
- Cache size is calculated as: `Pool Size × cache_to_pool_ratio`

**Example Configuration:**
```yaml
# opensearch.yml
node.store.crypto.pool_size_percentage: 0.3
node.store.crypto.cache_to_pool_ratio: 0.75
node.store.crypto.warmup_percentage: 0.05
node.store.crypto.key_refresh_interval: 1h
node.store.crypto.key_expiry_interval: 24h
```

## Monitoring

### Metrics

The plugin reports metrics through OpenSearch's telemetry framework (enable a metrics exporter such as `telemetry-otel` to collect them). Every metric is per node.

| Metric | Type | Tags | What it shows |
| --- | --- | --- | --- |
| `crypto.error.total` | counter | `error_type` | Errors by type: `kms_key_error`, `kms_index_blocked`, `auth_failure`, `pool_exhausted`, `readahead_failure`, `index_input_error`, `index_output_error`, `directory_creation_error`, and segment refcount errors |
| `crypto.index.error.total` | counter | `error_type`, `index_name` | The same count for errors that affect one index (`kms_key_error`, `kms_index_blocked`, `auth_failure`), so you can see which index |
| `crypto.kms.blocked_indices` | gauge | none | Indices this node's key health monitor has blocked because their master key can't be loaded |
| `crypto.pool.segments.max`, `.allocated`, `.free` | gauge | none | Shared segment pool capacity, segments allocated, and allocated segments not in use |
| `crypto.cache.blocks` | gauge | none | Blocks in the shared block cache |
| `crypto.cache.hits`, `.misses`, `.evictions` | gauge | none | Running totals since the node started; graph their rate |
| `crypto.fd_cache.open` | gauge | none | Open file channels in the shared cache |
| `crypto.fd_cache.hits`, `.misses`, `.evictions` | gauge | none | Running totals since the node started; graph their rate |

`crypto.index.error.total` has one series per affected index. If your metrics backend bills or limits by series count, drop `crypto.index.*` in your collector; `crypto.error.total` and the WARN log carry the same events at node level.

Worth alerting on: any `auth_failure` (corruption, tampering or a wrong key), `crypto.kms.blocked_indices` above 0, and a sustained rate of `pool_exhausted`.

### Logs

The plugin never logs key material, IVs, file contents or KMS encryption context values. At the default level it logs startup configuration (crypto provider, FIPS mode, pool and cache sizes) and these warnings:

- `Can't load the master key for index [...]`: the first key provider failure of an episode, with what happens next and the root cause. It is logged again if the episode turns critical, and `Master key for index [...] loads again` is logged at INFO on recovery.
- `Applied write|read block to index ...`: the key health monitor blocked the index.
- `segment pool exhausted`, `Large readahead request`, `Readahead failed`: at most one per minute each, with a count of suppressed repeats.

Per-shard and per-block detail is at DEBUG (`logger.org.opensearch.index.store: debug`).

## Security Considerations

### Data Protection
- **Encryption at Rest**: Lucene files other than `segments_N` and `.si`, and translog operation data, are encrypted with AES-256. See [What is not encrypted](#what-is-not-encrypted).
- **Key Derivation**: one data key per index on each node; a separate key per file, derived from the data key with the SP 800-108 counter-mode KDF (HMAC-SHA-384) and a random 16-byte message ID
- **Integrity**: Lucene file contents are authenticated on every read (AES-GCM per 8 KiB chunk), and so is the footer, including the file length. Changed, reordered or removed chunks fail with `CorruptIndexException`. Whole files are not bound to their name or index (see below).

### Key Management
- **Master Key**: held by the master key provider (for example AWS KMS) and never written to disk
- **Data Keys**: wrapped by the master key and stored in `indices/<index-uuid>/keyfile` on each node that holds a copy of the index
- **Key Health**: `MasterKeyHealthMonitor` refreshes data keys (default every hour) and applies read/write blocks to affected indices when the master key becomes unavailable. It records the blocks it applied in `index.store.crypto.health_monitor_blocks` and removes only those on recovery, so shrink write blocks and operator-set blocks are left in place
- **Rotation**: data key rotation and re-encryption are not implemented

## Testing

Run the test suites:

```bash
# Unit tests
./gradlew test

# Integration tests
./gradlew internalClusterTest

# YAML REST tests
./gradlew yamlRestTest

# All tests
./gradlew allTests
```

## JMH Benchmarks

The project includes JMH microbenchmarks for measuring read throughput of the BufferPool (encrypted) directory vs MMap (plaintext) directory. Benchmark sources live under `src/jmh/java/org/opensearch/index/store/benchmark/`.

### Running Benchmarks

```bash
# Full run (defaults: 2 forks, 3 warmup iterations, 5 measurement iterations, 3s/5s durations)
./gradlew jmh

# Quick smoke test with overrides
./gradlew jmh -Pjmh.fork=1 -Pjmh.wi=1 -Pjmh.i=1 -Pjmh.w=1s -Pjmh.r=1s
```

All JMH parameters are overridable via `-P` flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-Pjmh.fork` | `2` | Number of forked JVM processes |
| `-Pjmh.wi` | `3` | Warmup iterations |
| `-Pjmh.i` | `5` | Measurement iterations |
| `-Pjmh.w` | `3s` | Warmup iteration duration |
| `-Pjmh.r` | `5s` | Measurement iteration duration |

Results are written to:
- `build/reports/jmh/human.txt` — human-readable output
- `build/reports/jmh/results.json` — JSON format for tooling

### Regenerating JMH Harness Classes

After adding, removing, or renaming any `@Benchmark` method, regenerate the JMH harness:

```bash
./gradlew jmhPrepare
```

### Running Benchmarks from Fat JAR

You can also build a self-contained fat JAR and run benchmarks directly:

```bash
# Build the fat JAR
./gradlew jmhJar

# List all available benchmarks
java --enable-preview --enable-native-access=ALL-UNNAMED \
  -jar build/distributions/storage-encryption-jmh.jar -l

# Run a specific benchmark with custom settings
java --enable-preview --enable-native-access=ALL-UNNAMED \
  -jar build/distributions/storage-encryption-jmh.jar RadixBlockTable -wi 2 -i 3 -f 1

# Run all benchmarks
java --enable-preview --enable-native-access=ALL-UNNAMED \
  -jar build/distributions/storage-encryption-jmh.jar
```

### Benchmark Classes

- `HotPathReadBenchmarks` — 16 benchmark methods measuring throughput with data pre-warmed in block cache (BufferPool) or page cache (MMap). Covers all `RandomAccessInput` and `IndexInput` read APIs plus a mixed workload that randomly interleaves all API types.
- `RadixBlockTableBenchmark` — 7 benchmark methods comparing L1/L2 cache lookup strategies: RadixBlockTable (two plain array loads), CaffeineBlockCache (ConcurrentHashMap), and stamp-gated cache (VarHandle acquire/release). Includes L1+L2 fallback paths and sparse directory growth scenarios.
- `CipherBenchmarks` — raw AES-GCM seal/open of one chunk and AES-CTR over a translog write, with no I/O. Compares the buffer shapes the read paths use (native, heap, one array) and takes a `provider` parameter, so the same benchmarks can run against SunJCE, Amazon Corretto Crypto Provider or Bouncy Castle FIPS.

### Filtering Benchmarks

Use `-Pjmh.includes` to run a specific benchmark method (regex match):

```bash
# Run only the sequential readByte benchmark
./gradlew jmh -Pjmh.includes='sequentialReadBytesFromClone'

# Run all random read benchmarks
./gradlew jmh -Pjmh.includes='randomRead.*'
```

### Key Parameters

| Parameter | Values | Description |
|-----------|--------|-------------|
| `directoryType` | `bufferpool`, `mmap`, `multisegment_mmap_impl` | `bufferpool`: encrypted block cache + direct I/O; `mmap`: single contiguous mmap (Lucene default); `multisegment_mmap_impl`: mmap chunked at `CACHE_BLOCK_SIZE` boundaries |
| `fileSizeMB` | `32` | Size of each test file in MB |
| `threadCount` | `8` | Number of concurrent reader threads per benchmark invocation |
| `numFilesToRead` | `1` | Number of files read per invocation |

> **Note:** The `@Warmup`, `@Measurement`, and `@Fork` annotations in `HotPathReadBenchmarks` take precedence over `-Pjmh.*` command-line flags. To override them, edit the annotation values directly in the source.

### Hardware acceleration

With the JDK's default provider order, encryption uses SunJCE's AES-GCM and AES-CTR. HotSpot compiles both to CPU crypto instructions: AES-NI and PCLMULQDQ on x86_64 (with wider VAES/VPCLMULQDQ paths on CPUs that have them), and the ARMv8 AES and PMULL instructions on aarch64. Nothing needs to be configured. They are on whenever the CPU reports those features, which the AWS and GCP instance types listed below all do, including Graviton and Axion. Without them AES-GCM was about 70 times slower in our measurements, so check the JVM flags (`UseAESIntrinsics`, `UseAESCTRIntrinsics`, `UseGHASHIntrinsics`) if throughput looks wrong. A JVM option that turns them off is the usual culprit.

`scripts/benchmark-cipher.sh` measures all of this on the machine it runs on. It prints the CPU's crypto features and the JVM's intrinsic flags, then runs `CipherBenchmarks` with each provider: SunJCE with intrinsics, SunJCE without them, Amazon Corretto Crypto Provider (AWS-LC; regular and FIPS builds) and Bouncy Castle FIPS. It also runs `openssl speed` as a native ceiling. The provider jars are fetched from Maven Central into `build/bench-providers`. Results and a summary table go to `bench-results/<instance>-<arch>-<time>/`.

```bash
JAVA_HOME=/path/to/jdk-25 scripts/benchmark-cipher.sh
RUNS="sunjce accp" scripts/benchmark-cipher.sh     # subset: sunjce sunjce-nohw accp accp-fips bcfips openssl
```

On a fresh cloud VM, `scripts/cloud-benchmark-bootstrap.sh` installs a JDK 25, clones the repository and runs the script. It works as EC2 user data, a GCE startup script, or over SSH. Instance types worth comparing, at 4 vCPUs each:

| Cloud | x86_64 | aarch64 |
|-------|--------|---------|
| AWS | `c7i.xlarge` (Intel Sapphire Rapids, VAES), `c7a.xlarge` (AMD Zen 4, VAES), `c5.xlarge` (Intel Skylake/Cascade Lake, AES-NI only) | `c6g.xlarge` (Graviton2), `c7g.xlarge` (Graviton3), `c8g.xlarge` (Graviton4) |
| GCP | `c3-standard-4` (Sapphire Rapids), `c3d-standard-4` (AMD Zen 4), `n2-standard-4` (Cascade Lake or Ice Lake) | `c4a-standard-4` (Axion), `t2a-standard-4` (Ampere Altra) |

Use a dedicated (non-burstable) instance and run each one twice; shared hosts vary by 20% or more between runs.

## Limitations and known issues

The plugin has no release yet and is not ready for production use. The items below are open issues with the current code, not design goals.

### Known security issues
- **Translog integrity.** Translog data is not authenticated yet. It is encrypted with AES-CTR, which hides its contents; core's per-operation checksums catch accidental corruption, not deliberate changes.
- **Footer not bound to its file.** The footer does not include the index, shard or file name, so swapping or rolling back whole files is not detected.

### Durability and availability
- KMS encryption context is recomputed from repository settings each time a shard opens. Changing repositories can make an index unopenable.
- A revoked or unavailable master key is not enforced immediately: cached data keys keep working for up to `node.store.crypto.key_expiry_interval` (default 24 hours).

### Upgrading
- The `dummy` key provider is now rejected unless `node.store.crypto.allow_dummy_key_provider: true` is set. Existing indices that use `dummy` will not open, and their shards stay unassigned (red), on nodes without that setting. Move that data to an index with a real key provider before upgrading, or set the flag on test clusters only.

### Known data-correctness bugs
None are known to be open. Fixed on `main`: translog nonce reuse (every chunk of every generation used the same AES-GCM nonce) and the translog tail tag that was written only on close, remote-store translog files that were uploaded decrypted but read back through the decrypting channel after download (which broke remote-store translog failover, promotion and restore), the L2 block cache lookup/recycle race that could return another block's plaintext, encrypted translog reads returning 0 instead of -1 at end of data, wrong plaintext for buffer-pool reads that cross a 32 GiB frame boundary, missing EOF and slice-bounds checks in `CachedMemorySegmentIndexInput` (reads past a compound-file slice returned neighbouring bytes), NIOFS input clones closing the shared file channel, a thread interrupt during a block read closing the shared file channel for other readers, the shared read-ahead worker being stopped when any one directory closed, cache misses stalling searches while waiting for a free block when the block pool is exhausted, and keyfiles written without fsync or atomic rename.

### What is not encrypted
- `segments_N`, `pending_segments_N` and `.si` files, kept plaintext on purpose because core's `Store` opens them with a plain `NIOFSDirectory`; also `write.lock`
- Translog `.ckp` files and translog headers
- Index metadata under `_state` (mappings and settings, including the KMS key ARN) and cluster state
- The encryption footer and tag table of each file (message ID, plaintext length, chunk size, GCM nonces and tags)
- The last 16 bytes of each Lucene file's plaintext (its codec footer: a fixed magic, the algorithm ID and the CRC32 checksum)
- Snapshots, remote-store segments and remote translog: uploaded as plaintext, so use repository-side encryption such as S3 SSE-KMS
- Peer recovery and replication traffic: plaintext over the transport layer, so enable TLS
- Searchable-snapshot file cache
- The off-heap block cache, which holds decrypted blocks and is not wiped on eviction

### Platform and features
- Only AWS KMS is supported as a master key provider
- Linux only, x86_64 or aarch64 (see [Requirements](#requirements)); aarch64 is not covered by CI
- No key rotation or re-encryption
- Pinned timestamps (snapshot v2) are not supported
- Reads through `BufferPoolDirectory` bypass the page cache, so indices larger than the block cache read from disk more often than with `mmapfs`

## Contributing

We welcome contributions! Please see our [Developer Guide](DEVELOPER_GUIDE.md) for detailed information on contributing.

## Documentation

- [Developer Guide](DEVELOPER_GUIDE.md) - Comprehensive guide for developers
- [Maintainers](MAINTAINERS.md) - Project maintainers

## License

This project is licensed under the Apache License 2.0. See [LICENSE.txt](src/LICENSE.txt) for details.

## Support

For issues, questions, or contributions:
- **Issues**: [GitHub Issues](https://github.com/opensearch-project/opensearch-storage-encryption/issues)
- **Discussions**: [OpenSearch Forums](https://forum.opensearch.org/)
- **Security**: Report vulnerabilities privately, following the [OpenSearch security policy](https://github.com/opensearch-project/.github/blob/main/SECURITY.md); do not open a public issue
