# Opensearch Storage Encryption

A high-performance OpenSearch plugin that provides transparent, on-the-fly encryption and decryption of index data at rest. This plugin implements encryption at the Lucene Directory level, offering a seamless integration that requires no changes to application code. Currently only supporting AWS KMS as master key provider but will allow other key providers as well in future versions.

## Features

The plugin provides transparent on-the-fly encryption and decryption at the Lucene Directory level. It offers two encrypted directory implementations: an NIO-based directory (`CryptoNIOFSDirectory`) and a buffer-pool directory (`BufferPoolDirectory`) that reads with O_DIRECT and keeps decrypted blocks in an off-heap cache. `HybridCryptoDirectory` routes each file to one of the two by extension. Both encrypt every file they write.

Performance is optimized through a Caffeine-based block cache, read-ahead prefetching for sequential access patterns, and pooled off-heap memory segments. Writes use AES-256-GCM through OpenSSL (called via the Panama foreign function API); reads use the JDK's AES-CTR.

Key management uses an envelope scheme: a data key per index is wrapped by a master key in the key provider (AWS KMS), each file gets its own key derived with HKDF, data keys are cached per node, and master key health is monitored. Translog files are also encrypted, with the known issues listed under [Limitations and known issues](#limitations-and-known-issues).

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
`DefaultKeyResolver` loads or creates the index data key: a 256-bit key generated by the key provider, stored wrapped by the master key in `indices/<index-uuid>/keyfile` on each node. Each node generates its own data key for its copy of the index. `NodeLevelKeyCache` caches unwrapped data keys on the node and refreshes them from the key provider, `ShardKeyResolverRegistry` shares one resolver per index and shard, and `MasterKeyHealthMonitor` watches master key availability and applies index blocks when it is lost. Per-file keys are derived from the data key with HKDF-SHA384 and a random 16-byte message ID stored in the file footer.

#### Encryption Engine
Index files are written with AES-256-GCM by `OpenSslNativeCipher` (OpenSSL through Panama) in 32 GiB frames. The per-frame GCM tags and an authenticated footer are appended to the file. Reads decrypt the same keystream with AES-CTR (`AesCipherFactory`) so they can start at any offset; the per-frame tags are not checked on read (see [Limitations and known issues](#limitations-and-known-issues)). `AesGcmCipherFactory` holds the GCM helpers used by the footer and the translog.

#### Memory Management
Efficient memory management is achieved through `MemorySegmentPool`, which provides pooling of off-heap memory segments. `RefCountedMemorySegment` ensures safe concurrent access through reference counting. The system supports configurable pool sizes and warmup strategies to optimize resource utilization.

#### I/O Optimization
`ReadaheadManager` prefetches blocks for sequential reads. `CryptoDirectIOBlockLoader` loads and decrypts blocks on a cache miss, and `DirectIOReaderUtil` opens files with O_DIRECT so reads bypass the OS page cache. Because of that, data that is not in the block cache is read from disk, not from the page cache.

## Requirements

- **JDK**: 25
- **OpenSearch**: 3.6.0 (the build targets `3.6.0-SNAPSHOT` by default)
- **Master Key Provider**: a key provider plugin, such as OpenSearch's `crypto-kms` plugin for AWS KMS
- **Operating System**: Linux on x86_64. OpenSSL's `libcrypto` must be in `/lib64` or `/lib`, which RHEL-family and Amazon Linux provide; Debian and Ubuntu keep it under `/usr/lib/<arch>-linux-gnu` and are not supported yet. Other platforms and ARM are not tested in CI.

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

The JCE provider for reads is fixed to `SunJCE`; there is no setting for it.

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
| `node.store.crypto.key_refresh_interval` | Interval for refreshing data keys from KMS | TimeValue | `-1` (never) or positive duration |
| `node.store.crypto.key_expiry_interval` | Expiration time for keys after refresh failures | TimeValue | `-1` (never) or positive duration |
| `node.store.crypto.allow_dummy_key_provider` | Allow indices to use the `dummy` key provider, which stores the data key in plaintext. **For tests only** | Boolean | `false` (default) or `true` |
| `node.store.crypto.write_cache_enabled` | Cache blocks in the block cache as they are written (dynamic) | Boolean | default `true` |
| `node.store.crypto.max_file_channels` | Maximum open file channels in the node-wide channel cache | Integer | default `256`, minimum `1` |
| `node.store.crypto.fd_cache_expire_after_access_seconds` | Close cached file channels not used for this long; `0` disables | Long | default `300` |

**Time Value Format:**
- Supported units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- Examples: `30s`, `5m`, `1h`, `24h`
- Special value: `-1` disables refresh/expiry

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

## Security Considerations

### Data Protection
- **Encryption at Rest**: Lucene files other than `segments_N` and `.si`, and translog operation data, are encrypted with AES-256. See [What is not encrypted](#what-is-not-encrypted).
- **Key Derivation**: one data key per index on each node; a separate key per file, derived from the data key with HKDF-SHA384 and a random 16-byte message ID
- **Integrity**: for Lucene files only the footer is authenticated. Lucene file contents are written with AES-GCM, but reads use AES-CTR and do not verify the GCM tags, so file contents are not protected against tampering. Lucene's own CRC32 checksums catch accidental corruption, not deliberate changes.

### Key Management
- **Master Key**: held by the master key provider (for example AWS KMS) and never written to disk
- **Data Keys**: wrapped by the master key and stored in `indices/<index-uuid>/keyfile` on each node that holds a copy of the index
- **Key Health**: `MasterKeyHealthMonitor` refreshes data keys (default every hour) and applies read/write blocks to affected indices when the master key becomes unavailable
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

## Limitations and known issues

The plugin has no release yet and is not ready for production use. The items below are open issues with the current code, not design goals.

### Known security issues
- **Translog nonce reuse.** Every translog chunk of a shard is encrypted with the same AES-GCM key and nonce. Anyone who can read the translog files can recover the XOR of two document sources and forge translog content. Treat translog contents as unprotected against disk access until this is fixed (upstream [PR #181](https://github.com/opensearch-project/opensearch-storage-encryption/pull/181)).
- **Unauthenticated reads.** Lucene file contents are read with AES-CTR and the GCM tags are never checked. Someone with write access to the disk can flip chosen plaintext bits without detection.
- **`dummy` key provider.** It can be set on any index and stores the data key in plaintext next to the data. Restrict it with index templates or policy.
- **Footer not bound to its file.** The footer does not include the index, shard or file name, so swapping or rolling back whole files is not detected.

### Durability and availability
- The translog's last GCM tag is written only when the file is closed. After a crash or `kill -9`, up to 8 KB of acknowledged operations per translog generation cannot be decrypted, and realtime GET or `_update` of unrefreshed documents can fail. Keep at least one replica.
- The keyfile is written without fsync or an atomic rename. If a node crashes right after creating an index, its copy can become undecryptable.
- Segment replication and remote-store failover, promotion and restore do not work with encrypted indices.
- KMS encryption context is recomputed from repository settings each time a shard opens. Changing repositories can make an index unopenable.
- A revoked or unavailable master key is not enforced immediately: cached data keys keep working for up to `node.store.crypto.key_expiry_interval` (default 24 hours).

### What is not encrypted
- `segments_N`, `pending_segments_N` and `.si` files, kept plaintext on purpose because core's `Store` opens them with a plain `NIOFSDirectory`; also `write.lock`
- Translog `.ckp` files and translog headers
- Index metadata under `_state` (mappings and settings, including the KMS key ARN) and cluster state
- The encryption footer of each file (message ID, frame size, GCM tags)
- Snapshots, remote-store segments and remote translog: uploaded as plaintext, so use repository-side encryption such as S3 SSE-KMS
- Peer recovery and replication traffic: plaintext over the transport layer, so enable TLS
- Searchable-snapshot file cache
- The off-heap block cache, which holds decrypted blocks and is not wiped on eviction

### Platform and features
- Only AWS KMS is supported as a master key provider
- Linux x86_64 with `libcrypto` in `/lib64` or `/lib` only (see [Requirements](#requirements))
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
