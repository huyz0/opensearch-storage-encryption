#!/usr/bin/env bash
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Measures the AES-GCM / AES-CTR cost of the plugin's encryption paths on this machine and compares
# crypto providers: the JDK's SunJCE with its hardware intrinsics on and off, Amazon Corretto Crypto
# Provider (AWS-LC, regular and FIPS builds), Bouncy Castle FIPS, and `openssl speed` as a native
# ceiling. It also reports which CPU crypto features the machine has. Run it on each instance type
# you care about (x86_64 and aarch64, AWS and GCP) and compare the summary tables. See README.md,
# "Hardware acceleration".
#
# Usage (from the repository root, with JDK 25 as JAVA_HOME or on PATH):
#   scripts/benchmark-cipher.sh               # all providers (~8 minutes)
#   RUNS="sunjce accp" scripts/benchmark-cipher.sh   # a subset: sunjce sunjce-nohw accp accp-fips bcfips openssl
#   SKIP_BUILD=1 scripts/benchmark-cipher.sh  # reuse an existing build/distributions/*-jmh.jar
#
# Extra JMH arguments can be passed in JMH_ARGS, e.g. JMH_ARGS="-t 4" for four threads.
# Results land in bench-results/<instance>-<arch>-<timestamp>/.
set -euo pipefail

RUNS=${RUNS:-"sunjce sunjce-nohw accp accp-fips bcfips openssl"}
ACCP_VERSION=${ACCP_VERSION:-2.5.0}
BCFIPS_VERSION=${BCFIPS_VERSION:-2.1.3}
MAVEN=${MAVEN:-https://repo1.maven.org/maven2}

cd "$(dirname "$0")/.."

JAVA="${JAVA_HOME:+$JAVA_HOME/bin/}java"
if ! "$JAVA" -version 2>&1 | grep -qE 'version "(2[5-9]|[3-9][0-9])'; then
    echo "JDK 25 or newer is required (set JAVA_HOME). Found:" >&2
    "$JAVA" -version >&2 || true
    exit 1
fi

# ---- Where are we running? --------------------------------------------------------------------
ARCH=$(uname -m)
INSTANCE=unknown
CLOUD=unknown
# AWS IMDSv2
if TOKEN=$(curl -s -m 1 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null) && [[ -n "$TOKEN" ]]; then
    T=$(curl -s -m 1 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type || true)
    [[ "$T" =~ ^[a-z0-9-]+\.[a-z0-9]+$ ]] && INSTANCE=$T && CLOUD=aws
fi
# GCP metadata server
if [[ "$CLOUD" == unknown ]]; then
    T=$(curl -s -m 1 -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/machine-type 2>/dev/null || true)
    [[ "$T" =~ ^projects/.*/machineTypes/[a-z0-9-]+$ ]] && INSTANCE=${T##*/} && CLOUD=gcp
fi
OUT="bench-results/${INSTANCE}-${ARCH}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

if [[ "$ARCH" == x86_64 ]]; then
    WANT='aes|pclmulqdq|avx|avx2|avx512f|avx512vl|avx512bw|vaes|vpclmulqdq|sha_ni'
    ACCP_CLASSIFIER=linux-x86_64
else
    WANT='aes|pmull|sha1|sha2|sha3|sha512|sve|sve2|asimd'
    ACCP_CLASSIFIER=linux-aarch_64
fi
{
    echo "cloud:    $CLOUD"
    echo "instance: $INSTANCE"
    echo "arch:     $ARCH"
    echo "cpu:      $(lscpu 2>/dev/null | grep -E '^(Model name|Vendor ID)' | cut -d: -f2 | xargs)"
    echo "cpus:     $(nproc)"
    echo "crypto cpu flags: $(grep -m1 -E '^(flags|Features)' /proc/cpuinfo | cut -d: -f2 | tr ' ' '\n' | grep -xE "$WANT" | sort | xargs)"
    echo "java:     $("$JAVA" -version 2>&1 | grep -v JAVA_TOOL | head -1)"
    echo "jvm intrinsics:"
    "$JAVA" -XX:+UnlockDiagnosticVMOptions -XX:+PrintFlagsFinal -version 2>/dev/null \
        | grep -E ' (UseAES|UseAESIntrinsics|UseAESCTRIntrinsics|UseGHASHIntrinsics|UseAVX|UseSHA) ' \
        | awk '{print "  " $2 " = " $4}'
} | tee "$OUT/environment.txt"

# ---- Build and fetch providers ----------------------------------------------------------------
if [[ -z "${SKIP_BUILD:-}" ]]; then
    ./gradlew jmhJar -Dopensearch.version="${OPENSEARCH_VERSION:-3.6.0}" -Dbuild.snapshot=false --console=plain -q
fi
JAR=$(ls -t build/distributions/*-jmh.jar build/libs/*-jmh.jar 2>/dev/null | head -1 || true)
[[ -n "$JAR" ]] || { echo "No JMH jar under build/distributions; run ./gradlew jmhJar" >&2; exit 1; }

LIB=build/bench-providers
mkdir -p "$LIB"
fetch() { # fetch <maven path> <file>; drops the run from RUNS if the jar can't be downloaded
    [[ -s "$LIB/$2" ]] && return 0
    if ! curl -sSfL --retry 5 --retry-delay 10 -o "$LIB/$2.tmp" "$MAVEN/$1/$2"; then
        echo "Could not download $2; skipping run $r (put the jar in $LIB to retry)" >&2
        SKIPPED+=" $r"
        return 0
    fi
    mv "$LIB/$2.tmp" "$LIB/$2"
}
SKIPPED=""
ACCP_JAR=AmazonCorrettoCryptoProvider-$ACCP_VERSION-$ACCP_CLASSIFIER.jar
ACCP_FIPS_JAR=AmazonCorrettoCryptoProvider-FIPS-$ACCP_VERSION-$ACCP_CLASSIFIER.jar
BCFIPS_JAR=bc-fips-$BCFIPS_VERSION.jar
for r in $RUNS; do
    case $r in
        accp) fetch "software/amazon/cryptools/AmazonCorrettoCryptoProvider/$ACCP_VERSION" "$ACCP_JAR" ;;
        accp-fips) fetch "software/amazon/cryptools/AmazonCorrettoCryptoProvider-FIPS/$ACCP_VERSION" "$ACCP_FIPS_JAR" ;;
        bcfips) fetch "org/bouncycastle/bc-fips/$BCFIPS_VERSION" "$BCFIPS_JAR" ;;
    esac
done
KEEP=""
for r in $RUNS; do [[ " $SKIPPED " == *" $r "* ]] || KEEP+=" $r"; done
RUNS=$KEEP

# ---- Run -------------------------------------------------------------------------------------
NO_HW="-XX:+UnlockDiagnosticVMOptions -XX:-UseAESIntrinsics -XX:-UseAESCTRIntrinsics -XX:-UseGHASHIntrinsics"
jmh() { # jmh <run name> <extra class path or ""> <provider> <benchmark regex> [jvm args]
    local name=$1 cp=$2 provider=$3 pattern=$4 jvm=${5:-}
    echo "== $name =="
    local args=("$pattern" -p size=1024,8192 -p provider="$provider" -rf json -rff "$OUT/$name.json")
    [[ -n "$jvm" ]] && args+=(-jvmArgsAppend "$jvm")
    # shellcheck disable=SC2086
    "$JAVA" --enable-native-access=ALL-UNNAMED -cp "$JAR${cp:+:$cp}" org.openjdk.jmh.Main "${args[@]}" ${JMH_ARGS:-} \
        2>&1 | tee "$OUT/$name.txt" || echo "$name failed; see $OUT/$name.txt"
}
for r in $RUNS; do
    case $r in
        sunjce) jmh sunjce "" SunJCE 'CipherBenchmarks' ;;
        sunjce-nohw) jmh sunjce-nohw "" SunJCE 'CipherBenchmarks' "$NO_HW" ;;
        # ACCP has no AES/CTR, so only the GCM benchmarks run.
        accp) jmh accp "$LIB/$ACCP_JAR" AmazonCorrettoCryptoProvider 'CipherBenchmarks.gcm' ;;
        accp-fips) jmh accp-fips "$LIB/$ACCP_FIPS_JAR" AmazonCorrettoCryptoProvider 'CipherBenchmarks.gcm' ;;
        bcfips) jmh bcfips "$LIB/$BCFIPS_JAR" BCFIPS 'CipherBenchmarks' ;;
        openssl)
            if command -v openssl >/dev/null; then
                echo "== openssl =="
                { openssl version
                  for alg in aes-256-gcm aes-256-ctr; do
                      for bytes in 1024 8192; do
                          echo "$bytes $(openssl speed -elapsed -seconds 3 -bytes $bytes -evp $alg 2>/dev/null | tail -1)"
                      done
                  done; } | tee "$OUT/openssl.txt"
            fi ;;
        *) echo "unknown run $r" >&2 ;;
    esac
done

# ---- Summary ---------------------------------------------------------------------------------
if command -v python3 >/dev/null; then
    python3 - "$OUT" $RUNS <<'EOF' | tee "$OUT/summary.txt"
import json, os, re, sys
out, runs = sys.argv[1], [r for r in sys.argv[2:] if r != "openssl"]
results = {}
for run in runs:
    p = os.path.join(out, run + ".json")
    if not os.path.exists(p) or os.path.getsize(p) == 0:
        continue
    for b in json.load(open(p)):
        size = int(b["params"]["size"])
        key = (b["benchmark"].rsplit(".", 1)[1], size)
        results.setdefault(key, {})[run] = b["primaryMetric"]["score"] * size / 1e6
env = open(os.path.join(out, "environment.txt")).read().splitlines()
print(" | ".join(l.split(":", 1)[1].strip() for l in env[:5]))
print("MB/s (higher is better)")
cols = [r for r in runs if any(r in v for v in results.values())]
print(f"{'benchmark':<24}{'size':>6}" + "".join(f"{c:>13}" for c in cols))
for key in sorted(results):
    row = results[key]
    print(f"{key[0]:<24}{key[1]:>6}" + "".join(f"{row[c]:>13.0f}" if c in row else f"{'-':>13}" for c in cols))
p = os.path.join(out, "openssl.txt")
if os.path.exists(p):
    print("openssl speed (MB/s):")
    for line in open(p):
        m = re.match(r"(\d+) (AES-256-\w+)\s+([\d.]+)k", line.strip())
        if m:
            print(f"  {m.group(2):<12}{m.group(1):>6}{float(m.group(3)) / 1000:>8.0f}")
        elif line.startswith("OpenSSL"):
            print("  " + line.strip())
EOF
fi
echo "Results: $OUT"
