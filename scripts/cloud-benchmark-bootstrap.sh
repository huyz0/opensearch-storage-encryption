#!/usr/bin/env bash
# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0
#
# One-shot setup for a fresh Linux cloud VM (x86_64 or aarch64; Amazon Linux 2023, Ubuntu, Debian,
# RHEL-like): installs git, curl, python3 and a JDK 25 under ~/jdk-25, clones this repository and
# runs scripts/benchmark-cipher.sh. Usable as EC2 user data or a GCE startup script, or over SSH:
#
#   curl -sSfL https://raw.githubusercontent.com/huyz0/opensearch-storage-encryption/main/scripts/cloud-benchmark-bootstrap.sh | bash
#
# Environment:
#   REPO    git URL to clone   (default https://github.com/huyz0/opensearch-storage-encryption.git)
#   REF     branch or tag      (default main)
#   RUNS    passed through to benchmark-cipher.sh
#   WORKDIR where to work      (default $HOME)
set -euo pipefail

REPO=${REPO:-https://github.com/huyz0/opensearch-storage-encryption.git}
REF=${REF:-main}
WORKDIR=${WORKDIR:-$HOME}
cd "$WORKDIR"

SUDO=""
[[ $(id -u) -ne 0 ]] && SUDO=sudo
if command -v dnf >/dev/null; then
    $SUDO dnf install -y -q git tar gzip python3 openssl >/dev/null
elif command -v yum >/dev/null; then
    $SUDO yum install -y -q git tar gzip python3 openssl >/dev/null
elif command -v apt-get >/dev/null; then
    $SUDO apt-get update -qq && $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git curl python3 openssl >/dev/null
fi

case $(uname -m) in
    x86_64) JDK_ARCH=x64 ;;
    aarch64) JDK_ARCH=aarch64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
if [[ ! -x "$WORKDIR/jdk-25/bin/java" ]]; then
    mkdir -p "$WORKDIR/jdk-25"
    curl -sSfL "https://api.adoptium.net/v3/binary/latest/25/ga/linux/$JDK_ARCH/jdk/hotspot/normal/eclipse" \
        | tar xz -C "$WORKDIR/jdk-25" --strip-components=1
fi
export JAVA_HOME=$WORKDIR/jdk-25

if [[ ! -d opensearch-storage-encryption ]]; then
    git clone -q --depth 1 --branch "$REF" "$REPO" opensearch-storage-encryption
fi
cd opensearch-storage-encryption
scripts/benchmark-cipher.sh
echo "Copy the results back with, for example:"
echo "  scp -r <host>:$(pwd)/bench-results ."
