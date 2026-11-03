#!/usr/bin/env bash
# Builds the AWS-LC FIPS module (libcrypto) that the FIPS build of the plugin bundles and calls through the
# Foreign Function and Memory API.
#
# usage: scripts/build-aws-lc-fips.sh <output .so> [work dir]
#
# Builds the AWS-LC-FIPS-3.0.0 tag, the FIPS 140-3 validated release, for the host architecture with
# -DFIPS=1 as AWS-LC's crypto/fipsmodule/FIPS.md describes; the module's integrity check is computed at build
# time and verified every time the library loads. Needs git, cmake, ninja, Go, Perl and a C compiler (clang or gcc).
set -euo pipefail

TAG=AWS-LC-FIPS-3.0.0
COMMIT=190be0667cf1f7b39bed2c96760f08a6295b652b
REPO=${AWS_LC_REPO:-https://github.com/aws/aws-lc.git}

out=${1:?usage: $0 <output .so> [work dir]}
work=${2:-$(dirname "$out")/work}
mkdir -p "$work" "$(dirname "$out")"
out=$(cd "$(dirname "$out")" && pwd)/$(basename "$out")
work=$(cd "$work" && pwd)

for tool in git cmake ninja go perl; do
  command -v "$tool" >/dev/null || { echo "build-aws-lc-fips: $tool is required" >&2; exit 1; }
done

src=$work/src
if [ ! -d "$src/.git" ]; then
  rm -rf "$src"
  git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$src"
fi
actual=$(git -C "$src" rev-parse HEAD)
if [ "$actual" != "$COMMIT" ]; then
  echo "build-aws-lc-fips: $TAG is $actual, expected $COMMIT" >&2
  exit 1
fi

cmake -S "$src" -B "$work/build" -GNinja \
  -DFIPS=1 -DBUILD_SHARED_LIBS=1 -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF >"$work/cmake.log" 2>&1 \
  || { tail -40 "$work/cmake.log" >&2; exit 1; }
ninja -C "$work/build" crypto >"$work/ninja.log" 2>&1 || { tail -40 "$work/ninja.log" >&2; exit 1; }

cp "$work/build/crypto/libcrypto.so" "$out.tmp"
mv "$out.tmp" "$out"
echo "built $out from $TAG ($COMMIT)"
