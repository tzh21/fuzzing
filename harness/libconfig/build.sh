#!/usr/bin/env bash
# Build the libconfig libFuzzer harness.
# Requires brew-installed llvm on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
SRC_DIR="$ROOT/targets/libconfig"
BUILD_DIR="$SRC_DIR/build-fuzz"
LIB="$BUILD_DIR/out/libconfig.a"
OUT="$ROOT/build/fuzz_config"

# Build instrumented static library if missing or stale.
if [ ! -f "$LIB" ] || [ "$(find "$SRC_DIR/lib" -name '*.c' -newer "$LIB" | head -1)" ]; then
    echo "==> building instrumented libconfig.a"
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. \
        -DCMAKE_C_COMPILER="$LLVM_BIN/clang" \
        -DCMAKE_C_FLAGS="-g -O1 -fsanitize=fuzzer-no-link,address" \
        -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=out \
        -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=out \
        -DCMAKE_RUNTIME_OUTPUT_DIRECTORY=out \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_CXX=OFF \
        >/dev/null
    cmake --build . -j --target config >/dev/null
    cd "$ROOT"
fi

if [ ! -f "$LIB" ]; then
    echo "error: $LIB not produced; check $BUILD_DIR for cmake errors" >&2
    exit 1
fi

mkdir -p "$ROOT/build"

echo "==> linking fuzz_config"
"$LLVM_BIN/clang" \
    -g -O1 \
    -fsanitize=fuzzer,address \
    -I "$SRC_DIR/lib" \
    "$ROOT/harness/libconfig/fuzz_config.c" \
    "$LIB" \
    -o "$OUT"

echo "built: $OUT"
