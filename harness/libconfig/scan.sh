#!/usr/bin/env bash
# Run Clang Static Analyzer on libconfig.
#
# Output: build/scan-report/libconfig/<date>/index.html
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
SRC_DIR="$ROOT/targets/libconfig"
BUILD_DIR="$SRC_DIR/build-scan"
REPORT="$ROOT/build/scan-report/libconfig"

if [ ! -x "$LLVM_BIN/scan-build" ]; then
    echo "error: $LLVM_BIN/scan-build not found." >&2
    exit 1
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$REPORT"
cd "$BUILD_DIR"

"$LLVM_BIN/scan-build" \
    --use-cc="$LLVM_BIN/clang" \
    --use-c++="$LLVM_BIN/clang++" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_FUZZERS=OFF \
        -DBUILD_CXX=OFF

"$LLVM_BIN/scan-build" \
    --use-cc="$LLVM_BIN/clang" \
    --use-c++="$LLVM_BIN/clang++" \
    -o "$REPORT" \
    -v \
    cmake --build . --target config -j

echo
echo "report directory: $REPORT"
echo "open with: $LLVM_BIN/scan-view \"\$(ls -td $REPORT/*/ | head -1)\""
