#!/usr/bin/env bash
# Run Clang Static Analyzer (scan-build) on libexpat.
#
# Output: build/scan-report/libexpat/<date>/index.html
# Open with: scan-view <report-dir>   or just open the index.html
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
EXPAT="$ROOT/targets/libexpat/expat"
BUILD="$EXPAT/build-scan"
REPORT="$ROOT/build/scan-report/libexpat"

if [ ! -x "$LLVM_BIN/scan-build" ]; then
    echo "error: $LLVM_BIN/scan-build not found." >&2
    exit 1
fi

rm -rf "$BUILD"
mkdir -p "$BUILD" "$REPORT"

cd "$BUILD"

# Configure (debug build, no shared lib, no tests/examples/tools).
# We don't use any fuzz/sanitizer flags here — pure SA pass.
"$LLVM_BIN/scan-build" \
    --use-cc="$LLVM_BIN/clang" \
    --use-c++="$LLVM_BIN/clang++" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DEXPAT_SHARED_LIBS=OFF \
        -DEXPAT_BUILD_TESTS=OFF \
        -DEXPAT_BUILD_EXAMPLES=OFF \
        -DEXPAT_BUILD_TOOLS=OFF \
        -DEXPAT_BUILD_FUZZERS=OFF

# Run the analyzer wrapped around make. -o sets report output dir.
"$LLVM_BIN/scan-build" \
    --use-cc="$LLVM_BIN/clang" \
    --use-c++="$LLVM_BIN/clang++" \
    -o "$REPORT" \
    -v \
    make -j

echo
echo "report directory: $REPORT"
echo "open the latest report's index.html with your browser, or run:"
echo "  $LLVM_BIN/scan-view \"$(ls -td "$REPORT"/*/ 2>/dev/null | head -1)\""
