#!/usr/bin/env bash
# Run the libexpat libFuzzer harness for 12 hours.
#
# Layout:
#   build/fuzz_xml                          - fuzzer binary
#   build/corpus/libexpat/                  - runtime corpus (writable)
#   build/findings/libexpat/                - crash artifacts
#   build/logs/libexpat/fuzz-<ts>.log       - per-run log
#   corpus/libexpat/seeds/                  - read-only seed corpus
#   harness/libexpat/xml.dict               - XML token dictionary
#
# Usage:
#   tmux new -s fuzz
#   ./harness/libexpat/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/build/fuzz_xml"
WORK="$ROOT/build/corpus/libexpat"
SEEDS="$ROOT/corpus/libexpat/seeds"
FINDINGS="$ROOT/build/findings/libexpat"
LOGDIR="$ROOT/build/logs/libexpat"
DICT="$ROOT/harness/libexpat/xml.dict"

if [ ! -x "$BIN" ]; then
    echo "error: $BIN not found. Run harness/libexpat/build.sh first." >&2
    exit 1
fi

mkdir -p "$WORK" "$FINDINGS" "$LOGDIR"
LOG="$LOGDIR/fuzz-$(date +%Y%m%d-%H%M%S).log"

echo "logging to: $LOG"
echo "corpus:     $WORK"
echo "seeds:      $SEEDS"
echo "findings:   $FINDINGS"
echo

# libFuzzer args:
#   first dir (WORK)  - writable working corpus
#   second dir (SEEDS) - read-only seed corpus
#   -max_total_time   - 12h in seconds
#   -max_len          - cap input size at 4 KiB
#   -dict             - XML token dictionary
#   -artifact_prefix  - where crash files land
#   -print_final_stats - dump summary on exit
#   -print_pcs=0      - quieter output
exec "$BIN" \
    -max_total_time=43200 \
    -max_len=4096 \
    -dict="$DICT" \
    -artifact_prefix="$FINDINGS/" \
    -print_final_stats=1 \
    "$WORK" "$SEEDS" 2>&1 | tee "$LOG"
