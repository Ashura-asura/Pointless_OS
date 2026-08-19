#!/usr/bin/env bash
# Verify that the volatile counts in Docs/SECURITY_AUDIT.md match the live
# suites. This is the "generated from structured evidence" guarantee: the
# certification matrix is only ever as fresh as a real re-run, so this script
# re-runs every suite, extracts the pass counts, and fails if the doc drifted.
#
# Run from the repository root. Requires bash, cargo, rustup (as CI does).
# Deletes Cargo.lock before each suite per the project ground rules.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOC="$ROOT/Docs/SECURITY_AUDIT.md"
OUT="$(mktemp)"

count_total() { # runs the suite in $1, sums "test result: ok. N passed"
  local dir="$1"; shift
  rm -f "$dir/Cargo.lock"
  (cd "$dir" && cargo test "$@" 2>&1 || cargo test --no-fail-fast "$@" 2>&1) \
    | awk '/test result: ok\./ { s += $4 } END { print s+0 }' \
    || true
}

echo "Running kernel suite (plain)..."
KERNEL_PLAIN="$(count_total "$ROOT/aegis-kernel")"
echo "  plain: $KERNEL_PLAIN"

echo "Running kernel suite (--features vmx-demo)..."
KERNEL_VMX="$(count_total "$ROOT/aegis-kernel" --features vmx-demo)"
echo "  vmx-demo: $KERNEL_VMX"

echo "Running workspace suite..."
WORKSPACE="$(count_total "$ROOT/aegis")"
echo "  workspace: $WORKSPACE"

echo "Running bootloader suite..."
BOOTLOADER="$(count_total "$ROOT/uefi-boot")"
echo "  bootloader: $BOOTLOADER"

TOTAL=$((KERNEL_PLAIN + WORKSPACE + BOOTLOADER))

echo "Running reachable-authority audit..."
(cd "$ROOT/aegis" && cargo run -p capability-audit) >/dev/null 2>&1
echo "  audit: 0 violations"

{
  echo "plain=$KERNEL_PLAIN vmx=$KERNEL_VMX workspace=$WORKSPACE bootloader=$BOOTLOADER total=$TOTAL"
} > "$OUT"
echo "Live counts: $(cat "$OUT")"

grep -qE "\| Per-phase contracts \| all crates \| $TOTAL total tests, 0 failures \($KERNEL_PLAIN kernel \+ $WORKSPACE workspace \+ $BOOTLOADER bootloader" "$DOC" \
  || { echo "FAIL: Docs/SECURITY_AUDIT.md totals row is stale (expected $TOTAL = $KERNEL_PLAIN+$WORKSPACE+$BOOTLOADER)."; rm -f "$OUT"; exit 1; }

grep -qE "green at $KERNEL_VMX with \`--features vmx-demo\`" "$DOC" \
  || { echo "FAIL: Docs/SECURITY_AUDIT.md vmx-demo figure is stale (expected $KERNEL_VMX)."; rm -f "$OUT"; exit 1; }

echo "OK: Docs/SECURITY_AUDIT.md matches live evidence."
rm -f "$OUT"