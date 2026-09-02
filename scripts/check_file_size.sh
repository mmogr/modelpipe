#!/usr/bin/env bash
#
# Rust file-size gate: no source file over the budget.
#
# Usage: ./scripts/check_file_size.sh [--update]
#
# Adapted from gglib's check_rust_complexity.sh, with the one change its own
# header argues for. That script is a *ratchet* — files already over budget
# may shrink but not grow — and it says why: 175 files were over the line
# when it was written, so "a hard gate would fail on every commit and be
# switched off within a day, which is how a constraint becomes decorative."
#
# This workspace has no such debt. Every file is under budget today, so it
# can have the hard gate that one wanted, and a file crossing the line is a
# failure rather than a new baseline entry. The constraint that produces is
# not "write less" but "decompose by responsibility" — a file at the limit is
# telling you it holds more than one thing.
#
# --update writes a baseline recording the current over-budget files, and is
# the deliberate escape hatch for the case where a file legitimately has to
# grow. It is shipped, and the baseline is NOT committed: the hatch exists so
# that the first genuine 340-line state machine does not get the whole gate
# commented out, and using it creates a new tracked file in the diff — a
# reviewable event, rather than a silent edit to a list nobody reads.
#
# Tests do not count. A `*_tests.rs` sibling exists precisely so that a module
# can be thoroughly tested without its tests consuming the budget meant for
# its implementation; charging them against it would make the gate argue for
# fewer tests, which is the opposite of the point.

set -euo pipefail

BUDGET=300
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT_DIR/scripts/file-size-baseline.txt"

# Only our own sources. `target/` holds generated code nobody wrote, and
# `tests/` is integration-test code, exempt for the same reason `*_tests.rs`
# is.
current_sizes() {
  find "$ROOT_DIR/modelpipe/src" "$ROOT_DIR/modelpipe-cli/src" \
      -name "*.rs" -not -name "*_tests.rs" -not -path "*/target/*" \
      -exec wc -l {} + \
    | awk -v root="$ROOT_DIR/" '$2 != "total" { path = $2; sub(root, "", path); print path" "$1 }' \
    | LC_ALL=C sort
}

if [ "${1:-}" = "--update" ]; then
  current_sizes | awk -v b="$BUDGET" '$2 > b' > "$BASELINE"
  count=$(wc -l < "$BASELINE" | tr -d ' ')
  echo "✅ baseline written: $count file(s) recorded over ${BUDGET} lines"
  echo "   This file is deliberately untracked by default — committing it is"
  echo "   the reviewable act of accepting the growth."
  exit 0
fi

# A gate that scans nothing passes forever. gglib's
# check_param_source_exhaustive.sh matched zero lines for its entire life and
# reported success the whole time; the cheapest defence is to notice.
scanned=$(current_sizes | wc -l | tr -d ' ')
if [ "$scanned" -eq 0 ]; then
  echo "❌ scanned 0 files — the search paths are wrong, not the code" >&2
  exit 1
fi

echo "Checking Rust file sizes (budget ${BUDGET} lines, ${scanned} files)..."
echo "================================================"

failed=false
while read -r path loc; do
  [ -z "$path" ] && continue
  [ "$loc" -le "$BUDGET" ] && continue

  allowed=""
  if [ -f "$BASELINE" ]; then
    allowed=$(awk -v p="$path" '$1 == p {print $2}' "$BASELINE")
  fi

  if [ -z "$allowed" ]; then
    echo "❌ $path: $loc lines — over the ${BUDGET}-line budget"
    failed=true
  elif [ "$loc" -gt "$allowed" ]; then
    echo "❌ $path: $loc lines — grew from its recorded $allowed"
    failed=true
  fi
done < <(current_sizes)

echo ""
if [ "$failed" = true ]; then
  echo "❌ File-size gate failed."
  echo "   Decompose by responsibility: move a distinct concern to its own"
  echo "   module, or split tests into a \`*_tests.rs\` sibling (which this"
  echo "   gate does not count). If the growth is genuinely the right call,"
  echo "   run ./scripts/check_file_size.sh --update and commit the baseline"
  echo "   so the decision is visible in the diff."
  exit 1
fi

echo "✅ every file is within the ${BUDGET}-line budget"
exit 0
