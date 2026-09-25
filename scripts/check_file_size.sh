#!/usr/bin/env bash
#
# Rust file-size gate: no source file over the budget of code lines.
#
# Usage: ./scripts/check_file_size.sh [--update | --self-test]
#
# The gate exists so that a file's logic can be read in one sitting. Prose
# is not logic, so a `//` comment or doc line does not spend the budget; how
# much prose a file carries is a question for review, not for this gate. A
# line counts unless it is blank or its first non-space characters are `//`,
# which covers `///` and `//!` docs as well as plain comments. A code line
# with a comment after it counts. The rule reads one line at a time and does
# not parse Rust, so it applies unchanged inside a `/* */` block or a
# multi-line string: there too a blank or `//`-led line is free and every
# other line counts like code.
#
# The rule is checked against a fixture of one-line cases before every run,
# so whichever awk runs the gate, on a CI runner or a laptop, is held to the
# same count. --self-test runs that check alone.
#
# Adapted from gglib's check_rust_complexity.sh, which is a *ratchet* —
# files already over budget may shrink but not grow — and says why: 175
# files were over the line when it was written, so "a hard gate would fail
# on every commit and be switched off within a day, which is how a
# constraint becomes decorative."
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

# Prints the number of code lines on stdin, by the rule in the header. A
# last line with no newline still counts, and no input prints 0.
count_code() {
  awk '
    /^[[:space:]]*$/    { next }
    /^[[:space:]]*\/\// { next }
                        { n++ }
    END                 { print n + 0 }
  '
}

# Each case is the count the rule must give one line, a space, then the
# line. Every case is checked on its own, so two wrong answers cannot cancel
# out, and then all of them together, which checks that the count adds up.
SELF_TEST_CASES=(
  $'0 '
  $'0     '
  $'0 \t'
  $'0 \r'
  $'0 //'
  $'0 // a comment'
  $'0 /// an outer doc'
  $'0 //! an inner doc'
  $'0     // an indented comment'
  $'0 \t// a tab-indented comment'
  $'1 fn f() {'
  $'1 }'
  $'1     let x = 1; // a comment after code'
  $'1     let url = "https://example.com/";'
  $'1         / 2;'
  $'1 /* a block comment */'
  $'1  * the middle of a block comment'
  $'1 #[doc = "an attribute doc"]'
)

self_test() {
  local entry expected line got total=0 all=() failed=false
  for entry in "${SELF_TEST_CASES[@]}"; do
    expected=${entry%% *}
    line=${entry#* }
    got=$(printf '%s\n' "$line" | count_code)
    if [ "$got" != "$expected" ]; then
      echo "❌ self-test: counted $got for the line '$line', want $expected" >&2
      failed=true
    fi
    total=$((total + expected))
    all+=("$line")
  done

  got=$(printf '%s\n' "${all[@]}" | count_code)
  if [ "$got" != "$total" ]; then
    echo "❌ self-test: counted $got for all the cases together, want $total" >&2
    failed=true
  fi
  got=$(printf 'fn f() {}' | count_code)
  if [ "$got" != 1 ]; then
    echo "❌ self-test: counted $got for a code line with no newline, want 1" >&2
    failed=true
  fi
  got=$(printf '' | count_code)
  if [ "$got" != 0 ]; then
    echo "❌ self-test: counted '$got' for no input, want 0" >&2
    failed=true
  fi

  if [ "$failed" = true ]; then
    echo "❌ the line-counting rule disagrees with its fixture; no file was checked" >&2
    return 1
  fi
  echo "✅ the line-counting rule passes its ${#SELF_TEST_CASES[@]}-case fixture"
}

# Only our own sources. `target/` holds generated code nobody wrote, and
# `tests/` is integration-test code, exempt for the same reason `*_tests.rs`
# is. A file that cannot be read fails the run: the `exit` is explicit
# because bash clears `set -e` inside the command substitution that counts
# the scanned files, and without it the loop would carry on and pass.
current_sizes() {
  find "$ROOT_DIR/modelpipe/src" "$ROOT_DIR/modelpipe-cli/src" \
      -name "*.rs" -not -name "*_tests.rs" -not -path "*/target/*" -print \
    | while IFS= read -r file; do
        loc=$(count_code < "$file") || exit 1
        echo "${file#"$ROOT_DIR/"} $loc"
      done \
    | LC_ALL=C sort
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

self_test

if [ "${1:-}" = "--update" ]; then
  current_sizes | awk -v b="$BUDGET" '$2 > b' > "$BASELINE"
  count=$(wc -l < "$BASELINE" | tr -d ' ')
  echo "✅ baseline written: $count file(s) recorded over ${BUDGET} code lines"
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

echo "Checking Rust file sizes (budget ${BUDGET} code lines, ${scanned} files)..."
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
    echo "❌ $path: $loc code lines — over the ${BUDGET}-code-line budget"
    failed=true
  elif [ "$loc" -gt "$allowed" ]; then
    echo "❌ $path: $loc code lines — grew from its recorded $allowed"
    failed=true
  fi
done < <(current_sizes)

echo ""
if [ "$failed" = true ]; then
  echo "❌ File-size gate failed."
  echo "   Decompose by responsibility: move a distinct concern to its own"
  echo "   module, or split tests into a \`*_tests.rs\` sibling (which this"
  echo "   gate does not count). Blank lines and lines that begin with //"
  echo "   (after any indent) are not counted, so deleting them does not"
  echo "   help. If the growth is genuinely the right call, run"
  echo "   ./scripts/check_file_size.sh --update and commit the baseline so"
  echo "   the decision is visible in the diff."
  exit 1
fi

echo "✅ every file is within the ${BUDGET}-code-line budget"
exit 0
