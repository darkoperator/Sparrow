#!/usr/bin/env bash
# Run `cargo test` with the given arguments, keep the full output in a log file, and print a short summary:
# total passed/failed, each failing test, and every panic with the lines that explain it.
#
#   scripts/test-summary.sh --workspace
#   scripts/test-summary.sh -p sparrow-core --test coverage
#
# It adds --no-fail-fast unless the arguments already choose (--fail-fast / --no-fail-fast), so one run
# reports every failing test binary instead of stopping at the first.
#
# Exit status is cargo's. The log path is printed last; read it when the summary is not enough.
set -uo pipefail

log_dir="${TMPDIR:-/tmp}/sparrow-test-logs"
mkdir -p "$log_dir"
log="$log_dir/cargo-test-$(date +%Y%m%dT%H%M%S)-$$.log"

args=("$@")
case " $* " in
  *" --fail-fast "* | *" --no-fail-fast "*) ;;
  *) args=(--no-fail-fast "${args[@]}") ;;
esac

CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}" cargo test "${args[@]}" >"$log" 2>&1
status=$?

passed=$(grep -Eo 'test result: [A-Za-z]+\. [0-9]+ passed' "$log" | grep -Eo '[0-9]+ passed' | awk '{s+=$1} END {print s+0}')
failed=$(grep -Eo '[0-9]+ failed' "$log" | awk '{s+=$1} END {print s+0}')

# Panics: the panic line plus the message lines that follow it (the message is what explains the failure).
if grep -q 'panicked at' "$log"; then
  echo "== panics"
  grep -A6 'panicked at' "$log" | grep -v '^note: run with `RUST_BACKTRACE' | head -200
fi

if grep -Eq '^test .* \.\.\. FAILED' "$log"; then
  echo "== failing tests"
  grep -E '^test .* \.\.\. FAILED' "$log" | sort -u
fi

if grep -Eq '^error(\[E[0-9]+\])?:' "$log"; then
  echo "== errors"
  grep -E -A4 '^error(\[E[0-9]+\])?:' "$log" | head -80
fi

echo "== cargo passed $passed failed $failed (exit $status)"
echo "== full log: $log"
exit "$status"
