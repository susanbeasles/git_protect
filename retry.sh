#!/usr/bin/env bash
# Unit tests for lib/core/retry.sh. Pure: no network, no HTTP knowledge.
set +e
cd "$(dirname "$0")/.." || exit 1
export CFDNS_ROOT="/tmp/cfez-retry-$$"
. test/lib/load.sh
load_modules "$PWD" core/retry.sh
trap 'rm -rf "$CFDNS_ROOT"' EXIT

fail=0
t() { printf '  %-56s ' "$1"; }
eq() { t "$1"; if [ "$2" = "$3" ]; then echo PASS; else echo FAIL; echo "      want [$3] got [$2]"; fail=1; fi; }

# ---- backoff arithmetic
eq "attempt 1 waits 1s"                   "$(backoff_seconds 1)" "1"
eq "attempt 2 waits 2s"                   "$(backoff_seconds 2)" "2"
eq "attempt 3 waits 4s"                   "$(backoff_seconds 3)" "4"
eq "attempt 6 waits 32s"                  "$(backoff_seconds 6)" "32"
eq "growth is capped"                     "$(backoff_seconds 12)" "32"
eq "a server Retry-After wins"            "$(backoff_seconds 5 7)" "7"
eq "Retry-After of 0 is honoured"         "$(backoff_seconds 5 0)" "0"
eq "a non-numeric Retry-After is ignored" "$(backoff_seconds 3 soon)" "4"
eq "an empty Retry-After is ignored"      "$(backoff_seconds 3 '')" "4"

t "cap is configurable"
RETRY_CAP=4 && [ "$(backoff_seconds 9)" = 4 ] && echo PASS || { echo FAIL; fail=1; }
RETRY_CAP=32

t "jitter stays within 0..999"
bad=0
for _ in $(seq 1 40); do j="$(jitter_ms)"; [ "$j" -ge 0 ] && [ "$j" -le 999 ] || bad=1; done
[ "$bad" -eq 0 ] && echo PASS || { echo FAIL; fail=1; }

# ---- the loop
SCRATCH="$CFDNS_ROOT/scratch"; mkdir -p "$SCRATCH"
ATTEMPTS=0

# The attempt contract: write $scratch/body, optionally $scratch/status, return 0 on
# success. It communicates through files precisely so a subshell cannot swallow it.
succeed_on() {
  local scratch="$1"
  ATTEMPTS=$((ATTEMPTS + 1))
  printf 'body-%s' "$ATTEMPTS" > "$scratch/body"
  if [ "$ATTEMPTS" -ge "$SUCCEED_AT" ]; then printf '200' > "$scratch/status"; return 0; fi
  printf '429' > "$scratch/status"
  return 1
}
always_retry() { return 0; }
never_retry()  { return 1; }
body_of() { cat "$SCRATCH/body" 2>/dev/null; }

RETRY_MAX=6; RETRY_CAP=0
ATTEMPTS=0; SUCCEED_AT=1
with_retry "$SCRATCH" always_retry succeed_on; rc=$?
eq "succeeds on the first attempt"        "$rc:$ATTEMPTS:$(body_of)" "0:1:body-1"

ATTEMPTS=0; SUCCEED_AT=3
with_retry "$SCRATCH" always_retry succeed_on 2>/dev/null; rc=$?
eq "retries until success"                "$rc:$ATTEMPTS:$(body_of)" "0:3:body-3"

ATTEMPTS=0; SUCCEED_AT=99
with_retry "$SCRATCH" always_retry succeed_on 2>/dev/null; rc=$?
eq "stops after RETRY_MAX+1 attempts"     "$ATTEMPTS" "7"
t "and reports failure"
[ "$rc" -ne 0 ] && echo PASS || { echo FAIL; fail=1; }

ATTEMPTS=0; SUCCEED_AT=99
with_retry "$SCRATCH" never_retry succeed_on 2>/dev/null
eq "does not retry when told not to"      "$ATTEMPTS" "1"

# The property the file-based contract exists to guarantee: what the attempt recorded
# is readable by the decision function and by the caller, even though with_retry may
# itself be called from inside a command substitution.
ATTEMPTS=0; SUCCEED_AT=2
out="$(with_retry "$SCRATCH" always_retry succeed_on 2>/dev/null; cat "$SCRATCH/body")"
eq "the attempt's result survives a subshell" "$out" "body-2"
eq "the attempt's status survives a subshell" "$(cat "$SCRATCH/status")" "200"

t "each attempt starts from a clean slate"
ATTEMPTS=0; SUCCEED_AT=1
with_retry "$SCRATCH" always_retry succeed_on
[ ! -f "$SCRATCH/retry_after" ] || [ ! -s "$SCRATCH/retry_after" ] && echo PASS || { echo FAIL; fail=1; }

t "the caller owns the scratch directory, not with_retry"
[ -d "$SCRATCH" ] && echo PASS || { echo FAIL; fail=1; }

printf '\n'
[ "$fail" -eq 0 ] && echo "RETRY TESTS PASS" || echo "RETRY TESTS FAILED"
exit "$fail"
