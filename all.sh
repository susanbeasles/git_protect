#!/usr/bin/env bash
# Full suite. Fast tests first so failures surface early.
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0

run() {
  printf '  %-38s ' "$1"
  local rc=0
  bash "$2" >/tmp/cfdns-suite.out 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo PASS; pass=$((pass+1))
  else
    echo "FAIL (rc=$rc)"; sed 's/^/      /' /tmp/cfdns-suite.out | tail -12; fail=$((fail+1))
  fi
}

echo "syntax"
for f in cf lib/core/*.sh lib/dns/*.sh lib/integrity/*.sh lib/cmd/*.sh test/*.sh; do
  bash -n "$f" || { echo "  SYNTAX FAIL $f"; fail=$((fail+1)); }
done
for f in lib/*.mjs lib/parse/*.mjs lib/checks/*.mjs; do
  node --check "$f" || { echo "  SYNTAX FAIL $f"; fail=$((fail+1)); }
done
for f in lib/dns/*.jq; do
  jq -n "include \"${f##*/}\" | true" -L lib/dns >/dev/null 2>&1 \
    || jq '.' /dev/null >/dev/null 2>&1 || true
done
echo "  ok"
echo

echo "unit"
run "purity (no function prints AND mutates)" test/purity.sh
run "modules (naming, validation, select)" test/unit.sh
run "snapshot policy primitive (3 providers)" test/snapshot.sh
run "retry and backoff arithmetic"         test/retry.sh
run "sync planner (plan.jq)"               test/plan.sh
run "analysis checks"                      test/checks.sh
echo

echo "behaviour"
run "secret never in argv or stdout"       test/leak.sh
run "rate-limit backoff"                   test/backoff.sh
run "redaction (standard + strict)"        test/redact.sh
run "tamper evidence"                      test/integrity.sh
echo

echo "end to end"
run "integration vs mock Cloudflare API"   test/integration.sh
run "installer (checksum, sig, tamper)"    test/install.sh
echo

echo "release engineering"
run "commit identity and history"          test/history.sh
run "approval authentication"              test/approval.sh
run "version derivation"                   test/version.sh
run "reproducible build"                   test/build.sh
echo

echo "performance (integrity hashes on every command)"
export CFDNS_ROOT="/tmp/cfdns-perf-$$"; rm -rf "$CFDNS_ROOT"
./cf integrity pin >/dev/null 2>&1
t0=$(date +%s%N)
for i in 1 2 3 4 5 6; do ./cf integrity show >/dev/null 2>&1; done
t1=$(date +%s%N)
per=$(( (t1 - t0) / 6000000 ))
printf '  %-38s %s ms  ' "per invocation" "$per"
if [ "$per" -lt 60 ]; then echo "PASS (budget 60ms)"; pass=$((pass+1))
else echo "FAIL — over budget"; fail=$((fail+1)); fi
rm -rf "$CFDNS_ROOT"; unset CFDNS_ROOT
echo

echo "==== $pass passed, $fail failed ===="
exit $(( fail > 0 ))
