#!/usr/bin/env bash
# Prove the token never lands in argv (ps aux) during an API call.
set +e
export CFDNS_NO_BANNER=1 CFDNS_ROOT="$PWD/test/.root"
export CF_API_TOKEN="SUPERSECRET_CANARY_abcdefghijklmnopqrstuvwxyz01"
. test/lib/load.sh
load_modules "$PWD" core/http.sh
jq_set "$CFDNS_CONFIG" '.token_backend = "env"'

# snapshot every process cmdline repeatedly while an API call runs
( for i in $(seq 1 60); do cat /proc/*/cmdline 2>/dev/null | tr '\0' ' '; sleep 0.02; done > test/psdump.txt ) &
WATCH=$!
CFDNS_MAX_RETRY=0 cf_api GET "/user/tokens/verify" >/dev/null 2>&1 || true
wait $WATCH 2>/dev/null || true

if grep -q 'SUPERSECRET_CANARY' test/psdump.txt; then
  echo "FAIL: token leaked into process args"
  grep -o '.\{0,40\}SUPERSECRET_CANARY.\{0,20\}' test/psdump.txt | head -3
else
  echo "PASS: canary token never appeared in any process cmdline"
fi
echo "--- also check it never hit stdout/stderr of a normal invocation ---"
out="$(CFDNS_MAX_RETRY=0 cf_api GET "/user/tokens/verify" 2>&1 || true)"
grep -q 'SUPERSECRET_CANARY' <<<"$out" && echo "FAIL: leaked to output" || echo "PASS: not in output"
