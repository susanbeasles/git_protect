#!/usr/bin/env bash
# End-to-end tests against a mock Cloudflare API. Exercises every write path —
# add, rm, update, sync, restore — which unit tests with stubbed functions cannot.
set +e
SRC="$(cd "$(dirname "$0")/.." && pwd -P)"
WORK="/tmp/cfdns-int-$$"
export CFDNS_ROOT="$WORK/root"
export PORTFILE="$WORK/port"
export CFDNS_NO_BANNER=1
mkdir -p "$CFDNS_ROOT"

python3 "$SRC/test/mock_cf.py" &
MOCK=$!
trap 'kill $MOCK 2>/dev/null; rm -rf "$WORK"' EXIT

for _ in $(seq 1 60); do [ -s "$PORTFILE" ] && break; sleep 0.1; done
PORT="$(cat "$PORTFILE" 2>/dev/null)"
[ -n "$PORT" ] || { echo "INTEGRATION FAILED (mock did not start)"; exit 1; }

export CFDNS_API="http://127.0.0.1:$PORT/client/v4"
export CF_API_TOKEN="TESTTOKENabcdefghijklmnopqrstuvwxyz012345"
export CFDNS_ASSUME_YES=1
CF="$SRC/cf"
ZONE="example.test"

printf '{"token_backend":"env","zone":"%s"}' "$ZONE" > "$CFDNS_ROOT/config.json"
chmod 600 "$CFDNS_ROOT/config.json"

fail=0
t() { printf '  %-52s ' "$1"; }
yes_() { echo PASS; }
no_() { echo FAIL; fail=1; }
records() { "$CF" dns ls 2>/dev/null; }
count() { records | grep -c '^  [A-Z]' ; }

# ---------------------------------------------------------------- read path
t "auth status verifies against the API"
"$CF" auth status 2>&1 | grep -q 'token is active' && yes_ || no_

t "dns ls returns the seeded zone"
n="$(count)"; [ "$n" -ge 6 ] && yes_ || { no_; echo "      saw $n"; }

# ---------------------------------------------------------------- add
t "add creates a TXT record"
out="$("$CF" dns add --name spf-test --type TXT --content "v=spf1 -all" --ttl 300 2>&1)"
echo "$out" | grep -q 'applied' && records | grep -q 'spf-test' && yes_ || { no_; echo "$out" | tail -4; }

t "add requires --priority for MX"
out="$("$CF" dns add --name mx-test --type MX --content mx9.example.test 2>&1)"
echo "$out" | grep -q 'priority is required for MX' && yes_ || { no_; echo "$out" | tail -3; }

t "add accepts MX with --priority"
out="$("$CF" dns add --name mx-test --type MX --content mx9.example.test --priority 20 2>&1)"
echo "$out" | grep -q 'applied' && yes_ || { no_; echo "$out" | tail -4; }

t "add rejects --proxy on TXT (before hitting the API)"
out="$("$CF" dns add --name p-test --type TXT --content x --proxy true 2>&1)"
echo "$out" | grep -q 'only applies to' && yes_ || { no_; echo "$out" | tail -3; }

t "add rejects an out-of-range ttl"
out="$("$CF" dns add --name t-test --type TXT --content x --ttl 5 2>&1)"
echo "$out" | grep -q 'ttl must be' && yes_ || { no_; echo "$out" | tail -3; }

t "add blocks a record with +all (record-scope validation)"
out="$("$CF" dns add --name bad-spf --type TXT --content "v=spf1 +all" 2>&1)"
echo "$out" | grep -q 'SPF_PLUS_ALL' && yes_ || { no_; echo "$out" | tail -4; }

t "--force overrides record validation"
out="$("$CF" dns add --name bad-spf --type TXT --content "v=spf1 +all" --force 2>&1)"
echo "$out" | grep -q 'applied' && yes_ || { no_; echo "$out" | tail -4; }

t "add surfaces the API's duplicate error"
out="$("$CF" dns add --name spf-test --type TXT --content "v=spf1 -all" --ttl 300 2>&1)"
echo "$out" | grep -qiE 'already exists|create failed' && yes_ || { no_; echo "$out" | tail -4; }

t "add with a valid MX does NOT report missing zone SPF"
out="$("$CF" dns add --name mx2-test --type MX --content mx8.example.test --priority 5 2>&1)"
echo "$out" | grep -q 'MX_NO_SPF' && no_ || yes_

# ---------------------------------------------------------------- selection guards
t "rm with no selector is refused"
out="$("$CF" dns rm 2>&1)"
echo "$out" | grep -q 'refusing to match every record' && yes_ || no_

t "rm with --type alone is refused"
out="$("$CF" dns rm --type TXT 2>&1)"
echo "$out" | grep -q 'would match every TXT' && yes_ || no_

t "rm with a selector that matches nothing errors cleanly"
out="$("$CF" dns rm --name nope-nothing --type TXT 2>&1)"
echo "$out" | grep -q 'no records matched' && yes_ || no_

# ---------------------------------------------------------------- rm
t "rm deletes only the selected record"
before="$(count)"
out="$("$CF" dns rm --name spf-test --type TXT 2>&1)"
after="$(count)"
[ "$after" -eq $((before - 1)) ] && ! records | grep -q 'spf-test' && yes_ \
  || { no_; echo "      $before -> $after"; }

t "rm snapshots before deleting"
echo "$out" | grep -q 'snapshot written before any change' && yes_ || no_

t "rm can delete duplicates by name+type"
before="$(count)"
out="$("$CF" dns rm --name _dmarc --type TXT 2>&1)"
after="$(count)"
[ "$after" -eq $((before - 2)) ] && yes_ || { no_; echo "      $before -> $after"; }

# ---------------------------------------------------------------- update
t "update patches content in place"
out="$("$CF" dns update --name @ --type TXT --content 'v=spf1' \
        --set-content 'v=spf1 include:mailgun.org ~all' 2>&1)"
records | grep -q '~all' && yes_ || { no_; echo "$out" | tail -5; }

t "update preserves the record id (patch, not delete+create)"
id_before="$("$CF" dns ls --name www --type A 2>/dev/null >/dev/null; \
             curl -sS -H "Authorization: Bearer $CF_API_TOKEN" \
             "$CFDNS_API/zones/zone0000000000000000000000000001/dns_records" \
             | jq -r '.result[] | select(.name|startswith("www")) | .id')"
"$CF" dns update --name www --type A --comment "touched" >/dev/null 2>&1
id_after="$(curl -sS -H "Authorization: Bearer $CF_API_TOKEN" \
            "$CFDNS_API/zones/zone0000000000000000000000000001/dns_records" \
            | jq -r '.result[] | select(.name|startswith("www")) | .id')"
[ -n "$id_before" ] && [ "$id_before" = "$id_after" ] && yes_ \
  || { no_; echo "      $id_before -> $id_after"; }

t "update with no fields errors"
out="$("$CF" dns update --name www --type A 2>&1)"
echo "$out" | grep -q 'nothing to change' && yes_ || no_

t "update is a no-op when values already match"
out="$("$CF" dns update --name www --type A --comment "touched" 2>&1)"
echo "$out" | grep -q 'already have those values' && yes_ || { no_; echo "$out" | tail -3; }

t "update validates the RESULT of the patch"
out="$("$CF" dns update --name @ --type TXT --content 'v=spf1' --set-content 'v=spf1 +all' 2>&1)"
echo "$out" | grep -q 'SPF_PLUS_ALL' && yes_ || { no_; echo "$out" | tail -4; }

t "update rejects --proxy on a TXT record"
out="$("$CF" dns update --name @ --type TXT --content 'v=spf1' --proxy true 2>&1)"
echo "$out" | grep -qiE 'does not apply to|proxied is not valid|only applies to' && yes_ || { no_; echo "$out" | tail -3; }

# ---------------------------------------------------------------- sync
t "sync --pull writes a desired-state file"
cd "$WORK" || exit 1
mkdir -p config
out="$("$CF" dns sync --pull 2>&1)"
[ -f config/masterDNS.json ] && jq -e '.records | length > 0' config/masterDNS.json >/dev/null \
  && yes_ || { no_; echo "$out" | tail -3; }

t "sync right after pull is a no-op"
out="$("$CF" dns sync 2>&1)"
echo "$out" | grep -q 'already matches' && yes_ || { no_; echo "$out" | tail -6; }

t "sync is dry-run by default"
jq '.records += [{"name":"synced","type":"TXT","content":"hello","ttl":300}]' \
  config/masterDNS.json > tmp.json && mv tmp.json config/masterDNS.json
out="$("$CF" dns sync 2>&1)"
echo "$out" | grep -q 'DRY RUN' && ! records | grep -q 'synced' && yes_ || { no_; echo "$out" | tail -4; }

t "sync --apply creates the new record"
out="$("$CF" dns sync --apply 2>&1)"
records | grep -q 'synced' && yes_ || { no_; echo "$out" | tail -6; }

t "sync deletes records absent from the file"
jq '.records |= map(select(.name != "synced"))' config/masterDNS.json > tmp.json \
  && mv tmp.json config/masterDNS.json
out="$("$CF" dns sync --apply 2>&1)"
records | grep -q 'synced' && { no_; echo "$out" | tail -4; } || yes_

t "sync metadata-only change is an UPDATE, never delete+create"
jq '.records |= map(if .name == "www.example.test" then .comment = "via sync" else . end)' \
  config/masterDNS.json > tmp.json && mv tmp.json config/masterDNS.json
out="$("$CF" dns sync 2>&1)"
echo "$out" | grep -q 'UPDATE' && ! (echo "$out" | grep -A3 DELETE | grep -q 'www') && yes_ \
  || { no_; echo "$out" | tail -8; }

t "sync rejects MX without priority in the file"
jq '.records += [{"name":"badmx","type":"MX","content":"m.example.test","ttl":300}]' \
  config/masterDNS.json > tmp.json && mv tmp.json config/masterDNS.json
out="$("$CF" dns sync 2>&1)"
echo "$out" | grep -q 'without a priority' && yes_ || { no_; echo "$out" | tail -3; }
jq '.records |= map(select(.name != "badmx"))' config/masterDNS.json > tmp.json \
  && mv tmp.json config/masterDNS.json

# ---------------------------------------------------------------- snapshots / restore
t "snapshots were written for every mutation"
# Snapshots live under a per-policy directory now, so count files not entries.
n="$(find "$CFDNS_ROOT/snapshots" -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' ')"
[ "$n" -ge 5 ] && yes_ || { no_; echo "      $n snapshots"; }

t "snapshot files are 0600"
bad="$(find "$CFDNS_ROOT/snapshots" -type f -not -perm 600 2>/dev/null)"
[ -z "$bad" ] && yes_ || { no_; echo "$bad"; }

t "restore from a snapshot round-trips the zone"
snap="$(find "$CFDNS_ROOT/snapshots" -type f -name '*.json' -print0 \
        | xargs -0 ls -1t 2>/dev/null | head -1)"
"$CF" dns add --name restore-probe --type TXT --content "temporary" --ttl 300 >/dev/null 2>&1
records | grep -q 'restore-probe' || { echo "SETUP FAILED"; }
out="$("$CF" dns restore --file "$snap" --apply 2>&1)"
records | grep -q 'restore-probe' && { no_; echo "$out" | tail -5; } || yes_

# ---------------------------------------------------------------- analysis
t "dns doctor runs against the live zone"
"$CF" dns sync --pull >/dev/null 2>&1
out="$("$CF" dns doctor --file config/masterDNS.json --format text 2>&1)"
echo "$out" | grep -qE 'analysis|findings|no findings' && yes_ || { no_; echo "$out" | tail -4; }

t "auth failure is reported clearly"
out="$(CF_API_TOKEN=wrongtokenwrongtokenwrongtokenwrongtok "$CF" dns ls 2>&1)"
echo "$out" | grep -qiE 'rejected the credential|Invalid API token' && yes_ || { no_; echo "$out" | tail -3; }

printf '\n'
[ "$fail" -eq 0 ] && echo "INTEGRATION TESTS PASS" || echo "INTEGRATION TESTS FAILED"
exit "$fail"
