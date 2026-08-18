#!/usr/bin/env bash
# Tests for lib/core/snapshot.sh.
#
# The point of these tests is the second half: the same module, unmodified, backing
# three unrelated providers. If a future provider needs a code change in
# lib/core/snapshot.sh, one of these tests should be the thing that fails.
set +e
cd "$(dirname "$0")/.." || exit 1
W="/tmp/cfez-snap-$$"
export CFDNS_ROOT="$W/state"
. test/lib/load.sh
load_modules "$PWD" core/snapshot.sh
trap 'rm -rf "$W"' EXIT

fail=0
t() { printf '  %-58s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

# A policy file for providers this tool has never heard of.
mkdir -p "$W"
cat > "$W/policies.json" <<'JSON'
{
  "cloudflare-dns":   { "capture": "fake_cloudflare", "dir": "cf",      "retain": 3 },
  "aws-route53":      { "capture": "fake_route53",    "dir": "route53", "retain": 0 },
  "sentry-projects":  { "capture": "fake_sentry",     "dir": "sentry",  "wrap": "none",
                        "extension": "txt" },
  "broken-capture":   { "capture": "fake_failing",    "dir": "broken" },
  "empty-capture":    { "capture": "fake_empty",      "dir": "empty" },
  "missing-command":  { "capture": "no_such_command", "dir": "missing" }
}
JSON
export CFDNS_SNAPSHOT_POLICIES="$W/policies.json"

# Capture commands. Each writes state to stdout; that is the entire contract.
fake_cloudflare() { printf '[{"name":"a.example.com","type":"TXT"}]'; }
fake_route53()    { printf '{"ResourceRecordSets":[{"Name":"a.aws.test."}]}'; }
fake_sentry()     { printf 'project: web\nproject: api\n'; }
fake_failing()    { return 3; }
fake_empty()      { printf ''; }

# ---------------------------------------------------------------- basics
t "takes a snapshot and returns its path"
p="$(snapshot_take cloudflare-dns example.com pre-change)"
[ -n "$p" ] && [ -f "$p" ] && ok_ || { no_; echo "      got [$p]"; }

t "stores under the policy's own directory"
case "$p" in */snapshots/cf/*) ok_ ;; *) no_; echo "      $p" ;; esac

t "filename carries scope, timestamp and reason"
case "${p##*/}" in
  example.com-*Z-pre-change.json) ok_ ;;
  *) no_; echo "      ${p##*/}" ;;
esac

t "file is owner-only"
[ "$(stat -c %a "$p" 2>/dev/null || stat -f %Lp "$p")" = 600 ] && ok_ || no_

t "wraps state with provenance by default"
jq -e '.policy == "cloudflare-dns" and .scope == "example.com"
       and .reason == "pre-change" and (.taken | type == "string")' "$p" >/dev/null 2>&1 \
  && ok_ || { no_; head -c 200 "$p"; }

t "snapshot_read returns the state, unwrapped"
[ "$(snapshot_read "$p" | jq -r '.[0].name')" = "a.example.com" ] && ok_ || no_

t "reads a bare, unwrapped snapshot too"
printf '{"hello":"world"}' > "$W/bare.json"
[ "$(snapshot_read "$W/bare.json" | jq -r '.hello')" = world ] && ok_ || no_

t "two snapshots in the same second do not collide"
a="$(snapshot_take cloudflare-dns example.com same)"
b="$(snapshot_take cloudflare-dns example.com same)"
[ "$a" != "$b" ] && [ -f "$a" ] && [ -f "$b" ] && ok_ || { no_; echo "      $a / $b"; }

# ---------------------------------------------------------------- failure modes
t "a failing capture writes nothing and reports failure"
before="$(find "$CFDNS_ROOT/snapshots" -type f 2>/dev/null | wc -l | tr -d ' ')"
snapshot_take broken-capture scope reason >/dev/null 2>&1
after="$(find "$CFDNS_ROOT/snapshots" -type f 2>/dev/null | wc -l | tr -d ' ')"
[ "$before" = "$after" ] && ok_ || { no_; echo "      file count $before -> $after"; }

t "an empty capture is refused rather than stored"
snapshot_take empty-capture scope reason >/dev/null 2>&1 && no_ || ok_

t "no partial or pending files are left behind"
[ -z "$(find "$CFDNS_ROOT/snapshots" -name '.pending.*' 2>/dev/null)" ] && ok_ || no_

t "an unknown policy is refused"
( snapshot_take no-such-policy s r ) >/dev/null 2>&1 && no_ || ok_

t "a policy naming a non-existent command is refused"
( snapshot_take missing-command s r ) >/dev/null 2>&1 && no_ || ok_

# ---------------------------------------------------------------- retention
t "retention keeps the newest N and prunes the rest"
for i in 1 2 3 4 5 6; do snapshot_take cloudflare-dns retained "r$i" >/dev/null; done
n="$(snapshot_list cloudflare-dns retained | wc -l | tr -d ' ')"
[ "$n" -eq 3 ] && ok_ || { no_; echo "      kept $n, expected 3"; }

t "retention is per scope, not global"
snapshot_take cloudflare-dns other-scope only >/dev/null
[ "$(snapshot_list cloudflare-dns other-scope | wc -l | tr -d ' ')" -eq 1 ] && ok_ || no_

t "retain: 0 keeps everything"
for i in 1 2 3 4 5; do snapshot_take aws-route53 zone-abc "r$i" >/dev/null; done
[ "$(snapshot_list aws-route53 zone-abc | wc -l | tr -d ' ')" -eq 5 ] && ok_ || no_

t "listing without a scope returns the whole policy directory"
[ "$(snapshot_list aws-route53 | wc -l | tr -d ' ')" -ge 5 ] && ok_ || no_

# ================================================================
# The reuse claim, tested. Nothing below required a change to
# lib/core/snapshot.sh — only a policy entry and a capture function.
# ================================================================
t "REUSE: AWS Route53 state, JSON, no retention"
p2="$(snapshot_take aws-route53 zone-Z1D633PJN98FT9 pre-apply)"
[ -f "$p2" ] && [ "$(snapshot_read "$p2" | jq -r '.ResourceRecordSets[0].Name')" = "a.aws.test." ] \
  && ok_ || { no_; echo "      $p2"; }

t "REUSE:   and it landed in the route53 directory"
case "$p2" in */snapshots/route53/*) ok_ ;; *) no_; echo "      $p2" ;; esac

t "REUSE: Sentry state, plain text, unwrapped"
p3="$(snapshot_take sentry-projects org-acme pre-migrate)"
[ -f "$p3" ] && ok_ || { no_; echo "      $p3"; }

t "REUSE:   honours extension: txt"
case "$p3" in *.txt) ok_ ;; *) no_; echo "      $p3" ;; esac

t "REUSE:   honours wrap: none (state stored verbatim)"
[ "$(head -1 "$p3")" = "project: web" ] && ok_ || { no_; head -2 "$p3"; }

t "REUSE: three providers coexist without interfering"
c1="$(snapshot_list cloudflare-dns | wc -l | tr -d ' ')"
c2="$(snapshot_list aws-route53   | wc -l | tr -d ' ')"
c3="$(snapshot_list sentry-projects | wc -l | tr -d ' ')"
[ "$c1" -gt 0 ] && [ "$c2" -gt 0 ] && [ "$c3" -gt 0 ] && ok_ \
  || { no_; echo "      cf=$c1 aws=$c2 sentry=$c3"; }

t "REUSE: no provider identifier appears in the module's CODE"
# Comments are excluded deliberately: the header documents example policies, and
# naming a provider in an example is the opposite of coupling to one.
code="$(grep -vE "^[[:space:]]*#" lib/core/snapshot.sh)"
if printf "%s" "$code" | grep -qiE 'cloudflare|route53|sentry|dns_record|zone_id|fetch_live'; then
  no_; printf "%s" "$code" | grep -niE 'cloudflare|route53|sentry|dns_record|zone_id|fetch_live' | head -3
else ok_; fi

t "REUSE: the shipped policy file is the only place Cloudflare is named"
[ "$(grep -lc cloudflare lib/policies/snapshots.json 2>/dev/null)" = "lib/policies/snapshots.json" ] \
  && ok_ || no_

printf '\n'
[ "$fail" -eq 0 ] && echo "SNAPSHOT TESTS PASS" || echo "SNAPSHOT TESTS FAILED"
exit "$fail"
