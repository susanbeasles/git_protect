#!/usr/bin/env bash
# Unit tests for the composable modules: naming, field validation, selection,
# payload shaping, and the JSON store. Each module is loaded on its own so the
# tests also prove the dependency boundaries hold.
set +e
cd "$(dirname "$0")/.." || exit 1

export CFDNS_ROOT="/tmp/cfdns-unit-$$"
rm -rf "$CFDNS_ROOT"
CFDNS_LIB="$PWD/lib"

. test/lib/load.sh
load_modules "$PWD" dns/select.sh

fail=0
t() { printf '  %-54s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }
eq() { if [ "$2" = "$3" ]; then t "$1"; ok_; else t "$1"; no_; echo "      want [$3] got [$2]"; fi; }

zone_name() { printf 'example.com'; }

# ---------------------------------------------------------------- naming
eq "fqdn: bare label gets the zone appended" "$(fqdn www example.com)" "www.example.com"
eq "fqdn: @ means the apex"                  "$(fqdn @ example.com)"   "example.com"
eq "fqdn: empty means the apex"              "$(fqdn '' example.com)"  "example.com"
eq "fqdn: the zone itself is not doubled"    "$(fqdn example.com example.com)" "example.com"
eq "fqdn: an already-qualified name is left alone" "$(fqdn a.b.example.com example.com)" "a.b.example.com"
eq "fqdn: multi-label relative name"         "$(fqdn stg.mail example.com)" "stg.mail.example.com"
eq "fqdn: underscore names survive"          "$(fqdn _dmarc example.com)" "_dmarc.example.com"

eq "relative_name: inverse of fqdn"          "$(relative_name www.example.com example.com)" "www"
eq "relative_name: apex becomes @"           "$(relative_name example.com example.com)" "@"
eq "relative_name: multi-label"              "$(relative_name a.b.example.com example.com)" "a.b"
eq "relative_name: foreign name unchanged"   "$(relative_name other.org example.com)" "other.org"

# round trip
for n in www @ stg.mail _dmarc a.b.c; do
  r="$(relative_name "$(fqdn "$n" example.com)" example.com)"
  want="$n"; [ "$n" = "@" ] && want="@"
  [ "$r" = "$want" ] || { t "round trip $n"; no_; echo "      got [$r]"; }
done
t "fqdn/relative_name round-trip for all shapes"; ok_

# ---------------------------------------------------------------- type helpers
t "type_is matches a listed type"
type_is A "A AAAA CNAME" && ok_ || no_
t "type_is rejects an unlisted type"
type_is TXT "A AAAA CNAME" && no_ || ok_

# ---------------------------------------------------------------- field validation
try() { ( validate_fields "$@" ) >/dev/null 2>&1; }

t "validate: TXT with ttl 300 is accepted"
try TXT 300 "" "" && ok_ || no_
t "validate: ttl 1 (auto) is accepted"
try TXT 1 "" "" && ok_ || no_
t "validate: ttl 5 is rejected"
try TXT 5 "" "" && no_ || ok_
t "validate: ttl 999999 is rejected"
try TXT 999999 "" "" && no_ || ok_
t "validate: non-numeric ttl is rejected"
try TXT abc "" "" && no_ || ok_
t "validate: MX without priority is rejected"
try MX 300 "" "" && no_ || ok_
t "validate: MX with priority is accepted"
try MX 300 10 "" && ok_ || no_
t "validate: priority 70000 is rejected"
try MX 300 70000 "" && no_ || ok_
t "validate: negative priority is rejected"
try MX 300 -5 "" && no_ || ok_
t "validate: proxy on TXT is rejected"
try TXT 300 "" true && no_ || ok_
t "validate: proxy on A is accepted"
try A 300 "" true && ok_ || no_
t "validate: proxy=false on TXT is harmless"
try TXT 300 "" false && ok_ || no_
t "validate: non-boolean proxy is rejected"
try A 300 "" maybe && no_ || ok_
t "validate: lowercase type is rejected (dispatcher upcases)"
try txt 300 "" "" && no_ || ok_

# ---------------------------------------------------------------- payload shaping
body() { jq -c -L lib/dns 'include "api_body"; api_body' <<<"$1"; }

eq "api_body: TXT omits proxied and priority" \
  "$(body '{"name":"a","type":"TXT","content":"x","ttl":300}' | jq -c 'keys')" \
  '["comment","content","name","tags","ttl","type"]'
eq "api_body: A includes proxied" \
  "$(body '{"name":"a","type":"A","content":"1.2.3.4","ttl":1,"proxied":true}' | jq -r '.proxied')" \
  'true'
eq "api_body: MX includes priority" \
  "$(body '{"name":"a","type":"MX","content":"m","ttl":1,"priority":10}' | jq -r '.priority')" \
  '10'
eq "api_body: MX with null priority omits the key" \
  "$(body '{"name":"a","type":"MX","content":"m","ttl":1,"priority":null}' | jq -r 'has("priority")')" \
  'false'
eq "api_body: priority on TXT is dropped" \
  "$(body '{"name":"a","type":"TXT","content":"x","ttl":1,"priority":5}' | jq -r 'has("priority")')" \
  'false'
eq "api_body: tags are sorted for stable comparison" \
  "$(body '{"name":"a","type":"TXT","content":"x","ttl":1,"tags":["z","a"]}' | jq -c '.tags')" \
  '["a","z"]'

eq "unsupported_types: flags TXT and MX as unproxyable" \
  "$(echo '[{"type":"TXT"},{"type":"A"},{"type":"MX"}]' | jq -r -L lib/dns 'include "api_body"; unsupported_types(proxyable)')" \
  'MX, TXT'
eq "unsupported_types: empty when all are proxyable" \
  "$(echo '[{"type":"A"},{"type":"CNAME"}]' | jq -r -L lib/dns 'include "api_body"; unsupported_types(proxyable)')" \
  ''

# ---------------------------------------------------------------- selection guard
guard() { ( require_selector ) >/dev/null 2>&1; }

t "selector: nothing set is refused"
( unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_TAGS SEL_ID; guard ) && no_ || ok_
t "selector: --type alone is refused"
( SEL_TYPE=TXT; unset SEL_NAME SEL_CONTENT SEL_TAGS SEL_ID; guard ) && no_ || ok_
t "selector: --name alone is allowed"
( SEL_NAME=www; unset SEL_TYPE SEL_CONTENT SEL_TAGS SEL_ID; guard ) && ok_ || no_
t "selector: --name plus --type is allowed"
( SEL_NAME=www SEL_TYPE=A; unset SEL_CONTENT SEL_TAGS SEL_ID; guard ) && ok_ || no_
t "selector: --content alone is allowed"
( SEL_CONTENT=spf1; unset SEL_NAME SEL_TYPE SEL_TAGS SEL_ID; guard ) && ok_ || no_
t "selector: --tags alone is allowed"
( SEL_TAGS=email; unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_ID; guard ) && ok_ || no_
t "selector: --id alone is allowed"
( SEL_ID=abc; unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_TAGS; guard ) && ok_ || no_

# ---------------------------------------------------------------- selection filter
FIXTURE='[
 {"id":"1","name":"example.com","type":"TXT","content":"v=spf1 include:mailgun.org -all","tags":["email","spf"]},
 {"id":"2","name":"www.example.com","type":"A","content":"1.2.3.4","tags":["web"]},
 {"id":"3","name":"mail.example.com","type":"MX","content":"mx1.example.com","tags":["email"]},
 {"id":"4","name":"mail.example.com","type":"TXT","content":"v=spf1 include:mailgun.org ~all","tags":["email","spf"]}
]'
sel() { printf '%s' "$FIXTURE" | select_records | jq -r '[.[].id] | join(",")'; }

eq "select: by name resolves a bare label" \
  "$(SEL_NAME=www; unset SEL_TYPE SEL_CONTENT SEL_TAGS SEL_ID; sel)" "2"
eq "select: @ selects the apex" \
  "$(SEL_NAME=@; unset SEL_TYPE SEL_CONTENT SEL_TAGS SEL_ID; sel)" "1"
eq "select: name plus type narrows within a name" \
  "$(SEL_NAME=mail SEL_TYPE=TXT; unset SEL_CONTENT SEL_TAGS SEL_ID; sel)" "4"
eq "select: content is a substring match" \
  "$(SEL_CONTENT=mailgun; unset SEL_NAME SEL_TYPE SEL_TAGS SEL_ID; sel)" "1,4"
eq "select: content match is case-insensitive" \
  "$(SEL_CONTENT=MAILGUN; unset SEL_NAME SEL_TYPE SEL_TAGS SEL_ID; sel)" "1,4"
eq "select: tags require ALL listed tags" \
  "$(SEL_TAGS=email,spf; unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_ID; sel)" "1,4"
eq "select: a single tag matches more broadly" \
  "$(SEL_TAGS=email; unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_ID; sel)" "1,3,4"
eq "select: by id is exact" \
  "$(SEL_ID=3; unset SEL_NAME SEL_TYPE SEL_CONTENT SEL_TAGS; sel)" "3"
eq "select: filters AND together" \
  "$(SEL_TAGS=email SEL_TYPE=TXT; unset SEL_NAME SEL_CONTENT SEL_ID; sel)" "1,4"
eq "select: no match returns empty" \
  "$(SEL_NAME=absent; unset SEL_TYPE SEL_CONTENT SEL_TAGS SEL_ID; sel)" ""

# ---------------------------------------------------------------- json store
mkdir -p "$CFDNS_ROOT"
F="$CFDNS_ROOT/t.json"
printf '{"zone":"example.com","token_backend":"op"}' > F_tmp && mv F_tmp "$F"

eq "jq_get: reads a key"           "$(jq_get "$F" '.zone')" "example.com"
eq "jq_get: missing key is empty"  "$(jq_get "$F" '.nope')" ""
eq "jq_get: missing file is empty" "$(jq_get "$CFDNS_ROOT/none.json" '.a')" ""

t "jq_set writes and enforces 0600"
jq_set "$F" '.zone = "new.com"' && [ "$(jq -r .zone "$F")" = new.com ] \
  && [ "$(stat -c %a "$F" 2>/dev/null || stat -f %Lp "$F")" = 600 ] && ok_ || no_

t "jq_set with an invalid filter leaves the file intact"
jq_set "$F" 'not valid jq at all' 2>/dev/null
[ "$(jq -r .zone "$F")" = new.com ] && ok_ || no_

t "jq_set leaves no temp files behind"
[ "$(find "$CFDNS_ROOT" -name 't.json.*' | wc -l | tr -d ' ')" = 0 ] && ok_ || no_

t "jq_load reads several keys in one call"
eval "$(jq_load "$F" A .zone B .token_backend C .missing)"
[ "$A" = new.com ] && [ "$B" = op ] && [ -z "$C" ] && ok_ || { no_; echo "      A=$A B=$B C=$C"; }

t "jq_load on a missing file yields empty vars"
eval "$(jq_load "$CFDNS_ROOT/none.json" X .a Y .b)"
[ -z "$X" ] && [ -z "$Y" ] && ok_ || no_

rm -rf "$CFDNS_ROOT"
printf '\n'
[ "$fail" -eq 0 ] && echo "UNIT TESTS PASS" || echo "UNIT TESTS FAILED"
exit "$fail"
