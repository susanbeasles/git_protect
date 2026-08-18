#!/usr/bin/env bash
# test/redact.sh — redaction must never leak. Run this before shipping any
# change to report.mjs.
set +e
export CFDNS_NO_BANNER=1
cd "$(dirname "$0")/.." || exit 1

FIX=test/analyze_fixture.json
RAW=/tmp/cfdns-raw.json
node -e '1' 2>/dev/null || { echo "node required"; exit 1; }

jq '{zone,records}' "$FIX" | node lib/analyze.mjs --offline > "$RAW" || exit 1

# Secrets planted in the fixture that must never survive redaction.
SECRETS=(
  'sonarmd'                       # real zone name
  'MIGfMA0GCSqGSIb'               # DKIM pubkey (2048)
  'MFwwDQYJKoZIhvcN'              # DKIM pubkey (512)
  'Xy9AbCdEfGhIjKl'               # google-site-verification token
  '203\.0\.113\.42'               # public origin IP
  'rua\+sonarmd'                  # rua mailbox local-part
  'nonexistent-bucket-xyz'        # dangling CNAME target
)
# Additionally forbidden at strict only (vendor inventory).
STRICT_ONLY=(
  'ppe-hosted' 'barracuda' 'mailgun' 'nutshell' 'outlook'
  'emailsignatures' 'cpmails' '--name mail\b' '--name stg'
)
# Must SURVIVE — proof we did not over-redact into uselessness.
MUST_KEEP=(
  'DMARC_DUPLICATE' 'SPF_DUPLICATE' 'MX_NO_SPF' 'RFC 7208' 'RFC 7489'
  'mail-handling name' 'Remediation' 'CRITICAL'
)

fail=0
for level in standard strict; do
  out="/tmp/cfdns-red-$level.md"
  node lib/report.mjs --format md --redact "$level" < "$RAW" > "$out" 2>/dev/null
  printf '\n== %s ==\n' "$level"
  for p in "${SECRETS[@]}"; do
    if grep -qiE -e "$p" "$out"; then printf '  LEAK      %s\n' "$p"; fail=1; fi
  done
  if [ "$level" = strict ]; then
    for p in "${STRICT_ONLY[@]}"; do
      if grep -qiE -e "$p" "$out"; then printf '  LEAK      %s\n' "$p"; fail=1; fi
    done
  fi
  for p in "${MUST_KEEP[@]}"; do
    if ! grep -qE -e "$p" "$out"; then printf '  OVER-REDACTED (missing) %s\n' "$p"; fail=1; fi
  done
  [ "$fail" -eq 0 ] && printf '  clean, and still readable\n'
done

# timestamps must not be mangled by the IPv6 matcher
for level in standard strict; do
  if ! grep -qE '\*\*Generated:\*\* [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' "/tmp/cfdns-red-$level.md"; then
    printf '\n  TIMESTAMP CORRUPTED in %s\n' "$level"; fail=1
  fi
done

# keymap must be 0600 and must not be embedded in the report
node lib/report.mjs --format md --redact strict --keymap /tmp/cfdns-km.json \
  < "$RAW" > /tmp/cfdns-km-report.md 2>/dev/null
perms="$(stat -c '%a' /tmp/cfdns-km.json 2>/dev/null || stat -f '%Lp' /tmp/cfdns-km.json)"
[ "$perms" = "600" ] || { printf '\n  KEYMAP PERMS %s (want 600)\n' "$perms"; fail=1; }
grep -qi 'sonarmd' /tmp/cfdns-km-report.md && { printf '  KEYMAP LEAKED INTO REPORT\n'; fail=1; }

printf '\n'
if [ "$fail" -eq 0 ]; then echo "REDACTION TESTS PASS"; else echo "REDACTION TESTS FAILED"; fi
rm -f /tmp/cfdns-raw.json /tmp/cfdns-red-*.md /tmp/cfdns-km.json /tmp/cfdns-km-report.md
exit "$fail"
