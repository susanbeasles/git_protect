#!/usr/bin/env bash
# test/integrity.sh — tamper evidence must actually detect tampering.
set +e
SRC="$(cd "$(dirname "$0")/.." && pwd -P)"
WORK=/tmp/cfdns-it-$$
BUNDLE="$WORK/cfezcli"
BIN="$WORK/bin"
export CFDNS_ROOT="$WORK/root"
rm -rf "$WORK"; mkdir -p "$BIN" "$CFDNS_ROOT"
cp -r "$SRC" "$BUNDLE"
rm -rf "$BUNDLE/test/.root"
ln -sf "$BUNDLE/cf" "$BIN/cf"
CF="$BIN/cf"
TAMPER_FILE="$BUNDLE/lib/dns/select.sh"

# Flip one byte's case, preserving file length exactly. Content-independent so it
# cannot silently become a no-op when the code is refactored.
stealth_edit() {
  python3 - "$1" <<'PYEOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
for i in range(len(b) - 1, -1, -1):
    c = chr(b[i])
    if c.isalpha():
        b[i] = ord(c.upper() if c.islower() else c.lower())
        break
else:
    raise SystemExit("no alphabetic byte to flip")
open(p, 'wb').write(b)
PYEOF
}


fail=0
t() { printf '  %-46s ' "$1"; }
yes_() { echo PASS; }
no_() { echo FAIL; fail=1; }

# 1. symlink resolution — must hash the bundle, not the bin dir
t "hashes real bundle through symlink"
got="$("$CF" integrity show 2>/dev/null | awk '/^bundle/{print $2}')"
[ "$got" = "$BUNDLE" ] && yes_ || { no_; echo "      got: $got"; }

# 2. hash is stable across runs with no change
t "hash stable across invocations"
h1="$("$CF" integrity show 2>/dev/null | awk '/^state/{f=1} /^hash/{print $2}' | head -1)"
h2="$("$CF" integrity show 2>/dev/null | awk '/^hash/{print $2}' | head -1)"
[ -n "$h1" ] && [ "$h1" = "$h2" ] && yes_ || no_

# 3. pin then verify
t "pin then verify matches"
"$CF" integrity pin >/dev/null 2>&1
"$CF" integrity verify >/dev/null 2>&1 && yes_ || no_

# 4. content change is detected
t "content change detected"
echo '# injected' >> "$TAMPER_FILE"
"$CF" integrity verify >/dev/null 2>&1 && no_ || yes_

# 5. mutated bundle NOTIFIES but does not block
t "notifies on mismatch without blocking"
out="$("$CF" dns ls 2>&1)"
if echo "$out" | grep -q 'CLI CODE TAMPERING DETECTED' \
   && echo "$out" | grep -q 'Continuing anyway' \
   && ! echo "$out" | grep -q 'refusing to run'; then yes_; else no_; fi

t "notification names the write timestamp"
echo "$out" | grep -qE 'If you did not change this code at [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}' && yes_ || no_

t "notification points at cf doctor"
echo "$out" | grep -q 'cf doctor' && yes_ || no_

# 6. integrity subcommand still reachable on mismatch
t "integrity subcommand still usable"
"$CF" integrity show >/dev/null 2>&1 && yes_ || no_

# 7. changelog records the event with per-file evidence
t "changelog records changed file"
out="$("$CF" doctor 2>&1)"
echo "$out" | grep -q 'MODIFIED.*select.sh' && yes_ || no_

t "changelog shows written + inode-changed times"
echo "$out" | grep -qE 'written .* inode changed ' && yes_ || no_

# 8. diff names the changed file
t "diff identifies the changed file"
"$CF" integrity diff 2>&1 | grep -q '^+.*select.sh' && yes_ || no_

# 9. STEALTH: size and mtime preserved, ctime cannot be forged
sed -i '/^# injected$/d' "$TAMPER_FILE"
"$CF" integrity pin >/dev/null 2>&1
t "size+mtime-preserving edit detected"
f="$TAMPER_FILE"
om="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")"
sz_before="$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")"
h_before="$("$CF" integrity show 2>/dev/null | awk '/^hash/{print $2}')"
stealth_edit "$f"
touch -d "@$om" "$f" 2>/dev/null || touch -t "$(date -r "$om" +%Y%m%d%H%M.%S)" "$f"
sz_after="$(stat -c %s "$f" 2>/dev/null || stat -f %z "$f")"
out="$("$CF" dns ls 2>&1)"
if [ "$sz_before" = "$sz_after" ] \
   && echo "$out" | grep -q 'CLI CODE TAMPERING DETECTED'; then yes_
else
  no_
  echo "      size $sz_before -> $sz_after (must be equal)"
  echo "      hash before $h_before"
  echo "      hash now    $("$CF" integrity show 2>/dev/null | awk '/^hash/{print $2}')"
fi
stealth_edit "$f"   # restore
"$CF" integrity pin >/dev/null 2>&1

# 10. no cache: detection must not depend on timing at all
t "same-second tamper detected (no cache blind spot)"
"$CF" integrity pin >/dev/null 2>&1
stealth_edit "$TAMPER_FILE"
out="$("$CF" integrity show 2>&1)"
echo "$out" | grep -q 'CLI CODE TAMPERING DETECTED' && yes_ || { no_; echo "$out" | head -3; }
stealth_edit "$TAMPER_FILE"
"$CF" integrity pin >/dev/null 2>&1

# 11. runtime state must not affect the build hash
t "snapshots and config excluded from hash"
before="$("$CF" integrity show 2>/dev/null | awk '/^hash/{print $2}' | head -1)"
mkdir -p "$CFDNS_ROOT/snapshots"; ( umask 077; echo '{}' > "$CFDNS_ROOT/snapshots/x.json" )
echo '{"zone":"x","records":[]}' > "$BUNDLE/config/masterDNS.json"
after="$("$CF" integrity show 2>/dev/null | awk '/^hash/{print $2}' | head -1)"
[ "$before" = "$after" ] && yes_ || { no_; echo "      $before -> $after"; }

# 12. artifacts are owner-only
t "all artifacts are 0600/0700"
bad="$(find "$CFDNS_ROOT" \( -type f -not -perm 600 \) -o \( -type d -not -perm 700 \) 2>/dev/null)"
[ -z "$bad" ] && yes_ || { no_; echo "$bad" | sed 's/^/      /'; }

# 13. world-writable bundle raises a warning
t "group/world-writable bundle warns"
chmod 666 "$BUNDLE/lib/core/log.sh"
"$CF" integrity show 2>&1 | grep -q 'group- or world-writable' && yes_ || no_
chmod 644 "$BUNDLE/lib/core/log.sh"

# 14. banner suppressible for scripting
t "CFDNS_NO_BANNER suppresses banner"
out="$(CFDNS_NO_BANNER=1 "$CF" integrity show 2>/dev/null)"
echo "$out" | grep -q 'cf build' && no_ || yes_

# 15. back-dated mtime is surfaced as concealment
sed -i '/^# injected$/d' "$TAMPER_FILE" 2>/dev/null
"$CF" integrity pin >/dev/null 2>&1
t "back-dated write flagged as concealment"
printf '\n# exfil\n' >> "$BUNDLE/lib/cmd/auth.sh"
touch -d "@$(( $(date +%s) - 259200 ))" "$BUNDLE/lib/cmd/auth.sh" 2>/dev/null \
  || touch -t "$(date -r $(( $(date +%s) - 259200 )) +%Y%m%d%H%M.%S)" "$BUNDLE/lib/cmd/auth.sh"
out="$("$CF" doctor 2>&1)"
echo "$out" | grep -q 'BACK-DATED WRITES DETECTED' && yes_ || no_

t "changelog survives multiple events"
printf '\n# second\n' >> "$BUNDLE/lib/core/log.sh"
"$CF" integrity show >/dev/null 2>&1
n="$("$CF" doctor 2>&1 | grep -cE '^  [0-9]{4}-[0-9]{2}-[0-9]{2} ')"
[ "${n:-0}" -ge 2 ] && yes_ || { no_; echo "      events found: $n"; }

t "changelog and manifest are 0600"
bad="$(find "$CFDNS_ROOT" -maxdepth 1 -type f -not -perm 600 2>/dev/null)"
[ -z "$bad" ] && yes_ || { no_; echo "$bad" | sed 's/^/      /'; }

rm -rf "$WORK"
printf '\n'
[ "$fail" -eq 0 ] && echo "INTEGRITY TESTS PASS" || echo "INTEGRITY TESTS FAILED"
exit "$fail"
