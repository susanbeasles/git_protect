#!/usr/bin/env bash
# Forensic reproducer for the intermittent stealth-edit miss.
#
# Hypothesis: with whole-second ctime, if the tamper lands in the SAME second as
# the previous integrity check, the cheap fingerprint is byte-identical and the
# cached hash is reused, so the mismatch goes unreported until the TTL fires.
#
# Usage: repro.sh <iterations> <gnu_ns|gnu_s>
#   gnu_ns = nanosecond ctime (the fix)
#   gnu_s  = whole-second ctime (the original behaviour)
set +e

ITER="${1:-100}"
MODE="${2:-gnu_ns}"
SRC="$(cd "$(dirname "$0")/.." && pwd -P)"

miss=0; hit=0
same_second=0; diff_second=0
miss_same=0; miss_diff=0

for i in $(seq 1 "$ITER"); do
  W="/tmp/repro-$$-$i"
  B="$W/bundle"
  export CFDNS_ROOT="$W/root"
  mkdir -p "$CFDNS_ROOT"
  cp -r "$SRC" "$B" 2>/dev/null
  rm -rf "$B/test/.root"

  # force the stat dialect under test (only affects changelog evidence now)
  sed -i "s/^_STAT_MODE=\"\"/_STAT_MODE=\"$MODE\"/" "$B/lib/integrity/bundle.sh"

  export CFDNS_NO_BANNER=1
  "$B/cf" integrity pin >/dev/null 2>&1
  pin_ct="$(stat -c '%.9Z' "$B/lib/dns/select.sh")"

  # tamper: identical size, mtime restored — only ctime moves
  om="$(stat -c %Y "$B/lib/dns/select.sh")"
  python3 - "$B/lib/dns/select.sh" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
open(p,'w').write(s.replace('  require_matcher','  require_matchr ',1))
PY
  touch -d "@$om" "$B/lib/dns/select.sh"
  post_ct="$(stat -c '%.9Z' "$B/lib/dns/select.sh")"

  if [ "${pin_ct%.*}" = "${post_ct%.*}" ]; then
    same_second=$((same_second+1)); bucket=same
  else
    diff_second=$((diff_second+1)); bucket=diff
  fi

  unset CFDNS_NO_BANNER
  out="$("$B/cf" dns ls 2>&1)"
  if echo "$out" | grep -q 'CLI CODE TAMPERING DETECTED'; then
    hit=$((hit+1))
  else
    miss=$((miss+1))
    [ "$bucket" = same ] && miss_same=$((miss_same+1)) || miss_diff=$((miss_diff+1))
    if [ "$miss" -le 2 ]; then
      printf '\n  MISS #%s (iteration %s, %s-second)\n' "$miss" "$i" "$bucket"
      printf '    ctime at pin   %s\n' "$pin_ct"
      printf '    ctime after    %s\n' "$post_ct"
      printf '    cached reason  %s\n' "$(jq -r '.last.reason' "$CFDNS_ROOT/integrity.json")"
      printf '    banner said    %s\n' "$(echo "$out" | head -1 | grep -o '\[.*\]' || echo '-')"
    fi
  fi
  rm -rf "$W"
done

printf '\n  mode=%s  iterations=%s\n' "$MODE" "$ITER"
printf '  detected  %s\n' "$hit"
printf '  MISSED    %s\n' "$miss"
printf '  tamper landed in same second as pin: %s   (missed %s of those)\n' "$same_second" "$miss_same"
printf '  tamper landed in a later second:     %s   (missed %s of those)\n' "$diff_second" "$miss_diff"
[ "$miss" -eq 0 ] && printf '  RESULT: no misses\n' || printf '  RESULT: %s miss(es)\n' "$miss"
