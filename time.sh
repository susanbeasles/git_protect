# shellcheck shell=bash
# Time formatting. BSD and GNU `date` take incompatible flags for this, so the
# incompatibility is resolved once, here, rather than at each call site.

# epoch_to_local <epoch> -> "2026-08-13 09:41:07 PDT"
epoch_to_local() {
  local e="${1:-0}"
  date -d "@$e" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null \
    || date -r "$e" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null \
    || printf 'epoch %s' "$e"
}

# bash 5 exposes the clock directly. Falls back to `date` on bash 4, which is what
# a stock macOS install has unless a newer bash was installed.
now_epoch() {
  if [ -n "${EPOCHSECONDS:-}" ]; then printf '%s' "$EPOCHSECONDS"
  else date +%s; fi
}
now_utc()   { date -u +%Y-%m-%dT%H:%M:%SZ; }
now_stamp() { date -u +%Y%m%dT%H%M%SZ; }

# humanise_age <seconds> -> "4 minutes ago"
humanise_age() {
  local s="${1:-0}"
  [ "$s" -lt 0 ] 2>/dev/null && s=0
  if   [ "$s" -lt 90 ];     then printf '%s seconds ago' "$s"
  elif [ "$s" -lt 5400 ];   then printf '%s minutes ago' "$((s / 60))"
  elif [ "$s" -lt 172800 ]; then printf '%s hours ago'   "$((s / 3600))"
  else                           printf '%s days ago'    "$((s / 86400))"
  fi
}
