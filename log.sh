# shellcheck shell=bash
# Output only. No config, no network, no state.
# Optional fd argument: callers use `_tty` for stdout and `_tty 2` for stderr.
# shellcheck disable=SC2120  # the argument is used from other modules
_tty() { [ -t "${1:-1}" ]; }
_c() { if _tty; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi; }

info()  { printf '%s %s\n' "$(_c '0;36' '==>')" "$*"; }
ok()    { printf '%s %s\n' "$(_c '0;32' ' ok')" "$*"; }
warn()  { printf '%s %s\n' "$(_c '1;33' ' !!')" "$*" >&2; }
die()   { printf '%s %s\n' "$(_c '0;31' 'ERR')" "$*" >&2; exit 1; }
note()  { printf '    %s\n' "$*"; }

hr()    { printf '%s\n' "$(_c '2' '────────────────────────────────────────────────────────')"; }

# Wrap prose to a column with an indent. Used by every report renderer.
wrap() {
  local text="$1" indent="${2:-6}" width="${3:-92}"
  [ -z "$text" ] && return 0
  local pad line="" word
  pad="$(printf '%*s' "$indent" '')"
  for word in $text; do
    if [ "${#line}" -gt 0 ] && [ $(( ${#line} + ${#word} + 1 )) -gt $(( width - indent )) ]; then
      printf '%s%s\n' "$pad" "$line"; line="$word"
    else
      line="${line:+$line }$word"
    fi
  done
  [ -n "$line" ] && printf '%s%s\n' "$pad" "$line"
  return 0
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1${2:+ ($2)}"; }
