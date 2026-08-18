# shellcheck shell=bash
# Small JSON store helpers. Every read/write of a config-shaped file goes here,
# so file permissions and atomic replacement are enforced in exactly one place.

# jq_get <file> <filter>  -> value or empty
jq_get() {
  [ -f "$1" ] || return 0
  jq -r "$2 // empty" "$1" 2>/dev/null || true
}

# jq_set <file> <filter>  -> applies filter, replaces atomically, 0600
jq_set() {
  local file="$1" filter="$2" tmp
  tmp="$(mktemp "${file}.XXXXXX")" || return 1
  [ -f "$file" ] || printf '{}' > "$file"
  if jq "$filter" "$file" > "$tmp" 2>/dev/null; then
    chmod 600 "$tmp" && mv "$tmp" "$file"
  else
    rm -f "$tmp"; return 1
  fi
}

# Read several keys in ONE jq process. jq startup dominates on short calls, and
# the config is read three or four times per invocation.
# Usage: eval "$(jq_load <file> ZONE .zone BACKEND .token_backend)"
jq_load() {
  local file="$1"; shift
  [ -f "$file" ] || { while [ $# -gt 1 ]; do printf '%s=""\n' "$1"; shift 2; done; return 0; }
  local args=() filters=() var
  while [ $# -gt 1 ]; do
    args+=("$1"); filters+=("$2"); shift 2
  done
  local i=0 expr=""
  for var in "${args[@]}"; do
    expr="${expr}${expr:+, }\"${var}=\\\"\" + ((${filters[$i]}) // \"\" | tostring) + \"\\\"\""
    i=$((i+1))
  done
  jq -r "[${expr}] | join(\"\n\")" "$file" 2>/dev/null || true
}

json_write() {
  local file="$1"
  ( umask 077; cat > "$file" )
  chmod 600 "$file"
}
