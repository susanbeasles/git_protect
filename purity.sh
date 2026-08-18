#!/usr/bin/env bash
# Static check for the bug that appeared three times in this codebase:
#
#   x="$(some_function)"     # runs in a subshell
#
# If some_function also assigns to a variable the caller reads, that assignment is
# discarded when the subshell exits. It fails silently — the variable is simply empty,
# and the symptom shows up somewhere unrelated. It cost a broken retry loop, a broken
# file count, and a snapshot policy override that was ignored.
#
# The rule this enforces:
#
#   A function may PRINT a result, or it may SET caller-visible state. Not both.
#
# Setters are listed in test/setters.allow with the reason they exist. Anything else
# that assigns to a non-local uppercase variable is a failure. Any setter found inside
# a command substitution is a failure.
set +e
cd "$(dirname "$0")/.." || exit 1

SOURCES=(cf lib/core/*.sh lib/cli/*.sh lib/dns/*.sh lib/integrity/*.sh
         lib/analysis/*.sh lib/cmd/*.sh)
ALLOW=test/setters.allow

fail=0
t() { printf '  %-58s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

# ---------------------------------------------------------------- find setters
# A function is a "setter" if its body assigns to an UPPER_CASE name that was not
# declared local in the same function.
find_setters() {
  local f
  for f in "${SOURCES[@]}"; do
    [ -f "$f" ] || continue
    awk -v file="$f" '
      /^[a-z_][a-z0-9_]*\(\)/ {
        fname = $0; sub(/\(\).*/, "", fname); delete locals; next
      }
      fname && /^[[:space:]]*local[[:space:]]/ {
        line = $0
        sub(/^[[:space:]]*local[[:space:]]+/, "", line)
        n = split(line, parts, /[[:space:]]+/)
        for (i = 1; i <= n; i++) { v = parts[i]; sub(/=.*/, "", v); locals[v] = 1 }
        next
      }
      # Heredoc bodies are text, not code: `usage()` prints documentation that
      # mentions environment variables and must not be read as assigning them.
      fname && /<<-?[A-Z_'\''"]+/ {
        marker = $0
        sub(/^.*<<-?['\''"]?/, "", marker)
        sub(/['\''"].*$/, "", marker)
        sub(/[[:space:]].*$/, "", marker)
        inheredoc = marker; next
      }
      inheredoc { if ($0 == inheredoc) inheredoc = ""; next }

      # Assignments are found anywhere on the line, not only at the start: a case
      # branch like `--name) REC_NAME="$2"; shift 2 ;;` assigns mid-line, and an
      # earlier version of this check missed every one of them.
      fname {
        line = $0
        # `LC_ALL=C awk ...` is a one-command environment prefix, not shell state.
        if (line ~ /(^|[[:space:]])[A-Z_][A-Z0-9_]*=[^[:space:]]*[[:space:]]+[a-z_]+([[:space:]]|$)/) next
        rest = line
        while (match(rest, /(^|[;&|)(\{[:space:]])[A-Z_][A-Z0-9_]*(\[[^]]*\])?=/)) {
          tok = substr(rest, RSTART, RLENGTH)
          rest = substr(rest, RSTART + RLENGTH)
          gsub(/^[;&|)(\{[:space:]]+/, "", tok)
          sub(/(\[[^]]*\])?=$/, "", tok)
          if (tok != "" && !(tok in locals)) print fname "\t" tok "\t" file
        }
      }
      /^}/ { fname = ""; inheredoc = "" }
    ' "$f"
  done | sort -u
}

allowed() {
  [ -f "$ALLOW" ] || return 1
  grep -qE "^$1[[:space:]]" "$ALLOW"
}

# A memo is a setter whose variable no other function reads: losing it in a subshell
# costs a recomputation, never a wrong answer. Declared with a leading "memo " in the
# allowlist and verified below.
is_memo() {
  [ -f "$ALLOW" ] || return 1
  grep -qE "^memo[[:space:]]+$1[[:space:]]" "$ALLOW"
}

# ---------------------------------------------------------------- 1. no new setters
t "every state-mutating function is declared in $ALLOW"
undeclared=""
while IFS=$'\t' read -r fn var file; do
  [ -z "$fn" ] && continue
  allowed "$fn" || is_memo "$fn" \
    || undeclared="$undeclared  $fn sets $var  ($file)"$'\n'
done < <(find_setters)
if [ -z "$undeclared" ]; then ok_; else
  no_
  printf '%s' "$undeclared"
  printf '      A function that sets caller state must not also print a result.\n'
  printf '      Either return the value instead, or add it to %s with a reason.\n' "$ALLOW"
fi

# ---------------------------------------------------------------- 2. no setter in $()
t "no state-mutating function is called inside a command substitution"
misuse=""
while IFS=$'\t' read -r fn _ _; do
  [ -z "$fn" ] && continue
  is_memo "$fn" && continue
  hits="$(grep -nE "\\\$\\(\\s*$fn(\\s|\\)|\\s)" "${SOURCES[@]}" 2>/dev/null \
          | grep -v '^\s*#' || true)"
  [ -n "$hits" ] && misuse="$misuse$hits"$'\n'
done < <(find_setters)
if [ -z "$misuse" ]; then ok_; else
  no_
  printf '%s' "$misuse" | sed 's/^/      /'
  printf '      A subshell discards the state these set. Call them directly.\n'
fi

# ---------------------------------------------------------------- 3. allowlist is honest
t "$ALLOW lists no function that has since become pure"
stale=""
if [ -f "$ALLOW" ]; then
  actual="$(find_setters | cut -f1 | sort -u)"
  while read -r fn rest; do
    case "$fn" in ''|\#*) continue ;; esac
    [ "$fn" = memo ] && fn="${rest%% *}"
    printf '%s\n' "$actual" | grep -qx "$fn" || stale="$stale  $fn"$'\n'
  done < "$ALLOW"
fi
if [ -z "$stale" ]; then ok_; else
  no_
  printf '%s' "$stale"
  printf '      These no longer mutate state. Remove them from %s.\n' "$ALLOW"
fi

# ---------------------------------------------------------------- 4. setters print nothing
# A setter that also prints is the dangerous shape: it invites $( ) at the call site.
t "no declared setter writes to stdout"
chatty=""
while read -r fn rest; do
  case "$fn" in ''|\#*|memo) continue ;; esac
  defined_in="$(grep -lE "^$fn\\(\\)" "${SOURCES[@]}" 2>/dev/null | head -1)"
  [ -n "$defined_in" ] || continue
  body="$(awk -v want="$fn" '
    $0 ~ "^"want"\\(\\)" { inside = 1; next }
    inside && /^}/ { exit }
    inside { print }
  ' "$defined_in" 2>/dev/null)"
  # printf/echo to stdout, excluding redirects to a file or to stderr
  # A printf piped into another command or redirected to a file is not stdout; only a
  # bare printf is. Missing that made every setter look chatty.
  if printf '%s\n' "$body" | grep -qE '^[[:space:]]*(printf|echo)([[:space:]][^|>]*)?$'; then
    chatty="$chatty  $fn"$'\n'
  fi
done < "$ALLOW"
if [ -z "$chatty" ]; then ok_; else
  no_
  printf '%s' "$chatty"
  printf '      A setter that prints invites `x="$(fn)"`, which loses the state.\n'
fi

printf '\n'
[ "$fail" -eq 0 ] && echo "PURITY TESTS PASS" || echo "PURITY TESTS FAILED"
exit "$fail"
