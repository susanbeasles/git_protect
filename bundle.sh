# shellcheck shell=bash
# What "the build" is, and how to hash it.
#
# Every function here is pure: it reads its arguments and writes to stdout. Nothing
# assigns to a variable outside itself. That is load-bearing, not stylistic — a
# function that both prints a result and sets a variable breaks the moment anyone
# writes `x="$(fn)"`, because the assignment runs in a subshell and the variable is
# discarded. That bug appeared three times here before the state was removed instead
# of documented. test/purity.sh fails the build if it comes back.
#
# The scan is the expensive part, so callers compute it once and pass it along rather
# than each function re-walking the tree.

sha256_stdin() {
  local hash rest
  if command -v sha256sum >/dev/null 2>&1; then read -r hash rest < <(sha256sum)
  else read -r hash rest < <(shasum -a 256); fi
  printf '%s' "$hash"
}

# Resolve a symlink chain without GNU `readlink -f`, which stock macOS lacks.
resolve_path() {
  local p="$1" target n=0 dir base
  while [ -L "$p" ]; do
    n=$((n + 1))
    [ "$n" -gt 40 ] && die "symlink loop resolving $1"
    target="$(readlink "$p")"
    case "$target" in
      /*) p="$target" ;;
      *)  dir="${p%/*}"; [ "$dir" = "$p" ] && dir="."; p="$dir/$target" ;;
    esac
  done
  dir="${p%/*}"; [ "$dir" = "$p" ] && dir="."
  base="${p##*/}"
  ( cd "$dir" >/dev/null 2>&1 && printf '%s/%s' "$(pwd -P)" "$base" )
}

# Directory part of a path, without forking dirname.
path_dir() { local p="${1%/*}"; [ "$p" = "$1" ] && p="."; printf '%s' "$p"; }

# Excludes operator data and runtime output, so editing masterDNS.json is not
# mistaken for tampering while editing a module is.
bundle_prune_args() {
  printf '%s\n' \
    '(' -name .git -o -name node_modules -o -name config -o -name snapshots \
    -o -name .root -o -name '*.keymap.json' -o -name '*.bak.*' \
    -o -name integrity.json -o -name integrity.log \
    -o -name manifest.last -o -name manifest.pinned ')' -prune -o
}

# Probed once when this module loads, not on every scan. The probe is two processes
# and the answer cannot change during one invocation.
if find . -maxdepth 0 -printf '' >/dev/null 2>&1; then
  FIND_PRINTS_MODES=1
else
  FIND_PRINTS_MODES=""
fi

# bundle_scan <root> -> "mode|path" per line, sorted by path.
#
# GNU find prints the mode alongside the name, collapsing the walk and the mode lookup
# into one process, and `%P` gives the path relative to the starting point — which is
# why no `cd` subshell is needed. BSD find has neither, so macOS pays for one batched
# stat inside a subshell.
bundle_scan() {
  local root="$1" prune=()
  mapfile -t prune < <(bundle_prune_args)

  if [ -n "$FIND_PRINTS_MODES" ]; then
    find "$root" "${prune[@]}" -type f -printf '%m|./%P\n' | LC_ALL=C sort -t'|' -k2
    return 0
  fi

  local paths=() statfmt
  mapfile -t -d '' paths < <(
    cd "$root" && find . "${prune[@]}" -type f -print0 | LC_ALL=C sort -z
  )
  [ "${#paths[@]}" -gt 0 ] || return 0
  if stat -c '%a' . >/dev/null 2>&1; then statfmt=(-c '%a|%n'); else statfmt=(-f '%Lp|%N'); fi
  ( cd "$root" && printf '%s\0' "${paths[@]}" | xargs -0 stat "${statfmt[@]}" 2>/dev/null )
}

# bundle_manifest <root> <scan> -> "hash mode path" per line, sorted by path.
#
# One process for all hashes. The first version forked sha256sum and stat per file,
# which cost 271ms on a 22-file bundle and was the only reason a cache existed — and
# that cache had a same-second blind spot, so the cache is gone and this is fast
# enough to run unconditionally.
bundle_manifest() {
  local root="$1" scan="$2"
  [ -n "$scan" ] || return 0

  local hashcmd
  if command -v sha256sum >/dev/null 2>&1; then hashcmd=sha256sum; else hashcmd="shasum -a 256"; fi

  # The path list is built with shell builtins. Piping the scan through
  # `cut | tr` to produce it cost two processes for data already in memory.
  local rows=() paths=() row
  mapfile -t rows <<< "$scan"
  for row in "${rows[@]}"; do
    [ -n "$row" ] && paths+=("${row#*|}")
  done
  [ "${#paths[@]}" -gt 0 ] || return 0

  ( cd "$root" || return 1
    LC_ALL=C awk -F'|' '
      NR == FNR {
        mode = $1; path = $2
        for (i = 3; i <= NF; i++) path = path "|" $i
        m[path] = mode; next
      }
      {
        h = substr($0, 1, 64)
        p = substr($0, 67)
        sub(/^\\/, "", h)
        printf "%s %s %s\n", h, (p in m ? m[p] : "?"), p
      }
    ' <(printf '%s\n' "$scan") \
      <(printf '%s\0' "${paths[@]}" | xargs -0 $hashcmd 2>/dev/null)
  )
}

bundle_hash() { bundle_manifest "$1" "$2" | sha256_stdin; }

# Counts newlines with parameter expansion rather than piping to `wc -l | tr`. The
# data is already in memory; spending two processes to measure it is the kind of
# detail that turns a 35ms tool into a 50ms one.
bundle_count() {
  [ -n "$1" ] || { printf '0'; return 0; }
  local newlines="${1//[!$'\n']/}"
  printf '%s' $(( ${#newlines} + 1 ))
}

# bundle_newest_write <root> <scan> -> epoch of the most recent write.
#
# Max of mtime and ctime: mtime alone is forgeable with touch. Only called when a
# mismatch is being reported, so it may cost a few processes.
bundle_newest_write() {
  local root="$1" scan="$2" timefmt
  [ -n "$scan" ] || { printf '0'; return 0; }
  if stat -c '%Y' . >/dev/null 2>&1; then timefmt=(-c '%Y %Z'); else timefmt=(-f '%m %c'); fi
  ( cd "$root" || return 0
    printf '%s\n' "$scan" | cut -d'|' -f2- | tr '\n' '\0' \
      | xargs -0 stat "${timefmt[@]}" 2>/dev/null \
      | tr ' ' '\n' | cut -d. -f1 | LC_ALL=C sort -rn | head -1
  ) | { read -r v || true; printf '%s' "${v:-0}"; }
}

# bundle_writable <scan> -> "mode path" per group- or world-writable file.
#
# A writable bundle has no tamper evidence: anyone who can write it can change what
# is hashed. Modes come from the scan, so this costs no processes.
bundle_writable() {
  local scan="$1" row mode
  [ -n "$scan" ] || return 0
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    mode="${row%%|*}"
    case "$mode" in *[2367]) printf '  %s  %s\n' "$mode" "${row#*|}" ;; esac
  done <<< "$scan"
}
