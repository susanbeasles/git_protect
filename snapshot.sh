# shellcheck shell=bash
# Point-in-time state capture, before anything changes it.
#
# This module knows nothing about Cloudflare, DNS, or what state looks like. It takes
# a policy name and a scope, asks the policy's capture command for some bytes, and
# stores them under a derived path with retention applied.
#
# Adding a provider means adding a policy and a capture function. It means changing
# nothing here:
#
#   {
#     "cloudflare-dns": { "capture": "fetch_live",            "scope_label": "zone" },
#     "aws-route53":    { "capture": "route53_export_zone",   "scope_label": "hosted-zone" },
#     "sentry-projects":{ "capture": "sentry_export_projects", "scope_label": "org" }
#   }
#
# The capture command is any shell function or executable that writes the state to
# stdout and exits non-zero on failure. That is the entire contract.

# ---------------------------------------------------------------- policy lookup
# Resolved per call, not captured when this file is sourced. A configuration path
# frozen at source time cannot be overridden by anything that loads later — which is
# exactly what a test, or a second policy set, needs to do.
snapshot_policy_file() {
  printf '%s' "${CFDNS_SNAPSHOT_POLICIES:-$CFDNS_LIB/policies/snapshots.json}"
}

# snapshot_policy <name> <field> [default]
snapshot_policy() {
  local name="$1" field="$2" fallback="${3:-}"
  local value
  value="$(jq_get "$(snapshot_policy_file)" ".\"$name\".$field")"
  printf '%s' "${value:-$fallback}"
}

snapshot_policy_exists() {
  local file; file="$(snapshot_policy_file)"
  [ -f "$file" ] || return 1
  [ -n "$(jq_get "$file" ".\"$1\"")" ]
}

snapshot_policy_names() {
  jq -r 'keys[]' "$(snapshot_policy_file)" 2>/dev/null || true
}

# ---------------------------------------------------------------- paths
snapshot_dir() {
  local policy="$1" sub
  sub="$(snapshot_policy "$policy" dir "$policy")"
  printf '%s/%s' "$CFDNS_SNAPSHOTS" "$sub"
}

# snapshot_path <policy> <scope> <reason>
#
# Collisions are resolved by suffix rather than by making the timestamp finer: two
# snapshots in the same second is normal when a command takes several actions, and a
# lost snapshot is worse than an ugly filename.
snapshot_path() {
  local policy="$1" scope="$2" reason="$3"
  local dir ext stamp base candidate n=1
  dir="$(snapshot_dir "$policy")"
  ext="$(snapshot_policy "$policy" extension json)"
  stamp="$(now_stamp)"
  base="$dir/${scope}-${stamp}-${reason}"
  candidate="$base.$ext"
  while [ -e "$candidate" ]; do
    candidate="$base.$n.$ext"; n=$((n + 1))
  done
  printf '%s' "$candidate"
}

# ---------------------------------------------------------------- capture
# snapshot_take <policy> <scope> <reason> [capture-args...] -> path on stdout
#
# Returns non-zero without writing anything if the capture fails. A snapshot that
# silently contains an error message is worse than no snapshot, because it will be
# trusted as a restore point.
snapshot_take() {
  local policy="$1" scope="$2" reason="$3"; shift 3
  snapshot_policy_exists "$policy" \
    || die "no snapshot policy named '$policy' in $(snapshot_policy_file).
  Known policies: $(snapshot_policy_names | tr '\n' ' ')"

  local capture; capture="$(snapshot_policy "$policy" capture)"
  [ -n "$capture" ] || die "snapshot policy '$policy' declares no capture command"
  command -v "$capture" >/dev/null 2>&1 \
    || die "snapshot policy '$policy' names capture '$capture', which does not exist"

  local dir path tmp
  dir="$(snapshot_dir "$policy")"
  [ -d "$dir" ] || { mkdir -p "$dir" && chmod 700 "$dir"; }
  path="$(snapshot_path "$policy" "$scope" "$reason")"

  tmp="$(mktemp "$dir/.pending.XXXXXX")" || return 1
  if ! "$capture" "$@" > "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    warn "snapshot capture '$capture' failed — nothing was written"
    return 1
  fi
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    warn "snapshot capture '$capture' produced no output — refusing to store an empty snapshot"
    return 1
  fi

  # Wrapped with provenance so a snapshot is self-describing months later, then moved
  # into place atomically: a reader never sees a half-written restore point.
  local wrap; wrap="$(snapshot_policy "$policy" wrap json)"
  if [ "$wrap" = json ]; then
    jq --arg p "$policy" --arg s "$scope" --arg r "$reason" --arg t "$(now_utc)" \
       '{policy:$p, scope:$s, reason:$r, taken:$t, state:.}' "$tmp" > "$tmp.wrapped" \
      && mv "$tmp.wrapped" "$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$path"

  snapshot_prune "$policy" "$scope"
  printf '%s' "$path"
}

# ---------------------------------------------------------------- retention
# Newest kept. `retain: 0` or absent means keep everything.
snapshot_prune() {
  local policy="$1" scope="$2"
  local retain; retain="$(snapshot_policy "$policy" retain 0)"
  case "$retain" in ''|0|*[!0-9]*) return 0 ;; esac

  local dir; dir="$(snapshot_dir "$policy")"
  local victims
  victims="$(snapshot_list "$policy" "$scope" | tail -n "+$((retain + 1))")"
  [ -n "$victims" ] || return 0
  local f
  while IFS= read -r f; do
    [ -n "$f" ] && rm -f "$dir/$f"
  done <<< "$victims"
}

# snapshot_list <policy> [scope] -> filenames, newest first
#
# Sorted by the timestamp in the filename rather than by mtime. The name is the record
# of when the state was captured; mtime is a property of the file and can be changed
# by anything that touches it. A glob plus a reverse sort also avoids parsing `ls`.
snapshot_list() {
  local policy="$1" scope="${2:-}" dir entry name
  dir="$(snapshot_dir "$policy")"
  [ -d "$dir" ] || return 0

  for entry in "$dir"/*; do
    [ -f "$entry" ] || continue
    name="${entry##*/}"
    case "$name" in
      .pending.*) continue ;;
      *) [ -z "$scope" ] || case "$name" in "$scope"-*) ;; *) continue ;; esac ;;
    esac
    printf '%s\n' "$name"
  done | LC_ALL=C sort -r
}

# snapshot_read <path> -> the captured state, unwrapped
snapshot_read() {
  local path="$1"
  [ -f "$path" ] || die "no such snapshot: $path"
  # Accepts both wrapped and bare snapshots so a hand-written file still restores.
  if jq -e 'has("state")' "$path" >/dev/null 2>&1; then jq '.state' "$path"
  else jq '.' "$path"; fi
}
