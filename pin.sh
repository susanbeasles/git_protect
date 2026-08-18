# shellcheck shell=bash
# Pin state: what the bundle hashes to, what it is supposed to hash to.
#
# integrity_check is the one function in this codebase that deliberately populates
# variables for other modules to read. It therefore prints NOTHING, so there is never
# a reason to call it inside `$( )` — which is what made the same mistake possible
# three times elsewhere. test/purity.sh enforces that rule.
#
# There is no cache and no TTL. Every invocation computes a full content hash, so
# detection never consults a timestamp and cannot have a timing-dependent blind spot.
# An earlier design cached on a size/mtime/ctime fingerprint: a tamper landing in the
# same clock second as the previous check produced a byte-identical fingerprint and
# went unreported. test/repro.sh measures it — 5 misses in 40 with whole-second stat,
# every one of them a same-second case.

_INTEGRITY_READY=""

# Populates, for banner.sh and cmd/ to read:
#   BUNDLE_ROOT BUNDLE_SCAN BUNDLE_MANIFEST BUNDLE_HASH BUNDLE_FILES
#   INTEGRITY_STATE PINNED PINNED_AT
# shellcheck disable=SC2034
integrity_check() {
  [ -n "$_INTEGRITY_READY" ] && return 0

  BUNDLE_ROOT="$(path_dir "$(resolve_path "${CF_ENTRY:-$0}")")"
  BUNDLE_SCAN="$(bundle_scan "$BUNDLE_ROOT")"
  BUNDLE_MANIFEST="$(bundle_manifest "$BUNDLE_ROOT" "$BUNDLE_SCAN")"
  BUNDLE_HASH="$(printf '%s\n' "$BUNDLE_MANIFEST" | sha256_stdin)"
  BUNDLE_FILES="$(bundle_count "$BUNDLE_SCAN")"

  local previous now
  eval "$(jq_load "$CFDNS_INTEGRITY" previous .last.hash PINNED .pinned PINNED_AT .pinned_at)"
  now="$(now_epoch)"

  if [ -n "$previous" ] && [ "$previous" != "$BUNDLE_HASH" ]; then
    changelog_append "$BUNDLE_ROOT" "$previous" "$BUNDLE_HASH" \
      "$BUNDLE_MANIFEST" "$CFDNS_MANIFEST_LAST"
    printf '%s\n' "$BUNDLE_MANIFEST" | json_write "$CFDNS_MANIFEST_LAST"
  elif [ ! -f "$CFDNS_MANIFEST_LAST" ]; then
    printf '%s\n' "$BUNDLE_MANIFEST" | json_write "$CFDNS_MANIFEST_LAST"
  fi

  # Written only when the hash moved. Rewriting the same value cost a mktemp, a jq, a
  # mv and a chmod — 14ms to record that nothing happened, on every command.
  if [ "$previous" != "$BUNDLE_HASH" ]; then
    jq_set "$CFDNS_INTEGRITY" "$(printf '.last = {hash:"%s", checked:%s}' "$BUNDLE_HASH" "$now")"
  fi

  if   [ -z "$PINNED" ];                 then INTEGRITY_STATE=UNPINNED
  elif [ "$PINNED" = "$BUNDLE_HASH" ];   then INTEGRITY_STATE=PINNED
  else                                        INTEGRITY_STATE=MISMATCH
  fi

  _INTEGRITY_READY=1
}

integrity_pin() {
  integrity_check
  local previous="$PINNED"
  printf '%s\n' "$BUNDLE_MANIFEST" | json_write "$CFDNS_MANIFEST_PINNED"
  jq_set "$CFDNS_INTEGRITY" "$(printf '.pinned = "%s" | .pinned_at = "%s" | .previous_pin = "%s"' \
    "$BUNDLE_HASH" "$(now_utc)" "${previous:-}")"
  ok "pinned $BUNDLE_HASH"
  [ -n "$previous" ] && [ "$previous" != "$BUNDLE_HASH" ] && info "previous pin: $previous"
  return 0
}

# Always a fresh hash, never the values integrity_check already computed. This exists
# precisely so an operator can ask the question again from scratch.
integrity_verify() {
  local root scan fresh pinned
  root="$(path_dir "$(resolve_path "${CF_ENTRY:-$0}")")"
  scan="$(bundle_scan "$root")"
  fresh="$(bundle_hash "$root" "$scan")"
  pinned="$(jq_get "$CFDNS_INTEGRITY" '.pinned')"

  printf 'fresh   %s\n' "$fresh"
  [ -n "$pinned" ] || { warn "nothing is pinned — run: cf integrity pin"; return 1; }
  [ "$fresh" = "$pinned" ] && { ok "matches the pin"; return 0; }
  die "MISMATCH — pinned $pinned"
}

integrity_diff() {
  integrity_check
  [ -f "$CFDNS_MANIFEST_PINNED" ] \
    || { warn "no pinned manifest — run: cf integrity pin"; return 1; }
  if diff -u --label pinned --label current \
       "$CFDNS_MANIFEST_PINNED" <(printf '%s\n' "$BUNDLE_MANIFEST"); then
    ok "no per-file differences"
  else
    printf '\n'
    warn "the files above differ from the pinned manifest"
    return 1
  fi
}
