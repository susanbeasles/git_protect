# shellcheck shell=bash
# Reading from Cloudflare, plus snapshots. No mutations here.

# Read on first use rather than at startup: `cf integrity show` and `cf doctor` never
# need a zone, and an eager read cost them a jq process each.
zone_name() {
  if [ -z "${CFDNS_ZONE:-}" ]; then
    CFDNS_ZONE="$(jq_get "$CFDNS_CONFIG" '.zone')"
  fi
  printf '%s' "$CFDNS_ZONE"
}

zone_id() {
  local zone="${1:-$(zone_name)}"
  [ -n "$zone" ] || die "no zone set — run 'cf auth login', or pass --zone <zone>"
  local cached
  cached="$(jq_get "$CFDNS_CONFIG" ".zone_ids[\"$zone\"]")"
  if [ -n "$cached" ]; then printf '%s' "$cached"; return 0; fi
  local id
  id="$(cf_api_ok GET "/zones?name=$zone" | jq -r '.result[0].id // empty')" \
    || die "could not reach Cloudflare to look up zone '$zone'"
  [ -n "$id" ] || die "zone '$zone' not found — check the name, and that your token includes it"
  jq_set "$CFDNS_CONFIG" ".zone_ids[\"$zone\"] = \"$id\""
  printf '%s' "$id"
}

# Normalised live records. This shape is the contract every other module reads.
fetch_live() {
  local zone="${1:-$(zone_name)}" zid
  zid="$(zone_id "$zone")" || return 1
  cf_api_ok GET "/zones/$zid/dns_records?per_page=5000" | jq '
    [ .result[] | {
        id, name, type, content,
        ttl,
        proxied: (.proxied // false),
        comment: (.comment // ""),
        tags: ((.tags // []) | sort),
        priority: (.priority // null)
      } ] | sort_by(.type, .name, .content)'
}

# Snapshots are taken by lib/core/snapshot.sh, which knows nothing about Cloudflare.
# This is the whole Cloudflare-specific part: name the policy, and the policy names
# fetch_live as its capture command.
SNAPSHOT_POLICY_NAME="${CFDNS_SNAPSHOT_POLICY:-cloudflare-dns}"

# zone_snapshot <reason> -> path
zone_snapshot() {
  snapshot_take "$SNAPSHOT_POLICY_NAME" "${2:-$(zone_name)}" "$1"
}

zone_snapshot_list() {
  snapshot_list "$SNAPSHOT_POLICY_NAME" "${1:-}"
}

