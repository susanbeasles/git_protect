# shellcheck shell=bash
# Selecting records to act on. The guard against over-broad matches lives here,
# in the caller's shell, so `die` actually aborts.

# Refuses selections that would sweep the zone. Called by every destructive path.
require_selector() {
  local n=0
  [ -n "${SEL_NAME:-}" ]    && n=$((n+1))
  [ -n "${SEL_CONTENT:-}" ] && n=$((n+1))
  [ -n "${SEL_TAGS:-}" ]    && n=$((n+1))
  [ -n "${SEL_ID:-}" ]      && n=$((n+1))

  if [ "$n" -eq 0 ] && [ -z "${SEL_TYPE:-}" ]; then
    die "refusing to match every record in the zone. Narrow with --name, --type, --content, --tags, or --id."
  fi
  if [ "$n" -eq 0 ]; then
    die "--type alone would match every $SEL_TYPE record in the zone. Add --name, --content, or --tags."
  fi
}

# select_records <records-json> -> matching subset. Filters AND together.
select_records() {
  local zone; zone="$(zone_name)"
  local filter='.'
  [ -n "${SEL_ID:-}" ]      && filter="$filter | map(select(.id == \$id))"
  [ -n "${SEL_NAME:-}" ]    && filter="$filter | map(select(.name == \$fq))"
  [ -n "${SEL_TYPE:-}" ]    && filter="$filter | map(select(.type == \$type))"
  [ -n "${SEL_CONTENT:-}" ] && filter="$filter | map(select(.content | ascii_downcase | contains(\$content | ascii_downcase)))"
  [ -n "${SEL_TAGS:-}" ]    && filter="$filter | map(select(.tags as \$t | (\$tags | split(\",\")) | all(. as \$x | \$t | index(\$x))))"

  jq --arg id "${SEL_ID:-}" \
     --arg fq "$(fqdn "${SEL_NAME:-}" "$zone")" \
     --arg type "${SEL_TYPE:-}" \
     --arg content "${SEL_CONTENT:-}" \
     --arg tags "${SEL_TAGS:-}" \
     "$filter"
}
