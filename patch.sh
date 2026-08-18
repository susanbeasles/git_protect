# shellcheck shell=bash
# Building an update. One concern — turning the supplied flags into a patch, and
# refusing flags that cannot apply to the matched record types.

# build_patch -> a JSON object of the fields to change, {} if none were given.
# Uses ${VAR+x} rather than ${VAR:-} where an empty value is meaningful: clearing a
# comment or removing all tags are both legitimate edits.
build_patch() {
  local patch='{}'
  [ -n "${SET_CONTENT+x}" ]  && patch="$(jq -c --arg v "$SET_CONTENT" '.content = $v' <<<"$patch")"
  [ -n "${REC_TTL:-}" ]      && patch="$(jq -c --argjson v "$REC_TTL" '.ttl = $v' <<<"$patch")"
  [ -n "${REC_PROXY:-}" ]    && patch="$(jq -c --argjson v "$REC_PROXY" '.proxied = $v' <<<"$patch")"
  [ -n "${REC_PRIORITY:-}" ] && patch="$(jq -c --argjson v "$REC_PRIORITY" '.priority = $v' <<<"$patch")"
  [ -n "${REC_COMMENT+x}" ]  && patch="$(jq -c --arg v "${REC_COMMENT:-}" '.comment = $v' <<<"$patch")"
  [ -n "${REC_TAGS+x}" ]     && patch="$(jq -c --arg v "${REC_TAGS:-}" \
                                  '.tags = ($v | if . == "" then [] else split(",") end)' <<<"$patch")"
  printf '%s' "$patch"
}

# Reject a flag that cannot apply, rather than silently dropping it when the payload
# is shaped. Silently ignoring a flag the operator typed is its own bug.
reject_unsupported_fields() {
  local hits="$1" offending
  if [ -n "${REC_PROXY:-}" ] && [ "$REC_PROXY" != false ]; then
    offending="$(jq -r -L "$CFDNS_LIB/dns" 'include "api_body"; unsupported_types(proxyable)' <<<"$hits")"
    [ -n "$offending" ] && die "--proxy does not apply to $offending records; Cloudflare rejects it"
  fi
  if [ -n "${REC_PRIORITY:-}" ]; then
    offending="$(jq -r -L "$CFDNS_LIB/dns" 'include "api_body"; unsupported_types(prioritised)' <<<"$hits")"
    [ -n "$offending" ] && die "--priority does not apply to $offending records"
  fi
  return 0
}

# plan_of_patch <records> <patch> -> a plan containing only the records the patch
# would actually change. A record already holding the target values is not an update.
plan_of_patch() {
  jq -c --argjson p "$2" '
    { create: [], delete: [],
      update: [ .[] | {id, from: ., to: (. * $p)} ]
             | map(select((.from | del(.id)) != (.to | del(.id)))) }' <<<"$1"
}
