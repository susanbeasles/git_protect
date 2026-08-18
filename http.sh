# shellcheck shell=bash
# Cloudflare HTTP transport: turn a method, path and body into a response.
#
# Retry policy lives in core/retry.sh; credential lookup in core/secret.sh. Nothing
# here sets a variable outside itself, so every function may be called inside `$( )`.
#
# The token is written to curl's stdin as a config file (`curl -K -`), so it never
# appears in argv and cannot be read from ps or /proc/<pid>/cmdline.

CF_API="${CFDNS_API:-https://api.cloudflare.com/client/v4}"

# Statuses worth another attempt: rate limiting, server faults, and 000, which curl
# reports for a connection that never completed.
http_should_retry() {
  local scratch="$1"
  case "$(retry_scratch_read "$scratch" status)" in
    429|500|502|503|504|000) return 0 ;;
    *) return 1 ;;
  esac
}

# http_attempt <scratch> <method> <path> [body] <token>
# Writes body/status/retry_after into the scratch directory.
http_attempt() {
  local scratch="$1" method="$2" path="$3" data="$4" token="$5"
  local headers raw status

  headers="$scratch/headers"
  local args=(-sS -X "$method" -D "$headers" -w '\n%{http_code}' -K - "$CF_API$path")
  [ -n "$data" ] && args+=(--data-binary "$data")

  raw="$(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$token" \
         | curl "${args[@]}" 2>/dev/null)" || raw=$'\n000'

  status="${raw##*$'\n'}"
  printf '%s' "${raw%$'\n'*}" > "$scratch/body"
  printf '%s' "$status" > "$scratch/status"
  grep -i '^retry-after:' "$headers" 2>/dev/null | tr -d '\r' | awk '{print $2}' | head -1 \
    > "$scratch/retry_after"

  case "$status" in 2*) return 0 ;; *) return 1 ;; esac
}

# cf_api <METHOD> <path> [json-body] -> response body on stdout
cf_api() {
  local token scratch rc=0 status
  token="$(secret_read)" || return 1
  scratch="$(mktemp -d)" || return 1

  with_retry "$scratch" http_should_retry http_attempt "$1" "$2" "${3:-}" "$token" || rc=$?
  cat "$scratch/body" 2>/dev/null
  status="$(retry_scratch_read "$scratch" status)"
  rm -rf "$scratch"

  [ "$rc" -eq 0 ] && return 0
  case "$status" in
    401|403) warn "Cloudflare rejected the credential (HTTP $status). Check: cf auth status" ;;
  esac
  return 1
}

# As cf_api, but also asserts Cloudflare's own success flag: the API returns 200 with
# success:false for some errors, so the status code alone is not enough.
cf_api_ok() {
  local out
  out="$(cf_api "$@")" || { [ -n "$out" ] && cf_api_errors "$out"; return 1; }
  if [ "$(jq -r '.success' <<<"$out" 2>/dev/null)" != "true" ]; then
    cf_api_errors "$out"
    return 1
  fi
  printf '%s' "$out"
}

# Cloudflare's messages are more specific than the status code, so surface them.
# Note the ordering: `2>/dev/null >&2` would point stdout at the /dev/null that stderr
# was just sent to, discarding every message.
cf_api_errors() {
  local parsed
  parsed="$(jq -r '.errors[]? | "  cloudflare \(.code): \(.message)"' <<<"$1" 2>/dev/null)"
  if [ -n "$parsed" ]; then printf '%s\n' "$parsed" >&2
  else printf '  cloudflare returned an unparseable response\n' >&2; fi
}

# A no-op credential check, used by auth status and login verification.
cf_verify_token() {
  local out
  out="$(printf 'header = "Authorization: Bearer %s"\n' "$1" \
        | curl -sS -K - "$CF_API/user/tokens/verify" 2>/dev/null)" || return 1
  [ "$(jq -r '.success' <<<"$out" 2>/dev/null)" = "true" ] || return 1
  [ "$(jq -r '.result.status' <<<"$out" 2>/dev/null)" = "active" ] || return 1
  printf '%s' "$out"
}
