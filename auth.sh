# shellcheck shell=bash
# cf auth — token acquisition, verification, removal.

# Least privilege for this tool: Zone > DNS > Edit, nothing else.
AUTH_PERMISSIONS='[{"key":"dns","type":"edit"}]'
AUTH_TOKEN_NAME='cfdns-cli (DNS edit, single zone)'

# Cloudflare API tokens have no documented prefix (unlike ghp_ or sk-), so the
# only structural property is the charset. This finds CANDIDATES; the real gate is
# a live /user/tokens/verify call.
AUTH_TOKEN_PATTERN='^[A-Za-z0-9_-]{37,64}$'

auth_token_url() {
  local perms name
  perms="$(jq -rn --arg s "$AUTH_PERMISSIONS" '$s|@uri')"
  name="$(jq -rn --arg s "$AUTH_TOKEN_NAME" '$s|@uri')"
  printf 'https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%s&accountId=%%2A&zoneId=all&name=%s' \
    "$perms" "$name"
}

auth_open() {
  if   command -v open     >/dev/null 2>&1; then open "$1"
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$1"
  else warn "could not open a browser automatically — the URL is above"; fi
}

cmd_auth_status() {
  local backend token result
  backend="$(secret_backend)"
  printf 'backend   %s\n' "${backend:-<none>}"
  printf 'zone      %s\n' "$(zone_name || echo '<none>')"
  printf 'store     %s\n' "$CFDNS_ROOT"

  if ! token="$(secret_read 2>/dev/null)"; then
    warn "no usable credential — run: cf auth login"; return 1
  fi
  if result="$(cf_verify_token "$token")"; then
    ok "token is active"
    jq -r '"expires   \(.result.expires_on // "never")\nid        \(.result.id)"' <<<"$result"
    return 0
  fi
  warn "Cloudflare rejected the stored token. It may be expired or revoked."
  note "re-run: cf auth login"
  return 1
}

# Watch the clipboard for a token. Charset match finds a candidate; the verify
# call decides. Clears the clipboard on success.
auth_clipboard_watch() {
  command -v pbpaste >/dev/null 2>&1 || return 1
  local seen="" current tries=0
  info "watching the clipboard — copy the token and it will be picked up"
  note "ctrl-c to cancel, 180s timeout"
  while [ "$tries" -lt 360 ]; do
    current="$(pbpaste 2>/dev/null | tr -d '[:space:]')"
    if [ -n "$current" ] && [ "$current" != "$seen" ]; then
      seen="$current"
      if printf '%s' "$current" | grep -qE "$AUTH_TOKEN_PATTERN"; then
        printf '\r    candidate found, verifying with Cloudflare…            \n'
        if cf_verify_token "$current" >/dev/null; then
          printf '%s' "$current"
          pbcopy </dev/null 2>/dev/null || true
          return 0
        fi
        warn "that looked like a token but Cloudflare rejected it — still watching"
      fi
    fi
    printf '\r    waiting… %ss ' "$((tries / 2))"
    sleep 0.5; tries=$((tries + 1))
  done
  printf '\n'
  return 1
}

cmd_auth_login() {
  if cmd_auth_status >/dev/null 2>&1; then
    ok "already authenticated"; cmd_auth_status; return 0
  fi

  printf '\n%s\n\n' "$(_c '1;37' 'A Cloudflare API token is needed. Required settings:')"
  printf '    Permissions      Zone -> DNS -> Edit        (the only one needed)\n'
  printf '    Zone Resources   Include -> Specific zone -> your zone\n'
  printf '    Client IP        your VPN or office egress CIDR  (recommended)\n'
  printf '    TTL              90 days or less\n\n'
  printf '  [1] Easy    open the browser with the permissions pre-filled\n'
  printf '  [2] Manual  paste a token you already have\n\n'
  printf 'Choose [1/2]: '
  local choice token=""; read -r choice

  if [ "$choice" = 1 ]; then
    local url; url="$(auth_token_url)"
    info "opening: $url"
    auth_open "$url"
    printf '\n  Permissions are pre-filled. Zone Resources, Client IP, and TTL still\n'
    printf '  need setting by hand — Cloudflare cannot pre-fill those.\n\n'
    token="$(auth_clipboard_watch)" || token=""
  fi

  if [ -z "$token" ]; then
    printf '\nPaste the token (input hidden): '
    read -rs token; printf '\n'
    [ -n "$token" ] || die "nothing pasted"
    printf '%s' "$token" | grep -qE "$AUTH_TOKEN_PATTERN" \
      || warn "that does not look like a Cloudflare token — verifying anyway"
    cf_verify_token "$token" >/dev/null || die "Cloudflare rejected that token"
  fi
  ok "verified against Cloudflare (/user/tokens/verify)"

  local expiry
  expiry="$(cf_verify_token "$token" | jq -r '.result.expires_on // "unset"')"

  if command -v op >/dev/null 2>&1 && op whoami >/dev/null 2>&1; then
    secret_store_op "$token" "$expiry"
  else
    auth_choose_fallback "$token"
  fi
  token=""; unset token

  local zone; zone="$(zone_name)"
  if [ -z "$zone" ]; then printf 'Default zone (e.g. example.com): '; read -r zone; fi
  jq_set "$CFDNS_CONFIG" ".zone = \"$zone\""
  # shellcheck disable=SC2034  # read by lib/dns/query.sh via zone_name()
  CFDNS_ZONE="$zone"
  zone_id "$zone" >/dev/null && ok "zone $zone resolved and cached"

  printf '\n'
  ok "ready"
  note "next:  cf dns sync --pull     then     cf dns doctor"
  note "also:  cf integrity pin       so code changes become detectable"
}

auth_choose_fallback() {
  local token="$1"
  warn "1Password CLI is not available or not signed in."
  warn "The remaining options are all weaker. Least bad first:"
  printf '  [1] macOS Keychain   encrypted at rest, per-user\n'
  printf '  [2] env var only     never written to disk, dies with the shell\n'
  printf '  [3] file on disk     0600 in %s  (discouraged)\n' "$CFDNS_ROOT"
  printf '  [n] abort and set up 1Password first\n\n'
  printf 'Choose [1/2/3/n]: '
  local choice; read -r choice
  case "$choice" in
    1) command -v security >/dev/null 2>&1 || die "no macOS keychain available here"
       secret_store_keychain "$token" ;;
    2) jq_set "$CFDNS_CONFIG" '.token_backend = "env"'
       printf '\n  Run this in your shell — nothing is being saved:\n\n'
       printf '    export CF_API_TOKEN=<paste-your-token>\n\n'
       warn "no secret was printed; paste it yourself" ;;
    3) secret_store_file "$token" ;;
    *) die "aborted — nothing was stored" ;;
  esac
}

cmd_auth_logout() { secret_forget; }
