# shellcheck shell=bash
# Credential storage. One backend interface, four implementations.
#
# The token is only ever held in a shell variable and handed to curl through a
# stdin config file (see http.sh), so it never appears in argv or /proc/*/cmdline.
# There is a test that proves this: test/leak.sh.

OP_VAULT="${CFDNS_OP_VAULT:-automation}"
OP_ITEM="${CFDNS_OP_ITEM:-cf-internalcli-token}"

secret_backend() { jq_get "$CFDNS_CONFIG" '.token_backend'; }

# Prints the token on stdout for capture ONLY. Never log the result.
secret_read() {
  case "$(secret_backend)" in
    op)
      require_cmd op "1Password CLI"
      op read "op://$OP_VAULT/$OP_ITEM/credential" 2>/dev/null \
        || die "1Password read failed — is 'op' signed in? Try: op signin, then cf auth status"
      ;;
    keychain)
      security find-generic-password -a "$USER" -s cfdns-token -w 2>/dev/null \
        || die "keychain lookup failed — run: cf auth login"
      ;;
    file)
      [ -f "$CFDNS_ROOT/token" ] || die "token file missing — run: cf auth login"
      cat "$CFDNS_ROOT/token"
      ;;
    env)
      [ -n "${CF_API_TOKEN:-}" ] || die "CF_API_TOKEN is not set in this shell — run: cf auth login"
      printf '%s' "$CF_API_TOKEN"
      ;;
    *)
      if [ -n "${CF_API_TOKEN:-}" ]; then printf '%s' "$CF_API_TOKEN"; return 0; fi
      die "no credential configured — run: cf auth login"
      ;;
  esac
}

secret_store_op() {
  local token="$1" expiry="$2"
  op vault get "$OP_VAULT" >/dev/null 2>&1 || {
    info "creating 1Password vault '$OP_VAULT'"
    op vault create "$OP_VAULT" >/dev/null || die "could not create vault"
  }
  local notes="Cloudflare API token used by the internal 'cf' DNS CLI.
Scope: Zone > DNS > Edit, restricted to a single zone. Nothing else.
Used by: cf dns add|rm|update|sync — manages SPF/DKIM/DMARC and all zone records.
Rotate: re-run 'cf auth login'. Revoke at dash.cloudflare.com/profile/api-tokens.
Owner: platform/infra. Do not reuse this token for anything else."

  local template
  template="$(jq -n --arg t "$token" --arg title "$OP_ITEM" --arg n "$notes" --arg e "$expiry" '{
    title: $title, category: "API_CREDENTIAL",
    fields: [
      {id:"credential", type:"CONCEALED", purpose:"PASSWORD", label:"credential", value:$t},
      {id:"notesPlain", type:"STRING", purpose:"NOTES", label:"notesPlain", value:$n},
      {label:"expires",  type:"STRING", value:$e},
      {label:"provider", type:"STRING", value:"Cloudflare"},
      {label:"scope",    type:"STRING", value:"Zone:DNS:Edit (single zone)"}
    ],
    tags: ["automation","cloudflare","dns","cli","infra"]
  }')"

  op item get "$OP_ITEM" --vault "$OP_VAULT" >/dev/null 2>&1 \
    && op item delete "$OP_ITEM" --vault "$OP_VAULT" >/dev/null
  printf '%s' "$template" | op item create --vault "$OP_VAULT" --template=- >/dev/null \
    || die "1Password write failed"
  jq_set "$CFDNS_CONFIG" '.token_backend = "op"'
  ok "stored in 1Password: op://$OP_VAULT/$OP_ITEM/credential"
}

secret_store_keychain() {
  security add-generic-password -U -a "$USER" -s cfdns-token \
    -l "cfdns CLI Cloudflare token" \
    -j "Zone:DNS:Edit token for the internal cf DNS CLI. Revoke at dash.cloudflare.com." \
    -w "$1" >/dev/null 2>&1 || die "keychain write failed"
  jq_set "$CFDNS_CONFIG" '.token_backend = "keychain"'
  ok "stored in the macOS Keychain (service: cfdns-token)"
  warn "the value passed through this process's argv briefly. 1Password avoids that."
}

secret_store_file() {
  printf '%s' "$1" | json_write "$CFDNS_ROOT/token"
  jq_set "$CFDNS_CONFIG" '.token_backend = "file"'
  ok "stored at $CFDNS_ROOT/token (0600)"
  warn "plaintext on disk. Any process running as you can read it."
}

secret_forget() {
  case "$(secret_backend)" in
    op)       info "leaving the 1Password item in place — delete it manually if rotating" ;;
    keychain) security delete-generic-password -a "$USER" -s cfdns-token >/dev/null 2>&1 \
                && ok "removed from keychain" ;;
    file)     rm -f "$CFDNS_ROOT/token" && ok "token file removed" ;;
  esac
  jq_set "$CFDNS_CONFIG" 'del(.token_backend) | del(.zone_ids)'
  ok "local credential mapping cleared"
  warn "the token is still VALID at Cloudflare. Revoke it: https://dash.cloudflare.com/profile/api-tokens"
}
