# shellcheck shell=bash
# dns subcommands. Each is orchestration only: select, build a plan, hand it to
# apply_plan. No command talks to the write API, validates a field, or normalises a
# name itself — those live in lib/dns/.

cmd_dns_ls() {
  local records; records="$(fetch_live)"
  if [ -n "${SEL_TYPE:-}${SEL_NAME:-}${SEL_CONTENT:-}${SEL_TAGS:-}" ]; then
    records="$(printf '%s' "$records" | select_records)"
  fi
  printf '%s' "$records" | render_records
  printf '\n%s record(s)\n' "$(jq 'length' <<<"$records")"
}

cmd_dns_add() {
  [ -n "${REC_NAME+x}" ]    || die "--name is required (use @ for the zone apex)"
  [ -n "${REC_TYPE:-}" ]    || die "--type is required"
  [ -n "${REC_CONTENT:-}" ] || die "--content is required"

  validate_fields "$REC_TYPE" "${REC_TTL:-1}" "${REC_PRIORITY:-}" "${REC_PROXY:-}"

  local body
  body="$(record_body "$(fqdn "$REC_NAME" "$(zone_name)")" "$REC_TYPE" "$REC_CONTENT" \
            "${REC_TTL:-1}" "${REC_PROXY:-}" "${REC_COMMENT:-}" "${REC_TAGS:-}" "${REC_PRIORITY:-}")"

  record_is_publishable "$body" || die "record rejected — pass --force to publish anyway"

  apply_plan add "$(plan_of_creates "[$body]")" --yes-ok
}

cmd_dns_rm() {
  require_selector
  local hits; hits="$(fetch_live | select_records)"
  [ "$(jq 'length' <<<"$hits")" -gt 0 ] || die "no records matched that selection"
  apply_plan rm "$(plan_of_deletes "$hits")"
}

cmd_dns_update() {
  require_selector
  local hits; hits="$(fetch_live | select_records)"
  local n; n="$(jq 'length' <<<"$hits")"
  [ "$n" -gt 0 ] || die "no records matched that selection"

  reject_unsupported_fields "$hits"

  local patch; patch="$(build_patch)"
  [ "$patch" = '{}' ] && die "nothing to change — pass --set-content, --ttl, --proxy, --priority, --tags, or --comment"

  local plan; plan="$(plan_of_patch "$hits" "$patch")"
  if [ "$(jq '.update | length' <<<"$plan")" -eq 0 ]; then
    ok "all $n matched record(s) already have those values"; return 0
  fi

  # Validate the RESULT of the patch, not the patch: a bad end state is what matters.
  local row
  while IFS= read -r row; do
    record_is_publishable "$(jq -c '.to | del(.id)' <<<"$row")" \
      || die "the patched record would be invalid — pass --force to publish anyway"
  done < <(jq -c '.update[]' <<<"$plan")

  apply_plan update "$plan"
}

cmd_dns_sync() {
  local zone file; zone="$(zone_name)"; file="$(desired_path)"

  if [ -n "${SYNC_PULL:-}" ]; then
    desired_capture "$file" "$zone"
    ok "pulled $(jq '.records|length' "$file") record(s) into $file"
    return 0
  fi

  [ -f "$file" ] || die "no desired-state file at $file — create one, or run 'cf dns sync --pull'"

  local plan
  plan="$(jq -n --argjson live "$(fetch_live)" \
                --argjson desired "$(desired_load "$file" "$zone")" \
                -f "$CFDNS_LIB/dns/plan.jq")"
  apply_plan sync "$plan"
}

# Restore is sync against a snapshot rather than against masterDNS.json. The only
# extra step is translating the snapshot envelope into desired-state shape.
cmd_dns_restore() {
  [ -n "${MASTER_FILE:-}" ] || die "pass --file <snapshot>. List them with 'cf snapshots'."
  [ -f "$MASTER_FILE" ] || die "no such snapshot: $MASTER_FILE"

  local adapted; adapted="$(mktemp)"
  desired_from_snapshot "$MASTER_FILE" "$(zone_name)" > "$adapted" \
    || { rm -f "$adapted"; die "could not read $MASTER_FILE as a snapshot"; }
  MASTER_FILE="$adapted" cmd_dns_sync
  local rc=$?
  rm -f "$adapted"
  return "$rc"
}

cmd_dns_validate() {
  require_node
  local file; file="$(desired_path)"
  [ -f "$file" ] || die "no desired-state file at $file — run: cf dns sync --pull"
  desired_load "$file" "$(zone_name)" >/dev/null
  info "checking $file (offline — no DNS queries, nothing published)"
  analyse_zone "$(jq '{zone, records}' "$file")" --offline | reporter --format text
}

cmd_dns_doctor() {
  require_node
  local source
  if [ -n "${MASTER_FILE:-}" ]; then
    [ -f "$MASTER_FILE" ] || die "no such file: $MASTER_FILE"
    source="$(jq '{zone, records}' "$MASTER_FILE")"
    info "analysing file: $MASTER_FILE"
  else
    info "reading the live zone…"
    source="$(fetch_live | jq --arg z "$(zone_name)" '{zone:$z, records:.}')" || return 1
    ok "$(jq '.records | length' <<<"$source") record(s)"
  fi

  info "resolving SPF chains, DKIM selectors, MX targets, report authorisation…"
  local result; result="$(analyse_zone "$source")" || die "analysis failed"

  emit_report "$result"
  printf '\n'
  zone_exit_code "$result"
}
