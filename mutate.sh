# shellcheck shell=bash
# THE single path that changes DNS.
#
# Every mutating command — add, rm, update, sync, restore — builds a plan and
# hands it here. Nothing else calls the write API. That means the safety
# properties only have to be correct once, and a reviewer only has to read one
# function to know what can happen to their zone:
#
#   1. preview every change, in full
#   2. snapshot the live zone to disk, BEFORE prompting
#   3. require explicit confirmation (unless the plan is non-destructive and
#      --yes was given)
#   4. apply in the order delete -> update -> create
#   5. print the rollback command
#
# Plan shape:
#   { create: [record...],
#     update: [{id, from: record, to: record}...],
#     delete: [record...] }          records include .id for update/delete

plan_counts() { jq -r '"\(.create|length) \(.update|length) \(.delete|length)"' <<<"$1"; }

plan_is_empty() {
  local a b d
  read -r a b d <<<"$(plan_counts "$1")"
  [ $((a + b + d)) -eq 0 ]
}

plan_is_destructive() {
  local a b d
  read -r a b d <<<"$(plan_counts "$1")"
  [ $((b + d)) -gt 0 ]
}

# Human preview. Deletes and updates first: those are the ones that can hurt.
plan_preview() {
  local plan="$1" a b d
  read -r a b d <<<"$(plan_counts "$plan")"

  printf '\n%s\n' "$(_c '1;37' "plan for zone $(zone_name)")"
  printf '  delete %s   update %s   create %s\n' "$d" "$b" "$a"

  if [ "$d" -gt 0 ]; then
    printf '\n%s  %s record(s) — permanently removed\n' "$(_c '0;31' 'DELETE')" "$d"
    jq '.delete' <<<"$plan" | render_records
  fi
  if [ "$b" -gt 0 ]; then
    printf '\n%s  %s record(s) — patched in place, never removed and re-added\n' \
      "$(_c '1;33' 'UPDATE')" "$b"
    jq -r '.update[] |
      "  " + (.to.type + "      ")[0:6] + "  " + .to.name
      + (if .from.content != .to.content then
           "\n      - " + .from.content + "\n      + " + .to.content else "" end)
      + (if (.from|{ttl,proxied,comment,tags,priority}) != (.to|{ttl,proxied,comment,tags,priority}) then
           "\n      - ttl=" + (.from.ttl|tostring)
           + (if .from.proxied then " proxied" else "" end)
           + (if ((.from.priority // null) != null) then " prio=" + (.from.priority|tostring) else "" end)
           + " tags=" + ((.from.tags // [])|join(",")) + " # " + (.from.comment // "")
           + "\n      + ttl=" + (.to.ttl|tostring)
           + (if .to.proxied then " proxied" else "" end)
           + (if ((.to.priority // null) != null) then " prio=" + (.to.priority|tostring) else "" end)
           + " tags=" + ((.to.tags // [])|join(",")) + " # " + (.to.comment // "")
         else "" end)' <<<"$plan"
  fi
  if [ "$a" -gt 0 ]; then
    printf '\n%s  %s record(s)\n' "$(_c '0;32' 'CREATE')" "$a"
    jq '.create' <<<"$plan" | render_records
  fi
}

confirm_or_die() {
  local prompt="$1"
  if [ -n "${CFDNS_ASSUME_YES:-}" ]; then
    warn "auto-confirmed via CFDNS_ASSUME_YES"; return 0
  fi
  if ! _tty 0; then
    die "refusing to apply without confirmation on a non-interactive shell (set CFDNS_ASSUME_YES=1 to override)"
  fi
  printf '\n%s\n' "$(_c '1;33' "$prompt")"
  printf 'Type %s to proceed: ' "$(_c '1;37' 'yes')"
  local answer; read -r answer
  [ "$answer" = "yes" ] || die "aborted — nothing was changed"
}

# apply_plan <reason> <plan-json> [--yes-ok]
# --yes-ok permits --yes to skip confirmation. Never passed for destructive plans.
apply_plan() {
  local reason="$1" plan="$2" yes_ok="${3:-}"

  if plan_is_empty "$plan"; then ok "nothing to do — zone already matches"; return 0; fi

  plan_preview "$plan"

  if [ -n "${DRY_RUN:-}" ]; then
    printf '\n%s\n' "$(_c '1;36' 'DRY RUN — nothing was changed. Re-run with --apply to execute.')"
    return 0
  fi

  local snap; snap="$(zone_snapshot "$reason")"
  printf '\n'; ok "snapshot written before any change: $snap"

  local a b d; read -r a b d <<<"$(plan_counts "$plan")"
  if [ "$yes_ok" = "--yes-ok" ] && [ -n "${ASSUME_YES:-}" ] && ! plan_is_destructive "$plan"; then
    note "proceeding without prompt (--yes, and this plan only creates records)"
  else
    confirm_or_die "Apply $d delete(s), $b update(s), $a create(s) to $(zone_name)?"
  fi

  local zid; zid="$(zone_id)"
  local row rc=0

  # Deletes first: clears duplicate-record PermErrors before anything else moves.
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    if cf_api_ok DELETE "/zones/$zid/dns_records/$(jq -r '.id' <<<"$row")" >/dev/null; then
      printf '    %s %s %s\n' "$(_c '0;31' '-')" "$(jq -r .type <<<"$row")" "$(jq -r .name <<<"$row")"
    else
      warn "delete failed: $(jq -r '.type + " " + .name' <<<"$row")"; rc=1
    fi
  done < <(jq -c '.delete[]' <<<"$plan")

  # Updates are PUT in place, so a record is never briefly absent. That matters:
  # delete-then-create on an SPF record leaves a window with no SPF at all.
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    local id body
    id="$(jq -r '.id' <<<"$row")"
    body="$(jq -c -L "$CFDNS_LIB/dns" 'include "api_body"; .to | api_body' <<<"$row")"
    if cf_api_ok PUT "/zones/$zid/dns_records/$id" "$body" >/dev/null; then
      printf '    %s %s %s\n' "$(_c '1;33' '~')" "$(jq -r .to.type <<<"$row")" "$(jq -r .to.name <<<"$row")"
    else
      warn "update failed: $(jq -r '.to.type + " " + .to.name' <<<"$row")"; rc=1
    fi
  done < <(jq -c '.update[]' <<<"$plan")

  while IFS= read -r row; do
    [ -z "$row" ] && continue
    local body
    body="$(jq -c -L "$CFDNS_LIB/dns" 'include "api_body"; del(._i, .id) | api_body' <<<"$row")"
    if cf_api_ok POST "/zones/$zid/dns_records" "$body" >/dev/null; then
      printf '    %s %s %s\n' "$(_c '0;32' '+')" "$(jq -r .type <<<"$row")" "$(jq -r .name <<<"$row")"
    else
      warn "create failed: $(jq -r '.type + " " + .name' <<<"$row")"; rc=1
    fi
  done < <(jq -c '.create[]' <<<"$plan")

  printf '\n'
  if [ "$rc" -eq 0 ]; then ok "applied"; else warn "applied with errors — see above"; fi
  note "roll back with:  cf dns restore --file '$snap' --apply"
  return "$rc"
}

# Constructors so callers never hand-build plan JSON.
plan_of_deletes() { jq -c '{create: [], update: [], delete: .}' <<<"$1"; }
plan_of_creates() { jq -c '{create: ., update: [], delete: []}' <<<"$1"; }
plan_of_updates() { jq -c '{create: [], update: ., delete: []}' <<<"$1"; }
