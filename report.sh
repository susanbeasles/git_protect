# shellcheck shell=bash
# Emitting a report: format, redaction, and the warnings that go with each choice.
# One concern — getting findings in front of a human safely.

report_args() {
  local out="${REPORT_OUT:-}"
  printf '%s\n' --format "${REPORT_FORMAT:-text}" --redact "${REPORT_REDACT:-none}"
  [ "${REPORT_REDACT:-none}" != none ] && printf '%s\n' --keymap "${out:-report}.keymap.json"
  return 0
}

emit_report() {
  local result="$1" out="${REPORT_OUT:-}"
  local args=(); mapfile -t args < <(report_args)

  if [ -z "$out" ]; then
    printf '%s' "$result" | reporter "${args[@]}"
    return 0
  fi

  printf '%s' "$result" | reporter "${args[@]}" > "$out"
  chmod 600 "$out"
  ok "report written: $out"
  report_share_advice "$out"
}

# The advice is part of the feature. A redacted report the operator does not trust
# will not get shared, and an unredacted one they do trust is a disclosure.
report_share_advice() {
  local out="$1"
  if [ "${REPORT_REDACT:-none}" = none ]; then
    warn "UNREDACTED — contains DKIM keys, verification tokens, IPs, real hostnames."
    warn "Do not paste this into an LLM or a ticket. Re-run with --llm-safe."
    return 0
  fi
  printf '\n%s\n' "$(_c '1;32' 'This file is redacted and safe to upload.')"
  note "do NOT upload the .keymap.json beside it — that reverses the redaction"
  note "skim it first: grep -nEi 'p=[A-Za-z0-9+/]{40}|verification|([0-9]{1,3}\\.){3}' $out"
}
