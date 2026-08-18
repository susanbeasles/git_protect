# shellcheck shell=bash
# Turning findings into a decision. One concern — should this be allowed to proceed,
# and what should the operator be told. It does not run the analyzer.

# record_is_publishable <api-body-json> -> 0 if safe to publish
#
# Blocks on CRITICAL and HIGH only. MEDIUM is reported and allowed: a tool that
# refuses correct input gets routed around, and then it protects nothing.
record_is_publishable() {
  local body="$1" result blocking
  [ -n "${FORCE:-}" ] && return 0
  node_available || return 0        # analysis is a bonus, not a precondition

  result="$(analyse_record "$body" "$(zone_name)" 2>/dev/null)" || return 0

  blocking="$(findings_at_or_above HIGH "$result" | jq 'length')"
  if [ "$blocking" -gt 0 ]; then
    printf '\n%s\n' "$(_c '0;31' "$blocking problem(s) with this record:")"
    findings_at_or_above HIGH "$result" \
      | jq -r '.[] | "  \(.severity)  \(.code)  \(.title)\n      \(.remediation)"'
    return 1
  fi
  findings_at_or_above MEDIUM "$result" \
    | jq -r '.[] | "  note: \(.code) — \(.title)"' >&2
  return 0
}

# zone_exit_code <findings-json> -> 2 any critical, 1 any high, 0 otherwise.
# Shaped for CI: the caller can use it directly as an exit status.
zone_exit_code() {
  local json="$1" critical high
  critical="$(severity_count CRITICAL "$json")"
  high="$(severity_count HIGH "$json")"
  if [ "$critical" -gt 0 ]; then
    warn "$critical CRITICAL finding(s) — mail authentication is broken right now"
    return 2
  fi
  if [ "$high" -gt 0 ]; then warn "$high HIGH finding(s)"; return 1; fi
  ok "no critical or high findings"
  return 0
}
