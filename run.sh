# shellcheck shell=bash
# Invoking the analyzer and the reporter. One concern — the boundary between the
# shell CLI and the Node analysis modules. Nothing here interprets findings.

analyzer() { run_node analyze.mjs "$@"; }
reporter() { run_node report.mjs "$@"; }

# analyse_zone <json {zone,records}> [analyzer-args...] -> findings JSON
analyse_zone() {
  local source="$1"; shift
  printf '%s' "$source" | analyzer "$@"
}

# analyse_record <api-body-json> <zone> -> findings JSON, record scope only
#
# Record scope is the point: zone-level checks are meaningless for one record. A
# lone MX record can never demonstrate that the zone has no SPF, because the SPF
# record is a different record.
analyse_record() {
  jq -n --argjson r "$1" --arg z "$2" '{zone:$z, records:[$r]}' \
    | analyzer --offline --scope record
}

findings_at_or_above() {
  local level="$1" json="$2"
  case "$level" in
    CRITICAL) jq '[.findings[] | select(.severity == "CRITICAL")]' <<<"$json" ;;
    HIGH)     jq '[.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")]' <<<"$json" ;;
    *)        jq '[.findings[] | select(.severity == $l)]' --arg l "$level" <<<"$json" ;;
  esac
}

severity_count() { jq -r --arg s "$1" '.stats.bySeverity[$s] // 0' <<<"$2"; }
