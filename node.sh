# shellcheck shell=bash
# Node runtime detection and invocation. The only place that knows the analyzer is
# implemented in JavaScript or what version it needs.

NODE_MIN_MAJOR=18

node_major() {
  command -v node >/dev/null 2>&1 || { printf '0'; return 1; }
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null || printf '0'
}

node_available() {
  local major; major="$(node_major)" || return 1
  [ "${major:-0}" -ge "$NODE_MIN_MAJOR" ]
}

require_node() {
  command -v node >/dev/null 2>&1 \
    || die "node $NODE_MIN_MAJOR+ is required for analysis, and was not found"
  node_available \
    || die "node $NODE_MIN_MAJOR+ is required, found $(node -v 2>/dev/null)"
}

# run_node <script-relative-to-lib> [args...]
run_node() {
  local script="$1"; shift
  node "$CFDNS_LIB/$script" "$@"
}
