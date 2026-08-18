# shellcheck shell=bash
# Every constant here is consumed by other modules, so shellcheck sees them as
# unused when it analyses this file alone.
# shellcheck disable=SC2034
# Where things live. One root, owner-only. No ~/.local.
umask 077

if [ -z "${CFDNS_ROOT:-}" ]; then
  case "$(uname -s)" in
    Darwin) CFDNS_ROOT="$HOME/Library/Application Support/cfdns" ;;
    *)      CFDNS_ROOT="${XDG_CONFIG_HOME:-$HOME/.config}/cfdns" ;;
  esac
fi

CFDNS_SNAPSHOTS="$CFDNS_ROOT/snapshots"
CFDNS_CONFIG="$CFDNS_ROOT/config.json"
CFDNS_INTEGRITY="$CFDNS_ROOT/integrity.json"
CFDNS_INTEGRITY_LOG="$CFDNS_ROOT/integrity.log"
CFDNS_MANIFEST_LAST="$CFDNS_ROOT/manifest.last"
CFDNS_MANIFEST_PINNED="$CFDNS_ROOT/manifest.pinned"
CFDNS_MASTER_DEFAULT="./config/masterDNS.json"

# Created on first use only. `mkdir -p` and `chmod` on every invocation cost two
# processes to assert something that was already true.
if [ ! -d "$CFDNS_SNAPSHOTS" ]; then
  mkdir -p "$CFDNS_ROOT" "$CFDNS_SNAPSHOTS"
  chmod 700 "$CFDNS_ROOT" "$CFDNS_SNAPSHOTS" 2>/dev/null || true
fi
