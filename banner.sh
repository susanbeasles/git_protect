# shellcheck shell=bash
# Presentation of integrity state: the colour-coded hash, and the notification.
# Notify only — never blocks. The operator decides whether a change was theirs.

# Palette excludes red; red is reserved for a mismatch, so a healthy banner never
# renders red.
_PALETTE=(33 39 45 51 50 49 48 47 46 82 118 154 190 226 220 214 208 202
          171 177 141 105 69 75 81 87 120 156 192 228 165 129 93 57)

# Sets $_HUE. Deliberately not a command substitution: returning the colour on
# stdout forked 16 subshells per render, twice per invocation — 32 forks and
# ~160ms, more than the hashing itself.
_hue() { _HUE="${_PALETTE[$(( 16#${1} % ${#_PALETTE[@]} ))]}"; }

# Pure: builds a string and prints it. It used to memoise the result in two globals,
# which made it a function that both printed and mutated state — the shape that breaks
# under `$( )`. The colour lookup no longer forks, so the cache saved nothing.
render_hash() {
  local hash="$1" i out=""
  if _tty; then
    for ((i = 0; i < 64; i += 8)); do
      _hue "${hash:$i:2}"; out="${out}\033[48;5;${_HUE}m  \033[0m"
    done
    out="${out} "
    for ((i = 0; i < 64; i += 8)); do
      _hue "${hash:$i:2}"
      out="${out}\033[1;38;5;${_HUE}m${hash:$i:8}\033[0m"
      [ $((i + 8)) -lt 64 ] && out="${out}·"
    done
  else
    out=" "
    for ((i = 0; i < 64; i += 8)); do
      out="${out}${hash:$i:8}"; [ $((i + 8)) -lt 64 ] && out="${out}·"
    done
  fi
  printf '%b' "$out"
  return 0
}

integrity_banner() {
  [ -n "${CFDNS_NO_BANNER:-}" ] && return 0
  integrity_check
  seal_enforce

  printf 'cf build  '
  render_hash "$BUNDLE_HASH"
  case "$SEAL_STATE" in
    SEALED)   if _tty; then printf '  \033[1;32m🔒 sealed\033[0m'; else printf '  [sealed]'; fi ;;
    UNSEALED) if _tty; then printf '  \033[2munsealed build\033[0m'; else printf '  [unsealed]'; fi ;;
  esac
  case "$INTEGRITY_STATE" in
    PINNED)   if _tty; then printf '  \033[1;32m✓ pinned\033[0m'; else printf '  [pinned]'; fi ;;
    UNPINNED) if _tty; then printf '  \033[1;33m? unpinned\033[0m'; else printf '  [unpinned]'; fi ;;
    MISMATCH) if _tty; then printf '  \033[1;5;97;41m ✗ HASH MISMATCH \033[0m'; else printf '  [MISMATCH]'; fi ;;
  esac
  printf '\n'

  [ "$INTEGRITY_STATE" = MISMATCH ] && integrity_notify
  [ "$INTEGRITY_STATE" = UNPINNED ] && \
    warn "bundle hash is not pinned — run 'cf integrity pin' so future changes are detectable"

  local writable; writable="$(bundle_writable "$BUNDLE_SCAN")"
  if [ -n "$writable" ]; then
    warn "bundle files are group- or world-writable, which defeats tamper evidence:"
    printf '%s\n' "${writable%$'\n'}" >&2
    printf '  fix: chmod -R go-w %s\n' "$BUNDLE_ROOT" >&2
  fi
  return 0
}

integrity_notify() {
  local newest when_str
  newest="$(bundle_newest_write "$BUNDLE_ROOT" "$BUNDLE_SCAN")"
  when_str="$(epoch_to_local "$newest")"

  printf '\n' >&2
  if _tty 2; then printf '\033[1;31m' >&2; fi
  printf '  CLI CODE TAMPERING DETECTED\n' >&2
  if _tty 2; then printf '\033[0m' >&2; fi
  printf '  The bundle no longer matches its pinned hash.\n\n' >&2
  printf '    last write to the bundle   %s  (%s)\n' "$when_str" "$(humanise_age $(( $(now_epoch) - newest )))" >&2
  printf '    pinned                     %s\n' "$PINNED" >&2
  printf '    pinned at                  %s\n' "${PINNED_AT:--}" >&2
  printf '    running now                %s\n\n' "$BUNDLE_HASH" >&2
  if _tty 2; then printf '\033[1;33m' >&2; fi
  printf '  If you did not change this code at %s, something or someone else did.\n' "$when_str" >&2
  if _tty 2; then printf '\033[0m' >&2; fi
  printf '  Run  cf doctor  for the full evidentiary changelog. If those timestamps do\n' >&2
  printf '  not line up with changes you expected, treat this tool as COMPROMISED until\n' >&2
  printf '  you have reviewed the source, rebuilt, and re-pinned:  cf integrity pin\n\n' >&2
  printf '  Continuing anyway.\n\n' >&2
  return 0
}

# A broken seal stops the tool. This is the one condition that is not a warning: a
# bundle that carries a signature which does not verify has been modified since it was
# released, and running it anyway would defeat the entire point of shipping the
# signature. An unsealed build — a development checkout — is allowed with a notice,
# because refusing would make the tool undevelopable.
seal_enforce() {
  seal_check "$BUNDLE_MANIFEST"
  case "$SEAL_STATE" in
    SEALED) return 0 ;;
    UNSEALED)
      warn "unsealed build — no release signature to verify against"
      note "released builds carry a signed manifest that is checked on every run"
      return 0 ;;
  esac

  printf '\n' >&2
  if _tty 2; then printf '\033[1;5;97;41m BROKEN SEAL \033[0m\n' >&2
  else printf '  BROKEN SEAL\n' >&2; fi
  printf '\n  %s\n\n' "${SEAL_ERROR:-the release seal could not be verified}" >&2
  printf '  This bundle was released with a signed manifest. What is on disk now does\n' >&2
  printf '  not match it, so the code has been changed since it was signed.\n\n' >&2
  printf '  Refusing to run. Reinstall from a trusted source:\n\n' >&2
  printf '    curl --tls-max 1.3 --proto \x27=https\x27 -fsSL \\\n' >&2
  printf '      https://github.com/sonarmd/cfezcli/releases/latest/download/install.sh | bash\n\n' >&2
  printf '  To inspect without running anything:  cf seal --report\n\n' >&2
  exit 90
}
