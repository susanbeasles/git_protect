# shellcheck shell=bash
# cf doctor — evidentiary changelog for the CLI's own code.
# Distinct from `cf dns doctor`, which analyses the zone.
cmd_doctor() {
  integrity_check
  local newest; newest="$(bundle_newest_write "$BUNDLE_ROOT" "$BUNDLE_SCAN")"

  printf '\n%s\n\n' "$(_c '1;37' 'CLI CODE INTEGRITY — EVIDENTIARY CHANGELOG')"
  printf '  bundle            %s\n' "$BUNDLE_ROOT"
  printf '  files hashed      %s\n' "$BUNDLE_FILES"
  printf '  running hash      %s\n' "$BUNDLE_HASH"
  printf '  pinned hash       %s\n' "${PINNED:-<none>}"
  printf '  pinned at         %s\n' "${PINNED_AT:--}"
  printf '  last bundle write %s\n' "$(epoch_to_local "$newest")"
  printf '  hashing           every invocation, no cache\n'
  case "$INTEGRITY_STATE" in
    PINNED)   printf '  state             %s\n' "$(_c '0;32' 'MATCHES PIN')" ;;
    UNPINNED) printf '  state             %s\n' "$(_c '1;33' 'UNPINNED — nothing to compare against')" ;;
    MISMATCH) printf '  state             %s\n' "$(_c '1;31' 'DOES NOT MATCH PIN')" ;;
  esac
  printf '  log               %s\n' "$CFDNS_INTEGRITY_LOG"

  changelog_render

  doctor_verdict
}

doctor_verdict() {
  case "$INTEGRITY_STATE" in
    PINNED)
      printf '  %s\n\n' "$(_c '0;32' 'Running code matches the pinned hash.')"
      return 0 ;;
    UNPINNED)
      printf '  Nothing is pinned, so no change can be detected. Run: cf integrity pin\n\n'
      return 0 ;;
  esac

  printf '%s\n\n' "$(_c '1;31' '  VERDICT: the running code is not the code you pinned.')"
  printf '  Cross-check each timestamp above against your own edits:\n'
  printf '    - Was anything written when you were not working on this?\n'
  printf '    - Does "inode changed" sit LATER than "written"? That means someone edited\n'
  printf '      a file and then back-dated its mtime. ctime cannot be forged without root,\n'
  printf '      so a later ctime is deliberate concealment.\n'
  printf '    - Are there ADDED files you did not create?\n\n'
  printf '  If anything looks wrong, treat this install as compromised:\n'
  printf '    1. stop running commands that use live credentials\n'
  printf '    2. revoke the token: https://dash.cloudflare.com/profile/api-tokens\n'
  printf '    3. git status / git diff in %s, or re-clone from source\n' "$BUNDLE_ROOT"
  printf '    4. review, then re-pin:  cf integrity pin\n\n'
  printf '  Per-file diff against the pinned manifest:  cf integrity diff\n\n'

  local backdated; backdated="$(changelog_backdated)"
  if [ -n "$backdated" ]; then
    printf '%s\n' "$(_c '1;31' '  BACK-DATED WRITES DETECTED (mtime older than ctime):')"
    printf '%s\n\n' "$backdated"
    printf '  A normal edit moves mtime and ctime together. These files had mtime pushed\n'
    printf '  backwards after the write, which is what a deliberate cover-up looks like.\n\n'
  fi
  return 0
}
