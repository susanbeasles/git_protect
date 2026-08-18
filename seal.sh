# shellcheck shell=bash
# cf seal — report on the release seal without the fail-closed behaviour the banner
# applies. This is what an operator runs when the tool has refused to start.
cmd_seal() {
  printf '\n%s\n\n' "$(_c '1;37' 'RELEASE SEAL')"
  printf '  bundle            %s\n' "$BUNDLE_ROOT"
  printf '  manifest          %s\n' "$(seal_present && printf 'present' || printf 'absent')"
  printf '  signature         %s\n' \
    "$([ -f "$(seal_signature_path)" ] && printf 'present' || printf 'absent')"
  printf '  bundled key       %s\n' \
    "$([ -f "$(seal_pubkey_path)" ] && printf 'present' || printf 'absent')"
  printf '  expected key      %s\n' \
    "$(seal_fingerprint_pinned && printf '%s' "$SEAL_EXPECT_FINGERPRINT" || printf '<not compiled in>')"

  case "$SEAL_STATE" in
    SEALED)
      printf '  state             %s\n\n' "$(_c '0;32' 'SEALED — signature valid, all files match')"
      printf '  Every file in this bundle matches a manifest signed by the release key.\n'
      printf '  Verified on every invocation, not just at install time.\n\n'
      return 0 ;;
    UNSEALED)
      printf '  state             %s\n\n' "$(_c '1;33' 'UNSEALED — development build')"
      printf '  This bundle carries no signed manifest, so there is nothing to verify it\n'
      printf '  against. That is expected for a checkout and wrong for an install.\n\n'
      printf '  If you installed this from a release, it has been tampered with: the seal\n'
      printf '  files were removed. Reinstall.\n\n'
      return 1 ;;
    BROKEN)
      printf '  state             %s\n\n' "$(_c '1;31' 'BROKEN — do not trust this install')"
      printf '  %s\n\n' "${SEAL_ERROR:-the seal could not be verified}"
      printf '  Independent checks that do not rely on anything in this bundle:\n\n'
      printf '    gh attestation verify <tarball> --repo sonarmd/cfezcli\n'
      printf '    gh release verify-asset <tag> <asset> --repo sonarmd/cfezcli\n\n'
      return 2 ;;
  esac
}
