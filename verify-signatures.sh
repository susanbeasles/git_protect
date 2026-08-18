#!/usr/bin/env bash
# Assert that every commit in a range is signed by a key GitHub trusts.
#
# Why the API and not `git verify-commit`: locally, git only knows the keys in the
# runner's keyring, which is empty. GitHub's commit API returns a `verification`
# object computed against the keys the *author registered on their GitHub account*.
# That is the property we actually want — "signed by a trusted signature registered
# in GitHub" — and it cannot be checked with git alone.
#
#   scripts/verify-signatures.sh --repo owner/name --range BASE..HEAD
#   scripts/verify-signatures.sh --repo owner/name --sha <sha>
#
# Requires: gh (authenticated), jq.
# Exit 0 only if EVERY commit is verified. Any unverified commit fails the gate.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-}"
RANGE=""
SINGLE=""
ALLOW_BOT_AUTHORS="${ALLOW_BOT_AUTHORS:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)  REPO="$2"; shift 2 ;;
    --range) RANGE="$2"; shift 2 ;;
    --sha)   SINGLE="$2"; shift 2 ;;
    *) echo "verify-signatures.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

die() { printf '\nsignature gate: %s\n' "$*" >&2; exit 1; }
[ -n "$REPO" ] || die "--repo owner/name is required"
command -v gh >/dev/null 2>&1 || die "gh CLI is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

# Reasons GitHub gives that we accept. Everything else is a failure.
#   valid                 signed, key registered, trusted
#   bot_signature_valid   signed by GitHub on behalf of an App (our own bot)
ACCEPTABLE='valid bot_signature_valid'

acceptable() {
  case " $ACCEPTABLE " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

# Human-readable explanation for the common failure reasons, so a developer whose
# PR is blocked knows what to do instead of guessing.
explain() {
  case "$1" in
    unsigned)              printf 'not signed at all — configure commit signing and re-sign' ;;
    unknown_key)           printf 'signed with a key that is not registered on the author GitHub account' ;;
    unverified_email)      printf 'the signing identity email is not a verified email on the author account' ;;
    expired_key)           printf 'the signing key has expired' ;;
    not_signing_key)       printf 'the key is registered but not marked as a signing key' ;;
    invalid)               printf 'the signature does not match the commit contents' ;;
    malformed_signature)   printf 'the signature could not be parsed' ;;
    gpgverify_unavailable) printf 'GitHub could not verify right now — re-run the job' ;;
    ocsp_pending)          printf 'certificate check still pending — re-run the job' ;;
    *)                     printf '%s' "$1" ;;
  esac
}

collect_shas() {
  if [ -n "$SINGLE" ]; then printf '%s\n' "$SINGLE"; return; fi
  [ -n "$RANGE" ] || die "--range BASE..HEAD or --sha <sha> is required"
  # No-merges: a merge commit created by GitHub is signed by GitHub, but its
  # parents are what carry the actual changes.
  git rev-list --no-merges "$RANGE"
}

shas="$(collect_shas)"
if [ -z "$shas" ]; then
  printf 'signature gate: no commits in range — nothing to verify\n'
  exit 0
fi

total=0; bad=0
printf 'signature gate: checking %s commit(s) in %s\n\n' "$(printf '%s\n' "$shas" | wc -l | tr -d ' ')" "$REPO"

while IFS= read -r sha; do
  [ -z "$sha" ] && continue
  total=$((total + 1))

  # One API call per commit. Fine at PR scale; a 500-commit PR is its own problem.
  json="$(gh api "repos/$REPO/commits/$sha" 2>/dev/null)" || {
    printf '  %s  FAIL  could not fetch commit from the API\n' "${sha:0:12}"
    bad=$((bad + 1)); continue
  }

  verified="$(jq -r '.commit.verification.verified' <<<"$json")"
  reason="$(jq -r '.commit.verification.reason' <<<"$json")"
  author="$(jq -r '.commit.author.name // "unknown"' <<<"$json")"
  login="$(jq -r '.author.login // "—"' <<<"$json")"
  subject="$(jq -r '.commit.message' <<<"$json" | head -1)"

  if [ "$verified" = true ] && acceptable "$reason"; then
    printf '  %s  ok    %-18s %s\n' "${sha:0:12}" "$login" "${subject:0:56}"
  else
    printf '  %s  FAIL  %-18s %s\n' "${sha:0:12}" "$login" "${subject:0:56}"
    printf '                      reason: %s — %s\n' "$reason" "$(explain "$reason")"
    printf '                      author: %s\n' "$author"
    bad=$((bad + 1))
  fi
done <<< "$shas"

printf '\n'
if [ "$bad" -gt 0 ]; then
  cat >&2 <<EOF
signature gate: FAILED — $bad of $total commit(s) are not verifiably signed.

Every commit that reaches main must be signed with a key registered on the
author's GitHub account. To fix an existing branch:

  # one-time setup (SSH signing is simplest)
  git config --global gpg.format ssh
  git config --global user.signingkey ~/.ssh/id_ed25519.pub
  git config --global commit.gpgsign true
  # then register the PUBLIC key at:
  #   https://github.com/settings/keys  ->  New SSH key  ->  type: Signing Key

  # re-sign the commits already on this branch
  git rebase --exec 'git commit --amend --no-edit -S' origin/main
  git push --force-with-lease

EOF
  exit 1
fi

printf 'signature gate: PASSED — all %s commit(s) verified\n' "$total"
