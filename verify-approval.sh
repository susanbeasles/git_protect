#!/usr/bin/env bash
# Authenticate an integration approval, and verify CI independently of it.
#
# THE THREAT THIS EXISTS FOR
#
# `pull_request` workflows run the workflow definition from the PULL REQUEST'S OWN
# HEAD, and for same-repository branches those runs receive the repository secrets.
# A pull request can therefore modify the very workflow that is supposed to gate it:
# delete the signature check, then mint its own approval comment.
#
# So the merge step cannot trust the approval comment on its face. Two independent
# controls are needed:
#
#   1. Provenance of the marker. GitHub records which GitHub App created a comment
#      in `performed_via_github_app.id`. That field cannot be set by another app, by
#      `github-actions[bot]`, or by a user. Checking `user.type == "Bot"` is NOT
#      sufficient — every bot in the repository satisfies it, `github-actions[bot]`
#      included, and any workflow can post as that.
#
#   2. Evidence that CI actually ran. The check runs for the integration commit are
#      queried directly, so a forged comment claiming success is contradicted by the
#      Checks API. A tampered workflow can lie in a comment; it cannot retroactively
#      invent a successful check run under a name it did not execute.
#
# Neither control is sufficient alone. A workflow modified by a pull request holds
# the app token and could satisfy (1); it would still have to produce genuinely
# passing checks under the expected names for (2), and `--require-untouched` below
# refuses the whole class of change outright.
#
#   verify-approval.sh --repo O/R --pr N --app-id ID [--require-check NAME]...
#                      [--require-untouched GLOB]...
#
# On success prints `sha=<approved integration sha>` and `payload=<digest>`.
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-}"
PR=""; APP_ID=""
REQUIRED_CHECKS=(); PROTECTED_PATHS=()
MARKER='<!-- integration-approval -->'

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)              REPO="$2"; shift 2 ;;
    --pr)                PR="$2"; shift 2 ;;
    --app-id)            APP_ID="$2"; shift 2 ;;
    --require-check)     REQUIRED_CHECKS+=("$2"); shift 2 ;;
    --require-untouched) PROTECTED_PATHS+=("$2"); shift 2 ;;
    *) echo "verify-approval.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

die()  { printf '\nAPPROVAL REJECTED: %s\n' "$*" >&2; exit 1; }
pass() { printf '  ok    %s\n' "$*"; }
info() { printf '  note  %s\n' "$*"; }

[ -n "$REPO" ]   || die "--repo is required"
[ -n "$PR" ]     || die "--pr is required"
[ -n "$APP_ID" ] || die "--app-id is required (the integration app's numeric id)"
command -v gh >/dev/null 2>&1 || die "gh CLI is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

printf 'authenticating the integration approval for PR #%s\n\n' "$PR"

# ---------------------------------------------------------------- 1. provenance
comments="$(gh api "repos/$REPO/issues/$PR/comments" --paginate)" \
  || die "could not read the pull request comments"

approval="$(jq -c --arg m "$MARKER" \
  '[.[] | select(.body | contains($m))] | last // empty' <<<"$comments")"
[ -n "$approval" ] || die "no integration approval marker found — the gate has not passed"

# How many claim to be approvals? More than one is suspicious in itself: the gate
# edits a single comment rather than posting new ones.
claims="$(jq --arg m "$MARKER" '[.[] | select(.body | contains($m))] | length' <<<"$comments")"
[ "$claims" -le 1 ] || info "$claims comments carry the marker; only the last is considered"

via_app_id="$(jq -r '.performed_via_github_app.id // empty' <<<"$approval")"
author="$(jq -r '.user.login // "?"' <<<"$approval")"
author_type="$(jq -r '.user.type // "?"' <<<"$approval")"

printf '  marker author: %s (%s), via app id: %s\n' "$author" "$author_type" "${via_app_id:-<none>}"

[ -n "$via_app_id" ] || die "the approval was not created by a GitHub App.
  It was posted by '$author' (type $author_type). Only the integration app may
  approve. A comment with no app provenance is either hand-written or produced by a
  workflow using GITHUB_TOKEN, neither of which is the merge authority."

[ "$via_app_id" = "$APP_ID" ] || die "the approval was created by app id $via_app_id, expected $APP_ID.
  A different GitHub App produced this marker. Checking only that the author is a
  bot is not enough — every bot installed on this repository satisfies that,
  including github-actions[bot], and any workflow can post as it."
pass "approval provenance verified (app id $APP_ID)"

body="$(jq -r '.body' <<<"$approval")"
# shellcheck disable=SC2016
sha="$(printf '%s' "$body" | sed -n 's/.*approved SHA | `\([0-9a-f]\{40\}\)`.*/\1/p' | head -1)"
# shellcheck disable=SC2016
payload="$(printf '%s' "$body" | sed -n 's/.*payload sha256 | `\([0-9a-f]\{64\}\)`.*/\1/p' | head -1)"
[ -n "$sha" ]     || die "the approval does not contain a 40-hex approved SHA"
[ -n "$payload" ] || die "the approval does not contain a 64-hex payload digest"
pass "approved integration SHA: $sha"

# ---------------------------------------------------------------- 2. real CI
if [ "${#REQUIRED_CHECKS[@]}" -gt 0 ]; then
  raw="$(gh api "repos/$REPO/commits/$sha/check-runs?per_page=100" 2>/dev/null)" \
    || die "could not read check runs for $sha"
  runs="$(jq '[.check_runs[]? | {name, status, conclusion}]' <<<"$raw")" \
    || die "check-runs response was not the expected shape"

  total="$(jq 'length' <<<"$runs")"
  printf '  %s check run(s) reported for %s\n' "$total" "${sha:0:12}"

  for want in "${REQUIRED_CHECKS[@]}"; do
    got="$(jq -r --arg n "$want" \
      '([.[] | select(.name == $n)] | last) as $r
       | if $r == null then "missing" else ($r.conclusion // "incomplete") end' <<<"$runs")"
    if [ "$got" = success ]; then
      pass "check '$want' succeeded on the approved commit"
    else
      die "required check '$want' is '$got' on $sha.
  The approval claims the gate passed; the Checks API disagrees. A comment can be
  forged by a workflow the pull request modified — a successful check run under this
  name cannot. Treat the approval as untrustworthy and investigate the pull request."
    fi
  done
fi

# ---------------------------------------------------------------- 3. self-gating
if [ "${#PROTECTED_PATHS[@]}" -gt 0 ]; then
  raw_files="$(gh api "repos/$REPO/pulls/$PR/files?per_page=100" --paginate 2>/dev/null)" \
    || die "could not list the files changed by this pull request"
  files="$(jq -r '.[]?.filename // empty' <<<"$raw_files")" \
    || die "pull request files response was not the expected shape"

  touched=""
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    for guard in "${PROTECTED_PATHS[@]}"; do
      # Unquoted on purpose: $guard is a glob such as '.github/*' and must be
      # expanded as a pattern. In a case statement `*` also matches `/`, so
      # '.github/*' matches '.github/workflows/integration.yml'.
      # shellcheck disable=SC2254
      case "$f" in $guard) touched="$touched  $f"$'\n' ;; esac
    done
  done <<< "$files"

  if [ -n "$touched" ]; then
    printf '\n  this pull request modifies gate-controlling paths:\n%s' "$touched"

    # A pull request that changes the pipeline is reviewed by the pipeline it is
    # changing. Automated merge is withdrawn for that class of change; a human
    # review approval is required instead.
    raw_reviews="$(gh api "repos/$REPO/pulls/$PR/reviews?per_page=100" --paginate 2>/dev/null || echo '[]')"
    reviews="$(jq '[.[]? | select(.state == "APPROVED")] | length' <<<"$raw_reviews" 2>/dev/null || echo 0)"
    if [ "${reviews:-0}" -lt 1 ]; then
      die "this pull request changes the workflows, scripts, or installer that
  implement the merge gate, and has no human review approval.

  Because \`pull_request\` runs the workflow definition from the pull request's own
  head, a change here is gated by the version of the gate it is changing. Automated
  merge is deliberately withdrawn for this class of change.

  Get a review approval from a code owner, then request the merge again."
    fi
    pass "$reviews human review approval(s) present for a gate-affecting change"
  else
    pass "no gate-controlling paths modified"
  fi
fi

printf '\napproval authenticated\n'
printf 'sha=%s\n' "$sha"
printf 'payload=%s\n' "$payload"
