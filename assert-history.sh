#!/usr/bin/env bash
# Commit-identity assertions. The primary integrity mechanism of the pipeline.
#
# Git commit SHAs cover the tree AND the parent chain AND author and timestamp
# metadata. Content digests cover only the tree. Two commits can have byte-identical
# trees with different histories — squash a commit whose change was later reverted
# and the final tree is unchanged while a commit has been orphaned. A content
# comparison sees nothing; the commit SHA differs immediately.
#
# So: the commit SHA is what decides whether a build is legitimate. The payload
# digest only ever answers a narrower question — is the build reproducible — because
# at a fixed SHA the tree cannot vary.
#
#   assert-history.sh ff-safe  --main <sha> --target <sha> [--tag-prefix v]
#   assert-history.sh landed   --expected <sha> [--ref refs/heads/main]
#   assert-history.sh building --expected <sha>
set -euo pipefail

TAG_PREFIX="${TAG_PREFIX:-v}"
MAIN=""; TARGET=""; EXPECTED=""; REF="refs/heads/main"
CMD="${1:-}"; shift || true

while [ $# -gt 0 ]; do
  case "$1" in
    --main)       MAIN="$2"; shift 2 ;;
    --target)     TARGET="$2"; shift 2 ;;
    --expected)   EXPECTED="$2"; shift 2 ;;
    --ref)        REF="$2"; shift 2 ;;
    --tag-prefix) TAG_PREFIX="$2"; shift 2 ;;
    *) echo "assert-history.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

fail() { printf '\n%s\n' "HISTORY ASSERTION FAILED: $*" >&2; exit 1; }
pass() { printf '  ok    %s\n' "$*"; }
info() { printf '  note  %s\n' "$*"; }

full() { git rev-parse --verify "$1^{commit}" 2>/dev/null; }

release_tags() {
  git tag --list "${TAG_PREFIX}[0-9]*.[0-9]*.[0-9]*" --sort=-version:refname 2>/dev/null || true
}

case "$CMD" in
# ---------------------------------------------------------------------------
# Before main is moved. Everything that could make the move illegitimate.
ff-safe)
  [ -n "$MAIN" ] && [ -n "$TARGET" ] || fail "ff-safe needs --main and --target"
  MAIN="$(full "$MAIN")"     || fail "--main is not a commit in this repository"
  TARGET="$(full "$TARGET")" || fail "--target is not a commit in this repository"

  printf 'commit-identity checks (main -> target)\n'
  printf '  main   %s\n  target %s\n\n' "$MAIN" "$TARGET"

  if [ "$MAIN" = "$TARGET" ]; then
    fail "main already points at the target commit — there is nothing to release.
  If you expected a change, the replay did not produce a new commit."
  fi
  pass "target differs from the current main"

  # The defining property of a fast-forward. If main is not an ancestor, moving it
  # would discard whatever main points at now.
  if ! git merge-base --is-ancestor "$MAIN" "$TARGET"; then
    fail "main is NOT an ancestor of the target — this would not be a fast-forward.
  Moving main would orphan the commits currently on it. main advanced after the
  integration replay; push to the pull request to replay onto the new main."
  fi
  pass "main is an ancestor of the target (fast-forward is possible)"

  # Nothing on main may be lost. Redundant with the ancestor check today, stated
  # separately because it is the property we actually care about and the one a
  # future change to the merge strategy could silently break.
  lost="$(git rev-list "$TARGET..$MAIN" 2>/dev/null | wc -l | tr -d ' ')"
  [ "$lost" -eq 0 ] || fail "$lost commit(s) currently on main are not reachable from the target"
  pass "no commit currently on main becomes unreachable"

  # Every previously released commit must remain reachable. This is the check that
  # catches a rewritten trunk: a rebase or force-push that drops a commit whose
  # change was later reverted leaves the tree identical and the history short.
  # Content digests cannot see it. Reachability can.
  tags="$(release_tags)"
  if [ -z "$tags" ]; then
    info "no previous release tags to check (first release)"
  else
    orphaned=""
    count=0
    while IFS= read -r tag; do
      [ -z "$tag" ] && continue
      count=$((count + 1))
      tsha="$(git rev-list -n1 "$tag" 2>/dev/null || true)"
      [ -n "$tsha" ] || { orphaned="$orphaned$tag (unresolvable)\n"; continue; }
      git merge-base --is-ancestor "$tsha" "$TARGET" 2>/dev/null \
        || orphaned="$orphaned  $tag -> ${tsha:0:12}\n"
    done <<< "$tags"
    if [ -n "$orphaned" ]; then
      printf '\n  released commits NOT reachable from the target:\n' >&2
      printf "$orphaned" >&2
      fail "history has been rewritten — previously released commits would be orphaned.
  Do NOT proceed. Something rewrote trunk. Find out what before releasing anything:
    git log --oneline --graph --all
    git reflog show main
  A released commit that is no longer an ancestor of main means that release can no
  longer be reproduced from this repository."
    fi
    pass "all $count previously released commit(s) remain reachable"
  fi

  # A commit may be released once. Releasing the same commit twice would mean two
  # versions with identical content and no way to tell which a user has.
  existing="$(git tag --points-at "$TARGET" 2>/dev/null | grep -E "^${TAG_PREFIX}[0-9]" || true)"
  [ -z "$existing" ] || fail "the target commit is already released as: $existing"
  pass "the target commit is not already tagged as a release"

  printf '\ncommit identity verified — the fast-forward is safe\n'
  ;;

# ---------------------------------------------------------------------------
# After main is moved. Confirm the move landed exactly, not approximately.
landed)
  [ -n "$EXPECTED" ] || fail "landed needs --expected"
  ACTUAL="$(git rev-parse --verify "$REF" 2>/dev/null)" \
    || fail "$REF does not exist in this repository"
  printf 'post-merge verification\n'
  printf '  expected %s\n  %-8s %s\n\n' "$EXPECTED" "$REF" "$ACTUAL"
  [ "$ACTUAL" = "$EXPECTED" ] || fail "$REF is $ACTUAL but should be $EXPECTED.
  The fast-forward did not land as intended, or something pushed to main in the
  meantime. Do not release. Investigate before touching main again."
  pass "$REF is exactly the approved commit"
  ;;

# ---------------------------------------------------------------------------
# In the build job. Refuse to build anything other than the released commit.
building)
  [ -n "$EXPECTED" ] || fail "building needs --expected"
  HEAD_SHA="$(git rev-parse HEAD 2>/dev/null)" || fail "not a git repository"
  printf 'build-time commit check\n'
  printf '  expected %s\n  HEAD     %s\n\n' "$EXPECTED" "$HEAD_SHA"

  [ "$HEAD_SHA" = "$EXPECTED" ] || fail "checked out $HEAD_SHA, expected $EXPECTED.
  Refusing to build. An artifact built from a different commit than the one that was
  approved and merged must never be published."
  pass "HEAD is the approved commit"

  # main must agree. The whole point of fast-forward-only is that the released
  # commit IS main; if it is not, the release would not correspond to trunk.
  if git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null 2>&1; then
    MAIN_SHA="$(git rev-parse refs/remotes/origin/main)"
    if [ "$MAIN_SHA" != "$EXPECTED" ]; then
      fail "origin/main is $MAIN_SHA but the commit being built is $EXPECTED.
  These must be identical. Either main moved after the merge, or this build is not
  building trunk. Both are catastrophic for a release; stop and investigate."
    fi
    pass "origin/main is the same commit"
  else
    info "origin/main not fetched — skipped the trunk comparison"
  fi
  ;;

*)
  echo "usage: assert-history.sh ff-safe|landed|building [options]" >&2
  exit 2
  ;;
esac
