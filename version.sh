#!/usr/bin/env bash
# Derive the next semantic version from commits since the last release tag.
#
# Rules (conventional commits). First match wins, highest bump wins:
#   BREAKING CHANGE: in body, or a `!` before the colon  -> major
#   feat:                                                -> minor
#   fix: | perf: | refactor: | revert:                   -> patch
#   anything else (chore, docs, test, ci, build, style)  -> no bump on its own
#
# If there are only no-bump commits, this emits a patch bump — a release still
# needs a version, and silently reusing one is worse.
#
# Usage:
#   scripts/version.sh next            -> 1.4.0
#   scripts/version.sh next --tag      -> v1.4.0
#   scripts/version.sh current         -> 1.3.2   (last released, or 0.0.0)
#   scripts/version.sh bump            -> major|minor|patch
#   scripts/version.sh notes           -> grouped markdown changelog
#   scripts/version.sh --range A..B …  -> override the commit range
set -euo pipefail

TAG_PREFIX="${TAG_PREFIX:-v}"
RANGE=""

# ---- arg parsing -----------------------------------------------------------
CMD=""
while [ $# -gt 0 ]; do
  case "$1" in
    --range) RANGE="$2"; shift 2 ;;
    --prefix) TAG_PREFIX="$2"; shift 2 ;;
    --tag) WANT_TAG=1; shift ;;
    next|current|bump|notes) CMD="$1"; shift ;;
    *) echo "version.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
CMD="${CMD:-next}"

# ---- last released version -------------------------------------------------
# Sorted by version, not by date: a hotfix tagged later must not become "latest".
last_tag() {
  git tag --list "${TAG_PREFIX}[0-9]*.[0-9]*.[0-9]*" --sort=-version:refname \
    | head -n1
}

current_version() {
  local t; t="$(last_tag || true)"
  if [ -z "$t" ]; then printf '0.0.0'; else printf '%s' "${t#"$TAG_PREFIX"}"; fi
}

commit_range() {
  if [ -n "$RANGE" ]; then printf '%s' "$RANGE"; return; fi
  local t; t="$(last_tag || true)"
  if [ -z "$t" ]; then printf 'HEAD'; else printf '%s..HEAD' "$t"; fi
}

# ---- bump detection --------------------------------------------------------
detect_bump() {
  local range major=0 minor=0 patch=0 subject body
  range="$(commit_range)"

  while IFS= read -r sha; do
    [ -z "$sha" ] && continue
    subject="$(git log -1 --format=%s "$sha")"
    body="$(git log -1 --format=%B "$sha")"

    # `!` before the colon, or a BREAKING CHANGE / BREAKING-CHANGE footer
    if printf '%s' "$subject" | grep -qE '^[a-zA-Z]+(\([^)]*\))?!:' \
       || printf '%s' "$body" | grep -qE '^BREAKING[ -]CHANGE:'; then
      major=1; continue
    fi
    if printf '%s' "$subject" | grep -qE '^feat(\([^)]*\))?:'; then minor=1; continue; fi
    if printf '%s' "$subject" | grep -qE '^(fix|perf|refactor|revert)(\([^)]*\))?:'; then patch=1; fi
  done < <(git rev-list --no-merges "$range" 2>/dev/null || true)

  if [ "$major" -eq 1 ]; then printf 'major'
  elif [ "$minor" -eq 1 ]; then printf 'minor'
  elif [ "$patch" -eq 1 ]; then printf 'patch'
  else printf 'patch'; fi
}

next_version() {
  local cur bump major minor patch
  cur="$(current_version)"
  bump="$(detect_bump)"
  IFS=. read -r major minor patch <<<"$cur"
  major="${major:-0}"; minor="${minor:-0}"; patch="${patch:-0}"

  case "$bump" in
    major)
      # 0.x is pre-1.0: a breaking change bumps the minor, per semver §4.
      if [ "$major" -eq 0 ]; then minor=$((minor + 1)); patch=0
      else major=$((major + 1)); minor=0; patch=0; fi ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
  esac
  printf '%s.%s.%s' "$major" "$minor" "$patch"
}

# ---- release notes ---------------------------------------------------------
notes() {
  local range; range="$(commit_range)"
  local breaking features fixes other

  collect() {  # collect <grep-pattern>
    git log --no-merges --format='%s|%h|%an' "$range" 2>/dev/null \
      | grep -E "$1" || true
  }
  fmt() { sed -E 's#^([a-zA-Z]+)(\([^)]*\))?!?: *#- #; s#\|([0-9a-f]+)\|(.*)$# (\1, \2)#'; }

  breaking="$(collect '^[a-zA-Z]+(\([^)]*\))?!:' | fmt)"
  features="$(collect '^feat(\([^)]*\))?:' | fmt)"
  fixes="$(collect '^(fix|perf)(\([^)]*\))?:' | fmt)"
  other="$(collect '^(refactor|revert|docs|test|ci|build|chore|style)(\([^)]*\))?:' | fmt)"

  [ -n "$breaking" ] && { printf '### Breaking changes\n\n%s\n\n' "$breaking"; }
  [ -n "$features" ] && { printf '### Features\n\n%s\n\n' "$features"; }
  [ -n "$fixes" ]    && { printf '### Fixes\n\n%s\n\n' "$fixes"; }
  [ -n "$other" ]    && { printf '### Other\n\n%s\n\n' "$other"; }
  return 0
}

case "$CMD" in
  current) current_version; printf '\n' ;;
  bump)    detect_bump; printf '\n' ;;
  next)    if [ -n "${WANT_TAG:-}" ]; then printf '%s' "$TAG_PREFIX"; fi
           next_version; printf '\n' ;;
  notes)   notes ;;
esac
