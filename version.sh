#!/usr/bin/env bash
# Unit tests for scripts/version.sh in throwaway git repos.
set +e
SRC="$(cd "$(dirname "$0")/.." || exit 1; pwd -P)"
W="/tmp/cfez-ver-$$"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
fail=0
t() { printf '  %-52s ' "$1"; }
eq() { t "$1"; if [ "$2" = "$3" ]; then echo PASS; else echo FAIL; echo "      want [$3] got [$2]"; fail=1; fi; }

newrepo() {
  local d="$W/$1"; mkdir -p "$d"; cd "$d" || exit 1
  git init -q; git config user.email t@t.invalid; git config user.name T
  git config commit.gpgsign false
  cp "$SRC/scripts/version.sh" .; chmod +x version.sh
}
c() { git commit -q --allow-empty -m "$1"; }

newrepo a; c "chore: init"; git tag v1.2.3
eq "current version from the newest tag"      "$(./version.sh current)" "1.2.3"
eq "no bumpable commits still yields a patch" "$(./version.sh next)"    "1.2.4"
c "docs: x";  eq "docs alone is a patch"      "$(./version.sh next)"    "1.2.4"
c "fix: y";   eq "fix is a patch"             "$(./version.sh bump)"    "patch"
c "feat: z";  eq "feat outranks fix"          "$(./version.sh bump)"    "minor"
eq "minor resets the patch component"         "$(./version.sh next)"    "1.3.0"
c "feat!: b"; eq "bang outranks feat"         "$(./version.sh bump)"    "major"
eq "major resets minor and patch"             "$(./version.sh next)"    "2.0.0"
eq "tag form adds the prefix"                 "$(./version.sh next --tag)" "v2.0.0"

newrepo b; c "chore: init"; git tag v3.1.4
git commit -q --allow-empty -m "refactor: rework

BREAKING CHANGE: removed a flag"
eq "BREAKING CHANGE footer is a major"        "$(./version.sh bump)"    "major"

newrepo c; c "chore: init"; git tag v0.3.1; c "feat!: big"
eq "pre-1.0 breaking bumps the minor"         "$(./version.sh next)"    "0.4.0"

newrepo d; c "feat: first"
eq "untagged repo has no current version"     "$(./version.sh current)" "0.0.0"
eq "untagged repo first release"              "$(./version.sh next)"    "0.1.0"

newrepo e; c "chore: init"; git tag v0.9.0; git tag v0.10.0
eq "tags sort by version, not lexically"      "$(./version.sh current)" "0.10.0"

newrepo f; c "chore: init"; git tag v1.0.0; c "feat(dns): scoped checks"
eq "scoped feat is recognised"                "$(./version.sh bump)"    "minor"
c "fix(http)!: drop retry option"
eq "scoped bang is recognised"                "$(./version.sh bump)"    "major"

newrepo g; c "chore: init"; git tag v1.0.0
c "feat: a"; c "fix: b"; c "docs: c"
notes="$(./version.sh notes)"
t "notes group features and fixes separately"
if printf '%s' "$notes" | grep -q '### Features' && printf '%s' "$notes" | grep -q '### Fixes'; then
  echo PASS; else echo FAIL; fail=1; fi
t "notes strip the conventional prefix"
printf '%s' "$notes" | grep -q '^- a ' && echo PASS || { echo FAIL; fail=1; }

# ---- concurrent pull requests ----
# Two open PRs compute the same "next" version. The release workflow therefore
# resolves the version at MERGE time against the tags that exist then, and reserves
# the tag BEFORE moving main. These assertions document why.
newrepo conc; c "chore: base"; git tag v1.3.0
git checkout -qb featA 2>/dev/null; c "feat: A"
va="$(./version.sh next)"
git checkout -q "$(git rev-list --max-parents=0 HEAD)" 2>/dev/null
git checkout -qb featB 2>/dev/null; c "feat: B"
vb="$(./version.sh next)"
eq "two open branches compute the SAME next version"  "$va" "$vb"
t "which is why the tag must be reserved at merge, not PR time"
[ "$va" = "$vb" ] && echo PASS || { echo FAIL; fail=1; }

# After A lands and is tagged, B must resolve to a different version.
git tag "v$va" featA 2>/dev/null || git tag "v$va"
vb2="$(./version.sh next)"
t "after the first release is tagged, the next resolves higher"
if [ "$vb2" != "$vb" ]; then echo PASS; else echo FAIL; echo "      still $vb2"; fail=1; fi

t "--range scopes the bump to a specific set of commits"
r="$(./version.sh bump --range "v1.3.0..featB")"
[ "$r" = "minor" ] && echo PASS || { echo FAIL; echo "      got $r"; fail=1; }

printf '\n'
[ "$fail" -eq 0 ] && echo "VERSION TESTS PASS" || echo "VERSION TESTS FAILED"
exit "$fail"
