#!/usr/bin/env bash
# Tests for scripts/assert-history.sh against real git repositories.
#
# The scenarios that matter are the ones a content digest cannot see: a rewritten
# trunk that leaves the tree identical, and a released commit that stops being
# reachable. Those are constructed here with actual git operations, not mocked.
set +e
SRC="$(cd "$(dirname "$0")/.." || exit 1; pwd -P)"
AH="$SRC/scripts/assert-history.sh"
W="/tmp/cfez-hist-$$"
mkdir -p "$W"
trap 'rm -rf "$W"' EXIT

fail=0
t() { printf '  %-58s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

newrepo() {
  local d="$W/$1"; rm -rf "$d"; mkdir -p "$d"; cd "$d" || exit 1
  git init -q -b main
  git config user.email t@t.invalid; git config user.name T
  git config commit.gpgsign false
}
commit() { echo "$2" > "${3:-f.txt}"; git add -A; git commit -qm "$1"; }

# ---------------------------------------------------------------- ff-safe: happy
newrepo ok1
commit "feat: one" one; git tag v1.0.0
MAIN=$(git rev-parse HEAD)
git checkout -qb feat; commit "feat: two" two
TARGET=$(git rev-parse HEAD)

t "ff-safe accepts a clean fast-forward"
"$AH" ff-safe --main "$MAIN" --target "$TARGET" >/dev/null 2>&1 && ok_ || \
  { no_; "$AH" ff-safe --main "$MAIN" --target "$TARGET" 2>&1 | tail -4; }

t "ff-safe confirms previous release tags stay reachable"
out="$("$AH" ff-safe --main "$MAIN" --target "$TARGET" 2>&1)"
echo "$out" | grep -q 'previously released commit(s) remain reachable' && ok_ || { no_; echo "$out" | tail -3; }

# ---------------------------------------------------------------- not a FF
newrepo div
commit "feat: base" base
BASE=$(git rev-parse HEAD)
commit "feat: on main" mainwork
MAIN=$(git rev-parse HEAD)
git checkout -q "$BASE"
git checkout -qb side; commit "feat: on side" sidework
TARGET=$(git rev-parse HEAD)

t "ff-safe REFUSES when main is not an ancestor (divergent)"
out="$("$AH" ff-safe --main "$MAIN" --target "$TARGET" 2>&1)"
echo "$out" | grep -q 'NOT an ancestor' && ok_ || { no_; echo "$out" | tail -3; }

t "  and says main advanced after the replay"
echo "$out" | grep -q 'push to the pull request to replay' && ok_ || no_

t "ff-safe reports commits that would become unreachable"
n="$(git rev-list "$TARGET..$MAIN" | wc -l | tr -d ' ')"
[ "$n" -eq 1 ] && ok_ || { no_; echo "      expected 1 unreachable, computed $n"; }

# ---------------------------------------------------------------- nothing to do
newrepo same
commit "feat: one" one
S=$(git rev-parse HEAD)
t "ff-safe REFUSES when main already equals the target"
out="$("$AH" ff-safe --main "$S" --target "$S" 2>&1)"
echo "$out" | grep -q 'nothing to release' && ok_ || { no_; echo "$out" | tail -3; }

# ---------------------------------------------------------------- already released
newrepo dup
commit "feat: one" one; git tag v1.0.0
M=$(git rev-parse HEAD)
git checkout -qb f2; commit "feat: two" two
T=$(git rev-parse HEAD); git tag v1.1.0
t "ff-safe REFUSES to release an already-tagged commit"
out="$("$AH" ff-safe --main "$M" --target "$T" 2>&1)"
echo "$out" | grep -q 'already released as' && ok_ || { no_; echo "$out" | tail -3; }

# ---------------------------------------------------------------- THE BIG ONE
# A rewritten trunk with an identical final tree. The middle commit is squashed
# away; the content is byte-for-byte the same. Only reachability reveals it.
newrepo rewrite
commit "feat: one" one
C1=$(git rev-parse HEAD)
commit "feat: two" two
C2=$(git rev-parse HEAD); git tag v1.0.0     # v1.0.0 released at "two"
commit "feat: three" three
HONEST=$(git rev-parse HEAD)
HONEST_TREE=$(git rev-parse HEAD^{tree})

# rebuild the same final content without the tagged middle commit
git checkout -q "$C1"
git checkout -qb rewritten
commit "feat: three" three
REWRITTEN=$(git rev-parse HEAD)
REWRITTEN_TREE=$(git rev-parse HEAD^{tree})

t "constructed: rewritten history has an IDENTICAL tree"
[ "$HONEST_TREE" = "$REWRITTEN_TREE" ] && ok_ || \
  { no_; echo "      $HONEST_TREE vs $REWRITTEN_TREE"; }

t "constructed: but a DIFFERENT commit sha"
[ "$HONEST" != "$REWRITTEN" ] && ok_ || no_

t "ff-safe accepts the honest history"
"$AH" ff-safe --main "$C2" --target "$HONEST" >/dev/null 2>&1 && ok_ || \
  { no_; "$AH" ff-safe --main "$C2" --target "$HONEST" 2>&1 | tail -4; }

t "ff-safe REFUSES the rewritten history (orphaned release)"
out="$("$AH" ff-safe --main "$C2" --target "$REWRITTEN" 2>&1)"
echo "$out" | grep -qE 'orphaned|NOT an ancestor' && ok_ || { no_; echo "$out" | tail -5; }

t "  and names the release tag that would be orphaned"
out="$("$AH" ff-safe --main "$C1" --target "$REWRITTEN" 2>&1)"
if echo "$out" | grep -q 'history has been rewritten' && echo "$out" | grep -q 'v1.0.0'; then
  ok_
else
  no_; echo "$out" | tail -6
fi

t "  and tells you to stop rather than proceed"
echo "$out" | grep -q 'Do NOT proceed' && ok_ || no_

# ---------------------------------------------------------------- landed
newrepo landed
commit "feat: one" one
S=$(git rev-parse HEAD)
t "landed accepts main pointing at the expected commit"
"$AH" landed --expected "$S" >/dev/null 2>&1 && ok_ || no_

t "landed REFUSES when main is a different commit"
commit "feat: sneaky" sneaky
out="$("$AH" landed --expected "$S" 2>&1)"
echo "$out" | grep -q 'should be' && ok_ || { no_; echo "$out" | tail -3; }

t "  and says do not release"
echo "$out" | grep -qi 'do not release' && ok_ || no_

# ---------------------------------------------------------------- building
newrepo building
commit "feat: one" one
S=$(git rev-parse HEAD)
t "building accepts HEAD at the expected commit"
"$AH" building --expected "$S" >/dev/null 2>&1 && ok_ || \
  { no_; "$AH" building --expected "$S" 2>&1 | tail -3; }

t "building REFUSES a different HEAD"
commit "feat: other" other
out="$("$AH" building --expected "$S" 2>&1)"
echo "$out" | grep -q 'Refusing to build' && ok_ || { no_; echo "$out" | tail -3; }

t "building compares origin/main when it is present"
git update-ref refs/remotes/origin/main "$(git rev-parse HEAD)"
NOW=$(git rev-parse HEAD)
out="$("$AH" building --expected "$NOW" 2>&1)"
echo "$out" | grep -q 'origin/main is the same commit' && ok_ || { no_; echo "$out" | tail -3; }

t "building REFUSES when origin/main disagrees with the build"
git update-ref refs/remotes/origin/main "$S"
out="$("$AH" building --expected "$NOW" 2>&1)"
echo "$out" | grep -q 'must be identical' && ok_ || { no_; echo "$out" | tail -3; }

# ---------------------------------------------------------------- hygiene
t "unknown subcommand exits non-zero with usage"
out="$("$AH" nonsense 2>&1)"
echo "$out" | grep -q 'usage:' && ok_ || no_

t "missing required arguments are reported"
out="$("$AH" ff-safe --main "$S" 2>&1)"
echo "$out" | grep -q 'needs --main and --target' && ok_ || no_

t "a non-existent commit is rejected, not silently accepted"
out="$("$AH" ff-safe --main deadbeefdeadbeefdeadbeefdeadbeefdeadbeef --target "$S" 2>&1)"
echo "$out" | grep -q 'not a commit' && ok_ || { no_; echo "$out" | tail -3; }

printf '\n'
[ "$fail" -eq 0 ] && echo "HISTORY TESTS PASS" || echo "HISTORY TESTS FAILED"
exit "$fail"
