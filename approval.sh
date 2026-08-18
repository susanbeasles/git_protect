#!/usr/bin/env bash
# Tests for scripts/verify-approval.sh against a fake `gh` that returns fixtures.
#
# The forgery cases are the point: a marker posted by github-actions[bot], by a
# different app, or by a human must all be rejected, and a marker whose claimed
# success is contradicted by the Checks API must be rejected too.
set +e
SRC="$(cd "$(dirname "$0")/.." || exit 1; pwd -P)"
VA="$SRC/scripts/verify-approval.sh"
W="/tmp/cfez-appr-$$"; mkdir -p "$W/bin" "$W/fx"
trap 'rm -rf "$W"' EXIT

fail=0
t() { printf '  %-58s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

SHA=1111111111111111111111111111111111111111
PAYLOAD=$(printf 'a%.0s' $(seq 1 64))
APP_ID=987654

marker() {  # marker <app-id-json> <login> <type>
  cat <<JSON
[{"body":"<!-- integration-approval -->\n| approved SHA | \`$SHA\` |\n| payload sha256 | \`$PAYLOAD\` |\n",
  "user":{"login":"$2","type":"$3"},
  "performed_via_github_app":$1}]
JSON
}

# A stub gh that serves whatever fixtures the current test wrote.
cat > "$W/bin/gh" <<'STUB'
#!/usr/bin/env bash
# $1 = api, $2 = path
case "$2" in
  *"/issues/"*"/comments")  cat "$FX/comments.json" ;;
  *"/check-runs"*)          cat "$FX/checks.json" ;;
  *"/pulls/"*"/files"*)      cat "$FX/files.json" ;;
  *"/pulls/"*"/reviews"*)    cat "$FX/reviews.json" ;;
  *) echo "[]" ;;
esac
STUB
chmod +x "$W/bin/gh"
export PATH="$W/bin:$PATH"
export FX="$W/fx"

reset() {
  marker "{\"id\":$APP_ID}" "integration-bot[bot]" Bot > "$FX/comments.json"
  printf '{"check_runs":[{"name":"merge gate","status":"completed","conclusion":"success"}]}' > "$FX/checks.json"
  echo '[]' > "$FX/files.json"
  echo '[]' > "$FX/reviews.json"
}

run() { "$VA" --repo o/r --pr 1 --app-id "$APP_ID" "$@" 2>&1; }

# ---- happy path
reset
t "accepts a marker created by the integration app"
out="$(run)"; echo "$out" | grep -q "sha=$SHA" && ok_ || { no_; echo "$out" | tail -4; }

t "extracts the payload digest"
echo "$out" | grep -q "payload=$PAYLOAD" && ok_ || no_

# ---- forgery: github-actions[bot]
reset
marker 'null' "github-actions[bot]" Bot > "$FX/comments.json"
t "REJECTS a marker from github-actions[bot] (no app provenance)"
out="$(run)"; echo "$out" | grep -q 'not created by a GitHub App' && ok_ || { no_; echo "$out" | tail -4; }

t "  and explains that type==Bot is insufficient"
echo "$out" | grep -q 'workflow using GITHUB_TOKEN' && ok_ || no_

# ---- forgery: a different app
reset
marker '{"id":111}' "other-app[bot]" Bot > "$FX/comments.json"
t "REJECTS a marker from a DIFFERENT GitHub App"
out="$(run)"; echo "$out" | grep -q 'created by app id 111, expected' && ok_ || { no_; echo "$out" | tail -4; }

t "  and states why checking type==Bot is not enough"
echo "$out" | grep -q 'every bot installed on this repository' && ok_ || no_

# ---- forgery: a human
reset
marker 'null' "someuser" User > "$FX/comments.json"
t "REJECTS a hand-written marker from a user"
out="$(run)"; echo "$out" | grep -q 'not created by a GitHub App' && ok_ || no_

# ---- no marker
reset
echo '[]' > "$FX/comments.json"
t "REJECTS when no marker exists"
out="$(run)"; echo "$out" | grep -q 'no integration approval marker' && ok_ || no_

# ---- malformed marker
reset
printf '[{"body":"<!-- integration-approval -->\\nnothing useful","user":{"login":"b","type":"Bot"},"performed_via_github_app":{"id":%s}}]' "$APP_ID" > "$FX/comments.json"
t "REJECTS a marker with no approved SHA"
out="$(run)"; echo "$out" | grep -q 'does not contain a 40-hex' && ok_ || { no_; echo "$out" | tail -3; }

# ---- CI evidence
reset
t "accepts when the required check succeeded"
out="$(run --require-check 'merge gate')"
echo "$out" | grep -q "check 'merge gate' succeeded" && ok_ || { no_; echo "$out" | tail -4; }

reset
printf '{"check_runs":[{"name":"merge gate","status":"completed","conclusion":"failure"}]}' > "$FX/checks.json"
t "REJECTS when the Checks API says the gate FAILED"
out="$(run --require-check 'merge gate')"
echo "$out" | grep -q "is 'failure'" && ok_ || { no_; echo "$out" | tail -4; }

t "  and says the comment can be forged but a check run cannot"
echo "$out" | grep -q 'cannot' && ok_ || no_

reset
printf '{"check_runs":[]}' > "$FX/checks.json"
t "REJECTS when the required check is absent entirely"
out="$(run --require-check 'merge gate')"
echo "$out" | grep -q "is 'missing'" && ok_ || { no_; echo "$out" | tail -3; }

reset
printf '{"check_runs":[{"name":"something else","status":"completed","conclusion":"success"}]}' > "$FX/checks.json"
t "REJECTS a success under a DIFFERENT check name"
out="$(run --require-check 'merge gate')"
echo "$out" | grep -q "is 'missing'" && ok_ || { no_; echo "$out" | tail -3; }

# ---- self-gating
reset
echo '[{"filename":".github/workflows/integration.yml"}]' > "$FX/files.json"
echo '[]' > "$FX/reviews.json"
t "REJECTS a PR that edits the gate with no human review"
out="$(run --require-untouched '.github/*')"
echo "$out" | grep -q 'no human review approval' && ok_ || { no_; echo "$out" | tail -5; }

t "  and explains the pull request would be gating itself"
echo "$out" | grep -q "gate it is changing" && ok_ || no_

reset
echo '[{"filename":".github/workflows/integration.yml"}]' > "$FX/files.json"
echo '[{"state":"APPROVED"},{"state":"APPROVED"}]' > "$FX/reviews.json"
t "allows a gate change WITH human review approvals"
out="$(run --require-untouched '.github/*')"
echo "$out" | grep -q 'human review approval(s) present' && ok_ || { no_; echo "$out" | tail -4; }

reset
echo '[{"filename":"lib/core/log.sh"},{"filename":"README.md"}]' > "$FX/files.json"
echo '[]' > "$FX/reviews.json"
t "ordinary code changes need no extra review"
out="$(run --require-untouched '.github/*' --require-untouched 'scripts/*')"
echo "$out" | grep -q 'no gate-controlling paths modified' && ok_ || { no_; echo "$out" | tail -4; }

reset
echo '[{"filename":"scripts/build.sh"}]' > "$FX/files.json"
echo '[]' > "$FX/reviews.json"
t "scripts/ is also treated as gate-controlling"
out="$(run --require-untouched '.github/*' --require-untouched 'scripts/*')"
echo "$out" | grep -q 'no human review approval' && ok_ || { no_; echo "$out" | tail -3; }

# ---- hygiene
reset
t "missing --app-id is refused"
out="$("$VA" --repo o/r --pr 1 2>&1)"; echo "$out" | grep -q 'app-id is required' && ok_ || no_

printf '\n'
[ "$fail" -eq 0 ] && echo "APPROVAL TESTS PASS" || echo "APPROVAL TESTS FAILED"
exit "$fail"
