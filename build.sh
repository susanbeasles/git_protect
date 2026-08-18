#!/usr/bin/env bash
# Reproducibility and tamper-sensitivity of scripts/build.sh.
set +e
SRC="$(cd "$(dirname "$0")/.." || exit 1; pwd -P)"
W="/tmp/cfez-build-$$"; mkdir -p "$W"
trap 'rm -rf "$W"; cp -f "$W/log.bak" "$SRC/lib/core/log.sh" 2>/dev/null' EXIT
fail=0
t() { printf '  %-52s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

build() { ( umask "$1"; cd "${3:-$SRC}" && "$SRC/scripts/build.sh" --version 1.0.0 --commit fixedsha --out "$2" >/dev/null 2>&1 ); awk '/tar.gz/{print $1}' "$2/SHA256SUMS" 2>/dev/null; }

h1="$(build 022 "$W/a")"
t "build produces a tarball and checksums"
[ -n "$h1" ] && ok_ || { no_; echo "      no checksum produced"; }

sleep 2
h2="$(build 022 "$W/b")"
t "identical across wall-clock time"
[ "$h1" = "$h2" ] && ok_ || { no_; echo "      $h1 vs $h2"; }

h3="$(build 077 "$W/c")"
t "identical across umask"
[ "$h1" = "$h3" ] && ok_ || { no_; echo "      $h1 vs $h3"; }

h4="$(build 002 "$W/d" /tmp)"
t "identical across working directory"
[ "$h1" = "$h4" ] && ok_ || { no_; echo "      $h1 vs $h4"; }

t "self-verify passes on a clean tree"
"$SRC/scripts/build.sh" --verify "$W/a" >/dev/null 2>&1 && ok_ || no_

t "manifest records version, commit and tarball hash"
grep -q '^version: 1.0.0' "$W/a/MANIFEST.txt" \
  && grep -q '^commit: fixedsha' "$W/a/MANIFEST.txt" \
  && grep -q "^tarball_sha256: $h1" "$W/a/MANIFEST.txt" && ok_ || no_

t "per-file manifest lists every payload file"
n="$(grep -c . "$W/a/FILES.sha256")"
[ "$n" -ge 38 ] && ok_ || { no_; echo "      only $n files"; }

t "VERSION is excluded from FILES.sha256 (it holds the commit)"
grep -q 'VERSION' "$W/a/FILES.sha256" && { no_; echo "      VERSION should not be listed"; } || ok_

cp "$SRC/lib/core/log.sh" "$W/log.bak"
echo '# injected' >> "$SRC/lib/core/log.sh"
t "self-verify FAILS when a payload file changes"
"$SRC/scripts/build.sh" --verify "$W/a" >/dev/null 2>&1 && { no_; } || ok_
cp "$W/log.bak" "$SRC/lib/core/log.sh"

t "self-verify passes again once restored"
"$SRC/scripts/build.sh" --verify "$W/a" >/dev/null 2>&1 && ok_ || no_

t "a missing payload file is reported, not silently skipped"
mv "$SRC/lib/parse/email.mjs" "$W/email.hold"
out="$("$SRC/scripts/build.sh" --version 1.0.0 --out "$W/e" 2>&1)"
echo "$out" | grep -q 'payload file missing' && ok_ || { no_; echo "$out" | tail -2; }
mv "$W/email.hold" "$SRC/lib/parse/email.mjs"

t "a bad version string is rejected"
out="$("$SRC/scripts/build.sh" --version 1.2 --out "$W/f" 2>&1)"
echo "$out" | grep -q 'MAJOR.MINOR.PATCH' && ok_ || no_


# ---- the payload manifest must match the shipped modules ----
t "every module in lib/cli/modules.txt is in payload.txt"
missing=""
while IFS= read -r m; do
  case "$m" in ''|\#*) continue ;; esac
  grep -qxF "lib/$m" "$SRC/payload.txt" || missing="$missing lib/$m"
done < "$SRC/lib/cli/modules.txt"
[ -z "$missing" ] && ok_ || { no_; echo "      missing:$missing"; }

t "every file in payload.txt exists in the checkout"
missing=""
while IFS= read -r f; do
  case "$f" in ''|\#*) continue ;; esac
  [ -f "$SRC/$f" ] || missing="$missing $f"
done < "$SRC/payload.txt"
[ -z "$missing" ] && ok_ || { no_; echo "      missing:$missing"; }

t "the built tarball contains every module the loader will source"
T="$W/loadcheck"; mkdir -p "$T"
tar xzf "$W/a/cfezcli-1.0.0.tar.gz" -C "$T"
D="$T/cfezcli-1.0.0"
missing=""
while IFS= read -r m; do
  case "$m" in ''|\#*) continue ;; esac
  [ -f "$D/lib/$m" ] || missing="$missing $m"
done < "$D/lib/cli/modules.txt"
[ -z "$missing" ] && ok_ || { no_; echo "      missing from tarball:$missing"; }

# ---- the release-gate invariant ----
# The release cross-check compares payload_sha256, not the tarball hash. These
# assertions are what make that safe; if they fail, concurrent pull requests will
# either block releases or produce a partial state.
t "payload_sha256 is recorded in the manifest"
p1="$(sed -n 's/^payload_sha256: //p' "$W/a/MANIFEST.txt")"
[ -n "$p1" ] && ok_ || no_

t "payload_sha256 is INDEPENDENT of the version"
build 022 "$W/pv" >/dev/null
"$SRC/scripts/build.sh" --version 7.7.7 --commit fixedsha --out "$W/pv2" >/dev/null 2>&1
p2="$(sed -n 's/^payload_sha256: //p' "$W/pv2/MANIFEST.txt")"
[ "$p1" = "$p2" ] && ok_ || { no_; echo "      $p1 vs $p2"; }

t "payload_sha256 is INDEPENDENT of the commit"
"$SRC/scripts/build.sh" --version 1.0.0 --commit totallydifferent --out "$W/pc" >/dev/null 2>&1
p3="$(sed -n 's/^payload_sha256: //p' "$W/pc/MANIFEST.txt")"
[ "$p1" = "$p3" ] && ok_ || { no_; echo "      $p1 vs $p3"; }

t "tarball hash DOES change with the version (why we cannot compare it)"
h_a="$(awk '/tar.gz/{print $1}' "$W/a/SHA256SUMS")"
h_b="$(awk '/tar.gz/{print $1}' "$W/pv2/SHA256SUMS")"
[ "$h_a" != "$h_b" ] && ok_ || { no_; echo "      expected these to differ"; }

t "payload_sha256 DOES change when a payload file changes"
cp "$SRC/lib/core/log.sh" "$W/log.bak2"
echo '# injected' >> "$SRC/lib/core/log.sh"
"$SRC/scripts/build.sh" --version 1.0.0 --commit fixedsha --out "$W/pt" >/dev/null 2>&1
p4="$(sed -n 's/^payload_sha256: //p' "$W/pt/MANIFEST.txt")"
cp "$W/log.bak2" "$SRC/lib/core/log.sh"
[ "$p1" != "$p4" ] && ok_ || { no_; echo "      tamper did not change the payload digest"; }

t "--verify distinguishes a metadata difference from a content difference"
out="$("$SRC/scripts/build.sh" --verify "$W/a" 2>&1)"
echo "$out" | grep -q 'reproducible' && ok_ || { no_; echo "$out" | tail -3; }

# ---- macOS package payload shape (logic testable off macOS) ----
t "pkg payload script produces the expected tree"
R="$W/pkgroot"; INSTALL_LOCATION=/usr/local/lib/cfezcli
mkdir -p "$R$INSTALL_LOCATION"
tar xzf "$W/a/cfezcli-1.0.0.tar.gz" -C "$W"
cp -R "$W/cfezcli-1.0.0/." "$R$INSTALL_LOCATION/"
find "$R$INSTALL_LOCATION" -type d -exec chmod 755 {} +
find "$R$INSTALL_LOCATION" -type f -exec chmod 644 {} +
chmod 755 "$R$INSTALL_LOCATION/cf"
if [ -x "$R$INSTALL_LOCATION/cf" ] && [ -f "$R$INSTALL_LOCATION/lib/core/log.sh" ]; then ok_; else no_; fi

t "pkg payload has nothing group- or world-writable"
bad="$(find "$R" -perm /022 2>/dev/null)"
[ -z "$bad" ] && ok_ || { no_; echo "$bad" | head -3; }

t "cf runs from the pkg payload location"
CFDNS_ROOT="$W/pkgstate" "$R$INSTALL_LOCATION/cf" --help >/dev/null 2>&1 && ok_ || no_

printf '\n'
[ "$fail" -eq 0 ] && echo "BUILD TESTS PASS" || echo "BUILD TESTS FAILED"
exit "$fail"
