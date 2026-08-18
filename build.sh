#!/usr/bin/env bash
# Build the distributable artifacts.
#
# Reproducible by construction: the tarball is built with a fixed mtime, fixed
# uid/gid, fixed sort order, and no gzip timestamp. Building the same commit twice
# — on any runner, at any time — must produce byte-identical output, because the
# whole release model depends on the artifact from the PR build being the same one
# attached to the release.
#
#   scripts/build.sh --version 1.4.0 [--out dist] [--commit <sha>]
#   scripts/build.sh --verify dist    re-build and confirm checksums match
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
OUT="$ROOT/dist"
VERSION=""
COMMIT=""
VERIFY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out)     OUT="$2"; shift 2 ;;
    --commit)  COMMIT="$2"; shift 2 ;;
    --verify)  VERIFY="$2"; shift 2 ;;
    *) echo "build.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

die() { printf 'build: %s\n' "$*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }
_sha_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# The payload is defined in payload.txt, not here. A list embedded in the build
# script drifts silently whenever a module is added; a manifest can be diffed
# against the checkout, and test/build.sh does exactly that.
PAYLOAD_MANIFEST="${PAYLOAD_MANIFEST:-$ROOT/payload.txt}"
[ -f "$PAYLOAD_MANIFEST" ] || die "no payload manifest at $PAYLOAD_MANIFEST"
PAYLOAD=()
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  PAYLOAD+=("$line")
done < "$PAYLOAD_MANIFEST"
[ "${#PAYLOAD[@]}" -gt 0 ] || die "$PAYLOAD_MANIFEST lists no files"

EXECUTABLE=(cf)

# ---------------------------------------------------------------- verify mode
if [ -n "$VERIFY" ]; then
  [ -f "$VERIFY/SHA256SUMS" ] || die "no SHA256SUMS in $VERIFY"
  VERSION="$(sed -n 's/^version: //p' "$VERIFY/MANIFEST.txt" 2>/dev/null)"
  [ -n "$VERSION" ] || die "cannot read version from $VERIFY/MANIFEST.txt"
  # The commit is stamped into VERSION inside the tarball, so it is part of the
  # artifact's identity and must be replayed too. Omitting it made the verifier
  # compare a build of commit X against a build of HEAD.
  RECORDED_COMMIT="$(sed -n 's/^commit: //p' "$VERIFY/MANIFEST.txt" 2>/dev/null)"
  [ -n "$RECORDED_COMMIT" ] || die "cannot read commit from $VERIFY/MANIFEST.txt"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  "$0" --version "$VERSION" --commit "$RECORDED_COMMIT" --out "$TMP" >/dev/null
  if diff -u "$VERIFY/SHA256SUMS" "$TMP/SHA256SUMS"; then
    say "reproducible: rebuild matches $VERIFY/SHA256SUMS"
    exit 0
  fi
  # Distinguish the two failure modes: identical content built with a different
  # version or commit is a metadata difference, not a reproducibility failure.
  a="$(sed -n 's/^payload_sha256: //p' "$VERIFY/MANIFEST.txt" 2>/dev/null)"
  b="$(sed -n 's/^payload_sha256: //p' "$TMP/MANIFEST.txt" 2>/dev/null)"
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    die "payload content matches but the archive differs — check version/commit stamping, not the source tree"
  fi
  die "NOT reproducible — the payload content itself differs from the recorded build"
fi

[ -n "$VERSION" ] || die "--version is required"
printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || die "version must be MAJOR.MINOR.PATCH, got '$VERSION'"

cd "$ROOT"
[ -z "$COMMIT" ] && COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"

for f in "${PAYLOAD[@]}"; do
  [ -f "$f" ] || die "payload file missing: $f  (update PAYLOAD in scripts/build.sh)"
done

NAME="cfezcli"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKGROOT="$STAGE/$NAME-$VERSION"
mkdir -p "$PKGROOT"

say "staging $(printf '%s' "${#PAYLOAD[@]}") payload files"
for f in "${PAYLOAD[@]}"; do
  mkdir -p "$PKGROOT/$(dirname "$f")"
  cp "$f" "$PKGROOT/$f"
  chmod 644 "$PKGROOT/$f"
done
for f in "${EXECUTABLE[@]}"; do chmod 755 "$PKGROOT/$f"; done

# Normalise directory modes explicitly. mkdir -p honours the caller's umask, so
# without this the tarball's directory entries differ between a developer running
# umask 022 and a hardened runner running umask 077 — and the build stops being
# reproducible for a reason that has nothing to do with the code.
find "$PKGROOT" -type d -exec chmod 755 {} +

# Stamp the version so `cf --version` matches the release it came from, and so a
# user can tell what they are running without trusting the filename.
cat > "$PKGROOT/VERSION" <<EOF
version: $VERSION
commit: $COMMIT
EOF
chmod 644 "$PKGROOT/VERSION"

mkdir -p "$OUT"
rm -f "$OUT/$NAME-$VERSION.tar.gz" "$OUT/SHA256SUMS" "$OUT/MANIFEST.txt"

# Reproducibility: fixed mtime, fixed ownership, sorted names, gzip -n (no
# timestamp in the gzip header).
say "creating reproducible tarball"
# GNU tar is positional: options must precede --files-from, and --no-recursion
# must come before it too or it is silently ignored.
( cd "$STAGE" && \
  find "$NAME-$VERSION" -print0 | LC_ALL=C sort -z | \
  tar --create --file - \
      --mtime='2020-01-01 00:00:00 UTC' \
      --owner=0 --group=0 --numeric-owner \
      --format=gnu \
      --no-recursion \
      --null --files-from - ) | gzip -n -9 > "$OUT/$NAME-$VERSION.tar.gz"

# Per-file hashes: lets a reviewer diff a release against a checkout without
# unpacking anything, and lets `cf integrity` be cross-checked against a release.
say "computing per-file manifest"
( cd "$PKGROOT" && find . -type f -not -name VERSION | LC_ALL=C sort \
    | xargs sha256sum | sed 's#\./##' ) > "$OUT/FILES.sha256"

( cd "$OUT" && sha256sum "$NAME-$VERSION.tar.gz" "FILES.sha256" > SHA256SUMS )

TARBALL_SHA="$(awk -v f="$NAME-$VERSION.tar.gz" '$2 == f {print $1}' "$OUT/SHA256SUMS")"

# The digest of the per-file manifest. This identifies the PAYLOAD CONTENT and
# nothing else — not the version, not the commit, not the archive framing.
#
# It matters because the tarball's own hash is version- and commit-dependent: the
# version appears in the directory name inside the archive, and the commit is
# stamped into VERSION. So "does the release artifact match the tested artifact?"
# cannot be answered by comparing tarball hashes unless the version and commit are
# guaranteed identical, which they are not when two pull requests are open at once.
# payload_sha256 is the invariant that actually means "this is the tree that passed".
PAYLOAD_SHA="$(_sha_file "$OUT/FILES.sha256")"

cat > "$OUT/MANIFEST.txt" <<EOF
name: $NAME
version: $VERSION
commit: $COMMIT
tarball: $NAME-$VERSION.tar.gz
tarball_sha256: $TARBALL_SHA
payload_sha256: $PAYLOAD_SHA
files: ${#PAYLOAD[@]}
build_reproducible: yes (fixed mtime, uid/gid 0, sorted, gzip -n)
EOF

say "artifacts in $OUT:"
( cd "$OUT" && ls -1 ) | sed 's/^/    /'
say "tarball sha256: $TARBALL_SHA"
say "payload sha256: $PAYLOAD_SHA  (content only — version and commit independent)"
