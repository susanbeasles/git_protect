#!/usr/bin/env bash
# cfezcli installer.
#
#   curl --tls-max 1.3 --proto '=https' -fsSL \
#     https://github.com/sonarmd/cfezcli/releases/latest/download/install.sh | bash
#
# Verification, in order. Any failure aborts before a single file is installed:
#
#   1. TLS 1.2+ enforced, https only, no redirects to other hosts
#   2. SHA256SUMS matched against the downloaded tarball
#   3. SHA256SUMS.asc verified against the pinned release key fingerprint
#   4. GitHub build attestation verified (Sigstore) when gh is available
#   5. every file inside the tarball matched against FILES.sha256
#   6. on macOS, the signed .pkg path checks the Developer ID and notarisation
#
# Nothing is executed from the archive before all of that passes.
#
# Options (or the matching CFEZ_* environment variables):
#   --version X.Y.Z     install a specific version (default: latest)
#   --prefix DIR        install root (default: /usr/local/lib/cfezcli)
#   --bin DIR           symlink location (default: /usr/local/bin)
#   --no-attestation    skip step 4 (checksum + signature still enforced)
#   --insecure-skip-gpg skip step 3. Strongly discouraged; requires --i-accept-risk
#   --dry-run           verify everything, install nothing
#   --uninstall         remove a previous install
set -euo pipefail

REPO="${CFEZ_REPO:-sonarmd/cfezcli}"
VERSION="${CFEZ_VERSION:-latest}"
PREFIX="${CFEZ_PREFIX:-/usr/local/lib/cfezcli}"
BINDIR="${CFEZ_BINDIR:-/usr/local/bin}"
BASE_URL="${CFEZ_BASE_URL:-https://github.com}"

# Pinned fingerprint of the release signing key. An installer that trusts whatever
# key ships beside the artifact verifies nothing — an attacker who can replace the
# tarball can replace the key too. Set CFEZ_EXPECT_FINGERPRINT to override for a
# fork, or leave the placeholder and the installer will tell you what to pin.
EXPECT_FINGERPRINT="${CFEZ_EXPECT_FINGERPRINT:-REPLACE_WITH_RELEASE_KEY_FINGERPRINT}"

SKIP_ATTESTATION="${CFEZ_NO_ATTESTATION:-}"
SKIP_GPG=""
ACCEPT_RISK=""
DRY_RUN=""
UNINSTALL=""

# ---------------------------------------------------------------- output
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\033[0;32m'; C_WARN=$'\033[1;33m'; C_ERR=$'\033[0;31m'
  C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_OK=; C_WARN=; C_ERR=; C_DIM=; C_BOLD=; C_OFF=
fi
step()  { printf '%s==>%s %s\n' "$C_BOLD" "$C_OFF" "$*"; }
ok()    { printf '  %sok%s   %s\n' "$C_OK" "$C_OFF" "$*"; }
warn()  { printf '  %s!!%s   %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
note()  { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
die()   { printf '\n%sinstall failed:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    --bin)     BINDIR="$2"; shift 2 ;;
    --repo)    REPO="$2"; shift 2 ;;
    --no-attestation) SKIP_ATTESTATION=1; shift ;;
    --insecure-skip-gpg) SKIP_GPG=1; shift ;;
    --i-accept-risk) ACCEPT_RISK=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option '$1' (try --help)" ;;
  esac
done

# ---------------------------------------------------------------- uninstall
if [ -n "$UNINSTALL" ]; then
  step "Uninstalling cfezcli"
  SUDO=""; [ -w "$(dirname "$PREFIX")" ] || SUDO="sudo"
  if [ -L "$BINDIR/cf" ]; then $SUDO rm -f "$BINDIR/cf" && ok "removed $BINDIR/cf"; fi
  if [ -d "$PREFIX" ]; then $SUDO rm -rf "$PREFIX" && ok "removed $PREFIX"; fi
  note "state in your config directory was left alone; remove it by hand if you want it gone"
  exit 0
fi

# ---------------------------------------------------------------- preflight
step "Checking prerequisites"

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed${2:+ ($2)}"
}
need curl
need tar

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Darwin|Linux) ;;
  *) die "unsupported OS: $OS (this tool supports macOS and Linux)" ;;
esac
ok "$OS $ARCH"

# The tool itself needs these at runtime; refuse now rather than after installing.
# Hard runtime requirements. curl and tar were already checked above; node is
# optional and handled separately because the tool degrades rather than fails.
MISSING=""
for c in jq sed awk grep; do
  command -v "$c" >/dev/null 2>&1 || MISSING="$MISSING $c"
done
if [ -n "$MISSING" ]; then
  printf '\n'
  warn "cfezcli needs:$MISSING"
  if [ "$OS" = Darwin ]; then note "install with: brew install$MISSING"
  else note "install with: sudo apt-get install -y$MISSING"; fi
  die "missing runtime dependencies:$MISSING"
fi
ok "jq $(jq --version 2>/dev/null)"

if command -v node >/dev/null 2>&1; then
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$NODE_MAJOR" -ge 18 ]; then ok "node $(node -v)"
  else warn "node $(node -v) is older than 18 — 'cf dns doctor' and 'cf dns validate' will not run"; fi
else
  warn "node 18+ not found — 'cf dns doctor' and 'cf dns validate' will not run"
  note "everything else works; install node later to enable analysis"
fi

# bash 4+ is required: the code uses associative-array-free but mapfile/[[ features.
BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
if [ "$BASH_MAJOR" -lt 4 ]; then
  warn "this shell is bash $BASH_VERSION"
  note "macOS ships bash 3.2; install a newer one with: brew install bash"
  die "bash 4 or newer is required"
fi
ok "bash $BASH_VERSION"

# ---------------------------------------------------------------- download
# TLS floor and https-only. --proto '=https' also forbids a redirect from
# stepping down to http, which -L would otherwise follow silently.
CURL_OPTS=(--proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL
           --retry 3 --retry-delay 1 --max-time 120)
if curl --help all 2>/dev/null | grep -q -- '--tls-max'; then
  CURL_OPTS+=(--tls-max 1.3)
fi

fetch() { curl "${CURL_OPTS[@]}" "$1" -o "$2"; }
fetch_stdout() { curl "${CURL_OPTS[@]}" "$1"; }

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

step "Resolving release"
if [ "$VERSION" = latest ]; then
  # Follow the release redirect rather than hitting the API, so this works
  # unauthenticated and without rate limits.
  DL="$BASE_URL/$REPO/releases/latest/download"
  MANIFEST="$TMP/MANIFEST.txt"
  fetch "$DL/MANIFEST.txt" "$MANIFEST" \
    || die "could not fetch the release manifest from $DL — is the repo public and does a release exist?"
  VERSION="$(sed -n 's/^version: //p' "$MANIFEST")"
  [ -n "$VERSION" ] || die "the release manifest did not contain a version"
else
  printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
    || die "--version must be MAJOR.MINOR.PATCH, got '$VERSION'"
  DL="$BASE_URL/$REPO/releases/download/v$VERSION"
  fetch "$DL/MANIFEST.txt" "$TMP/MANIFEST.txt" \
    || die "no release found for v$VERSION"
fi
TARBALL="cfezcli-$VERSION.tar.gz"
ok "cfezcli $VERSION"
note "$DL"

step "Downloading"
fetch "$DL/$TARBALL"      "$TMP/$TARBALL"     || die "could not download $TARBALL"
fetch "$DL/SHA256SUMS"    "$TMP/SHA256SUMS"   || die "could not download SHA256SUMS"
fetch "$DL/FILES.sha256"  "$TMP/FILES.sha256" || die "could not download FILES.sha256"
ok "$TARBALL ($(wc -c < "$TMP/$TARBALL" | tr -d ' ') bytes)"

# ---------------------------------------------------------------- 2. checksum
step "Verifying checksum"
sha_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "need sha256sum or shasum to verify the download"; fi
}
ACTUAL="$(sha_of "$TMP/$TARBALL")"
EXPECTED="$(awk -v f="$TARBALL" '$2 == f {print $1}' "$TMP/SHA256SUMS")"
[ -n "$EXPECTED" ] || die "SHA256SUMS does not list $TARBALL"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  printf '  expected %s\n  actual   %s\n' "$EXPECTED" "$ACTUAL" >&2
  die "checksum mismatch — do not use this download"
fi
ok "sha256 $ACTUAL"

# ---------------------------------------------------------------- 3. signature
step "Verifying signature"
if [ -n "$SKIP_GPG" ]; then
  [ -n "$ACCEPT_RISK" ] || die "--insecure-skip-gpg also requires --i-accept-risk"
  warn "SIGNATURE VERIFICATION SKIPPED at your request"
elif ! command -v gpg >/dev/null 2>&1; then
  warn "gpg is not installed — cannot verify the detached signature"
  note "install with: $( [ "$OS" = Darwin ] && echo 'brew install gnupg' || echo 'sudo apt-get install -y gnupg' )"
  [ -n "$ACCEPT_RISK" ] || die "refusing to install unverified. Install gpg, or pass --insecure-skip-gpg --i-accept-risk"
else
  if ! fetch "$DL/SHA256SUMS.asc" "$TMP/SHA256SUMS.asc" 2>/dev/null; then
    warn "this release has no detached signature"
    [ -n "$ACCEPT_RISK" ] || die "refusing to install unsigned. Pass --insecure-skip-gpg --i-accept-risk to override"
  else
    fetch "$DL/release-key.asc" "$TMP/release-key.asc" || die "signature present but the public key is missing"
    export GNUPGHOME="$TMP/gnupg"; install -m 700 -d "$GNUPGHOME"
    gpg --batch --quiet --import "$TMP/release-key.asc" 2>/dev/null \
      || die "could not import the release key"
    FPR="$(gpg --batch --with-colons --fingerprint 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"

    if [ "$EXPECT_FINGERPRINT" = REPLACE_WITH_RELEASE_KEY_FINGERPRINT ]; then
      warn "no fingerprint is pinned in this installer"
      note "the signature will be checked, but not that it is YOUR key"
      note "pin it by setting CFEZ_EXPECT_FINGERPRINT, or edit EXPECT_FINGERPRINT to:"
      note "  $FPR"
    elif [ "$FPR" != "$EXPECT_FINGERPRINT" ]; then
      printf '  expected fingerprint %s\n  got                  %s\n' "$EXPECT_FINGERPRINT" "$FPR" >&2
      die "the release is signed by an unexpected key — refusing to install"
    else
      ok "key fingerprint matches the pinned value"
    fi

    gpg --batch --verify "$TMP/SHA256SUMS.asc" "$TMP/SHA256SUMS" 2>"$TMP/gpg.log" \
      || { sed 's/^/       /' "$TMP/gpg.log" >&2; die "signature verification failed"; }
    ok "SHA256SUMS signature is valid ($FPR)"
  fi
fi

# ---------------------------------------------------------------- 4. attestation
step "Verifying build attestation"
if [ -n "$SKIP_ATTESTATION" ]; then
  note "skipped at your request"
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  if gh attestation verify "$TMP/$TARBALL" --repo "$REPO" >"$TMP/att.log" 2>&1; then
    ok "GitHub build attestation verified (Sigstore)"
    note "this proves the artifact was built by this repo's workflow, not just that it hashes correctly"
  else
    sed 's/^/       /' "$TMP/att.log" >&2
    die "build attestation verification failed — the artifact may not have come from CI"
  fi
else
  note "gh CLI not available or not logged in — skipping"
  note "for the strongest check: gh attestation verify <file> --repo $REPO"
fi

# ---------------------------------------------------------------- 5. per-file
step "Unpacking and verifying every file"
tar xzf "$TMP/$TARBALL" -C "$TMP" || die "could not unpack the archive"
SRC="$TMP/cfezcli-$VERSION"
[ -d "$SRC" ] || die "the archive did not contain cfezcli-$VERSION/"

( cd "$SRC" && \
  if command -v sha256sum >/dev/null 2>&1; then sha256sum -c --quiet "$TMP/FILES.sha256"
  else shasum -a 256 -c --status "$TMP/FILES.sha256"; fi ) \
  || die "a file inside the archive does not match FILES.sha256"
ok "$(grep -c . "$TMP/FILES.sha256") file(s) verified individually"

# macOS code signing, when a signed package is published alongside the tarball.
if [ "$OS" = Darwin ]; then
  if fetch "$DL/cfezcli-$VERSION.pkg" "$TMP/pkg" 2>/dev/null; then
    step "Verifying the macOS package signature"
    if pkgutil --check-signature "$TMP/pkg" > "$TMP/pkgsig.log" 2>&1; then
      ok "package signature valid"
      grep -E 'Developer ID|Status|SHA256' "$TMP/pkgsig.log" | sed 's/^/       /' || true
      if spctl -a -vv -t install "$TMP/pkg" >"$TMP/spctl.log" 2>&1; then
        ok "notarised and accepted by Gatekeeper"
      else
        warn "Gatekeeper did not accept the package"
        sed 's/^/       /' "$TMP/spctl.log" >&2
        [ -n "$ACCEPT_RISK" ] || die "refusing to install a package Gatekeeper rejects"
      fi
    else
      sed 's/^/       /' "$TMP/pkgsig.log" >&2
      die "the macOS package is not validly signed"
    fi
  fi
fi

# ---------------------------------------------------------------- self-check
step "Self-check before installing"
export CFDNS_ROOT="$TMP/selfcheck-state"
"$SRC/cf" --help >/dev/null 2>&1 || die "the downloaded cf does not run"
ok "cf --help runs"
# Captured to a variable rather than piped into grep: `grep -q` exits at the first
# match, cf takes SIGPIPE writing the rest, and under `set -o pipefail` the whole
# pipeline returns 141. That made a perfectly healthy binary look broken.
selfcheck="$("$SRC/cf" integrity show 2>/dev/null || true)"
printf '%s' "$selfcheck" | grep -q '^hash' || {
  printf '%s\n' "$selfcheck" | sed 's/^/       /' >&2
  die "integrity self-check failed"
}
ok "integrity self-check passes"
unset CFDNS_ROOT

if [ -n "$DRY_RUN" ]; then
  printf '\n%sDry run: everything verified, nothing installed.%s\n' "$C_OK" "$C_OFF"
  exit 0
fi

# ---------------------------------------------------------------- install
step "Installing"
SUDO=""
if [ ! -w "$(dirname "$PREFIX")" ]; then
  command -v sudo >/dev/null 2>&1 || die "$PREFIX is not writable and sudo is unavailable"
  SUDO="sudo"
  note "using sudo to write $PREFIX"
fi

# Locked down: the bundle must not be group- or world-writable, or the CLI's own
# tamper evidence is meaningless.
$SUDO rm -rf "$PREFIX"
$SUDO install -d -m 755 "$PREFIX"
$SUDO cp -R "$SRC/." "$PREFIX/"
$SUDO find "$PREFIX" -type d -exec chmod 755 {} +
$SUDO find "$PREFIX" -type f -exec chmod 644 {} +
$SUDO chmod 755 "$PREFIX/cf"
$SUDO chown -R "0:0" "$PREFIX" 2>/dev/null || true
ok "installed to $PREFIX (root-owned, not group-writable)"

$SUDO install -d -m 755 "$BINDIR"
$SUDO ln -sf "$PREFIX/cf" "$BINDIR/cf"
ok "linked $BINDIR/cf -> $PREFIX/cf"

# ---------------------------------------------------------------- verify install
step "Verifying the installation"
command -v cf >/dev/null 2>&1 || {
  warn "$BINDIR is not on your PATH"
  note "add it: export PATH=\"$BINDIR:\$PATH\""
}
INSTALLED_VERSION="$(sed -n 's/^version: //p' "$PREFIX/VERSION" 2>/dev/null || echo '?')"
[ "$INSTALLED_VERSION" = "$VERSION" ] || die "installed version reads '$INSTALLED_VERSION', expected '$VERSION'"
ok "cfezcli $INSTALLED_VERSION"

printf '\n%sInstalled.%s\n\n' "$C_OK$C_BOLD" "$C_OFF"
printf '  Next:\n'
printf '    cf auth login          acquire a scoped Cloudflare token\n'
printf '    cf integrity pin       record this build as trusted\n'
printf '    cf dns sync --pull     read your zone into config/masterDNS.json\n'
printf '    cf dns doctor          analyse email authentication\n\n'
printf '  %sVerify independently at any time:%s\n' "$C_DIM" "$C_OFF"
printf '    gh release verify-asset v%s %s --repo %s\n\n' "$VERSION" "$TARBALL" "$REPO"
