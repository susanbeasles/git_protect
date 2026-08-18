#!/usr/bin/env bash
# Tests install.sh against a local release server, including the cases that
# matter: a tampered tarball, a bad signature, a wrong-key signature, and a
# missing signature. An installer that only works on the happy path is not a
# security control.
set +e
SRC="$(cd "$(dirname "$0")/.." || exit 1; pwd -P)"
W="/tmp/cfez-install-test-$$"
mkdir -p "$W/rel" "$W/dest"
export PORTFILE="$W/port"
export GNUPGHOME="$W/gnupg"
install -m 700 -d "$GNUPGHOME"

fail=0
t() { printf '  %-56s ' "$1"; }
ok_() { echo PASS; }
no_() { echo FAIL; fail=1; }

cleanup() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

VER="9.9.9"

# ---------------------------------------------------------------- build a release
( cd "$SRC" && ./scripts/build.sh --version "$VER" --commit deadbeefcafe --out "$W/rel" ) >/dev/null 2>&1 \
  || { echo "SETUP FAILED: build"; exit 1; }
cp "$SRC/install.sh" "$W/rel/install.sh"

# a throwaway signing key
GPG_OK=0
if command -v gpg >/dev/null 2>&1; then
  cat > "$W/keyspec" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: cfezcli test release
Name-Email: test@example.invalid
Expire-Date: 0
%commit
EOF
  if gpg --batch --quiet --gen-key "$W/keyspec" 2>/dev/null; then
    FPR="$(gpg --batch --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')"
    gpg --batch --yes --armor --detach-sign --output "$W/rel/SHA256SUMS.asc" "$W/rel/SHA256SUMS" 2>/dev/null
    gpg --batch --armor --export "$FPR" > "$W/rel/release-key.asc" 2>/dev/null
    [ -s "$W/rel/SHA256SUMS.asc" ] && GPG_OK=1
  fi
fi

# a SECOND, untrusted key — for the wrong-key test
GPG2_OK=0
if [ "$GPG_OK" = 1 ]; then
  export GNUPGHOME="$W/gnupg2"; install -m 700 -d "$GNUPGHOME"
  cat > "$W/keyspec2" <<EOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Name-Real: cfezcli ATTACKER
Name-Email: attacker@example.invalid
Expire-Date: 0
%commit
EOF
  if gpg --batch --quiet --gen-key "$W/keyspec2" 2>/dev/null; then
    FPR2="$(gpg --batch --with-colons --fingerprint | awk -F: '/^fpr:/{print $10; exit}')"
    gpg --batch --yes --armor --detach-sign --output "$W/evil.asc" "$W/rel/SHA256SUMS" 2>/dev/null
    gpg --batch --armor --export "$FPR2" > "$W/evil-key.asc" 2>/dev/null
    GPG2_OK=1
  fi
  export GNUPGHOME="$W/gnupg"
fi

# ---------------------------------------------------------------- serve it
rm -f "$W/port"
RELDIR="$W/rel" PORTFILE="$W/port" python3 - <<'PY' &
import http.server, os
d = os.environ['RELDIR']
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def translate_path(self, path):
        # both /<repo>/releases/download/v<ver>/<file> and
        # /releases/latest/download/<file> collapse to a flat directory
        name = path.rstrip('/').split('/')[-1]
        return os.path.join(d, name)
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
open(os.environ['PORTFILE'], 'w').write(str(srv.server_address[1]))
srv.serve_forever()
PY
SRV=$!
for _ in $(seq 1 50); do [ -s "$W/port" ] && break; sleep 0.1; done
PORT="$(cat "$W/port" 2>/dev/null)"
[ -n "$PORT" ] || { echo "SETUP FAILED: server"; exit 1; }

# The installer enforces https. For a local test we exercise the verification
# logic over http by pointing CFEZ_BASE_URL at the test server and relaxing the
# proto guard only for the fetch helper, via a patched copy.
sed -e "s#--proto '=https' --proto-redir '=https' --tlsv1.2#--tlsv1.2#" \
    -e "s#CURL_OPTS+=(--tls-max 1.3)#:#" \
    "$SRC/install.sh" > "$W/install-test.sh"
chmod +x "$W/install-test.sh"

run() {
  CFEZ_REPO="test/repo" \
  CFEZ_BASE_URL="http://127.0.0.1:$PORT" \
  CFEZ_VERSION="${CFEZ_VERSION:-$VER}" \
  CFEZ_PREFIX="$W/dest/lib" \
  CFEZ_BINDIR="$W/dest/bin" \
  CFEZ_NO_ATTESTATION=1 \
  CFEZ_EXPECT_FINGERPRINT="${EXPECT:-$FPR}" \
  bash "$W/install-test.sh" "$@" 2>&1
}

# ---------------------------------------------------------------- tests
t "proto guard: refuses plain http in the real installer"
grep -q "proto '=https'" "$SRC/install.sh" && grep -q 'proto-redir' "$SRC/install.sh" && ok_ || no_

t "TLS floor is set to 1.2 or better"
grep -qE '\-\-tlsv1\.2' "$SRC/install.sh" && ok_ || no_

t "dry run verifies and installs nothing"
out="$(run --dry-run)"
if echo "$out" | grep -q 'nothing installed' && [ ! -d "$W/dest/lib" ]; then ok_
else no_; echo "$out" | tail -6; fi

t "checksum is verified"
out="$(run --dry-run)"
echo "$out" | grep -q 'sha256 ' && ok_ || { no_; echo "$out" | tail -4; }

t "per-file hashes are verified"
echo "$out" | grep -qE '[0-9]+ file\(s\) verified individually' && ok_ || { no_; echo "$out" | tail -4; }

t "self-check runs the downloaded cf before installing"
echo "$out" | grep -q 'integrity self-check passes' && ok_ || { no_; echo "$out" | tail -4; }

if [ "$GPG_OK" = 1 ]; then
  t "valid signature from the pinned key is accepted"
  out="$(run --dry-run)"
  echo "$out" | grep -q 'signature is valid' && ok_ || { no_; echo "$out" | tail -6; }

  t "pinned fingerprint mismatch is REFUSED"
  out="$(EXPECT=AAAABBBBCCCCDDDDEEEEFFFF0000111122223333 run --dry-run)"
  echo "$out" | grep -q 'signed by an unexpected key' && ok_ || { no_; echo "$out" | tail -5; }

  if [ "$GPG2_OK" = 1 ]; then
    t "signature from a DIFFERENT key is REFUSED"
    cp "$W/rel/SHA256SUMS.asc" "$W/good.asc"; cp "$W/rel/release-key.asc" "$W/good-key.asc"
    cp "$W/evil.asc" "$W/rel/SHA256SUMS.asc"; cp "$W/evil-key.asc" "$W/rel/release-key.asc"
    out="$(run --dry-run)"
    if echo "$out" | grep -q 'unexpected key'; then ok_; else no_; echo "$out" | tail -5; fi
    cp "$W/good.asc" "$W/rel/SHA256SUMS.asc"; cp "$W/good-key.asc" "$W/rel/release-key.asc"
  fi

  t "corrupted signature is REFUSED"
  cp "$W/rel/SHA256SUMS.asc" "$W/good.asc"
  printf 'garbage\n' > "$W/rel/SHA256SUMS.asc"
  out="$(run --dry-run)"
  echo "$out" | grep -qi 'signature verification failed\|could not import' && ok_ || { no_; echo "$out" | tail -5; }
  cp "$W/good.asc" "$W/rel/SHA256SUMS.asc"

  t "missing signature is REFUSED without --i-accept-risk"
  mv "$W/rel/SHA256SUMS.asc" "$W/hold.asc"
  out="$(run --dry-run)"
  echo "$out" | grep -q 'refusing to install unsigned' && ok_ || { no_; echo "$out" | tail -5; }

  t "missing signature is allowed WITH the explicit risk flag"
  out="$(run --dry-run --insecure-skip-gpg --i-accept-risk)"
  echo "$out" | grep -q 'nothing installed' && ok_ || { no_; echo "$out" | tail -5; }
  mv "$W/hold.asc" "$W/rel/SHA256SUMS.asc"

  t "--insecure-skip-gpg alone is refused without --i-accept-risk"
  out="$(run --dry-run --insecure-skip-gpg)"
  echo "$out" | grep -q 'also requires --i-accept-risk' && ok_ || { no_; echo "$out" | tail -4; }
else
  echo "  (gpg unavailable — signature tests skipped)"
fi

t "tampered tarball is REFUSED"
cp "$W/rel/cfezcli-$VER.tar.gz" "$W/good.tgz"
printf 'evil' >> "$W/rel/cfezcli-$VER.tar.gz"
out="$(run --dry-run)"
echo "$out" | grep -q 'checksum mismatch' && ok_ || { no_; echo "$out" | tail -5; }
cp "$W/good.tgz" "$W/rel/cfezcli-$VER.tar.gz"

t "tampered file inside the tarball is REFUSED"
T2="$W/repack"; mkdir -p "$T2"
tar xzf "$W/rel/cfezcli-$VER.tar.gz" -C "$T2"
echo '# injected backdoor' >> "$T2/cfezcli-$VER/lib/core/log.sh"
( cd "$T2" && tar czf "$W/rel/cfezcli-$VER.tar.gz" "cfezcli-$VER" )
# recompute the top-level checksum so ONLY the per-file check can catch it
( cd "$W/rel" && sha256sum "cfezcli-$VER.tar.gz" "FILES.sha256" > SHA256SUMS )
if [ "$GPG_OK" = 1 ]; then
  gpg --batch --yes --armor --detach-sign --output "$W/rel/SHA256SUMS.asc" "$W/rel/SHA256SUMS" 2>/dev/null
fi
out="$(run --dry-run)"
echo "$out" | grep -q 'does not match FILES.sha256' && ok_ || { no_; echo "$out" | tail -6; }
# restore
cp "$W/good.tgz" "$W/rel/cfezcli-$VER.tar.gz"
( cd "$W/rel" && sha256sum "cfezcli-$VER.tar.gz" "FILES.sha256" > SHA256SUMS )
[ "$GPG_OK" = 1 ] && gpg --batch --yes --armor --detach-sign --output "$W/rel/SHA256SUMS.asc" "$W/rel/SHA256SUMS" 2>/dev/null

t "bad --version format is rejected"
out="$(CFEZ_VERSION=1.2 run --dry-run)"
echo "$out" | grep -q 'MAJOR.MINOR.PATCH' && ok_ || { no_; echo "$out" | tail -3; }

t "unknown option is rejected"
out="$(run --nonsense)"
echo "$out" | grep -q "unknown option" && ok_ || { no_; echo "$out" | tail -3; }

t "real install places files and a working symlink"
out="$(run)"
if [ -x "$W/dest/lib/cf" ] && [ -L "$W/dest/bin/cf" ] \
   && echo "$out" | grep -q 'Installed'; then ok_
else no_; echo "$out" | tail -8; fi

t "installed bundle is not group- or world-writable"
bad="$(find "$W/dest/lib" \( -type f -o -type d \) -perm /022 2>/dev/null)"
[ -z "$bad" ] && ok_ || { no_; echo "$bad" | head -3; }

t "installed VERSION matches the release"
[ "$(sed -n 's/^version: //p' "$W/dest/lib/VERSION")" = "$VER" ] && ok_ || no_

t "installed cf runs from the symlink"
CFDNS_ROOT="$W/state" "$W/dest/bin/cf" --help >/dev/null 2>&1 && ok_ || no_

t "installed cf resolves the symlink for integrity"
b="$(CFDNS_ROOT="$W/state" "$W/dest/bin/cf" integrity show 2>/dev/null | awk '/^bundle/{print $2}')"
[ "$b" = "$W/dest/lib" ] && ok_ || { no_; echo "      bundle reported: $b"; }

t "uninstall removes everything it installed"
out="$(run --uninstall)"
if [ ! -e "$W/dest/bin/cf" ] && [ ! -d "$W/dest/lib" ]; then ok_
else no_; echo "$out" | tail -4; fi

printf '\n'
[ "$fail" -eq 0 ] && echo "INSTALLER TESTS PASS" || echo "INSTALLER TESTS FAILED"
exit "$fail"
