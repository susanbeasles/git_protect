# Release engineering

How a change reaches `main`, and why the released commit is provably the tested one.

```
feature/x ──replay+sign──▶ integration/pr-123 ──fast-forward──▶ main ──▶ vX.Y.Z
             (rebased on main)   (all CI runs here)              (same SHA)   (immutable)
```

The property the whole design exists to guarantee:

> The SHA that ships is byte-for-byte the SHA that passed CI.

That holds because `main` is *fast-forwarded* to the integration SHA. No merge
commit is created, so no new tree, no new SHA, and no untested state ever exists on
`main`.

---

## Correcting one assumption

You said we can't sign commits in CI. **We can.** Two mechanisms, and this repo
uses both:

| What | How it's signed | Attribution |
|---|---|---|
| Replayed commits on the integration branch | SSH signing key held by the app | **original author preserved** |
| Release tags | GitHub's own key, via the Git Data API with an app token | app |

The reason the replay uses an SSH key rather than API commits: GitHub only applies
its web-flow signature to API commits that carry **no custom author information**.
Using the API would have signed everything and erased who wrote it. An SSH signing
key keeps both the original author and a valid signature. That trade-off is the
single most important decision in this pipeline, and it goes the other way for
tags, where there is no author to preserve.

---

## One-time setup

### 1. The integration GitHub App

Create at **Settings → Developer settings → GitHub Apps → New GitHub App**.

Repository permissions:

| Permission | Level | Why |
|---|---|---|
| Contents | Read and write | push integration branches, fast-forward main, create tags |
| Pull requests | Read and write | write the approval marker, comment, close |
| Metadata | Read | implied |

Nothing else. Do **not** grant Actions, Administration, or Workflows.

Install it on this repository only. Then generate a private key and record:

- App ID → secret `INTEGRATION_APP_ID`
- Private key (whole PEM) → secret `INTEGRATION_APP_PRIVATE_KEY`

### 2. The bot signing key

```bash
ssh-keygen -t ed25519 -C "integration-bot@sonarmd.com" -f ./integration_signing -N ""
```

- Private key → secret `INTEGRATION_SIGNING_KEY`
- Bot email → secret `INTEGRATION_BOT_EMAIL`
- **Public key** → register on the account the app acts as, at
  <https://github.com/settings/keys> → **New SSH key** → key type **Signing Key**.
  Without this the signature exists but GitHub reports `unknown_key`.

### 3. The release signing key

```bash
gpg --quick-generate-key "SonarMD Release Signing <release@sonarmd.com>" ed25519 sign never
gpg --armor --export-secret-keys release@sonarmd.com   # -> RELEASE_GPG_PRIVATE_KEY
gpg --fingerprint release@sonarmd.com                  # -> pin this in install.sh
```

- Private key → secret `RELEASE_GPG_PRIVATE_KEY`
- Passphrase → secret `RELEASE_GPG_PASSPHRASE`
- Fingerprint → edit `EXPECT_FINGERPRINT` in `install.sh`

**Pinning the fingerprint is what makes signature checking mean anything.** An
installer that trusts whichever key ships next to the artifact verifies nothing: an
attacker who can replace the tarball can replace the key. Until you pin it, the
installer warns and prints the fingerprint it saw.

### 4. Enable immutable releases

**Settings → General → Releases → Immutable releases.** Once on, published
assets can't be changed and release tags can't be moved or deleted. GitHub also
generates Sigstore attestations per asset, verifiable with:

```bash
gh release verify v1.2.3 --repo sonarmd/cfezcli
gh release verify-asset v1.2.3 cfezcli-1.2.3.tar.gz --repo sonarmd/cfezcli
```

---

## The self-gating problem, and what is done about it

`pull_request` workflows run the workflow definition from **the pull request's own
head**, and for same-repository branches those runs receive the repository secrets.
A pull request can therefore rewrite the gate that is supposed to police it: delete
the signature check, then mint its own approval marker using the app token.

An earlier version of the merge job authenticated the approval with
`[ "$approver_type" = Bot ]`. That is not sufficient — **every bot installed on the
repository satisfies it, `github-actions[bot]` included, and any workflow can post
as that identity.** It was a path to merging arbitrary code to `main`.

Three controls now stand in the way, in `scripts/verify-approval.sh`, which the
merge job runs **from a checkout of `main`** rather than from the pull request:

1. **Marker provenance.** GitHub records which App created a comment in
   `performed_via_github_app.id`. That field cannot be set by another app, by
   `github-actions[bot]`, or by a user. It must equal the integration app's id.
2. **Independent evidence that CI ran.** The check runs for the integration commit
   are queried from the Checks API. A forged comment can claim the gate passed; it
   cannot retroactively invent a successful check run under a name it never
   executed.
3. **Withdrawal of automation for gate changes.** A pull request touching
   `.github/**`, `scripts/**`, or `install.sh` is refused unless it carries a human
   review approval. This is the honest answer to the residual risk: a workflow the
   pull request modified still holds the app token and could satisfy control 1, so
   the whole class of change is taken out of the automated path.

`test/approval.sh` asserts every forgery case: a marker from `github-actions[bot]`,
from a different App, hand-written by a user, with no marker at all, malformed,
claiming success the Checks API contradicts, succeeding under a different check
name, and editing the gate without review — 22 assertions.

CODEOWNERS on those same paths is the other half of control 3. Neither works alone.

### Residual risk

Anyone holding `INTEGRATION_APP_PRIVATE_KEY` is the merge authority, full stop.
Treat it as a production credential and rotate on any suspicion. The controls above
raise the bar from "any contributor who can open a pull request" to "someone who can
obtain the app private key or a code-owner review", which is a different class of
problem but not an impossible one.

---

## Branch protection — the part that can't live in code

Create a **ruleset** (not legacy branch protection; only rulesets let you leave the
bypass list genuinely empty).

**Settings → Rules → Rulesets → New branch ruleset**

- Name: `main is machine-only`
- Enforcement: **Active**
- Target: `main`
- **Bypass list: EMPTY.** Not "org admins", not "repo admins". Empty. This is the
  clause that delivers "zero human bypass"; everything else is decoration.

Rules to enable:

| Rule | Setting |
|---|---|
| Restrict creations | on |
| Restrict updates | on |
| Restrict deletions | on |
| Require linear history | on |
| Require signed commits | on |
| Block force pushes | on |
| Require status checks | `merge gate` |

Then **Settings → Rules → Rulesets → your ruleset → Bypass list → Add → the
integration App.** The app is the only entry. Every human, including the repo
owner, is now unable to push, force-push, delete, or create `main`.

A third ruleset for the integration branches, so only the app can write them:

- Name: `integration branches are machine-only`
- Target: **Branches**, pattern `integration/**`
- Restrict creations, updates, deletions: on
- Bypass list: the integration App only

Without it a human with write access could force-push an integration branch. The
approval records a specific SHA and the merge job re-checks it, so this is
defence in depth rather than the primary control — but it costs nothing.

A second ruleset for tags:

- Name: `release tags are immutable`
- Target: **Tags**, pattern `v*`
- Restrict updates and deletions: on
- Bypass list: empty

### Also required

**Settings → Actions → General:**

- Workflow permissions → **Read repository contents permission** (the workflows
  request what they need per-job)
- Uncheck "Allow GitHub Actions to create and approve pull requests"

Disable the merge button entirely — **Settings → General → Pull Requests** — uncheck
allow merge commits, squash, and rebase. Merging happens only via `/merge`.

---

## Day-to-day

```bash
# one-time, per developer
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
# register the PUBLIC key as a Signing Key at github.com/settings/keys
```

Then work normally and open a PR against `main`. On every push:

1. every commit is checked for a signature from a key registered to its author
2. the branch is rebased onto the current `main`, re-signing each commit
3. `integration/pr-<n>` is force-pushed — **this is the only ref CI tests**
4. the full suite runs on Ubuntu and macOS, plus shellcheck
5. a reproducible production build runs, self-verifies, and is attested
6. the gate writes an approval comment recording the approved SHA

To ship, comment `/merge`. The merge job then:

- checks the commenter has write access
- reads the approval and refuses if it wasn't written by the app
- refuses if the integration branch moved since approval
- refuses if the merge would not be a true fast-forward
- re-verifies signatures on the exact commits about to land
- fast-forwards `main`, tags `vX.Y.Z`, and publishes an immutable release

If `main` moved after your replay, the fast-forward check fails by design. Push
again to trigger a fresh replay.

---

## Versioning

Derived from conventional commits since the last tag — no manual bumping, no
date-based versions.

| Commit | Bump |
|---|---|
| `feat!:` or `BREAKING CHANGE:` footer | major (minor while `0.x`, per semver §4) |
| `feat:` | minor |
| `fix:` `perf:` `refactor:` `revert:` | patch |
| `chore:` `docs:` `test:` `ci:` `build:` `style:` | patch, if nothing else applies |

Tags are sorted by version, not by date, so a hotfix tagged later never becomes
"latest" ahead of a higher version.

```bash
scripts/version.sh current   # last released
scripts/version.sh bump      # major | minor | patch
scripts/version.sh next      # the version that would be released
scripts/version.sh notes     # grouped changelog
```

---

## What actually guarantees integrity: the commit SHA

A git commit SHA covers the tree **and** the parent chain **and** author and
timestamp metadata. A content digest covers only the tree. That difference is the
whole ballgame.

Two commits can have byte-identical trees and different histories. Squash a commit
whose change was later reverted and the final tree is unchanged while a commit has
been orphaned:

```
honest:      one ── two ── three        tree ada51f69…  commit 02c6d0d1…
rewritten:   one ─────────── three      tree ada51f69…  commit 80a690c2…
                                        ^ identical      ^ different
```

A content comparison sees nothing wrong. The commit SHA differs immediately. If
`two` was a released commit, that release can no longer be reproduced from the
repository — and a payload check would have waved it through.

So the pipeline asserts commit identity, in `scripts/assert-history.sh`, at three
points:

| When | Subcommand | Asserts |
|---|---|---|
| before main is touched | `ff-safe` | target differs from main; main is an ancestor; no commit on main becomes unreachable; **every previously released tag stays reachable**; target is not already tagged |
| after the push | `landed` | `origin/main` is *exactly* the approved commit, verified by re-fetching rather than inferred from the push exit code |
| in every build job | `building` | `HEAD` is the approved commit **and** `origin/main` is the same commit |

The orphaned-release check is the one that catches a rewritten trunk. Every existing
`v*` tag must remain an ancestor of the new main. If one does not, the job refuses
and names the tag, because a released commit that is no longer reachable from main
means that release cannot be rebuilt from this repository. The correct response is
to stop and find out what rewrote trunk, not to look for a second opinion from a
content hash.

`test/history.sh` constructs the identical-tree/different-history case with real git
operations and asserts that `ff-safe` refuses it, alongside divergent branches,
nothing-to-release, and already-released commits — 23 assertions.

### What the payload digest is for

`payload_sha256` (the digest of `FILES.sha256`) answers exactly one narrower
question: **is the build reproducible?**

At a fixed commit SHA the tree cannot vary, because git is content-addressed. So a
payload difference at the same commit can only mean the build is not deterministic —
a toolchain difference between runners, or something reading the environment it
should not. That is worth failing on, and the release job does fail on it, but it is
a build check and the failure message says so.

An earlier version of this document described the payload comparison as answering
"is this the tree that passed CI?". That was wrong. The commit SHA answers that, and
nothing else needs to.

The digest is still designed to be version- and commit-independent, because the
tarball's own hash is not:

| | version | commit | payload contents |
|---|---|---|---|
| `tarball_sha256` | changes | changes | changes |
| `payload_sha256` | stable | stable | changes |

Without that property the reproducibility check would fail spuriously whenever the
version was resolved differently between the PR build and the release build — which
it can be, because the version is resolved at merge time.

### Why the version is resolved at merge time

Two open pull requests both compute the same "next" version; neither can know about
the other. If the version came from the PR's approval comment, the second to merge
would collide with an existing tag. It is computed in the merge job instead, against
the tags that exist at that moment, which is the only authoritative point. The
version shown in the approval comment is labelled indicative.

### Why the tag is reserved before the fast-forward

The tag existence check runs **before** main is moved. In an earlier ordering it ran
after: a colliding version left main advanced with no tag, no release and no
artifacts — a partial state needing manual repair, and the worst possible failure
for a pipeline whose purpose is that main is always releasable. A collision now
aborts with main untouched.

### On reverting a release

A revert lands as new commits on top of main, so the reverted state has a new commit
SHA even though its tree may match an older release. It therefore gets a new version
and a new release, and the history contains the revert. That is the desired
behaviour, and it is a direct consequence of keying identity on the commit rather
than the content: content-keyed identity would conclude "this equals v1.2.0, reuse
it", which would lose the fact that a revert happened.

---

## Reproducible builds

The release model depends on the PR's artifact and the release's artifact being the
same bytes. `scripts/build.sh` fixes mtime, uid/gid, sort order, directory modes,
and passes `gzip -n`, so the same commit produces an identical tarball on any
runner at any time.

```bash
scripts/build.sh --version 1.2.3    # build
scripts/build.sh --verify dist      # rebuild and compare checksums
```

Verified in testing across differing wall-clock times, umasks (022, 027, 077, 002),
and working directories. Normalising directory modes matters more than it sounds: a
hardened runner at `umask 077` otherwise produces a different tarball than a
developer at `umask 022`, and the build stops being reproducible for a reason
unrelated to the code.

The release job rebuilds at the merged SHA and **fails the release** if
`payload_sha256` doesn't match the one the PR recorded. `--verify` distinguishes the
two failure modes: identical content built with a different version or commit is a
metadata difference, not a reproducibility failure, and it says so rather than
crying wolf.

---

## What this does and does not protect against

Stated plainly, because a security control you misunderstand is worse than none.

**Protects against**

- a pull request rewriting the gate that reviews it, then approving itself

- a human pushing directly to `main`, including an org owner
- code reaching `main` that has not passed the full suite on Linux and macOS
- untested code shipping: the released SHA is the tested SHA, by construction
- unsigned or foreign-key commits landing
- a release artifact differing from the tested artifact
- a release being modified or a tag being moved after publication
- an installer accepting a tampered tarball, a modified file inside a valid
  tarball, an absent signature, or a signature from the wrong key

**Does not protect against**

- **Anyone holding the app private key or the signing secrets.** They are the
  merge authority. A workflow modified by a pull request still holds the app token,
  which is why gate-affecting changes require human review rather than relying on
  marker provenance alone.
- **Anyone holding the app private key or the signing secrets.** They are the
  merge authority. Rotate on any suspicion; treat them as production credentials.
- **A compromised GitHub account with a registered signing key.** The gate proves
  a trusted key signed the commit, not that the human meant to.
- **Malicious code that passes the tests.** CI proves the suite passed, nothing
  about intent. This is why human review still matters.
- **Dependency compromise.** Actions are pinned to full SHAs, which prevents tag
  re-pointing but not a compromised pinned commit.

---

## macOS signing

`.github/workflows/macos-sign.yml` — one reusable job, `macos-14`, called by the
release workflow:

```
build-release (ubuntu) ──▶ macos-sign (macos-14) ──▶ publish (ubuntu)
```

The mac runner does four things and gets out of the way:

1. **Verify before signing.** `gh attestation verify` on the incoming tarball, plus
   a checksum check against `SHA256SUMS`. Signing is an endorsement — endorsing an
   artifact whose provenance was never checked would let a tampered tarball inherit
   your Developer ID, which is strictly worse than shipping unsigned.
2. **Sign.** `pkgbuild` the payload, `productsign` with the Developer ID Installer
   identity from an ephemeral keychain.
3. **Notarise.** `xcrun notarytool submit --wait`, then `stapler staple` so the
   package validates offline instead of phoning Apple at install time.
4. **Hand back.** Upload the `.pkg` plus its checksum as an artifact. The publish
   job re-verifies that checksum before attaching, so a swap in artifact storage
   is caught.

It never rebuilds the payload — the bytes it signs are the bytes Linux built and
attested, so signing cannot change what ships.

The job also **installs the package on the runner and smoke-tests it**: `cf` runs,
`cf integrity verify` matches its pin, the symlink resolves to
`/usr/local/lib/cfezcli`, the stamped version matches, and nothing is
group-writable. Signing something that doesn't install is a real failure mode and
macOS is the only place it can be caught.

### Why publish waits for it

Immutable releases cannot have assets added after publication, so the `.pkg` has to
exist *before* `gh release create` runs. That is why the release was split into
build → sign → publish rather than appending the package afterwards.

### Secrets

| Secret | Where it comes from |
|---|---|
| `APPLE_INSTALLER_CERT_P12` | Developer ID Installer cert exported as `.p12`, then `base64` |
| `APPLE_INSTALLER_CERT_PASSWORD` | the export password |
| `APPLE_TEAM_ID` | Apple Developer account |
| `APPLE_API_KEY_ID` | App Store Connect → Users and Access → Integrations → Keys |
| `APPLE_API_ISSUER_ID` | same page |
| `APPLE_API_KEY_P8` | contents of the downloaded `AuthKey_*.p8` |

An App Store Connect API key is used rather than an Apple ID and app-specific
password: it has no MFA prompt, is scopeable, and is revocable independently of a
human account.

```bash
security find-identity -v -p basic | grep "Developer ID Installer"
security export -k login.keychain -t identities -f pkcs12 -o cert.p12
base64 -i cert.p12 | pbcopy
```

**If the secrets are absent the job reports skipped and returns `signed=false`.**
The release still publishes; `install.sh` only enforces package signing when a
`.pkg` is actually present, so an unconfigured repo degrades to checksum + GPG +
attestation rather than breaking.

`workflow_dispatch` is also wired up, so you can sign a version by hand without
re-running the pipeline.

---

## Not implemented

- Signing the tarball itself rather than the checksum file. Signing `SHA256SUMS`
  covers every artifact transitively and is the conventional approach.
- SBOM generation.
- Verifying that PR authors are org members.
- Universal binary or Intel-specific packaging. The payload is a script tree, so
  architecture does not apply; the `.pkg` installs the same files everywhere.
