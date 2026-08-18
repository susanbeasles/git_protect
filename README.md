# cf — Cloudflare DNS CLI

A small, auditable tool for managing a Cloudflare zone from the command line, with
email-authentication analysis built in.

No Terraform, no state file to corrupt. `config/masterDNS.json` is the desired
state; everything else is a snapshot you can roll back to.

---

## If you are vetting this, read these four files

The code is arranged so you do not have to read all of it to trust it.

| Question | File | Lines |
|---|---|---|
| What can this do to my zone? | `lib/dns/mutate.sh` | ~160 |
| How does it decide what to change? | `lib/dns/plan.jq` | ~50 |
| Where does my token go? | `lib/core/http.sh`, `lib/core/secret.sh` | ~90, ~110 |
| What does it refuse to do? | `lib/dns/select.sh` | ~50 |

`apply_plan` in `lib/dns/mutate.sh` is the **only** function that writes to
Cloudflare. Every mutating command — add, rm, update, sync, restore — builds a
plan and hands it there. The safety properties are therefore in one place:

1. preview every change, in full
2. snapshot the live zone to disk, **before** prompting
3. require explicit confirmation
4. apply in the order delete → update → create
5. print the rollback command

---

## Install

The project lives in a checkout; `/usr/local/bin/cf` is a symlink into it. The
integrity check resolves the symlink and hashes the real checkout, so the banner
always reflects the code that actually ran.

```bash
cd ~/code/cfezcli
chmod -R go-w .                    # a writable bundle has no tamper evidence
ln -s ~/code/cfezcli/cf /usr/local/bin/cf
cf auth login
cf integrity pin                   # record the trusted hash
```

Requires `bash 4+`, `curl`, `jq`, and `node` 18+ (analysis only). `op` (1Password
CLI) is optional but strongly preferred for credential storage.

Everything the tool writes lives under one directory, `$CFDNS_ROOT`:

| Platform | Default |
|---|---|
| macOS | `~/Library/Application Support/cfdns` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/cfdns` |

Override with `CFDNS_ROOT`, including to a path inside the repo. It holds
`config.json`, `integrity.json`, `integrity.log`, and `snapshots/` — all 0600
under a 0700 directory, enforced by a `umask 077` set before anything is created.

---

## Layout

Nothing exists to be glue. Every file performs one thin scoped function; `cf` is
wiring and a routing table, and the commands are orchestration over composables.

```
cf                      find bundle, load modules, route  (108 lines, 3 routing fns)
payload.txt             what a release contains           (data)
lib/cli/
  modules.txt           load order and dependency direction  (data)
  usage.sh              help text
  args.sh               flags -> variables; no validation, no dispatch
lib/core/               no knowledge of DNS, integrity, or the CLI
  log.sh                output, colour, wrapping
  paths.sh              where state lives
  time.sh               epoch/local formatting, BSD-vs-GNU date resolved once
  json.sh               config read/write, atomic, 0600
  retry.sh              backoff arithmetic and the retry loop; knows nothing of HTTP
  secret.sh             four credential backends behind one interface
  http.sh               method + path + body -> response
  node.sh               node detection and invocation
lib/integrity/          self-verification of this bundle; uses core only
  bundle.sh             what "the build" is, and how to hash it
  changelog.sh          append and render code-change events
  pin.sh                pin state only
  banner.sh             the coloured hash and the notification
lib/dns/                records and zone state; uses core only
  record.sh             naming, field validation
  api_body.jq           payload shaping and type guards
  query.sh              reads and snapshots
  select.sh             matching, and the refusal guard
  patch.sh              building an update, rejecting inapplicable flags
  desired.sh            the desired-state file: validate, normalise, capture
  mutate.sh             THE single write path
  plan.jq               live vs desired diff engine
lib/analysis/           the boundary to the Node analyzer; uses core
  run.sh                invoke analyzer and reporter
  gate.sh               findings -> a decision
  report.sh             format, redaction, and the advice that goes with each
lib/cmd/                orchestration only
  auth.sh dns.sh integrity.sh doctor.sh
lib/parse/              pure parsers, no I/O (Node)
  spf.mjs dmarc.mjs dkim.mjs email.mjs
lib/checks/             one file per analysis category (Node)
  spf dmarc dkim mail mx zone transport index
lib/analyze.mjs         orchestration only, ~65 lines
lib/report.mjs          rendering and redaction
lib/resolve.mjs         DNS with a seeded cache
lib/findings.mjs        the finding model
lib/records.mjs         record-list helpers
```

Dependencies run one way, and the direction is stated as data in
`lib/cli/modules.txt` rather than implied by a source order buried in a script:
`core` knows nothing about DNS, `dns` knows nothing about presentation, `analysis`
knows nothing about what a finding means, `cmd` composes all of them.

Two lists that used to live in code are now data, because a list embedded in a script
drifts silently when a module is added:

- `lib/cli/modules.txt` — load order, read by both `cf` and the test harness
- `payload.txt` — release contents, read by `scripts/build.sh`

`test/build.sh` asserts every module in `modules.txt` appears in `payload.txt`, that
every path in `payload.txt` exists, and that the built tarball contains every module
the loader will try to source. Those three assertions are what stop the manifests
from rotting.

---

## Records

```bash
cf dns ls [selectors]

cf dns add --name mail --type TXT --content "v=spf1 include:mailgun.org ~all" \
           --ttl 300 --tags email,spf --comment "had MX but no SPF"

cf dns rm     --name _dmarc --type TXT
cf dns update --name @ --type TXT --content "v=spf1" --set-content "v=spf1 ... -all"
```

### Selectors

Combine with AND. Available on `ls`, `rm`, and `update`.

| Flag | Meaning |
|---|---|
| `--name N` | exact name; `@` is the apex |
| `--type T` | record type |
| `--content S` | case-insensitive substring of the value |
| `--tags a,b` | record must carry **all** listed tags |
| `--id ID` | exact Cloudflare record id |

On `update`, `--content` **matches** and `--set-content` **changes**.

A selection that would sweep the zone is refused, and so is `--type` alone —
`--type TXT` with nothing else would take out every TXT record you have.

Flags that cannot apply to a matched type are rejected rather than silently
dropped: `--proxy` on a TXT record is an error, not a no-op.

---

## Desired state

```bash
cf dns sync --pull                    # live zone -> config/masterDNS.json
cf dns sync                           # preview (dry run)
cf dns sync --apply                   # execute
cf dns restore --file <snapshot>      # roll back
cf dns validate                       # offline syntax check of the file
```

The planner classifies every difference as **update**, **create**, or **delete**,
and prefers an in-place `PUT` over delete-then-create wherever a record can be
matched on name and type.

This matters more than it sounds. Delete-then-create on an SPF record leaves a
window with **no SPF record at all**, and mail sent in that window fails
authentication. `test/plan.sh` asserts it directly, including the case that
motivated it: collapsing a duplicated `_dmarc` record to a single different value
produces one in-place update plus one delete, never two deletes and a create.

Apply order is delete → update → create, so duplicate-record PermErrors clear
before anything else moves.

---

## Analysis

```bash
cf dns doctor                                 # live zone, full analysis
cf dns doctor --llm-safe --out report.md      # redacted, safe to share
cf dns validate                               # offline, syntax only
```

Exit codes: `2` if any CRITICAL, `1` if any HIGH, `0` otherwise. Usable as a CI
gate.

### Scoped checks

Every check declares a scope, and this is load-bearing:

- **`record`** — syntax and self-consistency. Judgeable from one record alone.
- **`zone`** — needs the whole zone.

`cf dns add` pre-flights the record you are about to publish using record-scoped
checks only. Without that distinction, adding a single valid MX record reported
three false criticals — `MX_NO_SPF`, `NO_DMARC`, `MX_NO_DKIM` — because the SPF
record is, obviously, a different record. A tool that blocks correct input is a
tool people route around. `--force` overrides regardless.

### What is checked

**SPF** — duplicate records, invalid syntax, unknown mechanisms and modifiers,
recursive DNS-lookup count against the RFC 7208 limit of 10, void-lookup limit,
include loops, `+all`, missing `all`, terms after `all`, deprecated `ptr`,
`redirect`/`all` conflict, oversized TXT values.

**DMARC** — duplicate records, full tag syntax, `p=none`, missing `rua`, `ruf`
privacy exposure, `pct<100`, missing `sp`, strict alignment against subdomain
envelope senders, records published off `_dmarc`, and external report-destination
authorisation per RFC 7489 §7.1.

**DKIM** — selector liveness, revoked (empty `p=`) selectors, key-size estimation,
malformed tags.

**Mail coverage** — sending names with no SPF, no DKIM, zones with MX but no DMARC.

**MX** — proxied records, missing priority, CNAME targets, unresolvable targets,
equal-priority spread.

**Zone** — dangling CNAMEs (subdomain takeover), CNAME coexistence, apex CNAME,
unproxied origin exposure, wildcards, exact duplicates, low TTLs, MTA-STS and
TLS-RPT absence.

Analysis is self-consistent: names inside the zone resolve from the data you
supplied, so analysing a snapshot or a proposed change does not silently mix in
live DNS. Only external names hit the network.

---

## LLM-safe reports

`--llm-safe` (or `--redact standard|strict`) mechanically redacts before export.

| | standard | strict |
|---|---|---|
| DKIM public keys | bit-length marker only | same |
| Verification tokens | removed | same |
| High-entropy TXT values | removed | same |
| Public IPs | `IPn` | same |
| Private IPs | kept | `IPn` |
| Email local-parts | `MAILBOXn` | same |
| Email domains | kept | `MAILDOMAINn` |
| Zone name | `example.com` | same |
| Cloudflare object IDs | dropped | same |
| Subdomain labels | kept | `SUBn` |
| Vendor domains | kept | `EXTDOMAINn` |

Vendor domains are kept at `standard` deliberately: the zone name is already
replaced, so an unattributed "uses Mailgun" carries little value, while the vendor
identity is often what makes a finding actionable. Use `strict` when even the
tech-stack inventory should not leave the building.

Placeholders are stable within a report, so structural relationships survive.
`--keymap` writes the reversal map at 0600 — keep it local; uploading it beside the
report defeats the exercise.

`test/redact.sh` asserts **both** directions: planted secrets never survive, and
the report stays readable. It fails if `RFC 7208`, `MX_NO_SPF`, or the prose
disappears, so over-redaction is caught too.

---

## Credentials

```bash
cf auth login      # easy mode opens the browser with scopes pre-filled
cf auth status     # verifies against /user/tokens/verify
cf auth logout     # forgets it locally; does NOT revoke
```

Easy mode opens Cloudflare's documented token-template URL with
`Zone > DNS > Edit` pre-selected — the only permission this tool needs. Zone
Resources, Client IP, and TTL still need setting by hand; the template cannot
pre-fill those.

It then watches the clipboard. Cloudflare tokens have no documented prefix like
`ghp_`, so the charset regex only finds *candidates* — a live
`/user/tokens/verify` call is the actual gate. The clipboard is cleared on success.

Storage, in preference order:

| Backend | Notes |
|---|---|
| 1Password | default when `op` is signed in. Creates the `automation` vault if absent and writes `cf-internalcli-token` with scope, expiry, owner, and rotation instructions in the notes, so it is legible in three months. |
| macOS Keychain | encrypted at rest. Caveat: the value transits `security`'s argv briefly. |
| env var | never written to disk, dies with the shell. |
| file | 0600 in `$CFDNS_ROOT`. Discouraged. |

The token is read into a shell variable and handed to curl through a stdin config
file (`curl -K -`), so it never appears in argv and cannot be read out of `ps` or
`/proc/<pid>/cmdline`. `test/leak.sh` proves this by polling `/proc/*/cmdline` with
a canary token during a live call.

Rate limiting: retries on 429 and 5xx, honouring `Retry-After`, falling back to
exponential backoff capped at 32s with 0–999ms of jitter so parallel invocations do
not resynchronise.

---

## Tamper evidence

Every command prints the SHA-256 of the executing bundle as a colour bar plus the
full 64 hex digits in eight colour-coded groups. Each group is coloured from its own
leading byte, so any change shifts the colours — a one-byte edit moved all eight
positions in testing.

```
cf build  ▉▉▉▉▉▉▉▉ 21bdbe84·15979fed·eef83572·983b8167·df84456e·042aa7e2·84afb364·29d59384  ✓ pinned
```

Red is reserved for a mismatch, so a healthy banner never renders red.

On a mismatch the tool **notifies and continues** — it does not block:

```
  CLI CODE TAMPERING DETECTED
  The bundle no longer matches its pinned hash.

    last write to the bundle   2026-08-13 09:41:07 PDT  (4 minutes ago)
    pinned                     83e221e4...
    running now                5e4f19f8...

  If you did not change this code at 2026-08-13 09:41:07 PDT, something or
  someone else did.
  Run  cf doctor  for the full evidentiary changelog. If those timestamps do
  not line up with changes you expected, treat this tool as COMPROMISED until
  you have reviewed the source, rebuilt, and re-pinned:  cf integrity pin

  Continuing anyway.
```

Written to stderr, so piped output stays clean. `CFDNS_NO_BANNER=1` suppresses it.

```bash
cf doctor               # evidentiary changelog of every observed code change
cf integrity show       # bundle path, hash, pin state
cf integrity pin        # accept the current bundle as trusted
cf integrity verify     # always a full rehash, never reused
cf integrity diff       # which file changed, against the pinned manifest
cf integrity manifest   # per-file hashes
```

### The changelog

Each hash change appends an event to `integrity.log` (JSONL, 0600) with when it was
observed and by which user on which tty, the hash transition, and for every changed
file whether it was modified, added, or removed — plus both when it was **written**
(mtime) and when its **inode changed** (ctime).

That pair is the useful part. A normal edit moves both together. If ctime is *later*
than mtime, someone wrote the file and then moved its mtime backwards. `cf doctor`
labels those `<-- BACK-DATED` and prints a dedicated warning, because mtime is
forgeable with `touch` and ctime is not.

### Freshness

No cache, no TTL. Every invocation computes a full content manifest, so detection
never consults a timestamp and cannot have a timing-dependent blind spot.

That is the second design. The first cached on a size/mtime/ctime/inode fingerprint
with a 300-second TTL, and it had a real hole: a tamper landing in the same clock
second as the previous check produced a byte-identical fingerprint, so the stale
hash was reused and the mismatch went unreported. `test/repro.sh` measures it — with
whole-second `stat`, 5 misses in 40, and **every** miss was a same-second case.
Nanosecond `stat` closed it on GNU, but macOS has no portable sub-second ctime, so
the hole would have stayed open on the platform this actually runs on. The real
answer was that hashing everything cost 30ms once the per-file forks were removed,
which made the cache pointless. Same reproducer against the no-cache build,
worst-case whole-second `stat`, 120 iterations, 107 of them same-second: zero misses.

`bash test/repro.sh 60 gnu_s` reruns the experiment.

**What is hashed:** every file in the bundle except operator data and runtime
output — `config/`, `snapshots/`, `integrity.*`, `manifest.*`, `.git`,
`node_modules`, keymaps. So editing `masterDNS.json` does not trip the alarm, and
editing `lib/dns/mutate.sh` does. Both directions are tested.

**Known limit.** The pin lives in `$CFDNS_ROOT/integrity.json`, so anyone who can
write your bundle can usually also write that and re-pin silently. This is tamper
*evidence*, not tamper *prevention*: it catches accident, drift, and a careless
attacker, not a determined one with your uid. For real assurance keep the checkout
under git with signed commits and compare `cf integrity manifest` against a value
stored somewhere you do not control. The banner also warns if any bundle file is
group- or world-writable, since that defeats the whole exercise.

---

## Purity: no function both prints and mutates

The same bug appeared three times in this codebase:

```bash
x="$(some_function)"        # runs in a subshell
```

If `some_function` also assigns to a variable the caller reads, that assignment is
discarded when the subshell exits. It fails silently — the variable is simply empty,
and the symptom surfaces somewhere unrelated. It cost a retry loop that never retried,
a file count that read zero, and a snapshot policy override that was ignored.

The rule now: **a function may print a result, or it may set caller-visible state, not
both.** `lib/integrity/bundle.sh` and `lib/core/retry.sh` were rewritten to hold no
state at all — the scan is computed once and passed as an argument, and the retry
attempt communicates through a scratch directory, because files cross a subshell
boundary and variables do not.

`test/purity.sh` enforces it statically. It finds every function that assigns to a
non-local variable, requires each to be declared in `test/setters.allow` with a
reason, requires declared setters to print nothing, and fails if any of them appears
inside a command substitution anywhere in the tree. Memoisers are declared separately,
because losing a cache in a subshell costs a recomputation rather than a wrong answer.

Verified by reintroducing the bug: the lint names both the offending function and the
exact call sites.

## Reusable primitives

The modules are built to take an input and produce an output, not to serve this
application. `lib/core/snapshot.sh` is the clearest example: it captures state before
a change, and it contains no reference to Cloudflare, DNS, or record shapes.

What it does know is a policy:

```json
{
  "cloudflare-dns":  { "capture": "fetch_live",            "dir": "cloudflare-dns", "retain": 100 },
  "aws-route53":     { "capture": "route53_export_zone",   "dir": "route53" },
  "sentry-projects": { "capture": "sentry_export_projects", "dir": "sentry",
                       "wrap": "none", "extension": "txt" }
}
```

The contract for a capture command is the whole interface: **write the state to
stdout, exit non-zero on failure.** Adding Route53 or Sentry means adding a policy
entry and a capture function. It means changing nothing in the snapshot module.

`test/snapshot.sh` proves this rather than asserting it: it drives the same
unmodified module with three fake providers — JSON with retention, JSON without,
and plain text unwrapped — checks they coexist without interfering, and fails if any
provider identifier appears anywhere in the module's code.

The same shape applies elsewhere:

| Module | Input | Output | Knows nothing about |
|---|---|---|---|
| `core/retry.sh` | a command and a should-retry predicate | the command's result | HTTP, Cloudflare, what it is retrying |
| `core/snapshot.sh` | a policy name and a scope | a stored, provenance-wrapped snapshot | providers, state shape |
| `core/json.sh` | a file and a filter | a value, or an atomic 0600 write | what the config means |
| `core/time.sh` | an epoch | a local timestamp or a human age | why you wanted it |
| `dns/plan.jq` | live and desired record sets | create/update/delete sets | how to apply them |
| `analysis/gate.sh` | findings | a decision and an exit code | how findings were produced |

Configuration is what makes a module dynamic. `lib/policies/snapshots.json` drives
snapshots, `lib/cli/modules.txt` drives loading, `payload.txt` drives the release.
None of those three lists lives in code.

## Performance

**43ms** for an installed release, ~50ms in the dev checkout, including a full bundle
hash on every command. `test/all.sh` asserts a 60ms budget.

Straight about the trade: this was 35ms when the bundle was 22 files. It is 58 files
now, because single-focus modules mean more files, and hashing scales with file count.
The per-file cost went down; the file count went up more. If that ever matters more
than the module boundaries do, the lever is the bundle contents in `payload.txt`, not
the hashing code.

Getting from 271ms to here meant removing processes, not removing checks:

- batched hashing and stat into one process each (271ms → 30ms)
- memoised the integrity check so the banner and subcommand share one hash
- dropped 32 subshell forks from colour rendering
- read file modes out of the manifest instead of re-statting every file
- `jq_load` reads several config keys in one `jq` process instead of one each
- the file walk collects modes via `find -printf` where available, so the mode lookup
  costs no extra process (macOS falls back to one batched `stat`)
- integrity state is written only when the hash actually changed — rewriting the same
  value cost a `mktemp`, a `jq`, a `mv` and a `chmod`, 14ms to record that nothing
  happened
- the zone is read from config on first use, so commands that never touch a zone
  never pay for it
- `bundle_writable` iterates an array already in memory instead of piping a
  here-string through `awk`
- state directories are created on first use, not asserted on every run

- the file walk uses `find -printf '%m|./%P'` where available: modes and
  project-relative paths from one process, and no `cd` subshell
- the GNU-vs-BSD `find` probe runs once at module load, not once per scan
- the path list for hashing is built with shell builtins instead of `cut | tr`
- line counting uses parameter expansion instead of `wc -l | tr`

---

## Install

```bash
curl --tls-max 1.3 --proto '=https' -fsSL \
  https://github.com/sonarmd/cfezcli/releases/latest/download/install.sh | bash
```

The installer verifies, in order, and aborts before writing anything if any step
fails: TLS floor and https-only (including on redirects), the tarball checksum, the
detached GPG signature against a **pinned** key fingerprint, the GitHub Sigstore
build attestation, and every individual file inside the archive against
`FILES.sha256`. It then runs the downloaded `cf` and its own integrity self-check
before installing. `--dry-run` does all of that and installs nothing.

See [docs/RELEASE_ENGINEERING.md](docs/RELEASE_ENGINEERING.md) for the branch
protection, signing, and release model.

---

## Tests

```bash
bash test/all.sh          # everything
bash test/unit.sh         # 62  naming, field validation, selection, JSON store
bash test/retry.sh        # 20  backoff arithmetic and the retry contract
bash test/snapshot.sh     # 24  the snapshot primitive against three fake providers
bash test/purity.sh       #  4  no function both prints and mutates caller state
bash test/checks.sh       # 83  parsers, finding model, registry, SPF cost
bash test/plan.sh         # 18  the sync planner
bash test/integration.sh  # 36  every write path against a mock Cloudflare API
bash test/integrity.sh    # 21  tamper evidence
bash test/install.sh      # 23  installer: checksum, signature, tamper cases
bash test/version.sh      # 23  version derivation, concurrent-PR collision
bash test/build.sh        # 22  reproducible build, payload invariant, pkg payload
bash test/history.sh      # 23  commit identity, rewritten-history detection
bash test/approval.sh     # 22  approval forgery and self-gating rejection
bash test/redact.sh       #     redaction leaks and over-redaction
bash test/leak.sh         #     token never reaches argv or stdout
bash test/backoff.sh      #     429 handling against a local server
bash test/repro.sh 60     #     the same-second race, as an experiment
```

`test/mock_cf.py` is an in-memory Cloudflare DNS API that mirrors the real one's
fussier validation — priority required on MX, `proxied` rejected on TXT, TTL range,
duplicate detection. It exists because stubbing out the API meant the write paths
had never actually run, and the first time they did, three bugs surfaced
immediately: a jq scoping error that broke every write, a redirect-order bug that
sent Cloudflare's error messages to `/dev/null`, and the false-positive validation
described above.

Two earlier tests were deleted rather than fixed. They sourced stubbed functions
and asserted nothing that could fail — one of them "verified" a tamper by
substituting a string that a refactor had renamed, so the tamper became a no-op and
the test passed for the wrong reason. Tamper tests now flip a byte
content-independently, so they cannot rot the same way.

---

## Not done

- `--proxy` is only sent for A/AAAA/CNAME; Cloudflare rejects it elsewhere.
- DKIM key-size estimation is derived from base64 length, so it is approximate. It
  reliably separates 512 / 1024 / 2048+, which is what the findings turn on.
- Snapshots are local only. Shipping them to R2 or KV would need broader token scope
  than `DNS:Edit`, which is why it is not here.
- The analyzer can see that SPF is absent for a name, not whether that name is
  actually used as an envelope-from. Confirm per stream from message headers.
- No BIMI or DNSSEC checks.
- **Not yet run against a real Cloudflare zone.** The mock mirrors the documented
  API and every path is covered, but the first real run deserves a throwaway zone.
