# cfez

A native binary. No interpreter, no embedded runtime, no script tree on disk.

That is the point, not a preference. `codesign` signs a Mach-O and macOS validates its
pages at fault time, so a modified binary is refused by the kernel. A signed installer
containing shell scripts protects the bytes in transit and nothing afterwards — the
signature is checked once and discarded, and what remains is a directory anything with
write access owns.

## Status

Foundation, compiling and green.

```
cargo fmt --check      0 diffs
cargo clippy           0 findings   (policy in src/lib.rs, pedantic enabled)
cargo test             102 passed, 0 failed
cargo build --release  318 KB stripped
```

| Module | Lines | Tests | What it owns |
|---|---|---|---|
| `dns/record.rs` | 760 | 34 | record types, names, field rules |
| `core/snapshot.rs` | 700 | 22 | `StateCapture` trait, storage, retention |
| `dns/plan.rs` | 515 | 24 | live-vs-desired reconciliation |
| `core/retry.rs` | 285 | 12 | backoff, with the clock injected |
| `core/time.rs` | 165 | 10 | UTC formatting, no calendar crate |

Remaining: `core/{config,paths,http,secret,logging}`, `dns/{select,patch,desired,mutate}`,
`integrity/*`, `analysis/*` (39 checks, 4 parsers), `cli/*`, `cmd/*`. The bash tree ships
alongside as the API-shape reference, and its ~350 tests are the acceptance spec.

## Dependency budget

Three direct: `serde`, `serde_json`, `sha2`. **21 transitive**, all of them serde's
proc-macro chain or RustCrypto's digest traits — verified with `cargo tree`, not
estimated. CI fails the build if the tree exceeds 25 crates, because a dependency budget
that is not enforced is a preference.

The HTTP client sits behind a trait, so the network is a seam rather than a dependency of
the logic. `cargo test --no-default-features` runs the entire logic suite with no TLS
stack compiled in at all, and CI runs it both ways.

## What the type system enforces

Each of these was a runtime check spread across several files in the shell version, and
at least one place got it wrong:

| Now | Was |
|---|---|
| `RecordType::supports_proxy()` | answered in three places; one silently dropped the flag instead of refusing it |
| `Fqdn` newtype | strings, which produced `example.com.example.com` when one function normalised and another assumed |
| `Ttl` | a number that could hold a value Cloudflare rejects |
| `Record::identity()` vs `metadata()` | a comment |
| `Outcome` / `Failure` | shell variables, so a command substitution discarded the status and nothing ever retried |
| `StateCapture` | a policy file naming a function nothing checked existed |

## The planner

`dns/plan.rs` is the file to read first. Deleting an SPF record and creating a replacement
leaves a window with no SPF policy, and mail sent in that window fails authentication. So
a change is never expressed as delete-then-create when it can be an in-place update, and
an update carries the live record's id specifically so `PUT` replaces it atomically.

Three passes, and the order is the design: exact matches, then positional pairing within a
name and type, then the remainder. That is what turns a duplicated `_dmarc` collapsing to
one different value into one update plus one delete, rather than two deletes and a create.

Twenty-four tests, including a 200-record reconciliation and a determinism check — a plan
that varies between runs makes a dry run worthless as a preview.

## Reuse

`core/snapshot.rs` contains no reference to Cloudflare, DNS, or record shapes. A provider
implements one trait:

```rust
impl StateCapture for Route53Zone { /* policy, scope, capture */ }
```

The test module implements Cloudflare, Route53 and Sentry — JSON with retention, JSON
without, and plain text unwrapped — and asserts they coexist, that one works through
`dyn StateCapture`, and that nothing in the module changed for any of them.

## Not verified in this environment

The `net` feature (`ureq`) does not compile here: the container has rustc 1.75 from
Ubuntu, `static.rust-lang.org` is not reachable so rustup is unavailable, and one of
ureq's transitive dependencies requires `edition2024`. Everything above was verified on
1.75 with `--no-default-features`, which is the entire logic layer.

`rust-toolchain.toml` pins 1.83, and CI runs `--all-features` on that. The first CI run
is the first real compile of the HTTP client. This is called out rather than glossed
because the rest of this file reports measurements, and that line would be a guess.

## Building

```bash
cargo test --no-default-features    # logic suite, no network stack
cargo clippy --all-targets          # policy is in src/lib.rs
cargo build --release --locked
```

`codegen-units = 1` and `lto = true`: the release gate depends on a pull request's
artifact being byte-identical to the released one, and parallel codegen is not
deterministic. CI asserts that by building twice and comparing.
