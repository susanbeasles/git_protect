//! Point-in-time state capture, taken before anything changes it.
//!
//! This module knows nothing about Cloudflare, DNS, or what state looks like. It knows
//! how to ask something for bytes, store them with provenance, and prune old ones.
//!
//! Adding a provider means implementing one trait. It means changing nothing here:
//!
//! ```ignore
//! impl StateCapture for Route53Zone { /* ... */ }
//! impl StateCapture for SentryProjects { /* ... */ }
//! ```
//!
//! In the shell version this contract was a convention — a policy file naming a function
//! that had to write to stdout — and nothing checked that the function existed until the
//! moment a snapshot was needed. Here the compiler checks it, and a provider that does
//! not satisfy the contract does not build.
//!
//! Failure handling is deliberate: a capture that errors, or returns nothing, writes no
//! file at all. A snapshot containing an error message is worse than a missing one,
//! because it will be trusted as a restore point.

use crate::core::time;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Anything that can produce a point-in-time copy of some state.
///
/// The whole interface. An implementation says what it is called, and hands back bytes.
pub trait StateCapture {
    /// Stable identifier for this kind of state, used as the storage directory.
    /// Lower-case, no spaces: it becomes a path component.
    fn policy(&self) -> &str;

    /// What this particular snapshot is of — a zone name, a hosted-zone id, an
    /// organisation slug. Becomes part of the filename and scopes retention.
    fn scope(&self) -> &str;

    /// The state itself. An `Err` means no file is written.
    fn capture(&self) -> Result<Vec<u8>, CaptureError>;

    /// File extension for the stored state. Defaults to JSON because most APIs speak it.
    fn extension(&self) -> &str {
        "json"
    }

    /// Whether the state can be wrapped in a JSON envelope carrying provenance.
    /// A provider returning YAML or plain text should say `false`.
    fn json_envelope(&self) -> bool {
        true
    }

    /// How many snapshots to keep per scope. `None` keeps everything.
    fn retain(&self) -> Option<usize> {
        Some(100)
    }
}

#[derive(Debug)]
pub enum CaptureError {
    /// The provider could not produce the state.
    Unavailable(String),
    /// The provider produced nothing. Treated as a failure, not an empty snapshot.
    Empty,
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(why) => write!(f, "state could not be captured: {why}"),
            Self::Empty => write!(f, "the provider returned no state"),
        }
    }
}

impl std::error::Error for CaptureError {}

#[derive(Debug)]
pub enum SnapshotError {
    Capture(CaptureError),
    Io(io::Error),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capture(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "could not write the snapshot: {e}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

impl From<io::Error> for SnapshotError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The provenance wrapper. A snapshot found in six months should say what it is without
/// anyone having to remember.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub policy: String,
    pub scope: String,
    pub reason: String,
    pub taken: String,
    pub state: serde_json::Value,
}

/// Where snapshots live, and the only thing that writes there.
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir_for(&self, policy: &str) -> PathBuf {
        self.root.join(policy)
    }

    /// Takes a snapshot and returns where it landed.
    ///
    /// The write is atomic: the state goes to a temporary file in the same directory and
    /// is renamed into place, so a reader never sees a half-written restore point.
    pub fn take<C: StateCapture>(
        &self,
        capture: &C,
        reason: &str,
    ) -> Result<PathBuf, SnapshotError> {
        let bytes = capture.capture().map_err(SnapshotError::Capture)?;
        if bytes.is_empty() {
            return Err(SnapshotError::Capture(CaptureError::Empty));
        }

        let dir = self.dir_for(capture.policy());
        fs::create_dir_all(&dir)?;
        restrict(&dir)?;

        let payload = if capture.json_envelope() {
            let state: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                SnapshotError::Capture(CaptureError::Unavailable(format!(
                    "the provider declared a JSON envelope but produced invalid JSON: {e}"
                )))
            })?;
            let envelope = Envelope {
                policy: capture.policy().to_string(),
                scope: capture.scope().to_string(),
                reason: reason.to_string(),
                taken: time::format_rfc3339(time::now_epoch()),
                state,
            };
            serde_json::to_vec_pretty(&envelope)
                .map_err(|e| SnapshotError::Io(io::Error::other(e)))?
        } else {
            bytes
        };

        let path = Self::next_path(&dir, capture.scope(), reason, capture.extension());
        let temp = dir.join(format!(".pending.{}", time::now_epoch()));
        fs::write(&temp, payload)?;
        restrict(&temp)?;
        fs::rename(&temp, &path)?;

        if let Some(keep) = capture.retain() {
            self.prune(capture.policy(), capture.scope(), keep)?;
        }
        Ok(path)
    }

    /// `take` for a trait object.
    ///
    /// `take` is generic so the common path monomorphises, but a caller holding a
    /// heterogeneous list of providers needs dynamic dispatch. Both go through the same
    /// code; this is only an unsizing shim.
    pub fn take_dyn(
        &self,
        capture: &dyn StateCapture,
        reason: &str,
    ) -> Result<PathBuf, SnapshotError> {
        struct Borrowed<'a>(&'a dyn StateCapture);
        impl StateCapture for Borrowed<'_> {
            fn policy(&self) -> &str {
                self.0.policy()
            }
            fn scope(&self) -> &str {
                self.0.scope()
            }
            fn capture(&self) -> Result<Vec<u8>, CaptureError> {
                self.0.capture()
            }
            fn extension(&self) -> &str {
                self.0.extension()
            }
            fn json_envelope(&self) -> bool {
                self.0.json_envelope()
            }
            fn retain(&self) -> Option<usize> {
                self.0.retain()
            }
        }
        self.take(&Borrowed(capture), reason)
    }

    /// Resolves a filename collision by suffix rather than by making the timestamp
    /// finer. Two snapshots in one second is normal when a command takes several actions,
    /// and losing one is worse than an ugly name.
    fn next_path(dir: &Path, scope: &str, reason: &str, ext: &str) -> PathBuf {
        let stamp = time::format_stamp(time::now_epoch());
        let base = format!("{scope}-{stamp}-{reason}");
        let mut candidate = dir.join(format!("{base}.{ext}"));
        let mut n = 1;
        while candidate.exists() {
            candidate = dir.join(format!("{base}.{n}.{ext}"));
            n += 1;
        }
        candidate
    }

    /// Snapshot filenames for a policy, newest first.
    ///
    /// Sorted by the timestamp in the name, not by mtime: the name records when the state
    /// was captured, while mtime is a property of the file that anything can change.
    pub fn list(&self, policy: &str, scope: Option<&str>) -> Vec<String> {
        let dir = self.dir_for(policy);
        let mut names: Vec<String> = match fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !n.starts_with(".pending."))
                .filter(|n| scope.map_or(true, |s| n.starts_with(&format!("{s}-"))))
                .collect(),
            Err(_) => return Vec::new(),
        };
        names.sort_by(|a, b| b.cmp(a));
        names
    }

    fn prune(&self, policy: &str, scope: &str, keep: usize) -> io::Result<()> {
        let dir = self.dir_for(policy);
        for name in self.list(policy, Some(scope)).into_iter().skip(keep) {
            fs::remove_file(dir.join(name))?;
        }
        Ok(())
    }

    /// Reads a snapshot back, unwrapping the envelope if there is one.
    ///
    /// Accepts a bare state document too, so a hand-written file still restores.
    pub fn read(path: &Path) -> io::Result<serde_json::Value> {
        let bytes = fs::read(path)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        // Accepts a bare state document as well as an envelope, so a hand-written
        // restore file still works.
        Ok(value.get("state").cloned().unwrap_or(value))
    }
}

/// Owner-only. A snapshot is a copy of production state and occasionally of the shape of
/// a private network; it is not world-readable.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mode = if meta.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that removes itself. Avoids a `tempfile` dependency for
    /// something this small.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("cfez-snap-{}-{}", std::process::id(), tag));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // ================================================================
    // Three unrelated providers. Nothing below this line required a change to the module
    // above it — which is the claim the trait exists to make good on.
    // ================================================================

    struct CloudflareDns {
        zone: String,
    }
    impl StateCapture for CloudflareDns {
        fn policy(&self) -> &str {
            "cloudflare-dns"
        }
        fn scope(&self) -> &str {
            &self.zone
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(br#"[{"name":"a.example.com","type":"TXT"}]"#.to_vec())
        }
    }

    struct Route53Zone {
        hosted_zone: String,
    }
    impl StateCapture for Route53Zone {
        fn policy(&self) -> &str {
            "aws-route53"
        }
        fn scope(&self) -> &str {
            &self.hosted_zone
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(br#"{"ResourceRecordSets":[{"Name":"a.aws.test."}]}"#.to_vec())
        }
        fn retain(&self) -> Option<usize> {
            None // keep every snapshot
        }
    }

    struct SentryProjects {
        org: String,
    }
    impl StateCapture for SentryProjects {
        fn policy(&self) -> &str {
            "sentry-projects"
        }
        fn scope(&self) -> &str {
            &self.org
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(b"project: web\nproject: api\n".to_vec())
        }
        fn extension(&self) -> &str {
            "txt"
        }
        fn json_envelope(&self) -> bool {
            false // plain text, stored verbatim
        }
    }

    struct Failing;
    impl StateCapture for Failing {
        fn policy(&self) -> &str {
            "broken"
        }
        fn scope(&self) -> &str {
            "scope"
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Err(CaptureError::Unavailable("the API returned 503".into()))
        }
    }

    struct EmptyProvider;
    impl StateCapture for EmptyProvider {
        fn policy(&self) -> &str {
            "empty"
        }
        fn scope(&self) -> &str {
            "scope"
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(Vec::new())
        }
    }

    struct LyingProvider;
    impl StateCapture for LyingProvider {
        fn policy(&self) -> &str {
            "lying"
        }
        fn scope(&self) -> &str {
            "scope"
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(b"this is not json".to_vec())
        }
        // declares an envelope but cannot produce JSON
    }

    struct Retaining(usize);
    impl StateCapture for Retaining {
        fn policy(&self) -> &str {
            "retaining"
        }
        fn scope(&self) -> &str {
            "scope"
        }
        fn capture(&self) -> Result<Vec<u8>, CaptureError> {
            Ok(br#"{"n":1}"#.to_vec())
        }
        fn retain(&self) -> Option<usize> {
            Some(self.0)
        }
    }

    // ---------------------------------------------------------------- basics

    #[test]
    fn a_snapshot_is_written_and_its_path_returned() {
        let s = Scratch::new("basic");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "pre-change",
            )
            .unwrap();
        assert!(p.exists(), "{p:?} should exist");
    }

    #[test]
    fn it_lands_in_the_policy_directory() {
        let s = Scratch::new("dir");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "r",
            )
            .unwrap();
        assert!(p.to_string_lossy().contains("cloudflare-dns"), "{p:?}");
    }

    #[test]
    fn the_filename_carries_scope_stamp_and_reason() {
        let s = Scratch::new("name");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "pre-change",
            )
            .unwrap();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert!(name.starts_with("example.com-"), "{name}");
        assert!(name.ends_with("-pre-change.json"), "{name}");
        assert!(name.contains('Z'), "the stamp should be UTC: {name}");
    }

    #[test]
    fn the_envelope_records_provenance() {
        let s = Scratch::new("envelope");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "pre-change",
            )
            .unwrap();
        let env: Envelope = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
        assert_eq!(env.policy, "cloudflare-dns");
        assert_eq!(env.scope, "example.com");
        assert_eq!(env.reason, "pre-change");
        assert!(
            env.taken.ends_with('Z'),
            "taken should be UTC: {}",
            env.taken
        );
    }

    #[test]
    fn reading_returns_the_state_unwrapped() {
        let s = Scratch::new("read");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "r",
            )
            .unwrap();
        let state = Store::read(&p).unwrap();
        assert_eq!(state[0]["name"], "a.example.com");
    }

    #[test]
    fn a_bare_document_reads_too() {
        let s = Scratch::new("bare");
        let file = s.path().join("hand-written.json");
        fs::write(&file, br#"{"hello":"world"}"#).unwrap();
        assert_eq!(Store::read(&file).unwrap()["hello"], "world");
    }

    #[test]
    fn two_snapshots_in_the_same_second_do_not_collide() {
        let s = Scratch::new("collide");
        let store = Store::new(s.path());
        let c = CloudflareDns {
            zone: "example.com".into(),
        };
        let a = store.take(&c, "same").unwrap();
        let b = store.take(&c, "same").unwrap();
        assert_ne!(a, b);
        assert!(a.exists() && b.exists());
    }

    #[cfg(unix)]
    #[test]
    fn snapshots_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new("perms");
        let store = Store::new(s.path());
        let p = store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "r",
            )
            .unwrap();
        let mode = fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    // ---------------------------------------------------------------- failure

    #[test]
    fn a_failing_capture_writes_nothing() {
        let s = Scratch::new("fail");
        let store = Store::new(s.path());
        assert!(store.take(&Failing, "r").is_err());
        let leftover: Vec<_> = walk(s.path());
        assert!(
            leftover.is_empty(),
            "nothing should be written: {leftover:?}"
        );
    }

    #[test]
    fn an_empty_capture_is_refused() {
        let s = Scratch::new("empty");
        let store = Store::new(s.path());
        match store.take(&EmptyProvider, "r") {
            Err(SnapshotError::Capture(CaptureError::Empty)) => {}
            other => panic!("expected Empty, got {other:?}"),
        }
    }

    #[test]
    fn a_provider_that_lies_about_json_is_refused() {
        let s = Scratch::new("lying");
        let store = Store::new(s.path());
        let err = store.take(&LyingProvider, "r").unwrap_err();
        assert!(err.to_string().contains("invalid JSON"), "{err}");
        assert!(
            walk(s.path()).is_empty(),
            "a bad snapshot must not be stored"
        );
    }

    #[test]
    fn no_pending_files_are_left_behind() {
        let s = Scratch::new("pending");
        let store = Store::new(s.path());
        let _ = store.take(&Failing, "r");
        let _ = store.take(&LyingProvider, "r");
        let _ = store.take(
            &CloudflareDns {
                zone: "example.com".into(),
            },
            "r",
        );
        let pending: Vec<_> = walk(s.path())
            .into_iter()
            .filter(|p| p.contains(".pending."))
            .collect();
        assert!(pending.is_empty(), "{pending:?}");
    }

    // ---------------------------------------------------------------- retention

    #[test]
    fn retention_keeps_the_newest_n() {
        let s = Scratch::new("retain");
        let store = Store::new(s.path());
        for _ in 0..6 {
            store.take(&Retaining(3), "r").unwrap();
        }
        assert_eq!(store.list("retaining", Some("scope")).len(), 3);
    }

    #[test]
    fn retention_is_per_scope() {
        struct Scoped(&'static str);
        impl StateCapture for Scoped {
            fn policy(&self) -> &str {
                "scoped"
            }
            fn scope(&self) -> &str {
                self.0
            }
            fn capture(&self) -> Result<Vec<u8>, CaptureError> {
                Ok(br#"{"a":1}"#.to_vec())
            }
            fn retain(&self) -> Option<usize> {
                Some(2)
            }
        }
        let s = Scratch::new("scoped");
        let store = Store::new(s.path());
        for _ in 0..4 {
            store.take(&Scoped("alpha"), "r").unwrap();
        }
        store.take(&Scoped("beta"), "r").unwrap();
        assert_eq!(store.list("scoped", Some("alpha")).len(), 2);
        assert_eq!(
            store.list("scoped", Some("beta")).len(),
            1,
            "beta must be untouched"
        );
    }

    #[test]
    fn retain_none_keeps_everything() {
        let s = Scratch::new("keepall");
        let store = Store::new(s.path());
        let c = Route53Zone {
            hosted_zone: "Z1D633PJN98FT9".into(),
        };
        for _ in 0..5 {
            store.take(&c, "r").unwrap();
        }
        assert_eq!(store.list("aws-route53", Some("Z1D633PJN98FT9")).len(), 5);
    }

    #[test]
    fn listing_without_a_scope_returns_the_whole_policy() {
        let s = Scratch::new("listall");
        let store = Store::new(s.path());
        store
            .take(
                &Route53Zone {
                    hosted_zone: "zone-a".into(),
                },
                "r",
            )
            .unwrap();
        store
            .take(
                &Route53Zone {
                    hosted_zone: "zone-b".into(),
                },
                "r",
            )
            .unwrap();
        assert_eq!(store.list("aws-route53", None).len(), 2);
    }

    #[test]
    fn listing_is_newest_first() {
        let s = Scratch::new("order");
        let store = Store::new(s.path());
        let c = Route53Zone {
            hosted_zone: "z".into(),
        };
        store.take(&c, "first").unwrap();
        store.take(&c, "second").unwrap();
        let names = store.list("aws-route53", Some("z"));
        assert_eq!(names.len(), 2);
        // Same second, so the collision suffix decides: the suffixed name sorts after
        // the unsuffixed one, and reverse order puts it first.
        assert!(names[0] >= names[1], "{names:?}");
    }

    #[test]
    fn listing_an_unknown_policy_is_empty_not_an_error() {
        let s = Scratch::new("unknown");
        assert!(Store::new(s.path()).list("never-used", None).is_empty());
    }

    // ================================================================
    // The reuse claim.
    // ================================================================

    #[test]
    fn reuse_aws_route53_needs_no_change_to_this_module() {
        let s = Scratch::new("aws");
        let store = Store::new(s.path());
        let p = store
            .take(
                &Route53Zone {
                    hosted_zone: "Z1D633PJN98FT9".into(),
                },
                "pre-apply",
            )
            .unwrap();
        assert!(p.to_string_lossy().contains("aws-route53"));
        let state = Store::read(&p).unwrap();
        assert_eq!(state["ResourceRecordSets"][0]["Name"], "a.aws.test.");
    }

    #[test]
    fn reuse_sentry_stores_plain_text_verbatim() {
        let s = Scratch::new("sentry");
        let store = Store::new(s.path());
        let p = store
            .take(&SentryProjects { org: "acme".into() }, "pre-migrate")
            .unwrap();
        assert!(p.to_string_lossy().ends_with(".txt"), "{p:?}");
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body, "project: web\nproject: api\n",
            "no envelope was added"
        );
    }

    #[test]
    fn reuse_three_providers_coexist_without_interfering() {
        let s = Scratch::new("coexist");
        let store = Store::new(s.path());
        store
            .take(
                &CloudflareDns {
                    zone: "example.com".into(),
                },
                "r",
            )
            .unwrap();
        store
            .take(
                &Route53Zone {
                    hosted_zone: "z".into(),
                },
                "r",
            )
            .unwrap();
        store
            .take(&SentryProjects { org: "acme".into() }, "r")
            .unwrap();
        assert_eq!(store.list("cloudflare-dns", None).len(), 1);
        assert_eq!(store.list("aws-route53", None).len(), 1);
        assert_eq!(store.list("sentry-projects", None).len(), 1);
    }

    #[test]
    fn reuse_a_provider_can_be_used_through_a_trait_object() {
        // Proves the contract is genuinely dynamic: a caller can hold a list of
        // heterogeneous providers and snapshot all of them without knowing what they are.
        let s = Scratch::new("dyn");
        let store = Store::new(s.path());
        let providers: Vec<Box<dyn StateCapture>> = vec![
            Box::new(CloudflareDns {
                zone: "example.com".into(),
            }),
            Box::new(Route53Zone {
                hosted_zone: "z".into(),
            }),
            Box::new(SentryProjects { org: "acme".into() }),
        ];
        for p in &providers {
            let path = store.take_dyn(p.as_ref(), "bulk").unwrap();
            assert!(path.exists());
        }
    }

    fn walk(root: &Path) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(root) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    out.extend(walk(&p));
                } else {
                    out.push(p.to_string_lossy().to_string());
                }
            }
        }
        out
    }
}
