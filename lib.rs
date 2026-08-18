//! cfez — Cloudflare DNS management with email-authentication analysis.
//!
//! LINT POLICY
//!
//! The build denies all warnings and enables `clippy::pedantic`. Four groups are allowed
//! deliberately, and nothing else is:
//!
//! * `must_use_candidate` — this is a binary, not a library. Annotating every getter
//!   with `#[must_use]` adds noise for callers that do not exist. Applied selectively
//!   where ignoring a result really would be a bug.
//! * `missing_errors_doc` / `missing_panics_doc` — the error types are enumerated and
//!   `Display`-formatted with actionable messages, which is where the information
//!   belongs. A prose `# Errors` section restating the enum is a second thing to keep
//!   in sync.
//! * `module_name_repetitions` — `dns::record::Record` reads correctly at the call site,
//!   and shortening it to satisfy a lint would make the code worse.
//!
//! Anything else clippy finds is a bug to fix, not a lint to suppress. Casts that
//! clippy cannot prove safe carry a comment naming the bound and the test that holds it.
#![deny(warnings)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

pub mod core;
pub mod dns;
