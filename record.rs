//! DNS record types, names, and the rules about which fields apply to which type.
//!
//! The point of this module is that an invalid record should be impossible to construct
//! rather than merely rejected somewhere later. In the shell version, "is `--proxy`
//! valid for a TXT record?" was answered in three different places — the field
//! validator, a jq filter, and the update path — and one of them silently dropped the
//! flag instead of refusing it. Here the answer lives on `RecordType` and there is
//! nowhere else for it to live.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The record types this tool manages.
///
/// An enum rather than a string: it makes the proxy and priority rules exhaustive, so
/// adding a type forces the compiler to ask whether those rules apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
    NS,
    SRV,
    CAA,
    PTR,
    SOA,
}

impl RecordType {
    /// Cloudflare accepts a proxy flag only for records that resolve to an address it
    /// can sit in front of. Sending it for anything else is an API error.
    pub const fn supports_proxy(self) -> bool {
        matches!(self, Self::A | Self::AAAA | Self::CNAME)
    }

    /// Types whose wire format carries a preference value. Cloudflare rejects an MX or
    /// SRV record without one, and rejects a priority on anything else.
    pub const fn requires_priority(self) -> bool {
        matches!(self, Self::MX | Self::SRV)
    }

    /// Cloudflare does not proxy SMTP, so a proxied MX record silently breaks inbound
    /// mail. Called out separately from `supports_proxy` because the consequence is
    /// different in kind: not an API error, a delivery failure.
    pub const fn is_mail_routing(self) -> bool {
        matches!(self, Self::MX)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::TXT => "TXT",
            Self::MX => "MX",
            Self::NS => "NS",
            Self::SRV => "SRV",
            Self::CAA => "CAA",
            Self::PTR => "PTR",
            Self::SOA => "SOA",
        }
    }

    pub fn parse(input: &str) -> Result<Self, FieldError> {
        match input.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "CNAME" => Ok(Self::CNAME),
            "TXT" => Ok(Self::TXT),
            "MX" => Ok(Self::MX),
            "NS" => Ok(Self::NS),
            "SRV" => Ok(Self::SRV),
            "CAA" => Ok(Self::CAA),
            "PTR" => Ok(Self::PTR),
            "SOA" => Ok(Self::SOA),
            other => Err(FieldError::UnknownType(other.to_string())),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a field was refused. Each variant carries what the operator needs to fix it,
/// because "invalid input" is not a message anyone can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    UnknownType(String),
    TtlOutOfRange { given: u32 },
    TtlNotNumeric(String),
    PriorityRequired(RecordType),
    PriorityNotApplicable(RecordType),
    PriorityOutOfRange { given: u64 },
    ProxyNotApplicable(RecordType),
    EmptyContent,
    NameTooLong { length: usize },
    LabelTooLong { label: String },
    LabelEmpty,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(t) => write!(
                f,
                "'{t}' is not a record type this tool manages \
                 (A, AAAA, CNAME, TXT, MX, NS, SRV, CAA, PTR, SOA)"
            ),
            Self::TtlOutOfRange { given } => write!(
                f,
                "ttl {given} is out of range: use 1 for Cloudflare's automatic TTL, \
                 or a value between {MIN_TTL} and {MAX_TTL}"
            ),
            Self::TtlNotNumeric(s) => write!(f, "ttl '{s}' is not a number"),
            Self::PriorityRequired(t) => {
                write!(f, "{t} records need a priority, for example --priority 10")
            }
            Self::PriorityNotApplicable(t) => write!(
                f,
                "priority does not apply to {t} records; Cloudflare rejects it"
            ),
            Self::PriorityOutOfRange { given } => {
                write!(
                    f,
                    "priority {given} is out of range: it must be 0 to {MAX_PRIORITY}"
                )
            }
            Self::ProxyNotApplicable(t) => write!(
                f,
                "proxying does not apply to {t} records; only A, AAAA and CNAME can be proxied"
            ),
            Self::EmptyContent => write!(f, "content cannot be empty"),
            Self::NameTooLong { length } => {
                write!(
                    f,
                    "name is {length} characters; DNS allows at most {MAX_NAME_LEN}"
                )
            }
            Self::LabelTooLong { label } => write!(
                f,
                "the label '{label}' is {} characters; DNS allows at most {MAX_LABEL_LEN}",
                label.len()
            ),
            Self::LabelEmpty => {
                write!(
                    f,
                    "the name contains an empty label (two consecutive dots, or a leading dot)"
                )
            }
        }
    }
}

impl std::error::Error for FieldError {}

/// Cloudflare's automatic TTL is expressed as 1, not as absent.
pub const AUTO_TTL: u32 = 1;
pub const MIN_TTL: u32 = 60;
pub const MAX_TTL: u32 = 86_400;
pub const MAX_PRIORITY: u64 = 65_535;
pub const MAX_NAME_LEN: usize = 253;
pub const MAX_LABEL_LEN: usize = 63;

/// A fully qualified, lower-cased record name.
///
/// A newtype rather than a `String` so that "is this absolute or relative to the zone?"
/// is answered by the type. The shell version passed both around as strings and the apex
/// ended up doubled — `example.com.example.com` — because one function normalised and
/// another assumed it already had.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Fqdn(String);

impl Fqdn {
    /// Resolves a user-supplied name against a zone.
    ///
    /// Accepts `@`, an empty string, the zone itself, a name already inside the zone, or
    /// a relative label. All five must produce the same answer for the apex, which is
    /// the case the shell version got wrong.
    pub fn resolve(input: &str, zone: &str) -> Result<Self, FieldError> {
        let zone = zone.trim_end_matches('.').to_ascii_lowercase();
        let input = input.trim().trim_end_matches('.').to_ascii_lowercase();

        let name = if input.is_empty() || input == "@" || input == zone {
            zone
        } else if input.ends_with(&format!(".{zone}")) {
            input
        } else {
            format!("{input}.{zone}")
        };

        Self::validate(&name)?;
        Ok(Self(name))
    }

    /// Wraps a name that is already absolute, such as one from the API.
    pub fn from_absolute(name: &str) -> Result<Self, FieldError> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        Self::validate(&name)?;
        Ok(Self(name))
    }

    fn validate(name: &str) -> Result<(), FieldError> {
        if name.len() > MAX_NAME_LEN {
            return Err(FieldError::NameTooLong { length: name.len() });
        }
        for label in name.split('.') {
            // A leading `*` is a wildcard, and `_dmarc` style underscore labels are
            // required by DMARC, DKIM and SRV. Both are legal here.
            if label.is_empty() {
                return Err(FieldError::LabelEmpty);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(FieldError::LabelTooLong {
                    label: label.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The inverse of `resolve`: the apex becomes `@`, and anything inside the zone
    /// loses the zone suffix. Used for display and for the `cf dns` commands printed as
    /// remediation, so a copied command works.
    pub fn relative_to(&self, zone: &str) -> String {
        let zone = zone.trim_end_matches('.').to_ascii_lowercase();
        if self.0 == zone {
            return "@".to_string();
        }
        match self.0.strip_suffix(&format!(".{zone}")) {
            Some(rest) => rest.to_string(),
            None => self.0.clone(),
        }
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.") || self.0 == "*"
    }

    /// True if this name sits at or under `other`.
    pub fn is_within(&self, other: &str) -> bool {
        let other = other.trim_end_matches('.').to_ascii_lowercase();
        self.0 == other || self.0.ends_with(&format!(".{other}"))
    }
}

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A TTL that is known to be acceptable to Cloudflare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ttl(u32);

impl Ttl {
    pub const AUTO: Ttl = Ttl(AUTO_TTL);

    pub fn new(seconds: u32) -> Result<Self, FieldError> {
        if seconds == AUTO_TTL || (MIN_TTL..=MAX_TTL).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(FieldError::TtlOutOfRange { given: seconds })
        }
    }

    pub fn parse(input: &str) -> Result<Self, FieldError> {
        input
            .trim()
            .parse::<u32>()
            .map_err(|_| FieldError::TtlNotNumeric(input.to_string()))
            .and_then(Self::new)
    }

    pub const fn seconds(self) -> u32 {
        self.0
    }

    pub const fn is_auto(self) -> bool {
        self.0 == AUTO_TTL
    }
}

impl Default for Ttl {
    fn default() -> Self {
        Self::AUTO
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_auto() {
            f.write_str("auto")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// A record as this tool models it.
///
/// `id` is `None` for a record that does not exist yet and `Some` for one read from the
/// API. That distinction is what lets the planner know whether an update can be a
/// patch-in-place, which is the difference between swapping an SPF record atomically and
/// leaving a window with no SPF at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<String>,
    pub name: Fqdn,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub content: String,
    #[serde(default)]
    pub ttl: Ttl,
    #[serde(default, skip_serializing_if = "is_false")]
    pub proxied: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u64>,
}

// serde requires a by-reference predicate for skip_serializing_if.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

impl Record {
    /// The identity of a record for planning: name, type and content.
    ///
    /// Deliberately excludes ttl, tags, comment and priority. Two records with the same
    /// identity are the same record with different metadata, and the planner turns that
    /// into an in-place update rather than a delete and a create.
    pub fn identity(&self) -> (&Fqdn, RecordType, &str) {
        (&self.name, self.record_type, self.content.as_str())
    }

    /// Everything that is not identity. If this differs between two records that share
    /// an identity, the difference is an update.
    pub fn metadata(&self) -> (Ttl, bool, &str, &[String], Option<u64>) {
        (
            self.ttl,
            self.proxied,
            self.comment.as_str(),
            &self.tags,
            self.priority,
        )
    }

    /// Checks the field combinations Cloudflare enforces, plus the ones it accepts but
    /// which break mail.
    pub fn validate(&self) -> Result<(), FieldError> {
        if self.content.trim().is_empty() {
            return Err(FieldError::EmptyContent);
        }
        match (self.record_type.requires_priority(), self.priority) {
            (true, None) => return Err(FieldError::PriorityRequired(self.record_type)),
            (false, Some(_)) => return Err(FieldError::PriorityNotApplicable(self.record_type)),
            _ => {}
        }
        if let Some(p) = self.priority {
            if p > MAX_PRIORITY {
                return Err(FieldError::PriorityOutOfRange { given: p });
            }
        }
        if self.proxied && !self.record_type.supports_proxy() {
            return Err(FieldError::ProxyNotApplicable(self.record_type));
        }
        Ok(())
    }

    /// Tags are sorted so that two records differing only in tag order compare equal.
    /// Without this, a `sync` would report a spurious update every run.
    #[must_use]
    pub fn normalised(mut self) -> Self {
        self.tags.sort();
        self.tags.dedup();
        self.content = unquote_txt(&self.content);
        self
    }
}

/// Joins the character-strings of a TXT record.
///
/// A TXT value longer than 255 bytes is transmitted as several strings, and the API
/// returns them quoted and concatenated. An SPF record split that way must compare equal
/// to the same policy written as one string, or every sync sees a change that is not
/// there.
pub fn unquote_txt(content: &str) -> String {
    if !content.contains('"') {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut in_quotes = false;
    for c in content.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if in_quotes => out.push(c),
            // Whitespace between two quoted strings is separator, not content.
            c if c.is_whitespace() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, t: RecordType, content: &str) -> Record {
        Record {
            id: None,
            name: Fqdn::from_absolute(name).unwrap(),
            record_type: t,
            content: content.to_string(),
            ttl: Ttl::AUTO,
            proxied: false,
            comment: String::new(),
            tags: Vec::new(),
            priority: None,
        }
    }

    // ---------------------------------------------------------------- names

    #[test]
    fn all_five_spellings_of_the_apex_agree() {
        let zone = "example.com";
        for input in ["@", "", "example.com", "EXAMPLE.COM", "example.com."] {
            let f = Fqdn::resolve(input, zone).unwrap();
            assert_eq!(f.as_str(), "example.com", "input {input:?}");
        }
    }

    #[test]
    fn a_relative_label_gains_the_zone() {
        assert_eq!(
            Fqdn::resolve("www", "example.com").unwrap().as_str(),
            "www.example.com"
        );
        assert_eq!(
            Fqdn::resolve("stg.mail", "example.com").unwrap().as_str(),
            "stg.mail.example.com"
        );
    }

    #[test]
    fn an_absolute_name_is_left_alone() {
        assert_eq!(
            Fqdn::resolve("a.b.example.com", "example.com")
                .unwrap()
                .as_str(),
            "a.b.example.com"
        );
    }

    #[test]
    fn names_are_lower_cased() {
        assert_eq!(
            Fqdn::resolve("WWW", "Example.COM").unwrap().as_str(),
            "www.example.com"
        );
    }

    #[test]
    fn underscore_labels_are_legal() {
        // Required by DMARC, DKIM and SRV, and rejected by a naive hostname validator.
        for name in ["_dmarc", "_domainkey", "selector1._domainkey", "_smtp._tls"] {
            assert!(
                Fqdn::resolve(name, "example.com").is_ok(),
                "{name} must be accepted"
            );
        }
    }

    #[test]
    fn wildcards_are_legal_and_identifiable() {
        let f = Fqdn::resolve("*", "example.com").unwrap();
        assert_eq!(f.as_str(), "*.example.com");
        assert!(f.is_wildcard());
        assert!(!Fqdn::resolve("www", "example.com").unwrap().is_wildcard());
    }

    #[test]
    fn resolve_and_relative_to_round_trip() {
        let zone = "example.com";
        for input in ["@", "www", "stg.mail", "_dmarc", "a.b.c"] {
            let f = Fqdn::resolve(input, zone).unwrap();
            let back = f.relative_to(zone);
            let expected = if input.is_empty() { "@" } else { input };
            assert_eq!(back, expected, "round trip failed for {input:?}");
        }
    }

    #[test]
    fn an_empty_label_is_refused() {
        assert_eq!(Fqdn::from_absolute("a..b.com"), Err(FieldError::LabelEmpty));
        assert_eq!(
            Fqdn::from_absolute(".leading.com"),
            Err(FieldError::LabelEmpty)
        );
    }

    #[test]
    fn an_overlong_label_is_refused() {
        let long = "x".repeat(64);
        assert!(matches!(
            Fqdn::from_absolute(&format!("{long}.example.com")),
            Err(FieldError::LabelTooLong { .. })
        ));
        let ok = "x".repeat(63);
        assert!(Fqdn::from_absolute(&format!("{ok}.example.com")).is_ok());
    }

    #[test]
    fn an_overlong_name_is_refused() {
        let name = (0..40).map(|_| "abcdef").collect::<Vec<_>>().join(".");
        assert!(name.len() > MAX_NAME_LEN);
        assert!(matches!(
            Fqdn::from_absolute(&name),
            Err(FieldError::NameTooLong { .. })
        ));
    }

    #[test]
    fn containment_is_zone_aware() {
        let f = Fqdn::from_absolute("mail.example.com").unwrap();
        assert!(f.is_within("example.com"));
        assert!(f.is_within("mail.example.com"));
        assert!(!f.is_within("other.com"));
        // Must not match a suffix that is not a label boundary.
        assert!(!Fqdn::from_absolute("notexample.com")
            .unwrap()
            .is_within("example.com"));
    }

    // ---------------------------------------------------------------- ttl

    #[test]
    fn ttl_accepts_auto_and_the_valid_range() {
        assert_eq!(Ttl::new(1).unwrap().seconds(), 1);
        assert!(Ttl::new(1).unwrap().is_auto());
        assert_eq!(Ttl::new(60).unwrap().seconds(), 60);
        assert_eq!(Ttl::new(86_400).unwrap().seconds(), 86_400);
    }

    #[test]
    fn ttl_refuses_values_cloudflare_would_reject() {
        for bad in [0, 2, 59, 86_401, 999_999] {
            assert!(Ttl::new(bad).is_err(), "ttl {bad} should be refused");
        }
    }

    #[test]
    fn ttl_parse_reports_a_useful_message() {
        let e = Ttl::parse("abc").unwrap_err();
        assert!(e.to_string().contains("not a number"), "{e}");
        let e = Ttl::parse("5").unwrap_err();
        assert!(e.to_string().contains("automatic"), "{e}");
    }

    // ---------------------------------------------------------------- type rules

    #[test]
    fn only_address_records_can_be_proxied() {
        for t in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
            assert!(t.supports_proxy(), "{t} should be proxyable");
        }
        for t in [
            RecordType::TXT,
            RecordType::MX,
            RecordType::NS,
            RecordType::SRV,
            RecordType::CAA,
        ] {
            assert!(!t.supports_proxy(), "{t} should not be proxyable");
        }
    }

    #[test]
    fn only_mx_and_srv_take_a_priority() {
        assert!(RecordType::MX.requires_priority());
        assert!(RecordType::SRV.requires_priority());
        for t in [
            RecordType::A,
            RecordType::TXT,
            RecordType::CNAME,
            RecordType::NS,
        ] {
            assert!(!t.requires_priority(), "{t} should not take a priority");
        }
    }

    #[test]
    fn record_type_parsing_is_case_insensitive() {
        assert_eq!(RecordType::parse("txt").unwrap(), RecordType::TXT);
        assert_eq!(RecordType::parse("Mx").unwrap(), RecordType::MX);
        assert_eq!(RecordType::parse("AAAA").unwrap(), RecordType::AAAA);
    }

    #[test]
    fn an_unknown_type_names_the_valid_ones() {
        let e = RecordType::parse("BANANA").unwrap_err();
        assert!(
            e.to_string().contains("AAAA"),
            "the message should list valid types: {e}"
        );
    }

    // ---------------------------------------------------------------- validation

    #[test]
    fn a_plain_txt_record_is_valid() {
        assert!(rec("example.com", RecordType::TXT, "v=spf1 -all")
            .validate()
            .is_ok());
    }

    #[test]
    fn mx_without_priority_is_refused() {
        let r = rec("example.com", RecordType::MX, "mx1.example.com");
        assert_eq!(
            r.validate(),
            Err(FieldError::PriorityRequired(RecordType::MX))
        );
    }

    #[test]
    fn mx_with_priority_is_accepted() {
        let mut r = rec("example.com", RecordType::MX, "mx1.example.com");
        r.priority = Some(10);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn priority_on_a_txt_record_is_refused_not_dropped() {
        // The shell version silently dropped it, which meant a typo did nothing at all.
        let mut r = rec("example.com", RecordType::TXT, "x");
        r.priority = Some(10);
        assert_eq!(
            r.validate(),
            Err(FieldError::PriorityNotApplicable(RecordType::TXT))
        );
    }

    #[test]
    fn an_out_of_range_priority_is_refused() {
        let mut r = rec("example.com", RecordType::MX, "mx1.example.com");
        r.priority = Some(70_000);
        assert!(matches!(
            r.validate(),
            Err(FieldError::PriorityOutOfRange { .. })
        ));
    }

    #[test]
    fn proxying_a_txt_record_is_refused() {
        let mut r = rec("example.com", RecordType::TXT, "x");
        r.proxied = true;
        assert_eq!(
            r.validate(),
            Err(FieldError::ProxyNotApplicable(RecordType::TXT))
        );
    }

    #[test]
    fn proxying_an_a_record_is_accepted() {
        let mut r = rec("www.example.com", RecordType::A, "203.0.113.1");
        r.proxied = true;
        assert!(r.validate().is_ok());
    }

    #[test]
    fn empty_content_is_refused() {
        assert_eq!(
            rec("example.com", RecordType::TXT, "   ").validate(),
            Err(FieldError::EmptyContent)
        );
    }

    // ---------------------------------------------------------------- identity

    #[test]
    fn identity_ignores_metadata() {
        let a = rec("example.com", RecordType::TXT, "v=spf1 -all");
        let mut b = a.clone();
        b.ttl = Ttl::new(300).unwrap();
        b.comment = "changed".into();
        b.tags = vec!["email".into()];
        assert_eq!(
            a.identity(),
            b.identity(),
            "metadata must not change identity"
        );
        assert_ne!(
            a.metadata(),
            b.metadata(),
            "but it must show up as metadata"
        );
    }

    #[test]
    fn identity_distinguishes_content() {
        let a = rec("example.com", RecordType::TXT, "v=spf1 -all");
        let b = rec("example.com", RecordType::TXT, "v=spf1 ~all");
        assert_ne!(a.identity(), b.identity());
    }

    #[test]
    fn identity_distinguishes_type_at_the_same_name() {
        let a = rec("example.com", RecordType::TXT, "x");
        let b = rec("example.com", RecordType::NS, "x");
        assert_ne!(a.identity(), b.identity());
    }

    // ---------------------------------------------------------------- txt joining

    #[test]
    fn split_txt_strings_are_joined() {
        // A long SPF record comes back from the API as several quoted strings.
        assert_eq!(
            unquote_txt(r#""v=spf1 " "include:a.com " "-all""#),
            "v=spf1 include:a.com -all"
        );
    }

    #[test]
    fn an_unquoted_value_is_untouched() {
        assert_eq!(unquote_txt("v=spf1 -all"), "v=spf1 -all");
    }

    #[test]
    fn a_single_quoted_value_loses_only_its_quotes() {
        assert_eq!(unquote_txt(r#""v=spf1 -all""#), "v=spf1 -all");
    }

    #[test]
    fn normalising_sorts_and_dedupes_tags() {
        let mut r = rec("example.com", RecordType::TXT, "x");
        r.tags = vec!["spf".into(), "email".into(), "spf".into()];
        let n = r.normalised();
        assert_eq!(n.tags, vec!["email".to_string(), "spf".to_string()]);
    }

    #[test]
    fn tag_order_does_not_make_two_records_differ() {
        let mut a = rec("example.com", RecordType::TXT, "x");
        a.tags = vec!["b".into(), "a".into()];
        let mut b = rec("example.com", RecordType::TXT, "x");
        b.tags = vec!["a".into(), "b".into()];
        assert_eq!(a.normalised().metadata(), b.normalised().metadata());
    }

    // ---------------------------------------------------------------- serde

    #[test]
    fn a_record_round_trips_through_json() {
        let mut r = rec("mail.example.com", RecordType::MX, "mx1.example.com");
        r.priority = Some(10);
        r.ttl = Ttl::new(300).unwrap();
        r.tags = vec!["email".into()];
        let json = serde_json::to_string(&r).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn absent_optional_fields_do_not_appear_in_json() {
        // Cloudflare rejects `proxied` on a TXT record, so it must be omitted rather
        // than serialised as false.
        let json = serde_json::to_string(&rec("example.com", RecordType::TXT, "x")).unwrap();
        assert!(!json.contains("proxied"), "{json}");
        assert!(!json.contains("priority"), "{json}");
        assert!(!json.contains("\"id\""), "{json}");
    }

    #[test]
    fn the_api_shape_deserialises() {
        // Exactly what Cloudflare returns, including fields this tool ignores.
        let json = r#"{
            "id": "abc123",
            "name": "mail.example.com",
            "type": "MX",
            "content": "mx1.example.com",
            "ttl": 300,
            "priority": 10,
            "proxied": false,
            "comment": "primary",
            "tags": ["email"]
        }"#;
        let r: Record = serde_json::from_str(json).unwrap();
        assert_eq!(r.id.as_deref(), Some("abc123"));
        assert_eq!(r.record_type, RecordType::MX);
        assert_eq!(r.priority, Some(10));
        assert_eq!(r.ttl.seconds(), 300);
    }
}
