//! Reconciling a live zone against a desired one.
//!
//! This is the most consequential code in the tool, because the shape of the plan
//! decides whether a change is safe.
//!
//! THE PROPERTY THAT MATTERS
//!
//! Deleting an SPF record and creating a replacement leaves a window — however brief —
//! in which the zone publishes no SPF policy at all. Mail sent during that window fails
//! authentication. The same is true of DMARC and of DKIM.
//!
//! So the planner never expresses a change as delete-then-create when it can express it
//! as an update. Cloudflare's `PUT /dns_records/{id}` replaces a record atomically, and
//! an update carries the live record's id, which is what makes that possible. A record
//! is only deleted when it genuinely has no counterpart in the desired state.
//!
//! Two records with the same name and type are matched by position after exact matches
//! are paired off, which is how a duplicated `_dmarc` collapsing to one different value
//! becomes one update plus one delete rather than two deletes and a create.

use crate::dns::record::{Fqdn, Record, RecordType};
use std::collections::BTreeMap;

/// A record to be replaced in place, carrying the id needed to do it atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// The live record's id. Present by construction: an update is only ever built from
    /// a live record, so this cannot be `None`.
    pub id: String,
    pub from: Record,
    pub to: Record,
}

impl Update {
    /// Whether the value changed, as opposed to only the metadata. Used by the preview,
    /// because "the TTL moved" and "the SPF policy changed" deserve different attention.
    pub fn changes_content(&self) -> bool {
        self.from.content != self.to.content
    }
}

/// What needs to happen, and in which order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub create: Vec<Record>,
    pub update: Vec<Update>,
    pub delete: Vec<Record>,
    /// Records that already match. Kept so a preview can say "47 unchanged" rather than
    /// leaving the operator to infer it.
    pub unchanged: usize,
}

impl Plan {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.create.is_empty() && self.update.is_empty() && self.delete.is_empty()
    }

    /// A plan that only creates records cannot lose data, which is the one case where
    /// skipping the confirmation prompt is defensible.
    pub fn is_destructive(&self) -> bool {
        !self.update.is_empty() || !self.delete.is_empty()
    }

    pub fn total_changes(&self) -> usize {
        self.create.len() + self.update.len() + self.delete.len()
    }

    /// Deletes first, then updates, then creates.
    ///
    /// Deleting first clears duplicate-record conditions — two SPF records on one name is
    /// a permanent error until one goes away — before anything else moves. Creating last
    /// means a new record only appears once the zone is otherwise consistent.
    pub fn ordered_steps(&self) -> Vec<Step<'_>> {
        let mut steps = Vec::with_capacity(self.total_changes());
        steps.extend(self.delete.iter().map(Step::Delete));
        steps.extend(self.update.iter().map(Step::Update));
        steps.extend(self.create.iter().map(Step::Create));
        steps
    }
}

/// One action, in the order it must be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<'a> {
    Delete(&'a Record),
    Update(&'a Update),
    Create(&'a Record),
}

/// Groups records by name and type. Two records can share a name and type — several MX
/// records, or an SPF and a DKIM TXT record at the same name — so the value is a list.
type Bucket<'a> = BTreeMap<(Fqdn, RecordType), Vec<&'a Record>>;

fn bucket<'a>(records: &'a [Record]) -> Bucket<'a> {
    let mut map: Bucket<'a> = BTreeMap::new();
    for r in records {
        map.entry((r.name.clone(), r.record_type))
            .or_default()
            .push(r);
    }
    map
}

/// Builds a plan to bring `live` to `desired`.
///
/// Both sides are matched in three passes, and the order of the passes is the whole
/// design:
///
///   1. exact matches on name, type and content. Identical records with identical
///      metadata are unchanged; identical records with different metadata are updates.
///   2. leftovers sharing a name and type are paired positionally into in-place updates.
///      This is what keeps a content change from becoming a delete plus a create.
///   3. whatever is still unmatched is a create or a delete.
pub fn build(live: &[Record], desired: &[Record]) -> Plan {
    let mut plan = Plan::default();

    let live_buckets = bucket(live);
    let desired_buckets = bucket(desired);

    // Every (name, type) present on either side.
    let mut keys: Vec<&(Fqdn, RecordType)> = live_buckets.keys().collect();
    keys.extend(desired_buckets.keys());
    keys.sort();
    keys.dedup();

    for key in keys {
        let live_group: &[&Record] = live_buckets.get(key).map_or(&[], std::vec::Vec::as_slice);
        let desired_group: &[&Record] = desired_buckets
            .get(key)
            .map_or(&[], std::vec::Vec::as_slice);

        let mut live_taken = vec![false; live_group.len()];
        let mut desired_taken = vec![false; desired_group.len()];

        // Pass 1: exact content matches.
        for (di, d) in desired_group.iter().enumerate() {
            let found = live_group
                .iter()
                .enumerate()
                .position(|(li, l)| !live_taken[li] && l.content == d.content);
            if let Some(li) = found {
                live_taken[li] = true;
                desired_taken[di] = true;
                let l = live_group[li];
                if l.metadata() == d.metadata() {
                    plan.unchanged += 1;
                } else {
                    plan.update.push(make_update(l, d));
                }
            }
        }

        // Pass 2: pair the leftovers positionally. Same name and type, different content:
        // an in-place replacement, never a delete and a create.
        let mut live_free: Vec<usize> = (0..live_group.len()).filter(|i| !live_taken[*i]).collect();
        let mut desired_free: Vec<usize> = (0..desired_group.len())
            .filter(|i| !desired_taken[*i])
            .collect();

        while let (Some(li), Some(di)) = (live_free.first().copied(), desired_free.first().copied())
        {
            live_free.remove(0);
            desired_free.remove(0);
            live_taken[li] = true;
            desired_taken[di] = true;
            plan.update
                .push(make_update(live_group[li], desired_group[di]));
        }

        // Pass 3: the remainder.
        for di in desired_free {
            plan.create.push(strip_id(desired_group[di]));
        }
        for li in live_free {
            plan.delete.push(live_group[li].clone());
        }
    }

    plan
}

/// Builds an update from a live record and the desired state for it.
///
/// The live id is carried through so the apply step can PUT rather than
/// delete-and-create. A live record without an id cannot be updated in place, so it
/// falls back to a replace — but the API always supplies one, and the fallback exists
/// only so this function has no way to panic.
fn make_update(live: &Record, desired: &Record) -> Update {
    let mut to = desired.clone();
    to.id = live.id.clone();
    Update {
        id: live.id.clone().unwrap_or_default(),
        from: live.clone(),
        to,
    }
}

/// A record being created must not carry an id from wherever it was read.
fn strip_id(r: &Record) -> Record {
    let mut copy = r.clone();
    copy.id = None;
    copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::record::Ttl;

    fn live(id: &str, name: &str, t: RecordType, content: &str) -> Record {
        Record {
            id: Some(id.to_string()),
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

    fn want(name: &str, t: RecordType, content: &str) -> Record {
        Record {
            id: None,
            ..live("unused", name, t, content)
        }
    }

    fn counts(p: &Plan) -> (usize, usize, usize) {
        (p.create.len(), p.update.len(), p.delete.len())
    }

    // ---------------------------------------------------------------- basics

    #[test]
    fn identical_states_produce_no_changes() {
        let l = vec![live("1", "a.example.com", RecordType::TXT, "hello")];
        let d = vec![want("a.example.com", RecordType::TXT, "hello")];
        let p = build(&l, &d);
        assert!(p.is_empty());
        assert_eq!(p.unchanged, 1);
        assert!(!p.is_destructive());
    }

    #[test]
    fn a_record_only_desired_is_created() {
        let p = build(&[], &[want("new.example.com", RecordType::TXT, "x")]);
        assert_eq!(counts(&p), (1, 0, 0));
        assert_eq!(
            p.create[0].id, None,
            "a created record must not carry an id"
        );
        assert!(!p.is_destructive());
    }

    #[test]
    fn a_record_only_live_is_deleted() {
        let p = build(&[live("1", "gone.example.com", RecordType::TXT, "x")], &[]);
        assert_eq!(counts(&p), (0, 0, 1));
        assert!(p.is_destructive());
    }

    // ---------------------------------------------------------------- the point

    #[test]
    fn a_content_change_is_an_update_not_a_delete_and_create() {
        // The property this module exists for: an SPF policy change must never leave the
        // zone without an SPF record.
        let l = vec![live(
            "id1",
            "example.com",
            RecordType::TXT,
            "v=spf1 include:old.example -all",
        )];
        let d = vec![want(
            "example.com",
            RecordType::TXT,
            "v=spf1 include:new.example -all",
        )];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (0, 1, 0));
        assert_eq!(
            p.delete.len(),
            0,
            "an SPF swap must never appear as a delete"
        );
        assert_eq!(
            p.update[0].id, "id1",
            "the update must carry the live id to PUT in place"
        );
        assert!(p.update[0].changes_content());
    }

    #[test]
    fn a_metadata_only_change_is_an_update() {
        let l = vec![live("id1", "a.example.com", RecordType::TXT, "same")];
        let mut d = want("a.example.com", RecordType::TXT, "same");
        d.ttl = Ttl::new(300).unwrap();
        d.comment = "documented".into();
        let p = build(&l, &[d]);
        assert_eq!(counts(&p), (0, 1, 0));
        assert!(!p.update[0].changes_content(), "content did not change");
        assert_eq!(p.update[0].id, "id1");
    }

    #[test]
    fn duplicate_dmarc_collapsing_to_one_new_value_is_one_update_and_one_delete() {
        // The real case this was written for. Two identical DMARC records, one desired
        // record with a different policy. The wrong plan is two deletes and a create,
        // which would leave the zone with no DMARC at all in between.
        let l = vec![
            live(
                "id1",
                "_dmarc.example.com",
                RecordType::TXT,
                "v=DMARC1; p=none",
            ),
            live(
                "id2",
                "_dmarc.example.com",
                RecordType::TXT,
                "v=DMARC1; p=none",
            ),
        ];
        let d = vec![want(
            "_dmarc.example.com",
            RecordType::TXT,
            "v=DMARC1; p=quarantine; sp=quarantine",
        )];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (0, 1, 1));
        assert_eq!(
            p.update[0].to.content,
            "v=DMARC1; p=quarantine; sp=quarantine"
        );
        assert!(p.update[0].changes_content());
    }

    #[test]
    fn identical_duplicates_reduce_to_a_delete() {
        let l = vec![
            live("id1", "a.example.com", RecordType::TXT, "same"),
            live("id2", "a.example.com", RecordType::TXT, "same"),
        ];
        let d = vec![want("a.example.com", RecordType::TXT, "same")];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (0, 0, 1));
        assert_eq!(p.unchanged, 1);
    }

    // ---------------------------------------------------------------- multiplicity

    #[test]
    fn three_live_one_desired_deletes_two() {
        let l = vec![
            live("1", "t.example.com", RecordType::TXT, "a"),
            live("2", "t.example.com", RecordType::TXT, "b"),
            live("3", "t.example.com", RecordType::TXT, "c"),
        ];
        let p = build(&l, &[want("t.example.com", RecordType::TXT, "a")]);
        assert_eq!(counts(&p), (0, 0, 2));
    }

    #[test]
    fn one_live_three_desired_creates_two() {
        let l = vec![live("1", "t.example.com", RecordType::TXT, "a")];
        let d = vec![
            want("t.example.com", RecordType::TXT, "a"),
            want("t.example.com", RecordType::TXT, "b"),
            want("t.example.com", RecordType::TXT, "c"),
        ];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (2, 0, 0));
        assert_eq!(p.unchanged, 1);
    }

    #[test]
    fn multiple_mx_records_are_matched_individually() {
        let l = vec![
            live("1", "example.com", RecordType::MX, "mx1.example.com"),
            live("2", "example.com", RecordType::MX, "mx2.example.com"),
        ];
        let d = vec![
            want("example.com", RecordType::MX, "mx1.example.com"),
            want("example.com", RecordType::MX, "mx3.example.com"),
        ];
        let p = build(&l, &d);
        // mx1 matches exactly; mx2 -> mx3 pairs into an in-place update.
        assert_eq!(counts(&p), (0, 1, 0));
        assert_eq!(p.unchanged, 1);
        assert_eq!(p.update[0].to.content, "mx3.example.com");
    }

    #[test]
    fn exact_matches_are_paired_before_positional_ones() {
        // If pass 2 ran first it could pair "b" with "a" and then need a create and a
        // delete for what is actually one unchanged record and one update.
        let l = vec![
            live("1", "t.example.com", RecordType::TXT, "a"),
            live("2", "t.example.com", RecordType::TXT, "b"),
        ];
        let d = vec![
            want("t.example.com", RecordType::TXT, "b"),
            want("t.example.com", RecordType::TXT, "c"),
        ];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (0, 1, 0));
        assert_eq!(p.unchanged, 1, "b must be recognised as already correct");
        assert_eq!(p.update[0].from.content, "a");
        assert_eq!(p.update[0].to.content, "c");
    }

    // ---------------------------------------------------------------- separation

    #[test]
    fn the_same_name_with_different_types_is_never_paired() {
        let l = vec![live("1", "x.example.com", RecordType::TXT, "value")];
        let d = vec![want("x.example.com", RecordType::A, "1.2.3.4")];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (1, 0, 1), "a TXT must not be updated into an A");
    }

    #[test]
    fn different_names_with_the_same_type_are_never_paired() {
        let l = vec![live("1", "a.example.com", RecordType::TXT, "x")];
        let d = vec![want("b.example.com", RecordType::TXT, "x")];
        let p = build(&l, &d);
        assert_eq!(counts(&p), (1, 0, 1));
    }

    // ---------------------------------------------------------------- fields

    #[test]
    fn a_priority_change_is_an_update() {
        let mut l = live("1", "example.com", RecordType::MX, "mx1.example.com");
        l.priority = Some(10);
        let mut d = want("example.com", RecordType::MX, "mx1.example.com");
        d.priority = Some(20);
        let p = build(&[l], &[d]);
        assert_eq!(counts(&p), (0, 1, 0));
        assert_eq!(p.update[0].to.priority, Some(20));
        assert!(!p.update[0].changes_content());
    }

    #[test]
    fn a_proxy_change_is_an_update() {
        let l = live("1", "www.example.com", RecordType::A, "203.0.113.1");
        let mut d = want("www.example.com", RecordType::A, "203.0.113.1");
        d.proxied = true;
        let p = build(&[l], &[d]);
        assert_eq!(counts(&p), (0, 1, 0));
        assert!(p.update[0].to.proxied);
    }

    #[test]
    fn a_tag_change_is_an_update() {
        let l = live("1", "www.example.com", RecordType::A, "203.0.113.1");
        let mut d = want("www.example.com", RecordType::A, "203.0.113.1");
        d.tags = vec!["web".into()];
        let p = build(&[l], &[d]);
        assert_eq!(counts(&p), (0, 1, 0));
    }

    // ---------------------------------------------------------------- ordering

    #[test]
    fn steps_are_ordered_delete_then_update_then_create() {
        let l = vec![
            live("1", "gone.example.com", RecordType::TXT, "x"),
            live("2", "change.example.com", RecordType::TXT, "old"),
        ];
        let d = vec![
            want("change.example.com", RecordType::TXT, "new"),
            want("added.example.com", RecordType::TXT, "y"),
        ];
        let p = build(&l, &d);
        let steps = p.ordered_steps();
        assert_eq!(steps.len(), 3);
        assert!(
            matches!(steps[0], Step::Delete(_)),
            "deletes clear conflicts first"
        );
        assert!(matches!(steps[1], Step::Update(_)));
        assert!(matches!(steps[2], Step::Create(_)), "creates land last");
    }

    #[test]
    fn a_create_only_plan_is_not_destructive() {
        let p = build(&[], &[want("a.example.com", RecordType::TXT, "x")]);
        assert!(!p.is_destructive(), "creating cannot lose data");
    }

    #[test]
    fn any_update_or_delete_makes_a_plan_destructive() {
        let l = vec![live("1", "a.example.com", RecordType::TXT, "old")];
        let d = vec![want("a.example.com", RecordType::TXT, "new")];
        assert!(build(&l, &d).is_destructive(), "an update replaces data");
        assert!(build(&l, &[]).is_destructive());
    }

    // ---------------------------------------------------------------- edges

    #[test]
    fn two_empty_states_produce_an_empty_plan() {
        let p = build(&[], &[]);
        assert!(p.is_empty());
        assert_eq!(p.unchanged, 0);
        assert_eq!(p.ordered_steps().len(), 0);
    }

    #[test]
    fn the_plan_is_deterministic() {
        // A plan that varies between runs makes a dry run worthless as a preview.
        let l = vec![
            live("1", "b.example.com", RecordType::TXT, "x"),
            live("2", "a.example.com", RecordType::MX, "mx"),
            live("3", "c.example.com", RecordType::A, "1.2.3.4"),
        ];
        let d = vec![
            want("c.example.com", RecordType::A, "5.6.7.8"),
            want("a.example.com", RecordType::TXT, "new"),
        ];
        let first = build(&l, &d);
        for _ in 0..20 {
            assert_eq!(build(&l, &d), first, "plan must not vary between runs");
        }
    }

    #[test]
    fn a_large_zone_reconciles_correctly() {
        // Exercises the bucketing rather than the pairing: 200 records, half changed.
        let mut l = Vec::new();
        let mut d = Vec::new();
        for i in 0..200 {
            let name = format!("host{i}.example.com");
            l.push(live(&format!("id{i}"), &name, RecordType::A, "203.0.113.1"));
            let content = if i % 2 == 0 {
                "203.0.113.1"
            } else {
                "203.0.113.2"
            };
            d.push(want(&name, RecordType::A, content));
        }
        let p = build(&l, &d);
        assert_eq!(counts(&p), (0, 100, 0));
        assert_eq!(p.unchanged, 100);
        assert!(
            p.delete.is_empty(),
            "no address change should ever be a delete"
        );
    }

    #[test]
    fn every_update_carries_a_usable_id() {
        let l = vec![live("real-id", "a.example.com", RecordType::TXT, "old")];
        let d = vec![want("a.example.com", RecordType::TXT, "new")];
        let p = build(&l, &d);
        for u in &p.update {
            assert!(
                !u.id.is_empty(),
                "an update without an id cannot be applied in place"
            );
            assert_eq!(
                u.to.id.as_deref(),
                Some("real-id"),
                "the target must carry the id"
            );
        }
    }
}
