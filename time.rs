//! Time formatting, in UTC only.
//!
//! There is no timezone handling and no calendar crate. An audit trail that records
//! local time is ambiguous the moment it is read on another machine or across a DST
//! change, so every timestamp this tool writes is UTC and says so.
//!
//! The civil-date conversion is Hinnant's `civil_from_days`: it shifts the era so March
//! is the first month, which puts the leap day at the end of the year and removes every
//! special case. Twenty lines, exact for any date this tool will see. Pulling in a
//! datetime crate to render six fields is not a trade worth making.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch. Saturates at 0 for a pre-1970 clock, because a
/// negative timestamp is never the right thing to write into an audit record.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `2026-08-14T11:50:22Z` — RFC 3339, UTC, second precision.
pub fn format_rfc3339(epoch: u64) -> String {
    let (y, m, d, hh, mm, ss) = decompose(epoch);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// `20260814T115022Z` — safe in a filename anywhere, and sorts lexicographically in
/// chronological order, which is why snapshot names use it.
pub fn format_stamp(epoch: u64) -> String {
    let (y, m, d, hh, mm, ss) = decompose(epoch);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// `2026-08-14 11:50:22 UTC` — for reading, not for parsing.
pub fn format_human(epoch: u64) -> String {
    let (y, m, d, hh, mm, ss) = decompose(epoch);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// `4 minutes ago`. Coarse on purpose: this answers "was that me, just now?", and
/// second-level precision does not help answer it.
pub fn format_age(seconds: u64) -> String {
    match seconds {
        s if s < 90 => format!("{s} seconds ago"),
        s if s < 5_400 => format!("{} minutes ago", s / 60),
        s if s < 172_800 => format!("{} hours ago", s / 3_600),
        s => format!("{} days ago", s / 86_400),
    }
}

fn decompose(epoch: u64) -> (i64, u32, u32, u32, u32, u32) {
    // `epoch / 86_400` is at most ~2e14 for any representable time, far inside i64.
    let day_number = i64::try_from(epoch / 86_400).unwrap_or(i64::MAX);
    let second_of_day = epoch % 86_400;
    let (year, month, day) = civil_from_days(day_number);
    // Each field is bounded by construction: hours < 24, minutes < 60, seconds < 60.
    let hour = (second_of_day / 3_600) as u32;
    let minute = ((second_of_day % 3_600) / 60) as u32;
    let second = (second_of_day % 60) as u32;
    (year, month, day, hour, minute, second)
}

/// Days since 1970-01-01 to a civil date.
// Every cast below is bounded by the algorithm, not by hope: day_of_era is [0, 146096],
// day_of_year is [0, 365], month is [1, 12] and day is [1, 31]. What actually holds that
// invariant is the test suite, which walks a full leap year, both century rules, and
// every month boundary.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400; // year_of_era is [0, 399]
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_shifted = (5 * day_of_year + 2) / 153; // [0, 11], March = 0
    let day = (day_of_year - (153 * month_shifted + 2) / 5 + 1) as u32;
    let month = if month_shifted < 10 {
        month_shifted + 3
    } else {
        month_shifted - 9
    } as u32;
    // January and February belong to the following calendar year in the shifted era.
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero_is_the_unix_epoch() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_timestamps_match_date_u() {
        // Cross-checked against `date -u -d @<epoch>`.
        assert_eq!(format_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_rfc3339(1_755_000_000), "2025-08-12T12:00:00Z");
    }

    #[test]
    fn leap_days_are_exact() {
        assert_eq!(format_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        // 2000 is a leap year despite being a century: divisible by 400.
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        // 1900 was not a leap year, so day -25508 must be 1 March, not 29 February.
        assert_eq!(civil_from_days(-25_508), (1900, 3, 1));
    }

    #[test]
    fn a_whole_leap_year_lands_correctly() {
        let jan1_2024 = 1_704_067_200u64;
        assert_eq!(format_rfc3339(jan1_2024), "2024-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339(jan1_2024 + 59 * 86_400),
            "2024-02-29T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339(jan1_2024 + 365 * 86_400),
            "2024-12-31T00:00:00Z"
        );
    }

    #[test]
    fn month_boundaries_are_exact() {
        for (epoch, expected) in [
            (1_722_470_400u64, "2024-08-01T00:00:00Z"),
            (1_722_384_000, "2024-07-31T00:00:00Z"),
            (1_735_689_600, "2025-01-01T00:00:00Z"),
            (1_735_603_200, "2024-12-31T00:00:00Z"),
        ] {
            assert_eq!(format_rfc3339(epoch), expected, "epoch {epoch}");
        }
    }

    #[test]
    fn stamps_sort_chronologically() {
        assert!(format_stamp(1_700_000_000) < format_stamp(1_700_000_001));
        assert!(format_stamp(1_699_999_999) < format_stamp(1_700_000_000));
    }

    #[test]
    fn stamps_are_filename_safe() {
        let s = format_stamp(1_755_000_000);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()), "{s}");
    }

    #[test]
    fn ages_use_useful_units() {
        assert_eq!(format_age(5), "5 seconds ago");
        assert_eq!(format_age(89), "89 seconds ago");
        assert_eq!(format_age(90), "1 minutes ago");
        assert_eq!(format_age(240), "4 minutes ago");
        assert_eq!(format_age(7_200), "2 hours ago");
        assert_eq!(format_age(864_000), "10 days ago");
    }

    #[test]
    fn every_hour_of_a_day_round_trips() {
        let midnight = 1_755_000_000 - (1_755_000_000 % 86_400);
        for h in 0..24u64 {
            let s = format_rfc3339(midnight + h * 3_600);
            assert!(s.contains(&format!("T{h:02}:00:00Z")), "{s}");
        }
    }
}
