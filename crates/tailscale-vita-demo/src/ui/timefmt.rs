#![allow(dead_code)] // apply/read paths are vita-gated; host sees some as dead

//! M17-B — pure RFC3339 date math for key-expiry / last-seen display.
//! No chrono/time dep: we only need whole-day granularity, so parse the
//! `YYYY-MM-DD` prefix and diff against the device clock via the civil
//! days-from-epoch algorithm (Howard Hinnant's `days_from_civil`).

/// Days from `1970-01-01` to `y-m-d` (proleptic Gregorian). Correct for
/// all reasonable dates; `m` in 1..=12, `d` in 1..=31.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse the date part of an RFC3339 timestamp into `(y, m, d)`.
fn parse_ymd(s: &str) -> Option<(i64, i64, i64)> {
    let date = s.get(..10)?; // "YYYY-MM-DD"
    let b = date.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = date.get(0..4)?.parse().ok()?;
    let m: i64 = date.get(5..7)?.parse().ok()?;
    let d: i64 = date.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Whole days from `now_unix` until the RFC3339 instant `s`. Negative if
/// already past. `None` if unparseable OR the Go zero value
/// (`0001-01-01…`, i.e. "expiry disabled").
pub fn days_until(s: &str, now_unix: u64) -> Option<i64> {
    let (y, m, d) = parse_ymd(s)?;
    if y <= 1 {
        return None; // Go zero value → "never"
    }
    let target_day = days_from_civil(y, m, d);
    let now_day = (now_unix / 86_400) as i64;
    Some(target_day - now_day)
}

/// Render a key-expiry string for display: "never" (disabled/unparseable),
/// "EXPIRED", "expires today", "expires in N days".
pub fn fmt_key_expiry(s: &Option<String>, now_unix: u64) -> String {
    match s.as_deref().and_then(|s| days_until(s, now_unix)) {
        None => "key: never expires".into(),
        Some(d) if d < 0 => "key: EXPIRED".into(),
        Some(0) => "key: expires TODAY".into(),
        Some(1) => "key: expires in 1 day".into(),
        Some(d) => format!("key: expires in {d} days"),
    }
}

/// Whether key-expiry warrants a warning color (< 14 days or past).
pub fn key_expiry_is_warning(s: &Option<String>, now_unix: u64) -> bool {
    matches!(s.as_deref().and_then(|s| days_until(s, now_unix)), Some(d) if d < 14)
}

/// Render a last-seen string: "" when None (peer is current/online),
/// else "last seen N days ago" at whole-day granularity.
pub fn fmt_last_seen(s: &Option<String>, now_unix: u64) -> String {
    match s.as_deref().and_then(|s| days_until(s, now_unix)) {
        None => String::new(),
        Some(d) => {
            let ago = -d; // days in the past
            if ago <= 0 {
                "last seen today".into()
            } else if ago == 1 {
                "last seen 1 day ago".into()
            } else {
                format!("last seen {ago} days ago")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-07-02 00:00:00 UTC
    const NOW: u64 = 1_782_000_000; // 2026-07-01T01:20:00Z-ish; exact day below
    fn day(y: i64, m: i64, d: i64) -> u64 {
        (days_from_civil(y, m, d) as u64) * 86_400
    }

    #[test]
    fn days_from_civil_anchors() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn days_until_basic() {
        let now = day(2026, 7, 2);
        assert_eq!(days_until("2026-07-02T00:00:00Z", now), Some(0));
        assert_eq!(days_until("2026-07-12T12:00:00Z", now), Some(10));
        assert_eq!(days_until("2026-06-30T00:00:00Z", now), Some(-2));
    }

    #[test]
    fn zero_value_is_none() {
        assert_eq!(days_until("0001-01-01T00:00:00Z", day(2026, 7, 2)), None);
        assert_eq!(days_until("garbage", NOW), None);
        assert_eq!(days_until("2026-13-40T00:00:00Z", NOW), None);
        assert_eq!(days_until("2026-07", NOW), None);
    }

    #[test]
    fn fmt_key_expiry_buckets() {
        let now = day(2026, 7, 2);
        assert_eq!(fmt_key_expiry(&None, now), "key: never expires");
        assert_eq!(
            fmt_key_expiry(&Some("0001-01-01T00:00:00Z".into()), now),
            "key: never expires"
        );
        assert_eq!(
            fmt_key_expiry(&Some("2026-06-30T00:00:00Z".into()), now),
            "key: EXPIRED"
        );
        assert_eq!(
            fmt_key_expiry(&Some("2026-07-02T00:00:00Z".into()), now),
            "key: expires TODAY"
        );
        assert_eq!(
            fmt_key_expiry(&Some("2026-08-01T00:00:00Z".into()), now),
            "key: expires in 30 days"
        );
    }

    #[test]
    fn key_expiry_warning_threshold() {
        let now = day(2026, 7, 2);
        assert!(key_expiry_is_warning(&Some("2026-07-10T00:00:00Z".into()), now)); // 8d
        assert!(key_expiry_is_warning(&Some("2026-06-01T00:00:00Z".into()), now)); // past
        assert!(!key_expiry_is_warning(&Some("2026-09-01T00:00:00Z".into()), now)); // far
        assert!(!key_expiry_is_warning(&None, now));
    }

    #[test]
    fn fmt_last_seen_buckets() {
        let now = day(2026, 7, 2);
        assert_eq!(fmt_last_seen(&None, now), "");
        assert_eq!(
            fmt_last_seen(&Some("2026-07-01T00:00:00Z".into()), now),
            "last seen 1 day ago"
        );
        assert_eq!(
            fmt_last_seen(&Some("2026-06-25T00:00:00Z".into()), now),
            "last seen 7 days ago"
        );
    }
}
