//! Timestamps and the frozen clock.
//!
//! Every timestamp the shell build writes is `date -u +%Y-%m-%dT%H:%M:%SZ`
//! (or the compact `%Y%m%dT%H%M%SZ` for IDs). `LCOAT_NOW` pins the clock to
//! a fixed RFC 3339 UTC instant, which the conformance harness uses to make
//! three implementations agree on timestamps and IDs. `ATLAS_TODAY` pins
//! the date alone, as the shell build allows.
//!
//! Both are test fixtures, honoured only by debug builds (`cargo test`, the
//! conformance harnesses). A release binary ignores them: a stale export
//! from a conformance run used to make expired Tier 3 grants valid and
//! stamp every record with the wrong time. The CLI warns when one is set
//! but ignored ([`ignored_overrides`]).

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC instant with second resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Utc {
    secs: i64,
}

impl Utc {
    /// The current time, or the `LCOAT_NOW` override when this build
    /// honours it ([`FROZEN_CLOCK_ALLOWED`]) and it is set and valid.
    pub fn now() -> Self {
        if let Some(v) = frozen("LCOAT_NOW", FROZEN_CLOCK_ALLOWED)
            && let Some(t) = Self::parse(&v)
        {
            return t;
        }
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Self { secs }
    }

    /// Seconds since the Unix epoch.
    pub fn unix(self) -> i64 {
        self.secs
    }

    /// An instant from seconds since the Unix epoch.
    pub fn from_unix(secs: i64) -> Self {
        Self { secs }
    }

    /// Parse `YYYY-MM-DDTHH:MM:SSZ`, strictly: ASCII digits only (no sign),
    /// a real calendar date, no leap second. Every accepted string is the
    /// one [`Utc::timestamp`] prints for it, so one instant has exactly one
    /// spelling on disk (fuzz target `timestamp`).
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 20
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'Z'
        {
            return None;
        }
        let num = |r: std::ops::Range<usize>| {
            let part = &b[r];
            if !part.iter().all(u8::is_ascii_digit) {
                return None;
            }
            part.iter()
                .try_fold(0i64, |acc, d| Some(acc * 10 + i64::from(d - b'0')))
        };
        let (y, mo, d, h, mi, sec) = (
            num(0..4)?,
            num(5..7)?,
            num(8..10)?,
            num(11..13)?,
            num(14..16)?,
            num(17..19)?,
        );
        if !(1..=12).contains(&mo)
            || d < 1
            || d > days_in_month(y, mo)
            || h > 23
            || mi > 59
            || sec > 59
        {
            return None;
        }
        Some(Self {
            secs: days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec,
        })
    }

    fn civil(self) -> (i64, i64, i64, i64, i64, i64) {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
    }

    /// `YYYY-MM-DDTHH:MM:SSZ`, the ledger timestamp form.
    pub fn timestamp(self) -> String {
        let (y, m, d, h, mi, s) = self.civil();
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }

    /// `YYYYMMDDTHHMMSSZ`, the ID form.
    pub fn compact(self) -> String {
        let (y, m, d, h, mi, s) = self.civil();
        format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{s:02}Z")
    }

    /// `YYYY-MM-DD`.
    pub fn date(self) -> String {
        let (y, m, d, _, _, _) = self.civil();
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// The shell build's `date -u +%Y-%m-%dT%H:%M:%SZ`.
pub fn timestamp() -> String {
    Utc::now().timestamp()
}

/// The shell build's `date -u +%F`, honouring `ATLAS_TODAY` where this
/// build allows a frozen clock.
pub fn today() -> String {
    if let Some(v) = frozen("ATLAS_TODAY", FROZEN_CLOCK_ALLOWED) {
        return v;
    }
    Utc::now().date()
}

/// Whether this build honours `LCOAT_NOW` and `ATLAS_TODAY`: debug builds
/// only, so no release binary runs on a frozen clock.
pub const FROZEN_CLOCK_ALLOWED: bool = cfg!(debug_assertions);

/// The clock overrides, by name.
pub const CLOCK_OVERRIDES: [&str; 2] = ["LCOAT_NOW", "ATLAS_TODAY"];

fn frozen(var: &str, allowed: bool) -> Option<String> {
    if !allowed {
        return None;
    }
    std::env::var(var).ok().filter(|v| !v.is_empty())
}

/// The clock overrides that are set but ignored by this build, for the CLI
/// to warn about. Empty in debug builds.
pub fn ignored_overrides() -> Vec<&'static str> {
    ignored_when(FROZEN_CLOCK_ALLOWED, &CLOCK_OVERRIDES)
}

fn ignored_when(allowed: bool, names: &[&'static str]) -> Vec<&'static str> {
    if allowed {
        return Vec::new();
    }
    names
        .iter()
        .copied()
        .filter(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
        .collect()
}

// Howard Hinnant's proleptic Gregorian algorithms.
/// Latest instant an expiry may name: the end of year 9999, the last one
/// the `YYYY-MM-DDTHH:MM:SSZ` form can print.
pub const MAX_EXPIRY_SECS: i64 = 253_402_300_799;

/// An expiry as operators type it: `YYYY-MM-DD` (the end of that day, UTC),
/// a full `YYYY-MM-DDTHH:MM:SSZ`, or `<N>h` / `<N>d` from `now`. `None` for
/// anything else, including a zero or negative count and a result past the
/// end of year 9999 (no arithmetic can overflow). Used by `approval grant`
/// and `finding accept`, so both store a real instant, never the text typed.
pub fn parse_expiry(v: &str, now: Utc) -> Option<Utc> {
    if let Some(t) = Utc::parse(v) {
        return Some(t);
    }
    if v.len() == 10
        && let Some(t) = Utc::parse(&format!("{v}T23:59:59Z"))
    {
        return Some(t);
    }
    let (num, unit) = match v.as_bytes().last() {
        Some(b'h') => (&v[..v.len() - 1], 3600i64),
        Some(b'd') => (&v[..v.len() - 1], 86_400i64),
        _ => return None,
    };
    if num.is_empty() || num.len() > 12 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = num.parse().ok()?;
    if n == 0 {
        return None;
    }
    let secs = now.unix().checked_add(n.checked_mul(unit)?)?;
    (secs <= MAX_EXPIRY_SECS).then(|| Utc::from_unix(secs))
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    /// Review 2026-10-05: `LCOAT_NOW` froze the clock in release binaries.
    /// PATH stands in for a set override (tests cannot set variables
    /// without `unsafe`).
    #[test]
    fn a_frozen_clock_is_honoured_only_where_allowed() {
        assert!(super::frozen("PATH", true).is_some());
        assert_eq!(super::frozen("PATH", false), None);
        assert_eq!(super::ignored_when(false, &["PATH"]), ["PATH"]);
        assert!(super::ignored_when(true, &["PATH"]).is_empty());
        assert!(super::ignored_when(false, &["LCOAT_SURELY_UNSET_VAR"]).is_empty());
        assert_eq!(super::FROZEN_CLOCK_ALLOWED, cfg!(debug_assertions));
    }

    /// Found by fuzz target `timestamp`: signs, impossible dates and leap
    /// seconds were accepted and printed back in a different spelling.
    #[test]
    fn parse_expiry_forms_and_limits() {
        let now = Utc::parse("2026-10-02T07:40:00Z").unwrap();
        let at = |v: &str| parse_expiry(v, now).map(Utc::timestamp);
        assert_eq!(at("90d").as_deref(), Some("2026-12-31T07:40:00Z"));
        assert_eq!(at("12h").as_deref(), Some("2026-10-02T19:40:00Z"));
        assert_eq!(at("2027-01-15").as_deref(), Some("2027-01-15T23:59:59Z"));
        assert_eq!(
            at("2027-01-15T10:00:00Z").as_deref(),
            Some("2027-01-15T10:00:00Z")
        );
        // Found in the field: "90d" used to be stored as text and never expire.
        // Malformed, zero, signed and overflowing counts are refused.
        for bad in [
            "",
            "d",
            "0d",
            "-5d",
            "+5d",
            "5 d",
            "5w",
            "90",
            "99999999999999d",
            "9223372036854775807h",
            "2026-13-01",
        ] {
            assert_eq!(parse_expiry(bad, now), None, "{bad:?} accepted");
        }
        // 2,900,000 days from 2026 is year 9966; 3,000,000 is past 9999.
        assert!(parse_expiry("2900000d", now).is_some(), "year 9966 refused");
        assert!(
            parse_expiry("3000000d", now).is_none(),
            "past year 9999 accepted"
        );
    }

    #[test]
    fn parse_is_strict_and_canonical() {
        for bad in [
            "+026-10-02T07:40:00Z",
            "2026-10-02T07:-0:00Z",
            "2026-10-02T+7:40:00Z",
            "2026-02-31T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "2026-10-02T07:40:60Z",
            "2026-10-02T24:00:00Z",
        ] {
            assert_eq!(Utc::parse(bad), None, "{bad} accepted");
        }
        for good in [
            "2024-02-29T12:00:00Z",
            "2000-02-29T00:00:00Z",
            "1970-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            assert_eq!(Utc::parse(good).map(Utc::timestamp).as_deref(), Some(good));
        }
    }

    use super::*;

    #[test]
    fn round_trips_known_instants() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2026-10-02T07:40:00Z",
            "2000-02-29T23:59:59Z",
            "2026-10-03T01:28:17Z",
            "1999-12-31T23:59:59Z",
        ] {
            let t = Utc::parse(s).unwrap();
            assert_eq!(t.timestamp(), s);
        }
        assert_eq!(
            Utc::parse("2026-10-02T07:40:00Z").unwrap().compact(),
            "20261002T074000Z"
        );
        assert_eq!(
            Utc::parse("2026-10-02T07:40:00Z").unwrap().date(),
            "2026-10-02"
        );
        // 2026-10-02T07:40:00Z = 1790926800 (checked against `date -d`).
        assert_eq!(
            Utc::parse("2026-10-02T07:40:00Z").unwrap().unix(),
            1_790_926_800
        );
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "2026-10-02T07:40:00",
            "2026-13-02T07:40:00Z",
            "2026-10-02 07:40:00Z",
            "",
            "x",
        ] {
            assert!(Utc::parse(s).is_none(), "{s:?}");
        }
    }
}
