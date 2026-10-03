//! Timestamps and the frozen clock.
//!
//! Every timestamp the shell build writes is `date -u +%Y-%m-%dT%H:%M:%SZ`
//! (or the compact `%Y%m%dT%H%M%SZ` for IDs). `LCOAT_NOW` pins the clock to
//! a fixed RFC 3339 UTC instant, which the conformance harness uses to make
//! three implementations agree on timestamps and IDs. `ATLAS_TODAY` pins
//! the date alone, as the shell build allows.

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC instant with second resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Utc {
    secs: i64,
}

impl Utc {
    /// The current time, or the `LCOAT_NOW` override when set and valid.
    pub fn now() -> Self {
        if let Ok(v) = std::env::var("LCOAT_NOW")
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

    /// Parse `YYYY-MM-DDTHH:MM:SSZ`.
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
        let num = |r: std::ops::Range<usize>| s[r].parse::<i64>().ok();
        let (y, mo, d, h, mi, sec) = (
            num(0..4)?,
            num(5..7)?,
            num(8..10)?,
            num(11..13)?,
            num(14..16)?,
            num(17..19)?,
        );
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
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

/// The shell build's `date -u +%F`, honouring `ATLAS_TODAY`.
pub fn today() -> String {
    if let Ok(v) = std::env::var("ATLAS_TODAY")
        && !v.is_empty()
    {
        return v;
    }
    Utc::now().date()
}

// Howard Hinnant's proleptic Gregorian algorithms.
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
