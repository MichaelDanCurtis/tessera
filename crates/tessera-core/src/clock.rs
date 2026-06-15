//! Injected time seam so core logic is deterministic in tests. `SystemClock` is
//! the ONE allowed wall-clock site in tessera-core; only `main` constructs it.

/// Supplies RFC-3339 timestamps to the versioning layer.
pub trait Clock: Send + Sync {
    fn now_rfc3339(&self) -> String;
}

/// Deterministic clock for tests: always returns the configured instant.
pub struct FixedClock(pub String);

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        self.0.clone()
    }
}

/// Wall-clock implementation. The only place tessera-core reads real time; used
/// solely by `main`. Implemented without extra deps via `std::time` + a minimal
/// RFC-3339 (UTC) formatter.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Civil-date conversion (days since 1970) — Howard Hinnant's algorithm.
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_is_deterministic() {
        let c = FixedClock("2026-06-14T00:00:00Z".into());
        assert_eq!(c.now_rfc3339(), "2026-06-14T00:00:00Z");
        assert_eq!(c.now_rfc3339(), "2026-06-14T00:00:00Z");
    }

    #[test]
    fn system_clock_formats_rfc3339_utc() {
        let s = SystemClock.now_rfc3339();
        // Shape check only (wall-clock, can't assert exact value).
        assert_eq!(s.len(), 20, "expected YYYY-MM-DDThh:mm:ssZ, got {s}");
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
    }
}
