//! Slugs and timestamp IDs, as `lib/common.sh` makes them.

use std::path::Path;

use crate::clock::Utc;

/// `slugify`: lowercase, every run of characters outside `[a-z0-9._-]`
/// becomes one `-`, leading and trailing `-` are trimmed, runs of `-`
/// collapse to one.
pub fn slugify(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut pending_dash = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-' {
            if pending_dash {
                out.push('-');
                pending_dash = false;
            }
            out.push(c);
        } else {
            pending_dash = true;
        }
    }
    // Trim leading/trailing '-' and collapse runs (the input may itself
    // contain runs of '-', which the shell's second sed collapses).
    let trimmed = out.trim_matches('-');
    let mut collapsed = String::with_capacity(trimmed.len());
    let mut last_dash = false;
    for c in trimmed.chars() {
        if c == '-' {
            if !last_dash {
                collapsed.push(c);
            }
            last_dash = true;
        } else {
            collapsed.push(c);
            last_dash = false;
        }
    }
    collapsed
}

/// Whether a slug may name a file or directory under the lab root: not
/// empty, not hidden (no leading `.`), and therefore never `.` or `..`.
/// `slugify` keeps dots (the shell build does), so every writer that turns
/// a name into a path checks this before using it.
pub fn is_safe_slug(slug: &str) -> bool {
    !slug.is_empty() && !slug.starts_with('.')
}

/// `<prefix>_<YYYYMMDDTHHMMSSZ>`, with a `_02`, `_03` suffix when a
/// directory for that ID already exists under `dir`. The caller creates the
/// directory immediately to claim the ID.
pub fn next_id(dir: &Path, prefix: &str) -> String {
    next_id_at(dir, prefix, Utc::now())
}

/// [`next_id`] for an explicit instant.
pub fn next_id_at(dir: &Path, prefix: &str, now: Utc) -> String {
    let base = format!("{prefix}_{}", now.compact());
    let mut candidate = base.clone();
    let mut index = 2;
    loop {
        if dir.join(&candidate).symlink_metadata().is_err() {
            return candidate;
        }
        candidate = format!("{base}_{index:02}");
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found while writing the `slug` fuzz target: slugify keeps dots, so
    /// `..` and `.hidden` survive it and would name the parent directory or
    /// a hidden file. Writers refuse them with `is_safe_slug`.
    #[test]
    fn dot_slugs_are_not_safe() {
        for name in ["..", ".", "...", ".hidden", "", "///"] {
            assert!(!is_safe_slug(&slugify(name)), "{name:?} considered safe");
        }
        for name in ["full-op", "v1.2", "a..b", "x."] {
            assert!(is_safe_slug(&slugify(name)), "{name:?} refused");
        }
    }

    #[test]
    fn slugify_matches_common_sh() {
        assert_eq!(slugify("Demo Node"), "demo-node");
        assert_eq!(slugify("  --Hello, World!--  "), "hello-world");
        assert_eq!(slugify("a__b.c-d"), "a__b.c-d");
        assert_eq!(slugify("full-op"), "full-op");
        assert_eq!(slugify("!!!"), "");
        assert_eq!(slugify("x---y"), "x-y");
        assert_eq!(slugify("Ünïcode"), "n-code");
    }

    #[test]
    fn next_id_suffixes_on_collision() {
        let dir = std::env::temp_dir().join(format!("lcoat-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = Utc::parse("2026-10-02T07:40:00Z").unwrap();
        let first = next_id_at(&dir, "ev", now);
        assert_eq!(first, "ev_20261002T074000Z");
        std::fs::create_dir(dir.join(&first)).unwrap();
        let second = next_id_at(&dir, "ev", now);
        assert_eq!(second, "ev_20261002T074000Z_02");
        std::fs::create_dir(dir.join(&second)).unwrap();
        assert_eq!(next_id_at(&dir, "ev", now), "ev_20261002T074000Z_03");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
