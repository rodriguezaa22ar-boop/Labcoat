//! `lcoat doctor`: is this machine and this lab root ready for an
//! operation, and is anything already on disk in a state the other
//! commands would trip over?
//!
//! The shell build's `atlas doctor` checks its runtime (directories, `jq`,
//! `sha256sum`, the wiremap/vector adapters). Lab Coat has no runtime
//! dependencies, so its doctor checks what field runs actually tripped
//! over instead: an unset or mistyped lab root, files left behind by a run
//! under `sudo` that a later run cannot write, an active pointer naming an
//! operation that is gone, interrupted writes, a frozen clock, and records
//! that no longer verify. Tool checks (nmap, privileges) are the CLI's,
//! because only the adapters crate may spawn a process.
//!
//! Strictly read-only, like every read-only command: nothing here creates,
//! opens for writing or locks anything under the root, so it is safe to run
//! while another `lcoat` holds a lock, and safe on a root that does not
//! exist yet.

use std::path::{Path, PathBuf};

use lcoat_format::clock::Utc;
use lcoat_format::envfile::Record;

use crate::chain::{self, ChainStatus};
use crate::evidence;
use crate::ledger;
use crate::operation::{Operation, SESSION_FILE};
use crate::root::LabRoot;

/// The verdict on one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Nothing to do.
    Ok,
    /// Works, but the operator should know (a missing directory the next
    /// write creates, permissions wider than Lab Coat writes).
    Warn,
    /// Something a command will refuse or get wrong until it is fixed.
    Fail,
}

impl Status {
    /// The word printed in the status column and in `--json`.
    pub fn word(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }
}

/// One row of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// Section heading the row is printed under.
    pub section: &'static str,
    /// Short label (first column).
    pub label: String,
    /// Verdict.
    pub status: Status,
    /// Path, value or what to do.
    pub detail: String,
}

/// Every check, in print order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The rows.
    pub checks: Vec<Check>,
}

impl Report {
    /// Add a row.
    pub fn push(
        &mut self,
        section: &'static str,
        label: impl Into<String>,
        status: Status,
        detail: impl Into<String>,
    ) {
        self.checks.push(Check {
            section,
            label: label.into(),
            status,
            detail: detail.into(),
        });
    }

    /// Number of `fail` rows.
    pub fn failures(&self) -> usize {
        self.count(Status::Fail)
    }

    /// Number of `warn` rows.
    pub fn warnings(&self) -> usize {
        self.count(Status::Warn)
    }

    fn count(&self, s: Status) -> usize {
        self.checks.iter().filter(|c| c.status == s).count()
    }
}

/// Section names, in print order.
pub const SECTION_ROOT: &str = "Lab Root";
/// Directory layout under the root.
pub const SECTION_LAYOUT: &str = "Layout";
/// Ownership, permissions and leftovers across every file under the root.
pub const SECTION_RECORDS: &str = "Records";
/// The active pointer and each operation's ledger chain and evidence.
pub const SECTION_OPERATIONS: &str = "Operations";
/// The clock every record is stamped with.
pub const SECTION_CLOCK: &str = "Clock";

/// The earliest plausible system time. A clock before this (a VM restored
/// from a snapshot, a board without an RTC) would stamp records in the past
/// and make every expiry and approval check wrong.
const CLOCK_FLOOR: &str = "2026-01-01T00:00:00Z";

/// Upper bound on entries walked under the root, so a root pointed at `/`
/// by mistake still finishes.
const WALK_LIMIT: usize = 200_000;

/// The effective uid of this process, where it can be read without libc
/// (Linux `/proc/self/status`); `None` elsewhere.
pub fn effective_uid() -> Option<u32> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = text.lines().find(|l| l.starts_with("Uid:"))?;
    // Uid: real effective saved fs
    line.split_whitespace().nth(2)?.parse().ok()
}

/// Run every root-side check. `euid` is the effective uid when known (the
/// CLI passes [`effective_uid`] or what the adapters crate found).
pub fn check(euid: Option<u32>) -> Report {
    let mut r = Report::default();
    if let Some(root) = check_root_variable(&mut r) {
        check_root_dir(&mut r, &root);
        // A root that does not exist yet already has its one `warn` row;
        // seven more saying each directory is missing would bury it.
        if root.root.is_dir() {
            check_layout(&mut r, &root);
            check_records(&mut r, &root, euid);
            check_operations(&mut r, &root);
        }
    }
    check_clock(&mut r);
    r
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn check_root_variable(r: &mut Report) -> Option<LabRoot> {
    let lab = env("LAB_ROOT");
    let lcoat = env("LCOAT_ROOT");
    let (var, value) = match (&lab, &lcoat) {
        (Some(l), Some(c)) if l != c => {
            r.push(
                SECTION_ROOT,
                "root variable",
                Status::Warn,
                format!("LAB_ROOT ({l}) overrides LCOAT_ROOT ({c}); unset one of them"),
            );
            ("LAB_ROOT", l.clone())
        }
        (Some(l), _) => ("LAB_ROOT", l.clone()),
        (None, Some(c)) => ("LCOAT_ROOT", c.clone()),
        (None, None) => {
            r.push(
                SECTION_ROOT,
                "root variable",
                Status::Fail,
                "LCOAT_ROOT is not set; set it once: echo 'export LCOAT_ROOT=\"$HOME/lcoat-lab\"' >> ~/.bashrc",
            );
            return None;
        }
    };
    if !r.checks.iter().any(|c| c.label == "root variable") {
        r.push(SECTION_ROOT, "root variable", Status::Ok, var);
    }
    if !Path::new(&value).is_absolute() {
        r.push(
            SECTION_ROOT,
            "root path",
            Status::Warn,
            format!("{var} is relative ({value}); it resolves against the current directory, so each directory gets its own lab"),
        );
    }
    match LabRoot::at(Path::new(&value)) {
        Ok(root) => Some(root),
        Err(e) => {
            r.push(SECTION_ROOT, "root path", Status::Fail, e.to_string());
            None
        }
    }
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o7777
}

fn check_root_dir(r: &mut Report, root: &LabRoot) {
    let path = root.root.display().to_string();
    match std::fs::symlink_metadata(&root.root) {
        Err(_) => r.push(
            SECTION_ROOT,
            "root",
            Status::Warn,
            format!(
                "{path} does not exist yet; the first command that records something creates it"
            ),
        ),
        Ok(m) if m.file_type().is_symlink() && !root.root.is_dir() => r.push(
            SECTION_ROOT,
            "root",
            Status::Fail,
            format!("{path} is a symlink to something that is not a directory"),
        ),
        Ok(m) if !m.file_type().is_symlink() && !m.is_dir() => r.push(
            SECTION_ROOT,
            "root",
            Status::Fail,
            format!("{path} is not a directory"),
        ),
        Ok(m) => {
            let detail = if m.file_type().is_symlink() {
                format!("{path} (symlink)")
            } else {
                path
            };
            r.push(SECTION_ROOT, "root", Status::Ok, detail);
            #[cfg(unix)]
            if let Ok(m) = root.root.metadata() {
                private_dir_row(r, SECTION_ROOT, "root permissions", &m);
            }
        }
    }

    match env("LAB_CONFIG") {
        Some(c) if !Path::new(&c).is_file() => r.push(
            SECTION_ROOT,
            "config",
            Status::Warn,
            format!("LAB_CONFIG names {c}, which does not exist; defaults apply"),
        ),
        Some(c) => r.push(
            SECTION_ROOT,
            "config",
            Status::Ok,
            format!("{c} (LAB_CONFIG)"),
        ),
        None => {
            let default = root.root.join("etc").join("lab.env");
            if default.is_file() {
                let status = if Record::load(&default).is_ok() {
                    Status::Ok
                } else {
                    Status::Fail
                };
                let detail = if status == Status::Ok {
                    default.display().to_string()
                } else {
                    format!(
                        "{} does not parse; its overrides are ignored",
                        default.display()
                    )
                };
                r.push(SECTION_ROOT, "config", status, detail);
            } else {
                r.push(SECTION_ROOT, "config", Status::Ok, "none (default layout)");
            }
        }
    }
}

#[cfg(unix)]
fn private_dir_row(r: &mut Report, section: &'static str, label: &str, m: &std::fs::Metadata) {
    let mode = mode_of(m);
    if mode & 0o077 == 0 {
        r.push(section, label, Status::Ok, format!("{mode:04o}"));
    } else {
        r.push(
            section,
            label,
            Status::Warn,
            format!("{mode:04o}: other users can read lab records; chmod 700 it"),
        );
    }
}

fn check_layout(r: &mut Report, root: &LabRoot) {
    let dirs: [(&str, &PathBuf, &str); 5] = [
        ("state dir", &root.state_dir, "LAB_STATE_DIR"),
        ("targets dir", &root.targets_dir, "LAB_TARGETS_DIR"),
        ("sessions dir", &root.sessions_dir, "LAB_SESSIONS_DIR"),
        ("reports dir", &root.reports_dir, "LAB_REPORTS_DIR"),
        ("atlas state dir", &root.atlas_state, ""),
    ];
    for (label, dir, var) in dirs {
        let mut detail = dir.display().to_string();
        if !var.is_empty() && env(var).is_some() {
            detail.push_str(&format!(" ({var})"));
        } else if !dir.starts_with(&root.root) {
            detail.push_str(" (outside the root, from the config)");
        }
        match dir.metadata() {
            Err(_) => r.push(
                SECTION_LAYOUT,
                label,
                Status::Warn,
                format!("missing: {detail}; created by the first command that records something"),
            ),
            Ok(m) if !m.is_dir() => r.push(
                SECTION_LAYOUT,
                label,
                Status::Fail,
                format!("not a directory: {detail}"),
            ),
            Ok(m) => {
                #[cfg(unix)]
                if mode_of(&m) & 0o077 != 0 {
                    r.push(
                        SECTION_LAYOUT,
                        label,
                        Status::Warn,
                        format!("{detail} is {:04o}; Lab Coat creates 0700", mode_of(&m)),
                    );
                    continue;
                }
                let _ = m;
                r.push(SECTION_LAYOUT, label, Status::Ok, detail);
            }
        }
    }
    let profiles = std::fs::read_dir(&root.profiles_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "env"))
                .count()
        })
        .unwrap_or(0);
    let detail = if profiles == 0 {
        "built-in default only".to_owned()
    } else {
        format!("{profiles} in {}", root.profiles_dir.display())
    };
    r.push(SECTION_LAYOUT, "scope profiles", Status::Ok, detail);
}

#[derive(Default)]
struct Walk {
    entries: usize,
    truncated: bool,
    foreign: Vec<(PathBuf, u32)>,
    open_files: Vec<PathBuf>,
    symlinks: Vec<PathBuf>,
    temps: Vec<PathBuf>,
}

/// Walk every entry under `dir` without following symlinks.
fn walk(dir: &Path, owner: Option<u32>, w: &mut Walk) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        if w.entries >= WALK_LIMIT {
            w.truncated = true;
            return;
        }
        w.entries += 1;
        let path = entry.path();
        let Ok(m) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if m.file_type().is_symlink() {
            w.symlinks.push(path);
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Some(uid) = owner
                && m.uid() != uid
            {
                w.foreign.push((path.clone(), m.uid()));
            }
            if m.is_file() && mode_of(&m) & 0o077 != 0 {
                w.open_files.push(path.clone());
            }
        }
        #[cfg(not(unix))]
        let _ = owner;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // `fsutil::write_private` writes `.<name>.<pid>.tmp` and renames it;
        // one left behind means a write was interrupted before the rename.
        if m.is_file() && name.starts_with('.') && name.ends_with(".tmp") {
            w.temps.push(path.clone());
        }
        if m.is_dir() {
            walk(&path, owner, w);
        }
    }
}

/// `1 event`, `2 events`; `1 entry`, `2 entries`.
fn plural(n: usize, word: &str) -> String {
    match (n, word.strip_suffix('y')) {
        (1, _) => format!("{n} {word}"),
        (_, Some(stem)) => format!("{n} {stem}ies"),
        _ => format!("{n} {word}s"),
    }
}

fn first(paths: &[PathBuf], root: &Path) -> String {
    paths
        .first()
        .map(|p| p.strip_prefix(root).unwrap_or(p).display().to_string())
        .unwrap_or_default()
}

fn check_records(r: &mut Report, root: &LabRoot, euid: Option<u32>) {
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        root.root.metadata().ok().map(|m| m.uid())
    };
    #[cfg(not(unix))]
    let owner: Option<u32> = None;

    if let (Some(me), Some(o)) = (euid, owner)
        && me != o
        && me != 0
    {
        r.push(
            SECTION_RECORDS,
            "root owner",
            Status::Fail,
            format!("the root is owned by uid {o} and this is uid {me}; commands that record something will fail"),
        );
    }

    let mut w = Walk::default();
    walk(&root.root, owner, &mut w);
    let base = &root.root;

    if w.foreign.is_empty() {
        let who = owner.map(|o| format!(" (uid {o})")).unwrap_or_default();
        r.push(
            SECTION_RECORDS,
            "ownership",
            Status::Ok,
            format!(
                "{}, all owned by the root's owner{who}",
                plural(w.entries, "entry")
            ),
        );
    } else {
        let uid = w.foreign[0].1;
        let paths: Vec<PathBuf> = w.foreign.iter().map(|(p, _)| p.clone()).collect();
        r.push(
            SECTION_RECORDS,
            "ownership",
            Status::Fail,
            format!(
                "{} owned by another user (first: {}, uid {uid}); a run under sudo leaves files a normal run cannot update: sudo chown -R {}: {}",
                plural(w.foreign.len(), "entry"),
                first(&paths, base),
                owner.map(|o| o.to_string()).unwrap_or_default(),
                base.display()
            ),
        );
    }
    if w.truncated {
        r.push(
            SECTION_RECORDS,
            "walk",
            Status::Warn,
            format!("stopped after {WALK_LIMIT} entries; is the root the right directory?"),
        );
    }
    if !w.open_files.is_empty() {
        r.push(
            SECTION_RECORDS,
            "file permissions",
            Status::Warn,
            format!(
                "{} readable by other users (first: {}); Lab Coat writes 0600",
                plural(w.open_files.len(), "file"),
                first(&w.open_files, base)
            ),
        );
    }
    if w.symlinks.is_empty() {
        r.push(SECTION_RECORDS, "symlinks", Status::Ok, "none");
    } else {
        r.push(
            SECTION_RECORDS,
            "symlinks",
            Status::Warn,
            format!(
                "{} (first: {}); Lab Coat never writes one, so something else put it there",
                w.symlinks.len(),
                first(&w.symlinks, base)
            ),
        );
    }
    if w.temps.is_empty() {
        r.push(SECTION_RECORDS, "interrupted writes", Status::Ok, "none");
    } else {
        r.push(
            SECTION_RECORDS,
            "interrupted writes",
            Status::Warn,
            format!(
                "{} (first: {}); the file they were replacing is intact, so they can be deleted",
                plural(w.temps.len(), "leftover temporary file"),
                first(&w.temps, base)
            ),
        );
    }
}

fn check_operations(r: &mut Report, root: &LabRoot) {
    // The pointer as recorded, not `Operation::active_slug`, which hides a
    // stale pointer by returning `None`.
    let pointer = Record::load(&root.active_file)
        .map(|rec| rec.get("ACTIVE_OPERATION").to_owned())
        .unwrap_or_default();

    let mut slugs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&root.sessions_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.join(SESSION_FILE).is_file() {
                slugs.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    slugs.sort();

    if pointer.is_empty() {
        r.push(SECTION_OPERATIONS, "active operation", Status::Ok, "none");
    } else if !slugs.contains(&pointer) {
        r.push(
            SECTION_OPERATIONS,
            "active operation",
            Status::Fail,
            format!("points to '{pointer}', which does not exist; start or resume one (lcoat op list shows them)"),
        );
    } else {
        r.push(
            SECTION_OPERATIONS,
            "active operation",
            Status::Ok,
            pointer.clone(),
        );
    }

    let mut active = 0;
    let mut closed = 0;
    let mut rows = Vec::new();
    for slug in &slugs {
        let row = operation_row(root, slug, &pointer, &mut active, &mut closed);
        rows.push((slug.clone(), row));
    }
    r.push(
        SECTION_OPERATIONS,
        "operations",
        Status::Ok,
        format!("{} ({active} active, {closed} closed)", slugs.len()),
    );
    for (slug, (status, detail)) in rows {
        r.push(SECTION_OPERATIONS, slug, status, detail);
    }
}

fn operation_row(
    root: &LabRoot,
    slug: &str,
    pointer: &str,
    active: &mut usize,
    closed: &mut usize,
) -> (Status, String) {
    let op = match Operation::load(root, slug) {
        Ok(op) => op,
        Err(e) => return (Status::Fail, format!("does not load: {e}")),
    };
    let mut status = Status::Ok;
    let mut parts = vec![op.status.clone()];
    match op.status.as_str() {
        "active" => *active += 1,
        "closed" => {
            *closed += 1;
            if pointer == slug {
                status = Status::Warn;
                parts.push("closed but still the active pointer".to_owned());
            }
        }
        other => {
            return (
                Status::Fail,
                format!("unknown status {other:?}; commands will refuse it"),
            );
        }
    }

    // A missing ledger reads as zero events, which the chain check would
    // call `unchained`; every operation has at least `op.started`.
    let ledger_file = op.ledger_file();
    if !ledger_file.is_file() {
        return (
            Status::Fail,
            format!("{}, ledger missing: {}", op.status, ledger_file.display()),
        );
    }
    match ledger::read_objects(&ledger_file) {
        Err(e) => {
            status = Status::Fail;
            parts.push(format!("ledger does not read: {e}"));
        }
        Ok(objects) => {
            let word = match chain::verify(&objects) {
                ChainStatus::Verified => "chain verified".to_owned(),
                ChainStatus::Unchained => "chain unchained (v1)".to_owned(),
                ChainStatus::Partial { first_chained } => {
                    format!("chain partial from event {}", first_chained + 1)
                }
                ChainStatus::Broken { index, reason } => {
                    status = Status::Fail;
                    format!("chain broken at event {}: {reason}", index + 1)
                }
            };
            parts.push(format!("{}, {word}", plural(objects.len(), "event")));
        }
    }

    match evidence::verify_artifacts(&op.dir) {
        Err(e) => {
            status = Status::Fail;
            parts.push(format!("evidence does not read: {e}"));
        }
        Ok((checks, 0)) if checks.is_empty() => parts.push("no evidence yet".to_owned()),
        Ok((checks, 0)) => parts.push(format!("{} verified", plural(checks.len(), "artifact"))),
        Ok((checks, problems)) => {
            status = Status::Fail;
            parts.push(format!(
                "{problems} of {} artifacts changed or missing: lcoat evidence verify {slug}",
                checks.len()
            ));
        }
    }
    (status, parts.join(", "))
}

fn check_clock(r: &mut Report) {
    if let Some(v) = env("LCOAT_NOW") {
        r.push(
            SECTION_CLOCK,
            "frozen clock",
            Status::Warn,
            format!("LCOAT_NOW={v} stamps every record with that instant; unset it outside tests"),
        );
    }
    if let Some(v) = env("ATLAS_TODAY") {
        r.push(
            SECTION_CLOCK,
            "frozen date",
            Status::Warn,
            format!("ATLAS_TODAY={v} pins the date for expiry checks; unset it outside tests"),
        );
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let now = Utc::from_unix(secs);
    let floor = Utc::parse(CLOCK_FLOOR).map(Utc::unix).unwrap_or(0);
    if now.unix() < floor {
        r.push(
            SECTION_CLOCK,
            "system clock",
            Status::Fail,
            format!(
                "{} is before {CLOCK_FLOOR}; records would be stamped in the past and expiries misjudged",
                now.timestamp()
            ),
        );
    } else {
        r.push(SECTION_CLOCK, "system clock", Status::Ok, now.timestamp());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_uid_reads_proc_on_linux() {
        if Path::new("/proc/self/status").is_file() {
            assert!(effective_uid().is_some());
        }
    }

    #[test]
    fn report_counts_by_status() {
        let mut r = Report::default();
        r.push(SECTION_ROOT, "a", Status::Ok, "");
        r.push(SECTION_ROOT, "b", Status::Warn, "");
        r.push(SECTION_ROOT, "c", Status::Fail, "");
        r.push(SECTION_ROOT, "d", Status::Fail, "");
        assert_eq!((r.failures(), r.warnings()), (2, 1));
        assert_eq!(Status::Warn.word(), "warn");
        assert_eq!(plural(1, "entry"), "1 entry");
        assert_eq!(plural(3, "entry"), "3 entries");
        assert_eq!(plural(0, "event"), "0 events");
    }

    #[test]
    fn walk_finds_symlinks_and_interrupted_writes_without_following_links() {
        let dir = std::env::temp_dir().join(format!("lcoat-doctor-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions/op")).unwrap();
        std::fs::write(dir.join("sessions/op/.session.env.123.tmp"), b"x").unwrap();
        std::fs::write(dir.join("sessions/op/session.env"), b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", dir.join("sessions/escape")).unwrap();
        let mut w = Walk::default();
        walk(&dir, None, &mut w);
        assert_eq!(w.temps.len(), 1);
        #[cfg(unix)]
        assert_eq!(w.symlinks.len(), 1);
        assert!(!w.truncated, "the symlink to / must not be followed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
