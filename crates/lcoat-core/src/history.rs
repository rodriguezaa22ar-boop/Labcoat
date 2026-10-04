//! `notes/history.log`: the operator-facing command history the shell build
//! keeps beside the ledger (`timestamp \t event \t detail`). The report's
//! "Commands Run" section is rendered from it.

use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::{append_locked, mkdir_private};

use crate::error::Result;

/// The history file for an operation directory.
pub fn file(op_dir: &Path) -> PathBuf {
    op_dir.join("notes").join("history.log")
}

/// Append one `record_operation_history` line.
pub fn record(op_dir: &Path, event: &str, detail: &str) -> Result<()> {
    mkdir_private(&op_dir.join("notes"))?;
    let line = format!("{}\t{event}\t{detail}\n", clock::timestamp());
    append_locked(&file(op_dir), line.as_bytes())?;
    Ok(())
}

/// One parsed history line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Timestamp.
    pub ts: String,
    /// `start`, `resume`, `close`, `handoff`, `closeout`, `audit-packet`, `archive-packet`, ...
    pub event: String,
    /// Free text (usually a path or the target).
    pub detail: String,
}

/// Every history line, in order; a missing file is empty.
pub fn read(op_dir: &Path) -> Vec<Entry> {
    let Ok(text) = std::fs::read_to_string(file(op_dir)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|raw| {
            let mut parts = raw.splitn(3, '\t');
            let ts = parts.next()?.to_owned();
            let event = parts.next()?.to_owned();
            let detail = parts.next().unwrap_or("").to_owned();
            Some(Entry { ts, event, detail })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_reads_back() {
        let dir = std::env::temp_dir().join(format!("lcoat-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read(&dir).is_empty());
        record(&dir, "start", "demo").unwrap();
        record(&dir, "handoff", "/x/y.md").unwrap();
        let entries = read(&dir);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].event, "handoff");
        assert_eq!(entries[1].detail, "/x/y.md");
        assert_eq!(entries[0].ts.len(), 20);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
