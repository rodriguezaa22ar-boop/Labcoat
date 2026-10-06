//! `op repair-tail`: set aside the half-written record an interrupted append
//! left at the end of an operation's NDJSON file.
//!
//! Every append refuses a file that does not end in a newline (gluing a new
//! record onto the fragment would lose both, and a torn ledger tail would
//! block every later write). The repair, under the operation lock, moves the
//! bytes after the last newline to `repaired/<file>.<timestamp>.torn`
//! (0600), truncates the file back to its last complete record, and records
//! one `op.tail-repaired` event per file with the fragment's size and hash.
//! Complete records are never touched, so a hash chain that verified before
//! the interrupted write verifies after the repair.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::{mkdir_private, torn_tail, write_private};
use lcoat_format::hash::Sha256Hex;

use crate::error::Result;
use crate::operation::{AnyState, Operation};
use crate::root::TOOL_NAME;
use crate::tier::Tier;
use crate::{approval, evidence, findings, history, ledger};

/// Ledger event recorded for each repaired file.
pub const EVENT: &str = "op.tail-repaired";

/// One file whose torn tail was set aside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repaired {
    /// The file, relative to the operation directory.
    pub file: String,
    /// Bytes moved out of it.
    pub bytes: u64,
    /// SHA-256 of those bytes.
    pub sha256: Sha256Hex,
    /// Where they were kept, relative to the operation directory.
    pub kept: String,
}

/// The append-only files of an operation directory, in repair order (the
/// ledger last, so its repair event can be appended once it is whole).
pub fn files(op_dir: &Path) -> Vec<PathBuf> {
    vec![
        approval::file(op_dir),
        evidence::index_file(op_dir),
        evidence::manifest_file(op_dir),
        findings::index_file(op_dir),
        history::file(op_dir),
        ledger::file(op_dir),
    ]
}

fn rel(op_dir: &Path, p: &Path) -> String {
    p.strip_prefix(op_dir)
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

/// Repair every torn tail in `op`'s files; an empty result means there was
/// nothing to repair (and nothing is recorded).
pub fn repair_tails(op: &Operation<AnyState>) -> Result<Vec<Repaired>> {
    let _lock = op.lock()?;
    let stamp: String = clock::timestamp()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let mut done = Vec::new();
    for path in files(&op.dir) {
        let mut f = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        // Appenders lock the file itself as well as the operation.
        f.lock()?;
        let result = (|| -> Result<Option<Repaired>> {
            let Some(n) = torn_tail(&f)? else {
                return Ok(None);
            };
            let len = f.metadata()?.len();
            let keep = len - n;
            let mut fragment = Vec::new();
            f.seek(SeekFrom::Start(keep))?;
            f.read_to_end(&mut fragment)?;
            let dir = op.dir.join("repaired");
            mkdir_private(&dir)?;
            let name = path
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let kept = dir.join(format!("{name}.{stamp}.torn"));
            if kept.exists() {
                crate::fail!("{} already exists; nothing was changed", kept.display());
            }
            write_private(&kept, &fragment)?;
            f.set_len(keep)?;
            f.sync_all()?;
            Ok(Some(Repaired {
                file: rel(&op.dir, &path),
                bytes: n,
                sha256: Sha256Hex::of_bytes(&fragment),
                kept: rel(&op.dir, &kept),
            }))
        })();
        let _ = f.unlock();
        if let Some(r) = result? {
            done.push(r);
        }
    }
    for r in &done {
        op.append_ledger(
            EVENT,
            Tier::ReadOnly.capability(),
            TOOL_NAME,
            "ok",
            &format!(
                "file={} bytes={} sha256={} kept={}",
                r.file,
                r.bytes,
                r.sha256.as_str(),
                r.kept
            ),
        )?;
    }
    Ok(done)
}
