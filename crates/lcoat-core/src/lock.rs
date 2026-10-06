//! Advisory locks for mutating commands.
//!
//! The shell build and Lite lock only the ledger line they append. Lab Coat
//! holds one lock for the whole mutating command: `<op dir>/.lock` for
//! anything inside an operation, `<state>/atlas/.lock` for the target
//! registry and the active pointer. Two `lcoat` processes in one root
//! therefore cannot interleave, say, an evidence copy with a packet render.
//! The lock files are empty, 0600, and ignored by every verifier.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use lcoat_format::fsutil::mkdir_private;

use crate::error::Result;

/// The lock file name inside an operation or state directory.
pub const LOCK_FILE: &str = ".lock";

/// An exclusive advisory lock, released on drop.
#[derive(Debug)]
pub struct Lock {
    _file: File,
    path: PathBuf,
}

impl Lock {
    /// Lock `dir/.lock`, creating the directory (0700) and the file (0600)
    /// if needed. Blocks until the lock is free.
    pub fn acquire(dir: &Path) -> Result<Self> {
        mkdir_private(dir)?;
        let path = dir.join(LOCK_FILE);
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                // A mutating command (often an adapter run, which holds the
                // lock for the whole scan) is running here; say so rather
                // than appear to hang.
                eprintln!(
                    "note: waiting for another lcoat command to finish in {}",
                    dir.display()
                );
                file.lock()
                    .map_err(|e| lcoat_format::fsutil::lock_error(&path, &e))?;
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(lcoat_format::fsutil::lock_error(&path, &e).into());
            }
        }
        Ok(Self { _file: file, path })
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self._file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_exclusive_and_released_on_drop() {
        let dir = std::env::temp_dir().join(format!("lcoat-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = Lock::acquire(&dir).unwrap();
        assert!(first.path().is_file());
        // A second non-blocking attempt on the same file fails while held.
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(first.path())
            .unwrap();
        assert!(matches!(
            probe.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(first);
        assert!(probe.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
