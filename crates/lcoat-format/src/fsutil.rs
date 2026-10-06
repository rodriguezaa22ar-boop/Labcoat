//! Filesystem primitives every writer goes through.
//!
//! Quality bar item 3: nothing on the write path can half-happen silently.
//! Whole files are written to a temporary name in the same directory,
//! flushed to disk, then renamed over the target, so a reader never sees a
//! truncated packet or env record; the two append-only logs use
//! [`append_locked`] instead. Everything is created private (0600 files,
//! 0700 directories), which the shell build does with `chmod` after the
//! fact and Lite did at open time.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// `mkdir -p` with mode 0700 on every created directory. Each directory
/// it creates is made durable (its parent's entry synced), so a crash
/// cannot lose a directory a later write already put files in.
pub fn mkdir_private(path: &Path) -> io::Result<()> {
    let missing: Vec<&Path> = path.ancestors().take_while(|a| !a.exists()).collect();
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    for created in missing.iter().rev() {
        sync_parent(created);
    }
    Ok(())
}

/// Sync the directory holding `path`, so a newly created or renamed entry
/// survives a crash. Best effort: some filesystems refuse to sync a
/// directory, and the data itself was already synced.
fn sync_parent(path: &Path) {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Whether `path` is an existing regular file.
pub fn file_exists(path: &Path) -> bool {
    path.metadata().map(|m| m.is_file()).unwrap_or(false)
}

fn open_private(path: &Path, opts: &mut OpenOptions) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Write `data` to `path` atomically with mode 0600: a temporary file in
/// the same directory is written, synced and renamed over `path`. On any
/// failure the temporary file is removed and `path` is untouched.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp: PathBuf = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut f = open_private(&tmp, OpenOptions::new().write(true).create_new(true))?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        // The rename is durable once the directory entry is; sync it too.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Append `line` to `path` under an exclusive advisory lock, creating the
/// file 0600. The write is a single `write_all` followed by `sync_data`, so
/// a crash leaves either the whole line or nothing (for lines under the
/// filesystem's atomic append size, which every record here is).
///
/// The lock is not optional: if the filesystem cannot take it (some network
/// mounts), nothing is appended (review 2026-10-05: the append carried on
/// unlocked, so two writers could interleave).
pub fn append_locked(path: &Path, line: &[u8]) -> io::Result<()> {
    let created = !path.exists();
    let mut f = open_private(path, OpenOptions::new().append(true).create(true))?;
    if created {
        sync_parent(path);
    }
    f.lock().map_err(|e| lock_error(path, &e))?;
    let written = f.write_all(line).and_then(|()| f.sync_data());
    let _ = f.unlock();
    written
}

/// The refusal for a file that cannot be locked.
pub fn lock_error(path: &Path, e: &io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!(
            "cannot lock {} ({e}); refusing to write without the lock. The lab root may be on a filesystem without advisory locks (some NFS or FUSE mounts): put LCOAT_ROOT on a local filesystem",
            path.display()
        ),
    )
}

/// Copy `src` to `dst` (which must not exist) with mode 0600, streaming,
/// returning the number of bytes copied. Used for evidence capture, where
/// the copy is hashed afterwards and compared with the source hash.
pub fn copy_private_new(src: &Path, dst: &Path) -> io::Result<u64> {
    let mut input = File::open(src)?;
    let mut out = open_private(dst, OpenOptions::new().write(true).create_new(true))?;
    let n = io::copy(&mut input, &mut out)?;
    out.sync_all()?;
    sync_parent(dst);
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lcoat-fsutil-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        mkdir_private(&d).unwrap();
        d
    }

    #[test]
    fn mkdir_private_creates_every_level_0700() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("mkdir");
        let deep = d.join("a/b/c");
        mkdir_private(&deep).unwrap();
        for p in [d.join("a"), d.join("a/b"), deep.clone()] {
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        mkdir_private(&deep).unwrap();
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let d = tmpdir("atomic");
        let p = d.join("a.env");
        write_private(&p, b"one\n").unwrap();
        write_private(&p, b"two\n").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two\n");
        let names: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["a.env"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&d).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn append_and_copy() {
        let d = tmpdir("append");
        let p = d.join("log.ndjson");
        append_locked(&p, b"{\"a\":1}\n").unwrap();
        append_locked(&p, b"{\"b\":2}\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "{\"a\":1}\n{\"b\":2}\n");
        let c = d.join("copy");
        assert_eq!(copy_private_new(&p, &c).unwrap(), 16);
        assert!(
            copy_private_new(&p, &c).is_err(),
            "destination must not exist"
        );
        assert!(file_exists(&c));
        assert!(!file_exists(&d));
        let _ = fs::remove_dir_all(&d);
    }
}
