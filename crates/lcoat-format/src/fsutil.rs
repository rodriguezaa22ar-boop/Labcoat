//! Filesystem primitives every writer goes through.
//!
//! Quality bar item 3: nothing on the write path can half-happen silently.
//! Whole files are written to a temporary name in the same directory,
//! flushed to disk, then renamed over the target, so a reader never sees a
//! truncated packet or env record; the two append-only logs use
//! [`append_locked`] instead. Everything is created private (0600 files,
//! 0700 directories), which the shell build does with `chmod` after the
//! fact and Lite did at open time.
//!
//! No write follows a symbolic link (review 2026-10-05: a planted
//! `manifest.ndjson` link made `evidence add` append outside the root, and a
//! `reports/` link made `op report` write there). [`check_write_path`]
//! refuses a link at the file itself and at every directory between the lab
//! root ([`confine_writes`]) and the file; appends also open with
//! `O_NOFOLLOW` where the flag's value is known, and tighten an existing
//! file's mode to 0600.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

thread_local! {
    static WRITE_ROOT: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Declare the lab root for this thread's writes: below it, no directory on
/// the way to a written file may be a symbolic link. (The root itself may
/// be one; `LAB_*_DIR` settings that point elsewhere are honoured, with the
/// file and its parent still checked.) Set by `LabRoot::at`.
pub fn confine_writes(root: &Path) {
    WRITE_ROOT.with(|r| *r.borrow_mut() = Some(root.to_path_buf()));
}

fn is_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Refuse to write `path` if it, or a directory between the lab root and
/// it (only its parent, when it is not under the root), is a symbolic link.
pub fn check_write_path(path: &Path) -> io::Result<()> {
    let root = WRITE_ROOT.with(|r| r.borrow().clone());
    let below_root = root
        .as_deref()
        .filter(|r| path.starts_with(r) && path != *r);
    let mut checked = vec![path];
    match below_root {
        Some(r) => checked.extend(path.ancestors().skip(1).take_while(|a| *a != r)),
        None => checked.extend(path.parent()),
    }
    for p in checked {
        if is_symlink(p) {
            let what = if p == path {
                "it is a symbolic link".to_owned()
            } else {
                format!("the directory {} is a symbolic link", p.display())
            };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to write {}: {what}, which could send lab data outside the lab root; replace it with a real file or directory (to keep data elsewhere, set LAB_SESSIONS_DIR or LAB_REPORTS_DIR instead)",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

/// `O_NOFOLLOW` where its value is known (the lstat check in
/// [`check_write_path`] covers the rest).
pub fn no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(0o400_000);
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(0x0100);
    }
    opts
}

/// Open `path` for appending (and reading), refusing symbolic links, creating
/// it 0600, and tightening an existing file's mode to 0600.
pub fn open_append(path: &Path) -> io::Result<File> {
    check_write_path(path)?;
    let f = open_private(
        path,
        no_follow(OpenOptions::new().read(true).append(true).create(true)),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if f.metadata()?.permissions().mode() & 0o077 != 0 {
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(f)
}

/// `mkdir -p` with mode 0700 on every created directory, refusing to go
/// through a symbolic link below the lab root.
pub fn mkdir_private(path: &Path) -> io::Result<()> {
    check_write_path(path)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
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
    check_write_path(path)?;
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
pub fn append_locked(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut f = open_append(path)?;
    let locked = f.lock().is_ok();
    let written = f.write_all(line).and_then(|()| f.sync_data());
    if locked {
        let _ = f.unlock();
    }
    written
}

/// Copy `src` to `dst` (which must not exist) with mode 0600, streaming,
/// returning the number of bytes copied. Used for evidence capture, where
/// the copy is hashed afterwards and compared with the source hash.
pub fn copy_private_new(src: &Path, dst: &Path) -> io::Result<u64> {
    check_write_path(dst)?;
    let mut input = File::open(src)?;
    let mut out = open_private(dst, OpenOptions::new().write(true).create_new(true))?;
    let n = io::copy(&mut input, &mut out)?;
    out.sync_all()?;
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
    fn writes_refuse_symlinks_below_the_root_and_tighten_modes() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tmpdir("confine");
        let elsewhere = tmpdir("confine-elsewhere");
        confine_writes(&root);
        // A link two levels up from the file.
        mkdir_private(&root.join("sessions")).unwrap();
        symlink(&elsewhere, root.join("sessions/op")).unwrap();
        let deep = root.join("sessions/op/evidence/x.ndjson");
        let e = append_locked(&deep, b"{}\n").unwrap_err();
        assert!(
            e.to_string().contains("sessions/op is a symbolic link"),
            "{e}"
        );
        assert!(mkdir_private(&root.join("sessions/op/evidence")).is_err());
        assert!(write_private(&root.join("sessions/op/a.env"), b"x").is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
        // The file itself.
        fs::write(elsewhere.join("t"), b"").unwrap();
        symlink(elsewhere.join("t"), root.join("t.ndjson")).unwrap();
        assert!(append_locked(&root.join("t.ndjson"), b"{}\n").is_err());
        assert!(write_private(&root.join("t.ndjson"), b"{}\n").is_err());
        assert_eq!(fs::read(elsewhere.join("t")).unwrap(), b"");
        // An existing file with a loose mode is tightened on append.
        let loose = root.join("loose.ndjson");
        fs::write(&loose, b"").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        append_locked(&loose, b"{}\n").unwrap();
        assert_eq!(
            fs::metadata(&loose).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The root itself may be a link.
        let via = tmpdir("confine-via").join("root");
        symlink(&root, &via).unwrap();
        confine_writes(&via);
        append_locked(&via.join("ok.ndjson"), b"{}\n").unwrap();
        WRITE_ROOT.with(|r| *r.borrow_mut() = None);
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
