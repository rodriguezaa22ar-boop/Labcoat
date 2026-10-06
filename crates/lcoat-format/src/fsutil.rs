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

/// `mkdir -p` with mode 0700 on every created directory.
pub fn mkdir_private(path: &Path) -> io::Result<()> {
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
/// A file that does not end in a newline holds a record an interrupted
/// append left half-written; appending would glue the new record onto it
/// and lose both, so this refuses ([`torn_tail_error`]) and writes nothing.
pub fn append_locked(path: &Path, line: &[u8]) -> io::Result<()> {
    let mut f = open_private(
        path,
        OpenOptions::new().read(true).append(true).create(true),
    )?;
    let locked = f.lock().is_ok();
    let written = match torn_tail(&f) {
        Ok(Some(n)) => Err(torn_tail_error(path, n)),
        Ok(None) => f.write_all(line).and_then(|()| f.sync_data()),
        Err(e) => Err(e),
    };
    if locked {
        let _ = f.unlock();
    }
    written
}

/// How many bytes follow the last newline of `f`: the length of a record an
/// interrupted append left half-written. `None` for an empty file or one
/// that ends in a newline. Reads backwards from the end, so it costs one
/// small read for any well-formed file.
pub fn torn_tail(f: &File) -> io::Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut r = f.try_clone()?;
    let len = r.metadata()?.len();
    let mut end = len;
    let mut buf = [0u8; 4096];
    while end > 0 {
        let start = end.saturating_sub(buf.len() as u64);
        let n = usize::try_from(end - start).unwrap_or(buf.len());
        r.seek(SeekFrom::Start(start))?;
        r.read_exact(&mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|&b| b == b'\n') {
            let tail = len - (start + i as u64 + 1);
            return Ok((tail > 0).then_some(tail));
        }
        end = start;
    }
    Ok((len > 0).then_some(len))
}

/// The refusal for a write onto a torn tail; names the repair command.
pub fn torn_tail_error(path: &Path, bytes: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} ends in a partial record ({bytes} bytes after the last newline), left by an interrupted write; nothing was appended. `lcoat op repair-tail` sets the fragment aside and records the repair in the ledger",
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

    /// Review 2026-10-05: after a partial append, the next record was glued
    /// onto the fragment and both were lost.
    #[test]
    fn append_refuses_a_torn_tail_and_writes_nothing() {
        let d = tmpdir("torn");
        let p = d.join("index.ndjson");
        fs::write(&p, b"{\"a\":1}\n{\"b\":").unwrap();
        let e = append_locked(&p, b"{\"c\":3}\n").unwrap_err();
        assert!(
            e.to_string().contains("ends in a partial record (5 bytes"),
            "{e}"
        );
        assert!(e.to_string().contains("lcoat op repair-tail"), "{e}");
        assert_eq!(fs::read(&p).unwrap(), b"{\"a\":1}\n{\"b\":");
    }

    #[test]
    fn torn_tail_measures_what_follows_the_last_newline() {
        let d = tmpdir("tail");
        let p = d.join("f");
        let tail = |bytes: &[u8]| {
            fs::write(&p, bytes).unwrap();
            torn_tail(&File::open(&p).unwrap()).unwrap()
        };
        assert_eq!(tail(b""), None);
        assert_eq!(tail(b"x\n"), None);
        assert_eq!(tail(b"x\nyz"), Some(2));
        assert_eq!(tail(b"no newline at all"), Some(17));
        // Longer than one backward read.
        let mut big = vec![b'a'; 10_000];
        big.push(b'\n');
        big.extend_from_slice(&[b'b'; 5000]);
        assert_eq!(tail(&big), Some(5000));
        let mut whole = vec![b'a'; 9000];
        whole.push(b'\n');
        assert_eq!(tail(&whole), None);
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
