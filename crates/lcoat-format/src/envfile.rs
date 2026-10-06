//! Shell-sourced `KEY=value` records: targets, operations, scope snapshots
//! and profiles.
//!
//! The shell build writes these with `printf %q`, so a value can appear as a
//! bare word with backslash escapes, in single quotes, in double quotes, or
//! as a `$'...'` ANSI-C string. [`Record::to_bytes`] reproduces `printf %q`
//! byte for byte, so either implementation can read the other's files, and
//! [`parse`] accepts every form the shell build (or an operator with an
//! editor) produces.
//!
//! Order matters: the shell build's `upsert_env` removes a key and
//! re-appends it at the end, and [`Record::upsert`] does the same.

use std::fmt;
use std::io;
use std::path::Path;

/// An ordered set of key/value pairs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    entries: Vec<(String, String)>,
}

impl Record {
    /// Empty record.
    pub fn new() -> Self {
        Self::default()
    }

    /// The value for `key`, or `""` when absent (the shell's unset-variable
    /// behaviour, which every reader in the shell build relies on).
    pub fn get(&self, key: &str) -> &str {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    }

    /// Whether `key` is present.
    pub fn has(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Keys in file order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    /// Remove any existing line for `key` and append the new value.
    pub fn upsert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        self.entries.retain(|(k, _)| *k != key);
        self.entries.push((key, value.into()));
    }

    /// Render as the shell build writes it: one `KEY=<%q value>` per line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.entries {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(quote(v).as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Read a record from disk.
    pub fn load(path: &Path) -> Result<Self, EnvError> {
        let data = std::fs::read(path).map_err(EnvError::Io)?;
        parse(&data)
    }

    /// Write the record to `path` with mode 0600, replacing it.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        write_private(path, &self.to_bytes())
    }
}

/// Write bytes to `path` atomically with mode 0600 (see [`crate::fsutil`]).
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    crate::fsutil::write_private(path, data)
}

/// Load `path` (or start empty when it does not exist), upsert, write back.
pub fn upsert_file(path: &Path, key: &str, value: &str) -> Result<(), EnvError> {
    upsert_many_file(path, &[(key, value)])
}

/// [`upsert_file`] for several keys in one atomic write, so a reader (or a
/// crash) never sees some of them changed and the rest not (review
/// 2026-10-05: `op close` wrote `STATUS` and `CLOSED_AT` as two writes).
pub fn upsert_many_file(path: &Path, pairs: &[(&str, &str)]) -> Result<(), EnvError> {
    let mut rec = match Record::load(path) {
        Ok(r) => r,
        Err(EnvError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Record::new(),
        Err(e) => return Err(e),
    };
    for &(k, v) in pairs {
        rec.upsert(k, v);
    }
    rec.save(path).map_err(EnvError::Io)
}

/// Errors from reading env records.
#[derive(Debug)]
pub enum EnvError {
    /// Filesystem error.
    Io(io::Error),
    /// A line that is not `KEY=value` in the accepted syntax.
    Syntax {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        message: String,
    },
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvError::Io(e) => write!(f, "{e}"),
            EnvError::Syntax { line, message } => write!(f, "env line {line}: {message}"),
        }
    }
}

impl std::error::Error for EnvError {}

impl EnvError {
    /// Whether this is a not-found error (the file is absent).
    pub fn is_not_found(&self) -> bool {
        matches!(self, EnvError::Io(e) if e.kind() == io::ErrorKind::NotFound)
    }
}

/// Parse an env file. Blank lines and `#` comments are skipped; a later
/// line for the same key replaces the earlier one and moves it to the end.
pub fn parse(data: &[u8]) -> Result<Record, EnvError> {
    let mut rec = Record::new();
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        let line_no = i + 1;
        let syntax = |message: String| EnvError::Syntax {
            line: line_no,
            message,
        };
        let line = strip_suffix(raw, b'\r');
        let trimmed = strip_leading_ws(line);
        if trimmed.iter().all(|b| b.is_ascii_whitespace()) || trimmed.starts_with(b"#") {
            continue;
        }
        let eq = trimmed
            .iter()
            .position(|&b| b == b'=')
            .filter(|&i| i > 0)
            .ok_or_else(|| syntax("expected KEY=value".into()))?;
        let key = &trimmed[..eq];
        if !valid_key(key) {
            return Err(syntax(format!(
                "invalid key {:?}",
                String::from_utf8_lossy(key)
            )));
        }
        let value = unquote(&trimmed[eq + 1..]).map_err(|m| syntax(m.to_owned()))?;
        let value =
            String::from_utf8(value).map_err(|_| syntax("value is not valid UTF-8".into()))?;
        rec.upsert(String::from_utf8_lossy(key).into_owned(), value);
    }
    Ok(rec)
}

fn strip_suffix(s: &[u8], b: u8) -> &[u8] {
    s.strip_suffix(&[b]).unwrap_or(s)
}

fn strip_leading_ws(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    &s[n..]
}

fn valid_key(key: &[u8]) -> bool {
    !key.is_empty()
        && key
            .iter()
            .enumerate()
            .all(|(i, &c)| c == b'_' || c.is_ascii_alphabetic() || (c.is_ascii_digit() && i > 0))
}

/// Decode the value part of a line: concatenated bare words, `'...'`,
/// `"..."` and `$'...'` segments, stopping at trailing whitespace or a
/// comment.
fn unquote(s: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        match c {
            b'\'' => {
                let end = s[i + 1..]
                    .iter()
                    .position(|&b| b == b'\'')
                    .ok_or("unterminated single quote")?;
                out.extend_from_slice(&s[i + 1..i + 1 + end]);
                i += end + 2;
            }
            b'$' if s.get(i + 1) == Some(&b'\'') => {
                let (decoded, used) = unquote_ansi(&s[i + 2..])?;
                out.extend_from_slice(&decoded);
                i += 2 + used;
            }
            b'"' => {
                i += 1;
                loop {
                    let &b = s.get(i).ok_or("unterminated double quote")?;
                    if b == b'"' {
                        i += 1;
                        break;
                    }
                    if b == b'\\'
                        && let Some(&next) = s.get(i + 1)
                        && matches!(next, b'"' | b'\\' | b'$' | b'`' | b'\n')
                    {
                        out.push(next);
                        i += 2;
                        continue;
                    }
                    out.push(b);
                    i += 1;
                }
            }
            b'\\' => {
                let &next = s.get(i + 1).ok_or("dangling backslash")?;
                out.push(next);
                i += 2;
            }
            b' ' | b'\t' => {
                // Trailing whitespace, or a comment after the value.
                let rest = String::from_utf8_lossy(&s[i..]);
                let trimmed = rest.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    return Err("unexpected text after value");
                }
                return Ok(out);
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Decode the body of a `$'...'` string; returns the bytes and the number
/// of input bytes consumed including the closing quote.
fn unquote_ansi(s: &[u8]) -> Result<(Vec<u8>, usize), &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c == b'\'' {
            return Ok((out, i + 1));
        }
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let &e = s.get(i + 1).ok_or("dangling backslash in $'' string")?;
        match e {
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'e' | b'E' => out.push(27),
            b'f' => out.push(12),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(11),
            b'\\' | b'\'' | b'"' | b'?' => out.push(e),
            b'0'..=b'7' => {
                let mut j = i + 1;
                let mut val: u32 = 0;
                let mut k = 0;
                while k < 3 && j < s.len() && (b'0'..=b'7').contains(&s[j]) {
                    val = val * 8 + u32::from(s[j] - b'0');
                    j += 1;
                    k += 1;
                }
                out.push((val & 0xff) as u8);
                i = j;
                continue;
            }
            b'x' => {
                let mut j = i + 2;
                let mut val: u32 = 0;
                let mut digits = 0;
                while digits < 2 && j < s.len() && (s[j] as char).is_ascii_hexdigit() {
                    val = val * 16 + (s[j] as char).to_digit(16).unwrap_or(0);
                    j += 1;
                    digits += 1;
                }
                if digits == 0 {
                    out.extend_from_slice(b"\\x");
                    i += 2;
                    continue;
                }
                out.push(val as u8);
                i = j;
                continue;
            }
            _ => {
                out.push(b'\\');
                out.push(e);
            }
        }
        i += 2;
    }
    Err("unterminated $'' string")
}

/// Reproduce bash's `printf %q` for `s`.
pub fn quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_owned();
    }
    let bytes = s.as_bytes();
    if bytes.iter().any(|c| !(0x20..0x7f).contains(c)) {
        return quote_ansi(bytes);
    }
    let mut out = String::with_capacity(bytes.len() + 8);
    for (i, &c) in bytes.iter().enumerate() {
        let escape = match c {
            b' ' | b'\t' | b'\'' | b'"' | b',' | b'!' | b'$' | b'`' | b'\\' | b'|' | b'&'
            | b';' | b'(' | b')' | b'<' | b'>' | b'{' | b'}' | b'[' | b']' | b'*' | b'?' | b'^' => {
                true
            }
            b'~' | b'#' => i == 0,
            _ => false,
        };
        if escape {
            out.push('\\');
        }
        out.push(c as char);
    }
    out
}

fn quote_ansi(bytes: &[u8]) -> String {
    let mut out = String::from("$'");
    for &c in bytes {
        match c {
            7 => out.push_str("\\a"),
            8 => out.push_str("\\b"),
            27 => out.push_str("\\E"),
            12 => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            11 => out.push_str("\\v"),
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            c if !(0x20..0x7f).contains(&c) => out.push_str(&format!("\\{c:03o}")),
            c => out.push(c as char),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: &str) {
        let q = quote(v);
        let rec =
            parse(format!("K={q}\n").as_bytes()).unwrap_or_else(|e| panic!("{v:?} -> {q}: {e}"));
        assert_eq!(rec.get("K"), v, "quoted as {q}");
    }

    #[test]
    fn upsert_many_writes_every_key_in_one_replace() {
        let dir = std::env::temp_dir().join(format!("lcoat-env-many-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::fsutil::mkdir_private(&dir).unwrap();
        let p = dir.join("session.env");
        std::fs::write(&p, b"NAME=x\nSTATUS=active\nCLOSED_AT=''\n").unwrap();
        let ino = |p: &Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).unwrap().ino()
        };
        let before = ino(&p);
        upsert_many_file(
            &p,
            &[("STATUS", "closed"), ("CLOSED_AT", "2026-10-02T07:40:00Z")],
        )
        .unwrap();
        // One atomic replace: a new inode with both keys, nothing else left.
        assert_ne!(ino(&p), before);
        let rec = Record::load(&p).unwrap();
        assert_eq!(rec.get("NAME"), "x");
        assert_eq!(rec.get("STATUS"), "closed");
        assert_eq!(rec.get("CLOSED_AT"), "2026-10-02T07:40:00Z");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quote_matches_printf_q() {
        assert_eq!(quote(""), "''");
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("prototype learning"), "prototype\\ learning");
        assert_eq!(quote("a,b!c$d"), "a\\,b\\!c\\$d");
        assert_eq!(quote("#lead"), "\\#lead");
        assert_eq!(quote("mid#hash"), "mid#hash");
        assert_eq!(quote("~home"), "\\~home");
        assert_eq!(quote("tab\there"), "$'tab\\there'");
        assert_eq!(quote("é"), "$'\\303\\251'");
        assert_eq!(quote("it's"), "it\\'s");
    }

    #[test]
    fn values_round_trip() {
        for v in [
            "",
            "plain",
            "two words",
            "quote ' inside",
            "double \" inside",
            "back\\slash",
            "tab\tnl\n",
            "unicode é 日",
            "$dollar `tick` ;semi |pipe &amp",
            "a=b=c",
            "#comment-looking",
            "~tilde",
            "trailing space ",
            " leading space",
            "ctrl\u{1}\u{1f}",
        ] {
            roundtrip(v);
        }
    }

    #[test]
    fn parses_hand_written_forms() {
        let rec = parse(
            b"# comment\n\nNAME='single quoted'\nADDR=\"double \\\"quoted\\\"\"\nBARE=plain\\ word   # trailing comment\nANSI=$'a\\tb\\x41\\101'\nCRLF=x\r\n",
        )
        .unwrap();
        assert_eq!(rec.get("NAME"), "single quoted");
        assert_eq!(rec.get("ADDR"), "double \"quoted\"");
        assert_eq!(rec.get("BARE"), "plain word");
        assert_eq!(rec.get("ANSI"), "a\tbAA");
        assert_eq!(rec.get("CRLF"), "x");
        assert_eq!(rec.get("MISSING"), "");
    }

    #[test]
    fn upsert_moves_key_to_end() {
        let mut r = Record::new();
        r.upsert("A", "1");
        r.upsert("B", "2");
        r.upsert("A", "3");
        assert_eq!(r.keys().collect::<Vec<_>>(), ["B", "A"]);
        assert_eq!(r.to_bytes(), b"B=2\nA=3\n");
    }

    #[test]
    fn rejects_bad_lines() {
        for bad in [
            "=novalue\n",
            "1BAD=x\n",
            "KEY='unterminated\n",
            "KEY=a b\n",
            "KEY=\\\n",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }
}
