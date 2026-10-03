//! `ledger.ndjson`: the append-only record of what an operation did.
//!
//! This module is the only code that opens a ledger for writing, and it
//! opens it append-only under an exclusive advisory lock. There is no
//! rewrite, truncate or reorder path, in the API or on disk. Reading is
//! tolerant of the format 1.1 additions (`prev_hash`, `event_hash`, future
//! fields): an [`Event`] carries the eight v1 fields the shell build
//! defined, and [`read_objects`] hands back the raw objects for the chain
//! verifier in [`crate::chain`].

use std::io::Write;
use std::path::{Path, PathBuf};

use lcoat_format::canonical::{canonical_line, compact};
use lcoat_format::clock;
use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::error::{Error, Result};
use crate::fail;
use crate::root::mkdir_private;

/// The ledger file name inside an operation directory.
pub const FILE_NAME: &str = "ledger.ndjson";

/// The ledger path for an operation directory.
pub fn file(op_dir: &Path) -> PathBuf {
    op_dir.join(FILE_NAME)
}

/// One operation ledger entry, in the shell build's field order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    /// `YYYY-MM-DDTHH:MM:SSZ`.
    pub ts: String,
    /// Event name (`op.started`, `scope.preflight`, `adapter.completed`, ...).
    pub event: String,
    /// Operation slug.
    pub op: String,
    /// Operation target.
    pub target: String,
    /// Capability name (`read-only`, `active-recon`, ...).
    pub capability: String,
    /// Tool that produced the event.
    pub tool: String,
    /// `ok`, `allowed`, `denied`, `failed`, ...
    pub status: String,
    /// Free-text metadata (never raw output).
    pub detail: String,
    /// 1-based line number, set when read back; 0 for a new event.
    pub line: usize,
}

impl Event {
    /// Decode an event from a ledger object. Unknown fields are ignored.
    pub fn from_object(o: &Object, line: usize) -> Self {
        Self {
            ts: o.str("ts").to_owned(),
            event: o.str("event").to_owned(),
            op: o.str("op").to_owned(),
            target: o.str("target").to_owned(),
            capability: o.str("capability").to_owned(),
            tool: o.str("tool").to_owned(),
            status: o.str("status").to_owned(),
            detail: o.str("detail").to_owned(),
            line,
        }
    }

    /// Encode in the shell build's field order (`jq -cn` argument order).
    pub fn to_object(&self) -> Object {
        let mut o = Object::new();
        o.insert("ts", Value::String(self.ts.clone()));
        o.insert("event", Value::String(self.event.clone()));
        o.insert("op", Value::String(self.op.clone()));
        o.insert("target", Value::String(self.target.clone()));
        o.insert("capability", Value::String(self.capability.clone()));
        o.insert("tool", Value::String(self.tool.clone()));
        o.insert("status", Value::String(self.status.clone()));
        o.insert("detail", Value::String(self.detail.clone()));
        o
    }

    /// The timeline row the shell build prints.
    pub fn describe(&self) -> String {
        let detail = self.detail.replace(['\t', '\n'], " ");
        format!(
            "{:<20} {:<28} {:<12} {:<16} {:<10} {}",
            self.ts, self.event, self.status, self.capability, self.tool, detail
        )
    }
}

/// Every event of an operation with its line number. A missing or empty
/// ledger is an empty vector.
pub fn read(op_dir: &Path) -> Result<Vec<Event>> {
    read_path(&file(op_dir))
}

/// [`read`] for an explicit ledger path.
pub fn read_path(path: &Path) -> Result<Vec<Event>> {
    let recs = ndjson::read_file(path)?;
    Ok(recs
        .iter()
        .enumerate()
        .map(|(i, r)| Event::from_object(r, i + 1))
        .collect())
}

/// The raw ledger objects, every field kept, for chain verification.
pub fn read_objects(path: &Path) -> Result<Vec<Object>> {
    Ok(ndjson::read_file(path)?)
}

/// Number of events, like `jq -s length`.
pub fn count(path: &Path) -> Result<usize> {
    Ok(ndjson::read_file(path)?.len())
}

/// Hash of the first `n` lines, like `head -n N | sha256sum`. Each line is
/// hashed with a trailing newline.
pub fn prefix_sha256(path: &Path, n: usize) -> Result<Sha256Hex> {
    let bytes = std::fs::read(path)?;
    let mut h = lcoat_format::sha256::Sha256::new();
    for line in lines_of(&bytes).take(n) {
        h.update(line);
        h.update(b"\n");
    }
    Ok(Sha256Hex::of_bytes_digest(h.finalize()))
}

/// Split on `\n` like `bufio.ScanLines`: a trailing newline does not make
/// an extra empty line; a trailing `\r` is dropped.
fn lines_of(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let empty = bytes.is_empty();
    body.split(|b| *b == b'\n')
        .filter(move |_| !empty)
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
}

/// The last event whose name is one of `names`.
pub fn latest<'a>(events: &'a [Event], names: &[&str]) -> Option<&'a Event> {
    events
        .iter()
        .rev()
        .find(|e| names.contains(&e.event.as_str()))
}

/// The last event whose name is not one of `names`.
pub fn latest_except<'a>(events: &'a [Event], names: &[&str]) -> Option<&'a Event> {
    events
        .iter()
        .rev()
        .find(|e| !names.contains(&e.event.as_str()))
}

/// Events grouped by name with counts, in name order: the audit packet's
/// "Event Counts" block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Event name.
    pub event: String,
    /// Occurrences.
    pub count: usize,
}

/// Tally events by name, sorted by name.
pub fn count_by_event(events: &[Event]) -> Vec<Summary> {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for e in events {
        *counts.entry(e.event.as_str()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(event, count)| Summary {
            event: event.to_owned(),
            count,
        })
        .collect()
}

// --- verification --------------------------------------------------------

/// The shell build's `atlas.ledger_verify.v1` result for an operation ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    /// Number of events (lines).
    pub event_count: usize,
    /// `sha256(canonical(last event) + "\n")`.
    pub head_event_hash: Sha256Hex,
}

// The shell build's atlas_ledger_verify_operation_json checks a smaller set
// than the receipt scanner, and it is kept separate so the two ledgers
// (operation, receipt) keep their own verdicts.
const LEDGER_BAD_KEYS: &[&str] = &[
    "raw_evidence",
    "evidence_body",
    "request_body",
    "response_body",
    "secret",
    "token",
    "private_key",
];

// (?i)password=|passwd=|api_key=|secret=|token=|authorization:|bearer[[:space:]]|set-cookie:|BEGIN RSA|BEGIN OPENSSH|session=|cookie=
const LEDGER_BAD_VALUES: &[&str] = &[
    "password=",
    "passwd=",
    "api_key=",
    "secret=",
    "token=",
    "authorization:",
    "set-cookie:",
    "begin rsa",
    "begin openssh",
    "session=",
    "cookie=",
];

/// Whether a string carries one of the ledger's forbidden markers.
pub fn ledger_value_is_forbidden(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    if LEDGER_BAD_VALUES.iter().any(|m| v.contains(m)) {
        return true;
    }
    // bearer[[:space:]]
    let b = v.as_bytes();
    v.match_indices("bearer").any(|(i, _)| {
        matches!(
            b.get(i + 6),
            Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
        )
    })
}

fn contains_forbidden(v: &Value) -> bool {
    match v {
        Value::Object(o) => o
            .iter()
            .any(|(k, child)| LEDGER_BAD_KEYS.contains(&k) || contains_forbidden(child)),
        Value::Array(items) => items.iter().any(contains_forbidden),
        Value::String(s) => ledger_value_is_forbidden(s),
        _ => false,
    }
}

fn valid_operation_event(o: &Object) -> bool {
    for k in [
        "ts",
        "event",
        "op",
        "target",
        "capability",
        "tool",
        "status",
    ] {
        if !o.nonempty(k) {
            return false;
        }
    }
    if !matches!(o.get("detail"), Some(Value::String(_))) {
        return false;
    }
    !contains_forbidden(&Value::Object(o.clone()))
}

/// The checks of the shell build's `atlas_ledger_verify_operation_json`:
/// every line is a JSON object with the seven required non-empty string
/// fields and a string `detail`, no forbidden keys, no forbidden markers in
/// any string value. Returns the event count and the head event hash.
pub fn verify_operation_ledger(path: &Path) -> Result<VerifyResult> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fail!("missing ledger: {}", path.display())
        }
        Err(e) => return Err(Error::Io(e)),
    };
    let mut line_no = 0;
    let mut head: Option<Sha256Hex> = None;
    for raw in lines_of(&bytes) {
        line_no += 1;
        let Ok(text) = std::str::from_utf8(raw) else {
            fail!("operation ledger event {line_no} invalid JSON");
        };
        if text.trim().is_empty() {
            fail!("operation ledger event {line_no} is empty");
        }
        let rec = match Value::parse(text) {
            Ok(Value::Object(o)) => o,
            _ => fail!("operation ledger event {line_no} invalid JSON"),
        };
        if !valid_operation_event(&rec) {
            fail!("operation ledger event {line_no} invalid fields");
        }
        head = Some(Sha256Hex::of_bytes(&canonical_line(&Value::Object(rec))));
    }
    match head {
        None => fail!("ledger is empty: {}", path.display()),
        Some(head_event_hash) => Ok(VerifyResult {
            event_count: line_no,
            head_event_hash,
        }),
    }
}

// --- the append-only handle ----------------------------------------------

/// An operation ledger opened for appending. The type offers `append` and
/// `events`; nothing on it can modify an existing line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    /// Address the ledger of an operation directory. Touches nothing.
    pub fn of(op_dir: &Path) -> Self {
        Self { path: file(op_dir) }
    }

    /// The ledger file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Every event with line numbers.
    pub fn events(&self) -> Result<Vec<Event>> {
        read_path(&self.path)
    }

    /// Append one event. An empty `ts` is filled with the current (possibly
    /// frozen) clock. The operation directory is created 0700 if missing,
    /// the file 0600, and the write happens under an exclusive lock.
    pub fn append(&self, mut event: Event) -> Result<()> {
        if event.ts.is_empty() {
            event.ts = clock::timestamp();
        }
        if let Some(dir) = self.path.parent() {
            mkdir_private(dir)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        let locked = f.lock().is_ok();
        let mut line = compact(&Value::Object(event.to_object()));
        line.push(b'\n');
        let written = f.write_all(&line).and_then(|()| f.flush());
        if locked {
            let _ = f.unlock();
        }
        written?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lcoat-ledger-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn append_then_read_round_trips_in_field_order() {
        let dir = tmp("rt");
        let l = Ledger::of(&dir);
        l.append(Event {
            ts: "2026-10-02T07:40:00Z".into(),
            event: "op.started".into(),
            op: "x".into(),
            target: "t".into(),
            capability: "read-only".into(),
            tool: "atlas".into(),
            status: "ok".into(),
            detail: "profile=default notes=".into(),
            line: 0,
        })
        .unwrap();
        let text = std::fs::read_to_string(l.path()).unwrap();
        assert_eq!(
            text,
            "{\"ts\":\"2026-10-02T07:40:00Z\",\"event\":\"op.started\",\"op\":\"x\",\"target\":\"t\",\"capability\":\"read-only\",\"tool\":\"atlas\",\"status\":\"ok\",\"detail\":\"profile=default notes=\"}\n"
        );
        let events = l.events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].line, 1);
        assert_eq!(events[0].event, "op.started");
        let v = verify_operation_ledger(l.path()).unwrap();
        assert_eq!(v.event_count, 1);
        // sha256 of the jq -cS form plus newline.
        assert_eq!(v.head_event_hash.as_str().len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_rejects_bad_lines() {
        let dir = tmp("bad");
        std::fs::create_dir_all(&dir).unwrap();
        let p = file(&dir);
        let good = "{\"ts\":\"t\",\"event\":\"e\",\"op\":\"o\",\"target\":\"x\",\"capability\":\"c\",\"tool\":\"a\",\"status\":\"ok\",\"detail\":\"d\"}\n";
        for (body, msg) in [
            ("", "ledger is empty"),
            ("\n", "event 1 is empty"),
            (&format!("{good}not json\n"), "event 2 invalid JSON"),
            (
                &format!("{good}{{\"ts\":\"t\"}}\n"),
                "event 2 invalid fields",
            ),
            (
                &format!(
                    "{good}{}",
                    good.replace("\"detail\":\"d\"", "\"detail\":\"password=hunter2\"")
                ),
                "event 2 invalid fields",
            ),
            (
                &format!(
                    "{good}{}",
                    good.replace("\"detail\":\"d\"", "\"detail\":\"d\",\"token\":\"x\"")
                ),
                "event 2 invalid fields",
            ),
            (
                &format!("{good}{}", good.replace("\"detail\":\"d\"", "\"detail\":1")),
                "event 2 invalid fields",
            ),
        ] {
            std::fs::write(&p, body).unwrap();
            let err = verify_operation_ledger(&p).unwrap_err().to_string();
            assert!(err.contains(msg), "{body:?} -> {err}");
        }
        std::fs::write(&p, format!("{good}{good}")).unwrap();
        assert_eq!(verify_operation_ledger(&p).unwrap().event_count, 2);
        assert!(
            verify_operation_ledger(&dir.join("nope.ndjson"))
                .unwrap_err()
                .to_string()
                .contains("missing ledger")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ledger_markers() {
        assert!(ledger_value_is_forbidden("Authorization: Bearer abc"));
        assert!(ledger_value_is_forbidden("x bearer\ty"));
        assert!(!ledger_value_is_forbidden("bearers"));
        assert!(ledger_value_is_forbidden("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!ledger_value_is_forbidden("tokens issued: 3"));
        assert!(ledger_value_is_forbidden("session=abc"));
    }

    #[test]
    fn latest_and_counts() {
        let ev = |name: &str| Event {
            event: name.into(),
            ..Default::default()
        };
        let events = vec![
            ev("op.started"),
            ev("scope.preflight"),
            ev("adapter.completed"),
            ev("scope.preflight"),
        ];
        assert_eq!(
            latest(&events, &["scope.preflight"]).map(|e| e.event.as_str()),
            Some("scope.preflight")
        );
        assert_eq!(
            latest_except(&events, &["scope.preflight"]).map(|e| e.event.as_str()),
            Some("adapter.completed")
        );
        assert!(latest(&events, &["nope"]).is_none());
        let c = count_by_event(&events);
        assert_eq!(c.len(), 3);
        assert_eq!(
            c[0],
            Summary {
                event: "adapter.completed".into(),
                count: 1
            }
        );
        assert_eq!(
            c[2],
            Summary {
                event: "scope.preflight".into(),
                count: 2
            }
        );
    }

    #[test]
    fn prefix_hash_matches_head_sha256sum() {
        let dir = tmp("prefix");
        std::fs::create_dir_all(&dir).unwrap();
        let p = file(&dir);
        std::fs::write(&p, "a\nb\nc\n").unwrap();
        // Values from `printf 'a\nb\n' | sha256sum` and friends.
        assert_eq!(
            prefix_sha256(&p, 2).unwrap().as_str(),
            "911169ddaaf146aff539f58c26c489af3b892dff0fe283c1c264c65ae5aa59a2"
        );
        assert_eq!(
            prefix_sha256(&p, 10).unwrap().as_str(),
            "880553fca8fcea94e325ee2cfb48e5a985cc797f39a14cc6d3cedecfeb2ae4d2"
        );
        // A file without a trailing newline hashes the same (bufio.ScanLines).
        std::fs::write(&p, "a\nb\nc").unwrap();
        assert_eq!(
            prefix_sha256(&p, 3).unwrap().as_str(),
            "880553fca8fcea94e325ee2cfb48e5a985cc797f39a14cc6d3cedecfeb2ae4d2"
        );
        assert_eq!(
            prefix_sha256(&p, 0).unwrap().as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_is_the_timeline_row() {
        let e = Event {
            ts: "2026-10-02T07:40:00Z".into(),
            event: "op.started".into(),
            status: "ok".into(),
            capability: "read-only".into(),
            tool: "atlas".into(),
            detail: "a\tb\nc".into(),
            ..Default::default()
        };
        assert_eq!(
            e.describe(),
            "2026-10-02T07:40:00Z op.started                   ok           read-only        atlas      a b c"
        );
    }
}
