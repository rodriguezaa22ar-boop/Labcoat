//! Newline-delimited JSON files: ledgers and the evidence, finding and
//! validation indexes.
//!
//! Reading tolerates a missing file (the shell build's `[ -s file ]`
//! check), skips blank lines, and rejects anything that is not strict JSON.
//! Writing appends one compact, insertion-ordered object per line, which is
//! what the shell build's `jq -cn` produces.

use std::io;
use std::path::Path;

use crate::canonical::compact;
use crate::json::{Object, Value};

/// Errors from reading an NDJSON file.
#[derive(Debug)]
pub enum NdjsonError {
    /// Filesystem error (a missing file is not an error; see [`read_file`]).
    Io(io::Error),
    /// A line that is not a JSON object.
    Line {
        /// The file.
        path: String,
        /// 1-based line number.
        line: usize,
        /// Parser message.
        message: String,
    },
}

impl std::fmt::Display for NdjsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NdjsonError::Io(e) => write!(f, "{e}"),
            NdjsonError::Line {
                path,
                line,
                message,
            } => write!(f, "{path}: line {line}: {message}"),
        }
    }
}

impl std::error::Error for NdjsonError {}

/// Parse every non-blank line of `path` as a JSON object. A missing file
/// yields an empty vector.
pub fn read_file(path: &Path) -> Result<Vec<Object>, NdjsonError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(NdjsonError::Io(e)),
    };
    parse_lines(&text, &path.display().to_string())
}

/// Parse NDJSON text; `label` names the source in errors.
pub fn parse_lines(text: &str, label: &str) -> Result<Vec<Object>, NdjsonError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let err = |message: String| NdjsonError::Line {
            path: label.to_owned(),
            line: i + 1,
            message,
        };
        match Value::parse(line) {
            Ok(Value::Object(o)) => out.push(o),
            Ok(_) => return Err(err("not a JSON object".into())),
            Err(e) => return Err(err(e.to_string())),
        }
    }
    Ok(out)
}

/// The newest record per `id`, in first-seen order: the shell build's
/// `reduce .[] as $r ({}; .[$r.id] = $r)`.
pub fn latest(records: &[Object]) -> Vec<Object> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: Vec<(String, Object)> = Vec::new();
    for r in records {
        let id = r.str("id").to_owned();
        if let Some(slot) = by_id.iter_mut().find(|(k, _)| *k == id) {
            slot.1 = r.clone();
        } else {
            order.push(id.clone());
            by_id.push((id, r.clone()));
        }
    }
    by_id.into_iter().map(|(_, o)| o).collect()
}

/// Append one compact object plus newline to `path`, creating it 0600,
/// under an exclusive lock (see [`crate::fsutil::append_locked`]).
pub fn append(path: &Path, obj: &Object) -> io::Result<()> {
    let mut line = compact(&Value::Object(obj.clone()));
    line.push(b'\n');
    crate::fsutil::append_locked(path, &line)
}

impl Object {
    /// The string at `key`, or `""` when absent or not a string.
    pub fn str(&self, key: &str) -> &str {
        match self.get(key) {
            Some(Value::String(s)) => s,
            _ => "",
        }
    }

    /// The boolean at `key`, or `false`.
    pub fn bool(&self, key: &str) -> bool {
        matches!(self.get(key), Some(Value::Bool(true)))
    }

    /// The string elements of the array at `key` (non-strings skipped).
    pub fn strs(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Length of the array at `key`, or 0.
    pub fn arr_len(&self, key: &str) -> usize {
        match self.get(key) {
            Some(Value::Array(items)) => items.len(),
            _ => 0,
        }
    }

    /// Whether `key` holds a non-empty string.
    pub fn nonempty(&self, key: &str) -> bool {
        !self.str(key).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_keeps_first_position_and_last_value() {
        let recs = parse_lines(
            r#"{"id":"a","v":1}
{"id":"b","v":1}
{"id":"a","v":2}"#,
            "t",
        )
        .unwrap();
        let l = latest(&recs);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].str("id"), "a");
        assert_eq!(l[0].get("v"), Some(&Value::Number("2".into())));
        assert_eq!(l[1].str("id"), "b");
    }

    #[test]
    fn missing_file_is_empty_and_bad_line_is_an_error() {
        assert!(
            read_file(Path::new("/nonexistent/x.ndjson"))
                .unwrap()
                .is_empty()
        );
        assert!(parse_lines("{\"a\":1}\n[1]\n", "t").is_err());
        assert!(
            parse_lines("{\"a\":1}\n\n  \n{\"b\":2}\n", "t")
                .unwrap()
                .len()
                == 2
        );
    }

    #[test]
    fn accessors() {
        let o = match Value::parse(r#"{"s":"x","b":true,"a":["p",1,"q"]}"#).unwrap() {
            Value::Object(o) => o,
            _ => unreachable!(),
        };
        assert_eq!(o.str("s"), "x");
        assert_eq!(o.str("missing"), "");
        assert!(o.bool("b"));
        assert_eq!(o.strs("a"), ["p", "q"]);
        assert_eq!(o.arr_len("a"), 3);
    }
}
