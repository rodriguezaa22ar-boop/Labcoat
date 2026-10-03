//! A strict JSON value and parser (RFC 8259), standard library only.
//!
//! Two properties matter for byte-compatibility and are why this is not a
//! general-purpose library:
//!
//! - **Numbers keep their literal.** `1.0`, `1e3` and `10` are stored as the
//!   text that appeared, exactly as `jq` and Go's `json.Number` do, so the
//!   canonical form never reformats a number and hashes stay stable.
//! - **Objects keep insertion order.** NDJSON lines written by the shell
//!   build have a fixed field order that Lite reproduces; the canonical
//!   writer sorts keys at output time instead. A repeated key keeps its first
//!   position and takes the last value, matching `jq`.
//!
//! The parser rejects anything RFC 8259 rejects (trailing commas, comments,
//! single quotes, bare control characters in strings, leading zeros, lone
//! surrogates). Tool output never reaches it; only files Lab Coat or its
//! siblings wrote do.

use std::fmt;

/// A parsed JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// A number, kept as its source literal.
    Number(String),
    /// A string (unescaped).
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object in insertion order.
    Object(Object),
}

/// An insertion-ordered object.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    /// Empty object.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace `key`. A replaced key keeps its original position.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }

    /// Remove `key`, returning its value if present.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let i = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(i).1)
    }

    /// Look up `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the object has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Value {
    /// Parse one complete JSON text. Leading and trailing whitespace is
    /// allowed; anything else after the value is an error.
    pub fn parse(text: &str) -> Result<Value, ParseError> {
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
        };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.i != p.s.len() {
            return Err(p.err("trailing characters after value"));
        }
        Ok(v)
    }

    /// The string if this is a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The object if this is an object.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

/// A parse failure with a byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the input.
    pub offset: usize,
    /// What went wrong.
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

const MAX_DEPTH: usize = 256;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.i,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, lit: &[u8], v: Value) -> Result<Value, ParseError> {
        if self.s[self.i..].starts_with(lit) {
            self.i += lit.len();
            Ok(v)
        } else {
            Err(self.err("invalid literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') => self.expect(b"null", Value::Null),
            Some(b't') => self.expect(b"true", Value::Bool(true)),
            Some(b'f') => self.expect(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1; // [
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1; // {
        let mut obj = Object::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(obj));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected string key"));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            obj.insert(key, v);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(obj));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.err("leading zero"));
                }
            }
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.err("expected digit")),
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit after '.'"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.err("expected digit in exponent"));
            }
            self.digits();
        }
        // The slice is ASCII by construction.
        let lit = std::str::from_utf8(&self.s[start..self.i])
            .map_err(|_| self.err("non-ascii number"))?;
        Ok(Value::Number(lit.to_owned()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            // Fast path: copy a run of plain bytes.
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            let run = std::str::from_utf8(&self.s[start..self.i])
                .map_err(|_| self.err("invalid UTF-8"))?;
            out.push_str(run);
            match self.peek() {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let esc = self.peek().ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                // High surrogate: a low surrogate must follow.
                                if !self.s[self.i..].starts_with(b"\\u") {
                                    return Err(self.err("lone high surrogate"));
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("invalid low surrogate"));
                                }
                                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))?
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err(self.err("lone low surrogate"));
                            } else {
                                char::from_u32(hi).ok_or_else(|| self.err("invalid code point"))?
                            };
                            out.push(ch);
                        }
                        _ => return Err(self.err("invalid escape")),
                    }
                }
                Some(_) => return Err(self.err("control character in string")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let chunk = self
            .s
            .get(self.i..self.i + 4)
            .ok_or_else(|| self.err("short \\u escape"))?;
        let mut v = 0u32;
        for &b in chunk {
            let d = (b as char)
                .to_digit(16)
                .ok_or_else(|| self.err("invalid hex in \\u escape"))?;
            v = (v << 4) | d;
        }
        self.i += 4;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Value {
        Value::parse(s).expect("valid JSON")
    }

    #[test]
    fn parses_scalars_and_keeps_number_literals() {
        assert_eq!(p("null"), Value::Null);
        assert_eq!(p(" true "), Value::Bool(true));
        assert_eq!(p("1.0"), Value::Number("1.0".into()));
        assert_eq!(p("-0.50"), Value::Number("-0.50".into()));
        assert_eq!(p("1e3"), Value::Number("1e3".into()));
        assert_eq!(
            p(r#""a\u00e9\n\ud83d\ude00""#),
            Value::String("aé\n😀".into())
        );
    }

    #[test]
    fn objects_keep_order_and_last_duplicate_wins() {
        let v = p(r#"{"b":1,"a":2,"b":3}"#);
        let o = v.as_object().unwrap();
        let keys: Vec<&str> = o.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["b", "a"]);
        assert_eq!(o.get("b"), Some(&Value::Number("3".into())));
    }

    #[test]
    fn rejects_what_rfc_8259_rejects() {
        for bad in [
            "",
            "01",
            "1.",
            ".5",
            "+1",
            "[1,]",
            "{\"a\":1,}",
            "{'a':1}",
            "[1 2]",
            "\"tab\there\"",
            "\"\\x\"",
            "\"\\ud800\"",
            "nul",
            "tru",
            "1 2",
            "{\"a\" 1}",
            "[",
            "\"unterminated",
        ] {
            assert!(Value::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn depth_limit_holds() {
        let deep = "[".repeat(300) + &"]".repeat(300);
        assert!(Value::parse(&deep).is_err());
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(Value::parse(&ok).is_ok());
    }

    #[test]
    fn parses_a_golden_ledger_line() {
        let line = r#"{"ts":"2026-10-02T05:39:55Z","event":"op.started","op":"learning-op-001","target":"demo-learning-node","capability":"read-only","tool":"atlas","status":"ok","detail":"profile=htb-starting-point"}"#;
        let v = p(line);
        let o = v.as_object().unwrap();
        assert_eq!(o.len(), 8);
        assert_eq!(o.get("event").and_then(Value::as_str), Some("op.started"));
        assert_eq!(o.iter().next().map(|(k, _)| k), Some("ts"));
    }
}
