//! Canonical JSON: the byte-exact output of `jq -cS .`.
//!
//! Receipts and ledger anchors are hashed over this form plus a trailing
//! newline, so a single byte of difference changes every hash downstream.
//! The rules, taken from the Go build's `ndjson.Canonical` (which was
//! verified byte-identical against jq):
//!
//! - objects: keys sorted by byte order, no whitespace;
//! - numbers: the literal as written (never reformatted);
//! - strings: `"`, `\`, `\n`, `\r`, `\t`, `\b`, `\f` escaped by name, other
//!   control characters and `0x7f` as `\u00XX`, everything else verbatim
//!   UTF-8;
//! - `null`, `true`, `false` as is.

use crate::json::Value;

/// Render `v` exactly as `jq -cS .` would, without a trailing newline.
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(&mut out, v);
    out
}

/// Render `v` canonically and append the newline that `jq` prints.
/// This is the exact byte sequence the receipt and ledger hashes cover.
pub fn canonical_line(v: &Value) -> Vec<u8> {
    let mut out = canonical(v);
    out.push(b'\n');
    out
}

/// Render `v` compactly in insertion order (the NDJSON line form, like
/// `jq -cn` with an ordered object). Same escaping as [`canonical`].
pub fn compact(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value_with(&mut out, v, false);
    out
}

fn write_value(out: &mut Vec<u8>, v: &Value) {
    write_value_with(out, v, true)
}

fn write_value_with(out: &mut Vec<u8>, v: &Value, sort_keys: bool) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(lit) => out.extend_from_slice(lit.as_bytes()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value_with(out, item, sort_keys);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&str, &Value)> = map.iter().collect();
            if sort_keys {
                entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            }
            out.push(b'{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                write_value_with(out, val, sort_keys);
            }
            out.push(b'}');
        }
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(text: &str) -> String {
        String::from_utf8(canonical(&Value::parse(text).unwrap())).unwrap()
    }

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        assert_eq!(
            canon(r#"{ "b": 1, "a": {"z": true, "y": null} }"#),
            r#"{"a":{"y":null,"z":true},"b":1}"#
        );
    }

    #[test]
    fn sorts_by_byte_order_not_locale() {
        // Uppercase sorts before lowercase; shorter prefix sorts first.
        assert_eq!(
            canon(r#"{"b":1,"B":2,"a":3,"aa":4}"#),
            r#"{"B":2,"a":3,"aa":4,"b":1}"#
        );
    }

    #[test]
    fn keeps_number_literals_verbatim() {
        assert_eq!(canon("[1.0, 10, 1e3, -0.50]"), "[1.0,10,1e3,-0.50]");
    }

    #[test]
    fn escapes_like_jq() {
        let v = Value::String("q\" b\\ n\n r\r t\t bs\u{8} ff\u{c} nul\u{0} del\u{7f} é 日".into());
        assert_eq!(
            String::from_utf8(canonical(&v)).unwrap(),
            "\"q\\\" b\\\\ n\\n r\\r t\\t bs\\b ff\\f nul\\u0000 del\\u007f é 日\""
        );
    }

    #[test]
    fn compact_keeps_insertion_order() {
        let v = Value::parse(r#"{"ts":"t","event":"e"}"#).unwrap();
        assert_eq!(compact(&v), br#"{"ts":"t","event":"e"}"#.to_vec());
        assert_eq!(canonical(&v), br#"{"event":"e","ts":"t"}"#.to_vec());
    }

    #[test]
    fn line_form_adds_exactly_one_newline() {
        assert_eq!(
            canonical_line(&Value::parse(r#"{"k":"v"}"#).unwrap()),
            b"{\"k\":\"v\"}\n".to_vec()
        );
    }

    #[test]
    fn output_reparses_to_the_same_value() {
        // A deterministic sweep over tricky strings stands in for a property
        // test until dev-dependencies are available in CI.
        let samples = [
            "",
            "plain",
            "quote\"back\\slash",
            "ctrl\u{1}\u{1f}\u{7f}",
            "uni é 日 😀",
            "nl\n\r\t",
        ];
        for s in samples {
            let mut o = crate::json::Object::new();
            o.insert("s", Value::String(s.into()));
            o.insert("n", Value::Number("1.50".into()));
            o.insert("a", Value::Array(vec![Value::Bool(true), Value::Null]));
            let v = Value::Object(o);
            let bytes = canonical(&v);
            let back = Value::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
            // Canonical sorts keys, so compare field by field.
            let bo = back.as_object().unwrap();
            assert_eq!(bo.get("s"), Some(&Value::String(s.into())), "{s:?}");
            assert_eq!(bo.get("n"), Some(&Value::Number("1.50".into())));
        }
    }
}
