#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The shape of every `lcoat.*.v1` document `--json` prints, pinned.
//!
//! Review 2026-10-05: most `--json` output had no schema test, so a renamed
//! or retyped field would reach scripts unnoticed. The `atlas.*` documents
//! are compared byte for byte with the shell build in
//! `conformance/readonly_diff.sh`; the `lcoat.*` ones exist only here, so
//! their shape (key order and value types, recursively) is pinned below.
//! A deliberate change edits the expected shape in the same commit, and a
//! new or retyped field means a new `schema_version` unless it only adds.
//!
//! Shape notation: `{key:shape,...}` in key order, `[shape]` for an array
//! (its first element; `[]` when empty), `s` string, `n` number, `b`
//! bool, `null`.

use std::path::Path;
use std::process::{Command, Output};

use lcoat_format::json::Value;

fn lcoat(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lcoat"))
        .args(args)
        .env_remove("LAB_ROOT")
        .env("LCOAT_ROOT", root)
        .env("LCOAT_NOW", "2026-10-02T07:40:00Z")
        .env("LCOAT_OPERATOR", "tester")
        .output()
        .unwrap()
}

fn ok(root: &Path, args: &[&str]) -> String {
    let out = lcoat(root, args);
    assert!(
        out.status.success(),
        "{args:?}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn shape(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(_) => "b".into(),
        Value::Number(_) => "n".into(),
        Value::String(_) => "s".into(),
        Value::Array(items) => format!("[{}]", items.first().map(shape).unwrap_or_default()),
        Value::Object(o) => {
            let fields: Vec<String> = o.iter().map(|(k, v)| format!("{k}:{}", shape(v))).collect();
            format!("{{{}}}", fields.join(","))
        }
    }
}

/// The document's `schema_version` and shape; stdout must be exactly one
/// JSON value and a newline.
fn doc(text: &str) -> (String, String) {
    assert!(
        text.ends_with('\n') && !text.trim_end().contains('\n'),
        "{text}"
    );
    let v = Value::parse(text.trim_end()).unwrap();
    let version = v
        .as_object()
        .and_then(|o| o.get("schema_version"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    (version, shape(&v))
}

/// A closed operation with one artifact, one resolved finding and all
/// three packets.
fn closed_root() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("lcoat-json-schemas-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("recon.txt"), b"PORT 22 open ssh\n").unwrap();
    let r = root.as_path();
    ok(
        r,
        &[
            "target",
            "add",
            "node",
            "10.10.10.5",
            "--scope-status",
            "in-scope",
        ],
    );
    ok(r, &["op", "start", "demo", "node", "lab"]);
    let recon = root.join("recon.txt").display().to_string();
    ok(r, &["evidence", "add", &recon, "--kind", "scan-output"]);
    let added = ok(r, &["finding", "add", "SSH exposed", "--severity", "low"]);
    let id = added
        .lines()
        .find_map(|l| l.strip_prefix("id: "))
        .unwrap()
        .to_owned();
    ok(r, &["finding", "resolve", &id, "--note", "firewalled"]);
    ok(r, &["op", "report"]);
    ok(r, &["op", "handoff"]);
    ok(r, &["op", "close"]);
    for c in ["closeout", "audit-packet", "archive-packet"] {
        ok(r, &["op", c, "demo"]);
    }
    root
}

const PACKET_VERIFY: &str = "{schema_version:s,packet_kind:s,operation:s,packet:s,status:s,\
verified_anchors:n,verification_gaps:n,verification_problems:n,rows:[s]}";

const TRUST_CHAIN: &str = "{schema_version:s,operation:{slug:s,name:s,target:s,status:s},\
status:s,next_step:s,\
readiness:{close:s,next_step:s,evidence_records:n,open_findings:n,accepted_risks:n,\
expired_accepted_risks:n,pending_validation:n},\
v1:{overall:s,note:s},\
freshness:{report:s,evidence_bundle:s,handoff:s,closeout:s,accepted_risk_review_packet:s,\
audit_packet:s,archive_packet:s},\
verification:{closeout:{status:s,path:s,problems:n},accepted_risk_review_packet:{status:s,path:s},\
audit_packet:{status:s,path:s},archive_packet:{status:s,path:s},\
evidence_artifacts:{status:s,checked:n,problems:n}},\
ledger:{file:s,events:n,sha256:s,chain:s,latest_at:s,latest_event:s}}";

const EVIDENCE_VERIFY: &str = "{schema_version:s,operation:s,status:s,checked:n,problems:n,\
artifacts:[{id:s,path:s,status:s,expected_sha256:s,actual_sha256:s}]}";

const CHAIN_VERIFY: &str = "{schema_version:s,operation:s,ledger:s,events:n,status:s,detail:s}";

#[test]
fn lcoat_json_documents_keep_their_shape() {
    let root = closed_root();
    let r = root.as_path();
    let cases: [(&[&str], &str, &str); 6] = [
        (
            &["op", "verify", "demo", "--json"],
            "lcoat.packet_verify.v1",
            PACKET_VERIFY,
        ),
        (
            &["op", "audit-verify", "demo", "--json"],
            "lcoat.packet_verify.v1",
            PACKET_VERIFY,
        ),
        (
            &["op", "archive-verify", "demo", "--json"],
            "lcoat.packet_verify.v1",
            PACKET_VERIFY,
        ),
        (
            &["op", "trust-chain", "demo", "--json"],
            "lcoat.operation_trust_chain.v1",
            TRUST_CHAIN,
        ),
        (
            &["evidence", "verify", "demo", "--json"],
            "lcoat.evidence_verify.v1",
            EVIDENCE_VERIFY,
        ),
        (
            &["ledger", "chain-verify", "demo", "--json"],
            "lcoat.ledger_chain_verify.v1",
            CHAIN_VERIFY,
        ),
    ];
    let mut wrong = Vec::new();
    for (args, version, expected) in cases {
        let (v, s) = doc(&ok(r, args));
        if v != version || s != expected {
            wrong.push(format!("{args:?}\n  version: {v}\n  shape:   {s}"));
        }
    }
    assert!(wrong.is_empty(), "\n{}", wrong.join("\n"));
    let _ = std::fs::remove_dir_all(&root);
}

/// `doctor --json` describes the machine, so value types differ by
/// platform (`uid` is null where `/proc` is absent); its top-level keys and
/// the shape of one check are pinned.
#[test]
fn doctor_json_keeps_its_keys() {
    let root = std::env::temp_dir().join(format!("lcoat-json-doctor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let out = lcoat(&root, &["doctor", "--json"]);
    let text = String::from_utf8(out.stdout).unwrap();
    let v = Value::parse(text.trim_end()).unwrap();
    let o = v.as_object().unwrap();
    let keys: Vec<&str> = o.iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "schema_version",
            "version",
            "commit",
            "platform",
            "adapters",
            "uid",
            "status",
            "failures",
            "warnings",
            "checks"
        ]
    );
    assert_eq!(
        o.get("schema_version").and_then(Value::as_str),
        Some("lcoat.doctor.v1")
    );
    let Some(Value::Array(checks)) = o.get("checks") else {
        panic!("checks is not an array: {text}");
    };
    let first = checks.first().map(shape).unwrap_or_default();
    assert_eq!(first, "{section:s,label:s,status:s,detail:s}");
    let _ = std::fs::remove_dir_all(&root);
}
