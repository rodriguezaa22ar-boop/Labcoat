//! `atlas.receipt.v1` proof records: verify, replay, create.
//!
//! Hashes are computed over canonical JSON (`jq -cS`) plus a trailing
//! newline, as the shell build's `receipt.sh` does:
//!
//! - `event_hash`   = sha256(canonical(receipt without event_hash, receipt_hash) + "\n")
//! - `receipt_hash` = sha256(canonical(receipt without receipt_hash) + "\n")
//!
//! Receipt signing (minisign/ed25519 over `receipt_hash`) is the phase 4
//! addition and lives outside these fields so v1 verifiers keep validating.

use std::path::Path;

use lcoat_format::canonical::pretty_sorted;
use lcoat_format::clock::{self, Utc};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::ids::slugify;
use lcoat_format::json::{Object, Value};

use crate::error::Result;
use crate::fail;
use crate::metadata::forbidden_paths;

/// The schema this module reads and writes.
pub const SCHEMA_VERSION: &str = "atlas.receipt.v1";
/// The verifier the receipt names.
pub const VERIFIER_NAME: &str = "atlas receipt verify";
/// The schema path the receipt names.
pub const VERIFIER_SCHEMA: &str = "schemas/atlas.receipt.v1.schema.json";

const RECEIPT_KEYS: &[&str] = &[
    "schema_version",
    "receipt_id",
    "timestamp",
    "metadata_only",
    "raw_artifacts_embedded",
    "action",
    "actor",
    "subject",
    "evidence_refs",
    "artifact_refs",
    "approval_refs",
    "prev_hash",
    "event_hash",
    "receipt_hash",
    "known_limitations",
    "verifier",
];

const DEFAULT_LIMITATIONS: &[&str] = &[
    "Metadata-only proof record; raw artifacts and sensitive contents are not embedded.",
    "Does not prove external artifact availability, human intent, legal compliance, or artifact correctness.",
];

fn is_hex64(s: &str) -> bool {
    Sha256Hex::parse(s).is_ok()
}

fn without(m: &Object, drop: &[&str]) -> Object {
    let mut c = m.clone();
    for k in drop {
        c.remove(k);
    }
    c
}

/// `event_hash` of a receipt object (its own hash fields excluded).
pub fn event_hash(m: &Object) -> Sha256Hex {
    Sha256Hex::of_canonical(&Value::Object(without(m, &["event_hash", "receipt_hash"])))
}

/// `receipt_hash` of a receipt object.
pub fn receipt_hash(m: &Object) -> Sha256Hex {
    Sha256Hex::of_canonical(&Value::Object(without(m, &["receipt_hash"])))
}

/// `atlas.receipt_verify.v1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyResult {
    /// `receipt_id`
    pub receipt_id: String,
    /// `action`
    pub action: String,
    /// `event_hash`
    pub event_hash: String,
    /// `prev_hash`, or `None` for a genesis receipt.
    pub prev_hash: Option<String>,
    /// `receipt_hash`
    pub receipt_hash: String,
    /// `evidence_refs` length.
    pub evidence_refs: usize,
    /// `artifact_refs` length.
    pub artifact_refs: usize,
    /// `approval_refs` length.
    pub approval_refs: usize,
}

impl VerifyResult {
    /// The `receipt verify --json` object, in Lite's field order.
    pub fn to_json(&self) -> Object {
        let mut o = Object::new();
        o.insert("schema_version", s("atlas.receipt_verify.v1"));
        o.insert("status", s("ok"));
        o.insert("receipt_id", s(&self.receipt_id));
        o.insert("action", s(&self.action));
        o.insert("event_hash", s(&self.event_hash));
        // Lite prints the string "null" for a genesis receipt here (a quirk
        // it inherited from the shell build's jq rendering); kept as is.
        o.insert("prev_hash", s(self.prev_hash.as_deref().unwrap_or("null")));
        o.insert("receipt_hash", s(&self.receipt_hash));
        o.insert(
            "evidence_ref_count",
            Value::Number(self.evidence_refs.to_string()),
        );
        o.insert(
            "artifact_ref_count",
            Value::Number(self.artifact_refs.to_string()),
        );
        o.insert(
            "approval_ref_count",
            Value::Number(self.approval_refs.to_string()),
        );
        o.insert("metadata_only", Value::Bool(true));
        o.insert("raw_artifacts_embedded", Value::Bool(false));
        o
    }
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn exact_keys(m: &Object, allowed: &[&str]) -> bool {
    m.iter().all(|(k, _)| allowed.contains(&k))
}

fn string_array(m: &Object, key: &str) -> bool {
    match m.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .all(|v| matches!(v, Value::String(x) if !x.is_empty())),
        _ => false,
    }
}

fn validate_fields(m: &Object) -> bool {
    if !exact_keys(m, RECEIPT_KEYS) || m.str("schema_version") != SCHEMA_VERSION {
        return false;
    }
    if !["receipt_id", "timestamp", "action", "actor"]
        .iter()
        .all(|k| m.nonempty(k))
    {
        return false;
    }
    if m.get("metadata_only") != Some(&Value::Bool(true))
        || m.get("raw_artifacts_embedded") != Some(&Value::Bool(false))
    {
        return false;
    }
    match m.get("subject") {
        Some(Value::Object(subj))
            if exact_keys(subj, &["type", "ref"])
                && subj.nonempty("type")
                && subj.nonempty("ref") => {}
        _ => return false,
    }
    if !string_array(m, "evidence_refs") || !string_array(m, "approval_refs") {
        return false;
    }
    match m.get("artifact_refs") {
        Some(Value::Array(arts)) => {
            for a in arts {
                match a {
                    Value::Object(am)
                        if exact_keys(am, &["path", "sha256"])
                            && am.nonempty("path")
                            && is_hex64(am.str("sha256")) => {}
                    _ => return false,
                }
            }
        }
        _ => return false,
    }
    match m.get("prev_hash") {
        None => return false,
        Some(Value::Null) => {}
        Some(Value::String(p)) if is_hex64(p) => {}
        Some(_) => return false,
    }
    if !is_hex64(m.str("event_hash")) || !is_hex64(m.str("receipt_hash")) {
        return false;
    }
    match m.get("known_limitations") {
        Some(Value::Array(lims)) if !lims.is_empty() => {
            if !lims
                .iter()
                .all(|l| matches!(l, Value::String(x) if !x.is_empty()))
            {
                return false;
            }
        }
        _ => return false,
    }
    match m.get("verifier") {
        Some(Value::Object(ver))
            if exact_keys(ver, &["name", "schema"])
                && ver.str("name") == VERIFIER_NAME
                && ver.str("schema") == VERIFIER_SCHEMA => {}
        _ => return false,
    }
    true
}

/// `atlas_receipt_validate_json`: parse, scan for forbidden content, check
/// the fields, recompute both hashes.
pub fn validate(data: &[u8]) -> Result<VerifyResult> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => fail!("invalid receipt JSON"),
    };
    let m = match Value::parse(text) {
        Ok(Value::Object(o)) => o,
        _ => fail!("invalid receipt JSON"),
    };
    let fb = forbidden_paths(&Value::Object(m.clone()));
    if !fb.is_empty() {
        fail!(
            "receipt contains forbidden raw-content marker: {}",
            fb.join(",")
        );
    }
    if !validate_fields(&m) {
        fail!("invalid receipt fields");
    }
    if m.str("event_hash") != event_hash(&m).as_str() {
        fail!("receipt event_hash mismatch");
    }
    if m.str("receipt_hash") != receipt_hash(&m).as_str() {
        fail!("receipt hash mismatch");
    }
    Ok(VerifyResult {
        receipt_id: m.str("receipt_id").to_owned(),
        action: m.str("action").to_owned(),
        event_hash: m.str("event_hash").to_owned(),
        prev_hash: match m.get("prev_hash") {
            Some(Value::String(p)) => Some(p.clone()),
            _ => None,
        },
        receipt_hash: m.str("receipt_hash").to_owned(),
        evidence_refs: m.arr_len("evidence_refs"),
        artifact_refs: m.arr_len("artifact_refs"),
        approval_refs: m.arr_len("approval_refs"),
    })
}

/// Read a receipt file (`-` is stdin).
pub fn read_input(path: &str) -> Result<Vec<u8>> {
    if path == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        return Ok(buf);
    }
    match std::fs::read(Path::new(path)) {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail!("missing receipt: {path}"),
        Err(e) => Err(e.into()),
    }
}

/// Validate a receipt file (`-` reads stdin).
pub fn verify_file(path: &str) -> Result<VerifyResult> {
    validate(&read_input(path)?)
}

/// One row of a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRow {
    /// 1-based position.
    pub index: usize,
    /// File path as given.
    pub path: String,
    /// `receipt_id`
    pub receipt_id: String,
    /// `action`
    pub action: String,
    /// `prev_hash` (`None` for genesis).
    pub prev_hash: Option<String>,
    /// `event_hash`
    pub event_hash: String,
    /// `receipt_hash`
    pub receipt_hash: String,
    /// `genesis` or `ok`.
    pub linkage_status: &'static str,
}

/// `atlas.receipt_replay.v1`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayResult {
    /// Receipts replayed.
    pub receipt_count: usize,
    /// First receipt's `event_hash`.
    pub first_event_hash: String,
    /// Last receipt's `event_hash`.
    pub chain_head_event_hash: String,
    /// Last receipt's `receipt_hash`.
    pub chain_head_receipt_hash: String,
    /// Per-receipt rows.
    pub chain: Vec<ChainRow>,
}

impl ReplayResult {
    /// The `receipt replay --json` object, field for field as the shell
    /// build's `atlas_receipt_replay_json` emits it.
    pub fn to_json(&self) -> Object {
        let strs = |items: &[&str]| Value::Array(items.iter().map(|x| s(x)).collect());
        let mut o = Object::new();
        o.insert("schema_version", s("atlas.receipt_replay.v1"));
        o.insert("status", s("ok"));
        o.insert("metadata_only", Value::Bool(true));
        o.insert("raw_artifacts_embedded", Value::Bool(false));
        o.insert(
            "receipt_count",
            Value::Number(self.receipt_count.to_string()),
        );
        o.insert("first_event_hash", s(&self.first_event_hash));
        o.insert("chain_head_event_hash", s(&self.chain_head_event_hash));
        o.insert("chain_head_receipt_hash", s(&self.chain_head_receipt_hash));
        let mut binding = Object::new();
        binding.insert("status", s("ok"));
        binding.insert("rule", s("receipt[n].prev_hash == receipt[n-1].event_hash"));
        binding.insert("genesis_prev_hash", Value::Null);
        o.insert("ledger_binding", Value::Object(binding));
        let mut checkpoint = Object::new();
        checkpoint.insert(
            "receipt_count",
            Value::Number(self.receipt_count.to_string()),
        );
        checkpoint.insert("head_event_hash", s(&self.chain_head_event_hash));
        checkpoint.insert("head_receipt_hash", s(&self.chain_head_receipt_hash));
        o.insert("chain_checkpoint", Value::Object(checkpoint));
        o.insert(
            "chain",
            Value::Array(self.chain.iter().map(ChainRow::to_json).collect()),
        );
        let mut boundary = Object::new();
        boundary.insert(
            "stores",
            strs(&[
                "receipt metadata",
                "provided receipt paths",
                "canonical event hashes",
                "canonical receipt hashes",
                "prev_hash linkage status",
            ]),
        );
        boundary.insert(
            "excludes",
            strs(&[
                "raw artifacts",
                "raw request or response bodies",
                "secrets",
                "tokens",
                "private keys",
                "session contents",
                "exploit payloads",
            ]),
        );
        o.insert("metadata_boundary", Value::Object(boundary));
        o.insert(
            "known_limitations",
            strs(&[
                "Replay verifies the provided receipt files in the caller-specified order only.",
                "Replay does not prove external artifact availability, human intent, legal compliance, artifact correctness, authorization, or production readiness.",
                "Replay is read-only and does not append to operation ledgers or create runtime state.",
            ]),
        );
        o
    }
}

impl ChainRow {
    /// One `chain[]` element of the replay JSON.
    pub fn to_json(&self) -> Value {
        let mut o = Object::new();
        o.insert("index", Value::Number(self.index.to_string()));
        o.insert("path", s(&self.path));
        o.insert("receipt_id", s(&self.receipt_id));
        o.insert("action", s(&self.action));
        o.insert(
            "prev_hash",
            self.prev_hash.as_deref().map(s).unwrap_or(Value::Null),
        );
        o.insert("event_hash", s(&self.event_hash));
        o.insert("receipt_hash", s(&self.receipt_hash));
        o.insert("linkage_status", s(self.linkage_status));
        Value::Object(o)
    }
}

/// `atlas_receipt_replay_json`: validate each receipt and check that each
/// `prev_hash` equals the previous receipt's `event_hash`, in the order
/// given. The first receipt must be genesis (`prev_hash` null).
pub fn replay(paths: &[String]) -> Result<ReplayResult> {
    if paths.is_empty() {
        fail!("receipt replay requires at least one receipt file");
    }
    let mut res = ReplayResult::default();
    let mut expected_prev = String::new();
    for (i, p) in paths.iter().enumerate() {
        if p == "-" {
            fail!("receipt replay requires receipt files, not stdin");
        }
        let v = validate(&read_input(p)?)?;
        let linkage = if i == 0 {
            if v.prev_hash.is_some() {
                fail!("receipt replay receipt 1 prev_hash must be null: {p}");
            }
            res.first_event_hash = v.event_hash.clone();
            "genesis"
        } else {
            let got = v.prev_hash.as_deref().unwrap_or("null");
            if got != expected_prev {
                fail!(
                    "receipt replay receipt {} prev_hash mismatch: expected {expected_prev} got {got}",
                    i + 1
                );
            }
            "ok"
        };
        res.chain.push(ChainRow {
            index: i + 1,
            path: p.clone(),
            receipt_id: v.receipt_id,
            action: v.action,
            prev_hash: v.prev_hash,
            event_hash: v.event_hash.clone(),
            receipt_hash: v.receipt_hash.clone(),
            linkage_status: linkage,
        });
        expected_prev = v.event_hash.clone();
        res.chain_head_event_hash = v.event_hash;
        res.chain_head_receipt_hash = v.receipt_hash;
    }
    res.receipt_count = paths.len();
    Ok(res)
}

/// Inputs to [`create`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateParams {
    /// Defaults to `receipt_<compact timestamp>_<slug(action)>`.
    pub receipt_id: String,
    /// Defaults to now.
    pub timestamp: String,
    /// Required.
    pub action: String,
    /// Required.
    pub actor: String,
    /// Required.
    pub subject_type: String,
    /// Required.
    pub subject_ref: String,
    /// Empty for a genesis receipt; else 64 lowercase hex characters.
    pub prev_hash: String,
    /// Evidence IDs.
    pub evidence_refs: Vec<String>,
    /// `path=sha256` pairs.
    pub artifact_refs: Vec<String>,
    /// Approval IDs.
    pub approval_refs: Vec<String>,
    /// Defaults to the two standard limitations.
    pub limitations: Vec<String>,
}

/// Build a receipt, compute its hashes and return it as the shell build
/// writes receipt files: `jq -S .` form (sorted keys, two-space indent) plus
/// a trailing newline. The hashes cover the canonical form, so the file
/// validates under this build, Lite and the shell build alike.
pub fn create(p: &CreateParams) -> Result<Vec<u8>> {
    if p.action.is_empty() {
        fail!("receipt create requires --action");
    }
    if p.actor.is_empty() {
        fail!("receipt create requires --actor");
    }
    if p.subject_type.is_empty() {
        fail!("receipt create requires --subject-type");
    }
    if p.subject_ref.is_empty() {
        fail!("receipt create requires --subject");
    }
    let prev = if p.prev_hash.is_empty() {
        Value::Null
    } else if is_hex64(&p.prev_hash) {
        s(&p.prev_hash)
    } else {
        fail!("receipt create requires --prev-hash as 64 lowercase hex characters");
    };
    let receipt_id = if p.receipt_id.is_empty() {
        format!("receipt_{}_{}", Utc::now().compact(), slugify(&p.action))
    } else {
        p.receipt_id.clone()
    };
    let timestamp = if p.timestamp.is_empty() {
        clock::timestamp()
    } else {
        p.timestamp.clone()
    };
    let limits: Vec<String> = if p.limitations.is_empty() {
        DEFAULT_LIMITATIONS
            .iter()
            .map(|l| (*l).to_owned())
            .collect()
    } else {
        p.limitations.clone()
    };
    let mut arts = Vec::with_capacity(p.artifact_refs.len());
    for a in &p.artifact_refs {
        let Some(eq) = a.rfind('=') else {
            fail!("receipt create requires --artifact-ref values formatted as path=sha256");
        };
        let (path, sha) = (&a[..eq], &a[eq + 1..]);
        if path.is_empty() || !is_hex64(sha) {
            fail!("receipt create requires --artifact-ref values formatted as path=sha256");
        }
        let mut am = Object::new();
        am.insert("path", s(path));
        am.insert("sha256", s(sha));
        arts.push(Value::Object(am));
    }
    let strs = |v: &[String]| Value::Array(v.iter().map(|x| s(x)).collect());

    let mut m = Object::new();
    m.insert("schema_version", s(SCHEMA_VERSION));
    m.insert("receipt_id", s(&receipt_id));
    m.insert("timestamp", s(&timestamp));
    m.insert("metadata_only", Value::Bool(true));
    m.insert("raw_artifacts_embedded", Value::Bool(false));
    m.insert("action", s(&p.action));
    m.insert("actor", s(&p.actor));
    let mut subject = Object::new();
    subject.insert("type", s(&p.subject_type));
    subject.insert("ref", s(&p.subject_ref));
    m.insert("subject", Value::Object(subject));
    m.insert("evidence_refs", strs(&p.evidence_refs));
    m.insert("artifact_refs", Value::Array(arts));
    m.insert("approval_refs", strs(&p.approval_refs));
    m.insert("prev_hash", prev);
    m.insert("known_limitations", strs(&limits));
    let mut verifier = Object::new();
    verifier.insert("name", s(VERIFIER_NAME));
    verifier.insert("schema", s(VERIFIER_SCHEMA));
    m.insert("verifier", Value::Object(verifier));
    let eh = event_hash(&m);
    m.insert("event_hash", s(eh.as_str()));
    let rh = receipt_hash(&m);
    m.insert("receipt_hash", s(rh.as_str()));
    let body = pretty_sorted(&Value::Object(m));
    validate(&body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> CreateParams {
        CreateParams {
            receipt_id: "receipt_test".into(),
            timestamp: "2026-10-02T07:40:00Z".into(),
            action: "demo.action".into(),
            actor: "tester".into(),
            subject_type: "operation".into(),
            subject_ref: "demo".into(),
            ..Default::default()
        }
    }

    #[test]
    fn create_then_validate_and_chain() {
        let first = create(&params()).unwrap();
        let v = validate(&first).unwrap();
        assert_eq!(v.receipt_id, "receipt_test");
        assert!(v.prev_hash.is_none());
        assert!(first.ends_with(b"\n"));
        // Written as `jq -S .` does: pretty, sorted keys, so "action" comes first.
        assert!(first.starts_with(b"{\n  \"action\": \"demo.action\",\n"));

        let mut p2 = params();
        p2.receipt_id = "receipt_test_2".into();
        p2.prev_hash = v.event_hash.clone();
        p2.artifact_refs = vec![format!("evidence/x.txt={}", "a".repeat(64))];
        p2.evidence_refs = vec!["ev_1".into()];
        let second = create(&p2).unwrap();
        let v2 = validate(&second).unwrap();
        assert_eq!(v2.prev_hash.as_deref(), Some(v.event_hash.as_str()));
        assert_eq!(
            (v2.evidence_refs, v2.artifact_refs, v2.approval_refs),
            (1, 1, 0)
        );

        let dir = std::env::temp_dir().join(format!("lcoat-receipt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p1 = dir.join("1.json");
        let p2f = dir.join("2.json");
        std::fs::write(&p1, &first).unwrap();
        std::fs::write(&p2f, &second).unwrap();
        let paths = [p1.display().to_string(), p2f.display().to_string()];
        let r = replay(&paths).unwrap();
        assert_eq!(r.receipt_count, 2);
        assert_eq!(r.chain[0].linkage_status, "genesis");
        assert_eq!(r.chain[1].linkage_status, "ok");
        assert_eq!(r.chain_head_event_hash, v2.event_hash);
        let err = replay(&[paths[1].clone(), paths[0].clone()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("receipt 1 prev_hash must be null"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_refuses_bad_input() {
        let mut p = params();
        p.action.clear();
        assert!(create(&p).unwrap_err().to_string().contains("--action"));
        let mut p = params();
        p.prev_hash = "xyz".into();
        assert!(create(&p).unwrap_err().to_string().contains("--prev-hash"));
        let mut p = params();
        p.artifact_refs = vec!["nohash".into()];
        assert!(create(&p).unwrap_err().to_string().contains("path=sha256"));
        // The scanner catches a credential in a field value.
        let mut p = params();
        p.actor = "token=abc".into();
        assert!(
            create(&p)
                .unwrap_err()
                .to_string()
                .contains("forbidden raw-content marker")
        );
    }

    #[test]
    fn validate_rejects_tampering() {
        let body = create(&params()).unwrap();
        let text = String::from_utf8(body).unwrap();
        let edited = text.replace("\"actor\": \"tester\"", "\"actor\": \"someone\"");
        assert_ne!(edited, text);
        assert!(
            validate(edited.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("event_hash mismatch")
        );
        let extra = text.replacen("{\n", "{\n  \"extra\": 1,\n", 1);
        assert!(
            validate(extra.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("invalid receipt fields")
        );
        assert!(
            validate(b"not json")
                .unwrap_err()
                .to_string()
                .contains("invalid receipt JSON")
        );
        assert!(
            validate(b"[1]")
                .unwrap_err()
                .to_string()
                .contains("invalid receipt JSON")
        );
    }

    #[test]
    fn json_objects_follow_lite_field_order() {
        let v = validate(&create(&params()).unwrap()).unwrap();
        let j = String::from_utf8(lcoat_format::canonical::compact(&Value::Object(
            v.to_json(),
        )))
        .unwrap();
        assert!(j.starts_with("{\"schema_version\":\"atlas.receipt_verify.v1\",\"status\":\"ok\",\"receipt_id\":\"receipt_test\",\"action\":\"demo.action\",\"event_hash\":\""));
        assert!(j.contains("\"prev_hash\":\"null\",\"receipt_hash\":\""));
        assert!(j.ends_with("\"evidence_ref_count\":0,\"artifact_ref_count\":0,\"approval_ref_count\":0,\"metadata_only\":true,\"raw_artifacts_embedded\":false}"));
    }
}
