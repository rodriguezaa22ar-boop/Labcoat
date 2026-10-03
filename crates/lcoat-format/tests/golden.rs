#![allow(clippy::unwrap_used)]
//! Day-0 exit check: reproduce the hashes the shell build and Lab Coat Lite
//! recorded for the golden fixtures. If any of these fail, nothing built on
//! this crate can be byte-compatible.

use std::path::PathBuf;

use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::Value;

fn golden(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/golden")
        .join(rel)
}

fn load(rel: &str) -> Value {
    Value::parse(&std::fs::read_to_string(golden(rel)).expect("fixture present"))
        .expect("fixture parses")
}

/// The archive packet of `learning-op-001` anchors its ledger as
/// `events=18 sha256=ba36a564...758f0c6f`.
#[test]
fn ledger_file_hash_matches_archive_anchor() {
    let path = golden("learning-op-001/ledger.ndjson");
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.lines().count(), 18);
    for line in text.lines() {
        Value::parse(line).expect("every ledger line is strict JSON");
    }
    assert_eq!(
        Sha256Hex::of_file(&path).unwrap().as_str(),
        "ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f"
    );
}

/// `evidence.ndjson` records the artifact's hash at capture time.
#[test]
fn evidence_artifact_hash_matches_index() {
    let path = golden("learning-op-001/evidence/ev_20261002T054004Z/recon-output.txt");
    assert_eq!(
        Sha256Hex::of_file(&path).unwrap().as_str(),
        "fa0def3c96e0f68e7fe02036187b47485ab9aabe60919692770bae396c1267ad"
    );
}

/// Receipt hashing, as `receipt.sh` defines it:
///   event_hash   = sha256(jq -cS of the receipt without event_hash and receipt_hash, + "\n")
///   receipt_hash = sha256(jq -cS of the receipt without receipt_hash, + "\n")
/// All three demo-site receipts must reproduce both values exactly.
#[test]
fn demo_site_receipts_rehash_exactly() {
    for name in ["demo-site-boundary", "demo-site-packet", "demo-site-replay"] {
        let receipt = load(&format!("demo-site-receipts/{name}.json"));
        let obj = receipt.as_object().unwrap();
        let recorded_event = obj.get("event_hash").and_then(Value::as_str).unwrap();
        let recorded_receipt = obj.get("receipt_hash").and_then(Value::as_str).unwrap();

        let mut without_both = obj.clone();
        without_both.remove("event_hash");
        without_both.remove("receipt_hash");
        let mut without_receipt = obj.clone();
        without_receipt.remove("receipt_hash");

        assert_eq!(
            Sha256Hex::of_canonical(&Value::Object(without_both)).as_str(),
            recorded_event,
            "{name}: event_hash"
        );
        assert_eq!(
            Sha256Hex::of_canonical(&Value::Object(without_receipt)).as_str(),
            recorded_receipt,
            "{name}: receipt_hash"
        );
    }
}

/// The three receipts form a chain: each prev_hash is the previous event_hash.
#[test]
fn demo_site_receipts_chain_in_order() {
    let a = load("demo-site-receipts/demo-site-boundary.json");
    let b = load("demo-site-receipts/demo-site-packet.json");
    let c = load("demo-site-receipts/demo-site-replay.json");
    let get = |v: &Value, k: &str| v.as_object().unwrap().get(k).cloned().unwrap();
    assert!(
        get(&a, "prev_hash").is_null(),
        "first receipt has null prev_hash"
    );
    assert_eq!(get(&b, "prev_hash"), get(&a, "event_hash"));
    assert_eq!(get(&c, "prev_hash"), get(&b, "event_hash"));
}
