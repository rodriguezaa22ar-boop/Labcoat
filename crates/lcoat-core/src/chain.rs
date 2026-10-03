//! Ledger hash chain (format 1.1, additive).
//!
//! Each ledger event gains two fields:
//!
//! - `prev_hash`: the previous event's `event_hash`, or `null` for the first
//!   chained event (the same convention receipts use);
//! - `event_hash`: `sha256( canonical(event without prev_hash and event_hash)
//!   + "\n" + prev_hash_hex_or_empty + "\n" )`.
//!
//! The canonical form is `jq -cS`, so the shell build can recompute every
//! link with `jq` and `sha256sum` if it ever wants to. v1 verifiers ignore
//! both fields; the whole-file ledger hash they anchor still holds.
//!
//! **This definition is frozen as of phase 0.** The test vector below is the
//! fixture every later implementation must reproduce; changing the formula
//! means changing the vector and bumping the format version.

use lcoat_format::canonical::canonical;
use lcoat_format::hash::Sha256Hex;
use lcoat_format::json::{Object, Value};
use lcoat_format::sha256::Sha256;

/// Field name of the previous event's hash.
pub const PREV_HASH: &str = "prev_hash";
/// Field name of this event's hash.
pub const EVENT_HASH: &str = "event_hash";

/// Compute the `event_hash` for `event` given the previous link.
///
/// `event` may already carry `prev_hash`/`event_hash`; both are excluded
/// from the hashed form so the result is the same whether or not the fields
/// have been written yet.
pub fn event_hash(event: &Object, prev: Option<&Sha256Hex>) -> Sha256Hex {
    let mut body = event.clone();
    body.remove(PREV_HASH);
    body.remove(EVENT_HASH);
    let mut h = Sha256::new();
    h.update(&canonical(&Value::Object(body)));
    h.update(b"\n");
    if let Some(p) = prev {
        h.update(p.as_str().as_bytes());
    }
    h.update(b"\n");
    Sha256Hex::of_bytes_digest(h.finalize())
}

/// Attach `prev_hash` and `event_hash` to `event` (in that order, at the
/// end, so the v1 field order the shell writes is undisturbed).
pub fn link(mut event: Object, prev: Option<&Sha256Hex>) -> Object {
    let h = event_hash(&event, prev);
    event.remove(PREV_HASH);
    event.remove(EVENT_HASH);
    event.insert(
        PREV_HASH,
        prev.map_or(Value::Null, |p| Value::String(p.as_str().to_owned())),
    );
    event.insert(EVENT_HASH, Value::String(h.as_str().to_owned()));
    event
}

/// Result of walking a ledger's chain fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// No event carries chain fields (a pure v1 ledger).
    Unchained,
    /// Events from `first_chained` (0-based) onward are chained and valid;
    /// earlier events predate the chain (a Lite operation continued here).
    Partial {
        /// Index of the first event that carries chain fields.
        first_chained: usize,
    },
    /// Every event is chained and every link verifies.
    Verified,
    /// The link at `index` does not verify; `reason` says why.
    Broken {
        /// 0-based index of the first bad event.
        index: usize,
        /// Human-readable cause.
        reason: &'static str,
    },
}

/// Verify the chain fields across `events` in order.
pub fn verify(events: &[Object]) -> ChainStatus {
    let first = match events.iter().position(|e| e.get(EVENT_HASH).is_some()) {
        None => return ChainStatus::Unchained,
        Some(i) => i,
    };
    let mut prev: Option<Sha256Hex> = None;
    for (i, e) in events.iter().enumerate().skip(first) {
        let recorded = match e.get(EVENT_HASH).and_then(Value::as_str) {
            Some(s) => match Sha256Hex::parse(s) {
                Ok(h) => h,
                Err(_) => {
                    return ChainStatus::Broken {
                        index: i,
                        reason: "malformed event_hash",
                    };
                }
            },
            None => {
                return ChainStatus::Broken {
                    index: i,
                    reason: "event_hash missing after chain began",
                };
            }
        };
        let recorded_prev = match e.get(PREV_HASH) {
            Some(Value::Null) | None => None,
            Some(Value::String(s)) => match Sha256Hex::parse(s) {
                Ok(h) => Some(h),
                Err(_) => {
                    return ChainStatus::Broken {
                        index: i,
                        reason: "malformed prev_hash",
                    };
                }
            },
            Some(_) => {
                return ChainStatus::Broken {
                    index: i,
                    reason: "prev_hash is not a string or null",
                };
            }
        };
        if recorded_prev != prev {
            return ChainStatus::Broken {
                index: i,
                reason: "prev_hash does not match previous event_hash",
            };
        }
        if event_hash(e, prev.as_ref()) != recorded {
            return ChainStatus::Broken {
                index: i,
                reason: "event_hash does not match event content",
            };
        }
        prev = Some(recorded);
    }
    if first == 0 {
        ChainStatus::Verified
    } else {
        ChainStatus::Partial {
            first_chained: first,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(line: &str) -> Object {
        match Value::parse(line).unwrap() {
            Value::Object(o) => o,
            _ => panic!("object"),
        }
    }

    const E1: &str = r#"{"ts":"2026-10-02T07:40:00Z","event":"op.started","op":"full-op","target":"demo-node","capability":"read-only","tool":"lcoat","status":"ok","detail":"profile=htb-starting-point"}"#;
    const E2: &str = r#"{"ts":"2026-10-02T07:40:00Z","event":"scope.preflight","op":"full-op","target":"demo-node","capability":"read-only","tool":"lcoat","status":"allowed","detail":"reason=add evidence artifact"}"#;

    /// FROZEN TEST VECTOR, computed independently with the shell tools:
    ///   printf '%s\n\n' "$(jq -cS . <<<"$E1")" | sha256sum
    /// Changing the chain formula means changing this value and bumping the
    /// format version.
    #[test]
    fn frozen_vector_first_event() {
        assert_eq!(
            event_hash(&ev(E1), None).as_str(),
            "3fb421358af5399102479a6d73ac5db8b9d28c3b484645e0e2c601bd2c3bac06"
        );
    }

    /// Second link, computed the same way with prev = the first vector:
    ///   printf '%s\n%s\n' "$(jq -cS . <<<"$E2")" "$PREV" | sha256sum
    #[test]
    fn frozen_vector_second_event() {
        let prev = event_hash(&ev(E1), None);
        assert_eq!(
            event_hash(&ev(E2), Some(&prev)).as_str(),
            "3ac78f62a8115d6da5d6ecc1406305e6f79656673dde3ffc6267554f67a9a3db"
        );
    }

    #[test]
    fn linking_is_order_sensitive_and_verifies() {
        let a = link(ev(E1), None);
        let ha = Sha256Hex::parse(a.get(EVENT_HASH).unwrap().as_str().unwrap()).unwrap();
        let b = link(ev(E2), Some(&ha));
        assert_eq!(verify(&[a.clone(), b.clone()]), ChainStatus::Verified);
        assert!(matches!(
            verify(&[b.clone(), a.clone()]),
            ChainStatus::Broken { index: 0, .. }
        ));
        // v1 field order is preserved; chain fields come last.
        let keys: Vec<&str> = a.iter().map(|(k, _)| k).collect();
        assert_eq!(&keys[..2], ["ts", "event"]);
        assert_eq!(&keys[keys.len() - 2..], [PREV_HASH, EVENT_HASH]);
    }

    #[test]
    fn rewritten_middle_event_is_named() {
        let a = link(ev(E1), None);
        let ha = Sha256Hex::parse(a.get(EVENT_HASH).unwrap().as_str().unwrap()).unwrap();
        let b = link(ev(E2), Some(&ha));
        let hb = Sha256Hex::parse(b.get(EVENT_HASH).unwrap().as_str().unwrap()).unwrap();
        let c = link(ev(E1), Some(&hb));
        let mut tampered = b.clone();
        tampered.insert("status", Value::String("denied".into()));
        assert_eq!(
            verify(&[a, tampered, c]),
            ChainStatus::Broken {
                index: 1,
                reason: "event_hash does not match event content"
            }
        );
    }

    #[test]
    fn v1_and_continued_ledgers() {
        assert_eq!(verify(&[ev(E1), ev(E2)]), ChainStatus::Unchained);
        let b = link(ev(E2), None);
        assert_eq!(
            verify(&[ev(E1), b]),
            ChainStatus::Partial { first_chained: 1 }
        );
    }

    #[test]
    fn hash_ignores_existing_chain_fields() {
        let plain = ev(E1);
        let linked = link(plain.clone(), None);
        assert_eq!(event_hash(&plain, None), event_hash(&linked, None));
    }
}
