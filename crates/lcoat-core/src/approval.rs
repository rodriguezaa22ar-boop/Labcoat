//! `approvals.ndjson`: recorded grants that let a Tier 3 capability run.
//!
//! The record is the shell build's (`atlas_approval_append_current`) with
//! one additive field, `expires_at`. The shell and Lite treat any record with
//! `status: approved` for the capability and target as current; Lab Coat is
//! stricter on purpose: the *latest* record for the pair must be `approved`
//! and unexpired, so a `revoked` record ends a grant and a grant cannot be
//! open-ended. A reason and an expiry are mandatory. Tier 4 and 5 cannot be
//! granted at all: [`grant`] refuses them before touching the file, and the
//! preflight refuses them before consulting approvals.

use std::path::{Path, PathBuf};

use lcoat_format::clock::{self, Utc};
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::error::Result;
use crate::fail;
use crate::metadata::MetadataOnly;
use crate::operation::{Active, Operation};
use crate::root::TOOL_NAME;
use crate::tier::Tier;

/// `approvals.ndjson` for an operation directory.
pub fn file(op_dir: &Path) -> PathBuf {
    op_dir.join("approvals.ndjson")
}

/// One approval record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    /// Recorded at.
    pub ts: String,
    /// Operation slug.
    pub op: String,
    /// Target the grant covers.
    pub target: String,
    /// Capability name.
    pub capability: String,
    /// Tier as the shell writes it (a string digit).
    pub tier: String,
    /// Operator (`LCOAT_OPERATOR`, else `USER`, else `unknown`).
    pub approved_by: String,
    /// Why.
    pub reason: String,
    /// `approved` or `revoked`.
    pub status: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`; empty on records the shell or Lite wrote.
    pub expires_at: String,
}

impl Grant {
    /// Decode from an index object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            ts: o.str("ts").to_owned(),
            op: o.str("op").to_owned(),
            target: o.str("target").to_owned(),
            capability: o.str("capability").to_owned(),
            tier: o.str("tier").to_owned(),
            approved_by: o.str("approved_by").to_owned(),
            reason: o.str("reason").to_owned(),
            status: o.str("status").to_owned(),
            expires_at: o.str("expires_at").to_owned(),
        }
    }

    /// Encode in the shell build's field order, `expires_at` last.
    pub fn to_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("ts", s(&self.ts));
        o.insert("op", s(&self.op));
        o.insert("target", s(&self.target));
        o.insert("capability", s(&self.capability));
        o.insert("tier", s(&self.tier));
        o.insert("approved_by", s(&self.approved_by));
        o.insert("reason", s(&self.reason));
        o.insert("status", s(&self.status));
        if !self.expires_at.is_empty() {
            o.insert("expires_at", s(&self.expires_at));
        }
        o
    }

    /// Whether this record is `approved` and unexpired at `now`
    /// (`YYYY-MM-DDTHH:MM:SSZ` strings compare lexically).
    pub fn is_current(&self, now: &str) -> bool {
        self.status == "approved"
            && (self.expires_at.is_empty() || now.as_bytes() < self.expires_at.as_bytes())
    }
}

/// The operator name the shell build records: `LCOAT_OPERATOR`, then
/// `ATLAS_OPERATOR`, then `USER`, then `unknown`.
pub fn operator() -> String {
    ["LCOAT_OPERATOR", "ATLAS_OPERATOR", "USER"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Every record, in order.
pub fn list(op_dir: &Path) -> Result<Vec<Grant>> {
    Ok(ndjson::read_file(&file(op_dir))?
        .iter()
        .map(Grant::from_object)
        .collect())
}

/// Whether a current grant exists: the latest record for this capability
/// and target is `approved` and unexpired at `now`.
pub fn current(op_dir: &Path, capability: Tier, target: &str, now: &str) -> bool {
    let Ok(records) = list(op_dir) else {
        return false;
    };
    records
        .iter()
        .rev()
        .find(|g| g.capability == capability.capability() && g.target == target)
        .is_some_and(|g| g.is_current(now))
}

/// Inputs to [`grant`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantParams {
    /// The capability to allow.
    pub capability: Tier,
    /// Why the grant is justified (scanned: no raw content).
    pub reason: MetadataOnly,
    /// When it lapses.
    pub expires_at: Utc,
}

/// `cmd_approval_grant` plus the Lab Coat rules: the capability must be
/// executable (Tier ≤ 3), allowed and not blocked by the snapshot, the
/// target must match the scope, the expiry must be in the future. Appends
/// the record and an `approval.granted` ledger event.
pub fn grant(op: &Operation<Active>, p: &GrantParams) -> Result<Grant> {
    let cap = p.capability.capability();
    if !p.capability.executable() {
        fail!(
            "approval refused: capability '{cap}' is above the Lab Coat ceiling ({}); it cannot be granted",
            crate::tier::MAX_EXECUTABLE_TIER
        );
    }
    if !p.capability.requires_approval() {
        fail!("approval not needed: capability '{cap}' runs without a grant");
    }
    let now = Utc::now();
    if p.expires_at <= now {
        fail!(
            "approval refused: expiry {} is not in the future",
            p.expires_at.timestamp()
        );
    }
    let snap = op.snapshot()?;
    if !snap.target_matches(&op.target) {
        fail!("approval refused: active target is outside active operation scope");
    }
    if !crate::scope::contains(&snap.allowed, cap) {
        fail!("approval refused: capability '{cap}' is not allowed for this operation");
    }
    if crate::scope::contains(&snap.blocked, cap) {
        fail!("approval refused: capability '{cap}' is blocked");
    }
    let _lock = op.lock()?;
    let g = Grant {
        ts: clock::timestamp(),
        op: op.slug.clone(),
        target: op.target.clone(),
        capability: cap.to_owned(),
        tier: (p.capability as u8).to_string(),
        approved_by: operator(),
        reason: p.reason.as_str().to_owned(),
        status: "approved".into(),
        expires_at: p.expires_at.timestamp(),
    };
    ndjson::append(&file(&op.dir), &g.to_object())?;
    op.append_ledger(
        "approval.granted",
        cap,
        TOOL_NAME,
        "approved",
        &format!("{} expires_at={}", g.reason, g.expires_at),
    )?;
    Ok(g)
}

/// Record a `revoked` entry for the capability, ending any current grant,
/// with an `approval.revoked` ledger event. Refuses when nothing is current.
pub fn revoke(op: &Operation<Active>, capability: Tier, reason: &MetadataOnly) -> Result<Grant> {
    let cap = capability.capability();
    let _lock = op.lock()?;
    if !current(&op.dir, capability, &op.target, &clock::timestamp()) {
        fail!(
            "no current approval for capability '{cap}' on target '{}'",
            op.target
        );
    }
    let g = Grant {
        ts: clock::timestamp(),
        op: op.slug.clone(),
        target: op.target.clone(),
        capability: cap.to_owned(),
        tier: (capability as u8).to_string(),
        approved_by: operator(),
        reason: reason.as_str().to_owned(),
        status: "revoked".into(),
        expires_at: String::new(),
    };
    ndjson::append(&file(&op.dir), &g.to_object())?;
    op.append_ledger(
        "approval.revoked",
        cap,
        TOOL_NAME,
        "revoked",
        reason.as_str(),
    )?;
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_follows_the_latest_record_and_the_clock() {
        let dir = std::env::temp_dir().join(format!("lcoat-approval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = file(&dir);
        assert!(!current(
            &dir,
            Tier::SafeValidation,
            "t",
            "2026-10-02T00:00:00Z"
        ));
        // A shell-written record has no expiry and is current forever, as the shell intends.
        std::fs::write(&p, "{\"ts\":\"2026-10-01T00:00:00Z\",\"op\":\"o\",\"target\":\"t\",\"capability\":\"safe-validation\",\"tier\":\"3\",\"approved_by\":\"me\",\"reason\":\"r\",\"status\":\"approved\"}\n").unwrap();
        assert!(current(
            &dir,
            Tier::SafeValidation,
            "t",
            "2030-01-01T00:00:00Z"
        ));
        assert!(!current(
            &dir,
            Tier::SafeValidation,
            "other",
            "2030-01-01T00:00:00Z"
        ));
        assert!(!current(
            &dir,
            Tier::ActiveRecon,
            "t",
            "2030-01-01T00:00:00Z"
        ));
        // A Lab Coat record expires; a revocation ends it immediately.
        let g = Grant {
            ts: "2026-10-02T00:00:00Z".into(),
            op: "o".into(),
            target: "t".into(),
            capability: "safe-validation".into(),
            tier: "3".into(),
            approved_by: "me".into(),
            reason: "r".into(),
            status: "approved".into(),
            expires_at: "2026-10-03T00:00:00Z".into(),
        };
        ndjson::append(&p, &g.to_object()).unwrap();
        assert!(current(
            &dir,
            Tier::SafeValidation,
            "t",
            "2026-10-02T12:00:00Z"
        ));
        assert!(!current(
            &dir,
            Tier::SafeValidation,
            "t",
            "2026-10-03T00:00:00Z"
        ));
        let r = Grant {
            status: "revoked".into(),
            expires_at: String::new(),
            ..g.clone()
        };
        ndjson::append(&p, &r.to_object()).unwrap();
        assert!(!current(
            &dir,
            Tier::SafeValidation,
            "t",
            "2026-10-02T12:00:00Z"
        ));
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .ends_with("\"status\":\"approved\",\"expires_at\":\"2026-10-03T00:00:00Z\"}")
        );
        assert_eq!(list(&dir).unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
