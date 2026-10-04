//! Scope profiles, the per-operation scope snapshot, and the preflight
//! decision every target-touching command must obtain before it acts.
//!
//! Ported from the shell build's `scope.sh` by way of Lite's `scope.go`.
//! Capabilities are [`Tier`]s here rather than strings, which is what lets
//! the ceiling be enforced by type: a blocked or unknown capability word in
//! a profile is still honoured as text, but the thing a runner asks to
//! execute is always a `Tier`, and `Tier::executable` is checked before any
//! approval is consulted.

use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::envfile::Record;
use lcoat_format::ids::{is_safe_slug, slugify};

use crate::error::{Error, Result};
use crate::tier::Tier;
use crate::{fail, user_err};

/// Default allowed capability list.
pub const DEFAULT_ALLOWED: &str = "read-only passive-recon active-recon safe-validation";
/// Default blocked capability list.
pub const DEFAULT_BLOCKED: &str =
    "destructive persistence credential-spraying denial-of-service out-of-scope-network";
/// Default profile summary.
pub const DEFAULT_SUMMARY: &str = "default bounded Atlas operation profile";
/// Default scope text.
pub const DEFAULT_TEXT: &str =
    "Bounded authorized reconnaissance and defensive posture review for the named target.";

const DEFAULT_ALLOWED_ACTIONS: &[&str] = &[
    "target-first recon against configured scope",
    "service validation and non-invasive fingerprint refresh",
    "HTTP/HTTPS probing of observed web surfaces",
    "HTTP posture review for headers, redirects, metadata routes, and common login/admin routes",
    "bounded API status and CORS preflight posture checks",
    "shared-intel summarization, story views, and report generation",
];

const DEFAULT_OUT_OF_SCOPE: &[&str] = &[
    "exploitation, payload delivery, or persistence",
    "brute forcing, password guessing, credential stuffing, or session hijacking",
    "destructive testing, denial of service, fuzzing, or high-volume crawling",
    "access to third-party systems beyond the configured target",
    "data extraction beyond minimal service, route, header, API status, CORS header, and posture evidence",
];

/// A loaded scope profile with defaults applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Profile name (`PROFILE_NAME` or the requested name).
    pub name: String,
    /// One-line summary.
    pub summary: String,
    /// Scope statement.
    pub scope_text: String,
    /// Whitespace-separated allowed capability words.
    pub allowed_capabilities: String,
    /// Whitespace-separated blocked capability words.
    pub blocked_capabilities: String,
    /// `|`-separated allowed actions (may be empty: defaults apply).
    pub allowed_actions: String,
    /// `|`-separated out-of-scope actions (may be empty: defaults apply).
    pub out_of_scope_actions: String,
    /// `|`-separated recommended workflows.
    pub recommended_workflows: String,
    /// `|`-separated validation lanes.
    pub validation_lanes: String,
}

/// Load a profile as `atlas_scope_load_profile` does. `""` and `"default"`
/// need no file; any other name must exist as `<slug>.env` under
/// `profiles_dir`.
pub fn load_profile(profiles_dir: &Path, name: &str) -> Result<Profile> {
    let name = if name.is_empty() { "default" } else { name };
    let rec = if name == "default" {
        Record::new()
    } else {
        let slug = slugify(name);
        if !is_safe_slug(&slug) {
            fail!("profile name {name:?} does not make a usable file name (slug {slug:?})");
        }
        match Record::load(&profiles_dir.join(format!("{slug}.env"))) {
            Ok(r) => r,
            Err(e) if e.is_not_found() => fail!("unknown Atlas profile: {name}"),
            Err(e) => return Err(Error::Env(e)),
        }
    };
    let pick = |key: &str, fallback: &str| -> String {
        let v = rec.get(key);
        if v.is_empty() {
            fallback.to_owned()
        } else {
            v.to_owned()
        }
    };
    Ok(Profile {
        name: pick("PROFILE_NAME", name),
        summary: pick("PROFILE_SUMMARY", DEFAULT_SUMMARY),
        scope_text: pick("SCOPE_TEXT", DEFAULT_TEXT),
        allowed_capabilities: pick("ALLOWED_CAPABILITIES", DEFAULT_ALLOWED),
        blocked_capabilities: pick("BLOCKED_CAPABILITIES", DEFAULT_BLOCKED),
        allowed_actions: rec.get("ALLOWED_ACTIONS").to_owned(),
        out_of_scope_actions: rec.get("OUT_OF_SCOPE_ACTIONS").to_owned(),
        recommended_workflows: rec.get("RECOMMENDED_WORKFLOWS").to_owned(),
        validation_lanes: rec.get("VALIDATION_LANES").to_owned(),
    })
}

/// The profile env files under `profiles_dir`, in name order. A missing
/// directory is an empty list.
pub fn list_profile_files(profiles_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(profiles_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(Error::Io(e)),
    };
    for entry in entries {
        let p = entry?.path();
        if p.extension().is_some_and(|x| x == "env") && p.is_file() {
            out.push(p);
        }
    }
    out.sort();
    Ok(out)
}

/// Split a `|`-separated list, dropping empty items.
pub fn pipe_lines(value: &str) -> Vec<String> {
    value
        .split('|')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whitespace-separated words.
pub fn words(list: &str) -> Vec<&str> {
    list.split_whitespace().collect()
}

/// `atlas_scope_word_contains`.
pub fn contains(list: &str, wanted: &str) -> bool {
    list.split_whitespace().any(|w| w == wanted)
}

/// Resolved target metadata, as written into a snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetInfo {
    /// Registered name, or the raw input.
    pub target: String,
    /// Address (falls back to the name).
    pub address: String,
    /// Label (falls back to the name).
    pub label: String,
    /// `unknown`, `review`, `in-scope`, `out-of-scope`.
    pub scope_status: String,
    /// `unknown`, `low`, `medium`, `high`, `critical`.
    pub criticality: String,
    /// Free-text tags.
    pub tags: String,
    /// Owner.
    pub owner: String,
}

/// The snapshot file name.
pub const SNAPSHOT_FILE: &str = "scope.snapshot.env";

/// The snapshot path for an operation directory.
pub fn snapshot_file(op_dir: &Path) -> PathBuf {
    op_dir.join(SNAPSHOT_FILE)
}

/// Write the snapshot as `atlas_scope_write_snapshot` does, key order
/// included.
pub fn write_snapshot(op_dir: &Path, t: &TargetInfo, p: &Profile) -> Result<()> {
    let mut rec = Record::new();
    rec.upsert("SCOPE_PROFILE", p.name.as_str());
    rec.upsert("SCOPE_PROFILE_SUMMARY", p.summary.as_str());
    rec.upsert("SCOPE_TARGET", t.target.as_str());
    rec.upsert("SCOPE_TARGET_ADDRESS", t.address.as_str());
    rec.upsert("SCOPE_TARGET_LABEL", t.label.as_str());
    rec.upsert("TARGET_SCOPE_STATUS", t.scope_status.as_str());
    rec.upsert("TARGET_CRITICALITY", t.criticality.as_str());
    rec.upsert("TARGET_TAGS", t.tags.as_str());
    rec.upsert("TARGET_OWNER", t.owner.as_str());
    rec.upsert("SCOPE_TEXT", p.scope_text.as_str());
    rec.upsert("ALLOWED_CAPABILITIES", p.allowed_capabilities.as_str());
    rec.upsert("BLOCKED_CAPABILITIES", p.blocked_capabilities.as_str());
    rec.upsert("ALLOWED_ACTIONS", p.allowed_actions.as_str());
    rec.upsert("OUT_OF_SCOPE_ACTIONS", p.out_of_scope_actions.as_str());
    rec.upsert("RECOMMENDED_WORKFLOWS", p.recommended_workflows.as_str());
    rec.upsert("VALIDATION_LANES", p.validation_lanes.as_str());
    rec.upsert("SNAPSHOT_AT", clock::timestamp());
    rec.save(&snapshot_file(op_dir))?;
    Ok(())
}

/// A loaded scope snapshot with the shell build's fallbacks applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Profile name.
    pub profile: String,
    /// Profile summary.
    pub profile_summary: String,
    /// Target name.
    pub target: String,
    /// Target address.
    pub target_address: String,
    /// Target label.
    pub target_label: String,
    /// Scope status.
    pub target_scope_status: String,
    /// Criticality.
    pub target_criticality: String,
    /// Tags.
    pub target_tags: String,
    /// Owner.
    pub target_owner: String,
    /// Scope statement.
    pub text: String,
    /// Allowed capability words.
    pub allowed: String,
    /// Blocked capability words.
    pub blocked: String,
    /// `|`-separated allowed actions.
    pub allowed_actions: String,
    /// `|`-separated out-of-scope actions.
    pub out_of_scope_actions: String,
    /// `|`-separated recommended workflows.
    pub recommended_workflows: String,
    /// `|`-separated validation lanes.
    pub validation_lanes: String,
}

fn or_unknown(s: &str) -> String {
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s.to_owned()
    }
}

/// Load the snapshot as `atlas_scope_load_snapshot` does. `fallback`
/// supplies the operation's own target fields for a snapshot-less
/// operation.
pub fn load_snapshot(op_dir: &Path, fallback: &TargetInfo) -> Result<Snapshot> {
    let rec = match Record::load(&snapshot_file(op_dir)) {
        Ok(r) => r,
        Err(e) if e.is_not_found() => Record::new(),
        Err(e) => return Err(Error::Env(e)),
    };
    let pick = |key: &str, fb: &str| -> String {
        let v = rec.get(key);
        if v.is_empty() {
            fb.to_owned()
        } else {
            v.to_owned()
        }
    };
    Ok(Snapshot {
        profile: pick("SCOPE_PROFILE", "default"),
        profile_summary: pick("SCOPE_PROFILE_SUMMARY", DEFAULT_SUMMARY),
        target: pick("SCOPE_TARGET", &fallback.target),
        target_address: pick("SCOPE_TARGET_ADDRESS", &fallback.address),
        target_label: pick("SCOPE_TARGET_LABEL", &fallback.label),
        target_scope_status: pick("TARGET_SCOPE_STATUS", &or_unknown(&fallback.scope_status)),
        target_criticality: pick("TARGET_CRITICALITY", &or_unknown(&fallback.criticality)),
        target_tags: pick("TARGET_TAGS", &fallback.tags),
        target_owner: pick("TARGET_OWNER", &fallback.owner),
        text: pick("SCOPE_TEXT", DEFAULT_TEXT),
        allowed: pick("ALLOWED_CAPABILITIES", DEFAULT_ALLOWED),
        blocked: pick("BLOCKED_CAPABILITIES", DEFAULT_BLOCKED),
        allowed_actions: rec.get("ALLOWED_ACTIONS").to_owned(),
        out_of_scope_actions: rec.get("OUT_OF_SCOPE_ACTIONS").to_owned(),
        recommended_workflows: rec.get("RECOMMENDED_WORKFLOWS").to_owned(),
        validation_lanes: rec.get("VALIDATION_LANES").to_owned(),
    })
}

/// The outcome of a preflight. The caller records it in the ledger (so the
/// ledger module stays the only writer) and surfaces `refusal` to the
/// operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Whether the action may proceed.
    pub allowed: bool,
    /// The ledger `detail` field for the `scope.preflight` event.
    pub detail: String,
    /// The operator-facing reason when refused.
    pub refusal: Option<String>,
}

impl Decision {
    /// `allowed` or `denied`: the ledger status word.
    pub fn status(&self) -> &'static str {
        if self.allowed { "allowed" } else { "denied" }
    }

    /// Turn a refusal into an error for the caller to return.
    pub fn into_result(self) -> Result<()> {
        match self.refusal {
            None => Ok(()),
            Some(msg) => Err(Error::User(msg)),
        }
    }
}

/// A target that passed a recorded preflight for a given tier. The fields
/// are read-only and the constructor is private to this crate: the only way
/// to obtain one is [`crate::operation::Operation::scoped_target`], which
/// records the `scope.preflight` decision first. An adapter runner that
/// takes a `ScopedTarget` therefore cannot be handed an unchecked target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedTarget {
    name: String,
    address: String,
    tier: Tier,
}

impl ScopedTarget {
    pub(crate) fn new(name: &str, address: &str, tier: Tier) -> Self {
        Self {
            name: name.to_owned(),
            address: address.to_owned(),
            tier,
        }
    }

    /// Test-only: a target that skipped the preflight. Behind the
    /// `test-support` feature so no binary can reach it.
    #[cfg(feature = "test-support")]
    pub fn new_for_test(name: &str, address: &str, tier: Tier) -> Self {
        Self::new(name, address, tier)
    }

    /// The identifier the operator gave (name, label or address).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The address a tool should be pointed at.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The tier the preflight allowed.
    pub fn tier(&self) -> Tier {
        self.tier
    }
}

impl Snapshot {
    /// An all-empty snapshot, for rendering a profile's action lists.
    pub fn empty() -> Self {
        Self {
            profile: String::new(),
            profile_summary: String::new(),
            target: String::new(),
            target_address: String::new(),
            target_label: String::new(),
            target_scope_status: String::new(),
            target_criticality: String::new(),
            target_tags: String::new(),
            target_owner: String::new(),
            text: String::new(),
            allowed: String::new(),
            blocked: String::new(),
            allowed_actions: String::new(),
            out_of_scope_actions: String::new(),
            recommended_workflows: String::new(),
            validation_lanes: String::new(),
        }
    }

    /// `atlas_scope_target_matches`: name, address or label.
    pub fn target_matches(&self, target: &str) -> bool {
        target == self.target
            || (!self.target_address.is_empty() && target == self.target_address)
            || (!self.target_label.is_empty() && target == self.target_label)
    }

    /// The profile's allowed actions, or the defaults.
    pub fn allowed_action_lines(&self) -> Vec<String> {
        let lines = pipe_lines(&self.allowed_actions);
        if lines.is_empty() {
            DEFAULT_ALLOWED_ACTIONS
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            lines
        }
    }

    /// The profile's out-of-scope list, or the defaults.
    pub fn out_of_scope_lines(&self) -> Vec<String> {
        let lines = pipe_lines(&self.out_of_scope_actions);
        if lines.is_empty() {
            DEFAULT_OUT_OF_SCOPE
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            lines
        }
    }

    /// Evaluate `capability` against this snapshot for `target`.
    ///
    /// Order, as in the shell build: target match, blocked list, allowed
    /// list; then the Lab Coat ceiling (Tier 4 and 5 are refused whatever
    /// the profile says); then the approval gate for Tier 3, answered by
    /// `has_approval`.
    pub fn preflight(
        &self,
        capability: Tier,
        target: &str,
        reason: &str,
        has_approval: impl Fn(Tier) -> bool,
    ) -> Decision {
        let cap = capability.capability();
        let detail = format!("reason={reason}");
        let deny = |detail: String, msg: String| Decision {
            allowed: false,
            detail,
            refusal: Some(msg),
        };
        if !self.target_matches(target) {
            return deny(
                format!("{detail} target={target}"),
                format!(
                    "scope refused: target '{target}' is outside active operation scope '{}'",
                    self.target
                ),
            );
        }
        if contains(&self.blocked, cap) {
            return deny(
                format!("{detail} blocked-capability={cap}"),
                format!("scope refused: capability '{cap}' is blocked"),
            );
        }
        if !contains(&self.allowed, cap) {
            return deny(
                format!("{detail} unsupported-capability={cap}"),
                format!("scope refused: capability '{cap}' is not allowed for this operation"),
            );
        }
        if !capability.executable() {
            return deny(
                format!("{detail} ceiling-refused={cap}"),
                format!(
                    "scope refused: capability '{cap}' is above the Lab Coat ceiling ({}); no approval can unlock it",
                    crate::tier::MAX_EXECUTABLE_TIER
                ),
            );
        }
        if capability.requires_approval() && !has_approval(capability) {
            return deny(
                format!("{detail} approval-required={cap}"),
                format!(
                    "approval required: capability '{cap}' needs a current approval grant for this operation"
                ),
            );
        }
        Decision {
            allowed: true,
            detail: format!("{detail} target={target}"),
            refusal: None,
        }
    }
}

/// Validate a target registry scope status (`target_validate_scope_status`).
pub fn valid_scope_status(s: &str) -> bool {
    matches!(s, "unknown" | "review" | "in-scope" | "out-of-scope")
}

/// Validate a target criticality (`target_validate_criticality`).
pub fn valid_criticality(s: &str) -> bool {
    matches!(s, "unknown" | "low" | "medium" | "high" | "critical")
}

/// The error for an out-of-scope target, as `cmd_op_start` words it.
pub fn out_of_scope_error(target: &str) -> Error {
    user_err!("target '{target}' is marked out-of-scope in target registry")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot {
            profile: "default".into(),
            profile_summary: DEFAULT_SUMMARY.into(),
            target: "astra".into(),
            target_address: "100.71.57.96".into(),
            target_label: "astra".into(),
            target_scope_status: "in-scope".into(),
            target_criticality: "medium".into(),
            target_tags: String::new(),
            target_owner: String::new(),
            text: DEFAULT_TEXT.into(),
            allowed: DEFAULT_ALLOWED.into(),
            blocked: DEFAULT_BLOCKED.into(),
            allowed_actions: String::new(),
            out_of_scope_actions: String::new(),
            recommended_workflows: String::new(),
            validation_lanes: String::new(),
        }
    }

    #[test]
    fn preflight_order_matches_shell_build() {
        let s = snap();
        let d = s.preflight(Tier::ActiveRecon, "elsewhere", "nmap", |_| false);
        assert!(!d.allowed);
        assert_eq!(d.detail, "reason=nmap target=elsewhere");
        assert_eq!(d.status(), "denied");
        assert!(
            d.refusal
                .as_deref()
                .unwrap()
                .contains("outside active operation scope 'astra'")
        );

        let d = s.preflight(Tier::Destructive, "astra", "x", |_| true);
        assert_eq!(d.detail, "reason=x blocked-capability=destructive");

        let d = s.preflight(Tier::IntrusiveValidation, "astra", "x", |_| true);
        assert_eq!(
            d.detail,
            "reason=x unsupported-capability=intrusive-validation"
        );

        let d = s.preflight(Tier::SafeValidation, "100.71.57.96", "x", |_| false);
        assert_eq!(d.detail, "reason=x approval-required=safe-validation");

        let d = s.preflight(Tier::SafeValidation, "100.71.57.96", "x", |_| true);
        assert!(d.allowed);
        assert_eq!(d.detail, "reason=x target=100.71.57.96");
        assert!(d.into_result().is_ok());

        let d = s.preflight(Tier::ActiveRecon, "astra", "nmap", |_| false);
        assert!(d.allowed);
        assert_eq!(d.status(), "allowed");
    }

    #[test]
    fn ceiling_beats_a_permissive_profile() {
        let mut s = snap();
        s.allowed = "read-only intrusive-validation destructive".into();
        s.blocked = String::new();
        let d = s.preflight(Tier::IntrusiveValidation, "astra", "x", |_| true);
        assert!(!d.allowed);
        assert_eq!(d.detail, "reason=x ceiling-refused=intrusive-validation");
        let d = s.preflight(Tier::Destructive, "astra", "x", |_| true);
        assert_eq!(d.detail, "reason=x ceiling-refused=destructive");
    }

    #[test]
    fn default_profile_and_lists() {
        let p = load_profile(Path::new("/nonexistent"), "").unwrap();
        assert_eq!(p.name, "default");
        assert_eq!(p.allowed_capabilities, DEFAULT_ALLOWED);
        assert!(
            load_profile(Path::new("/nonexistent"), "missing")
                .unwrap_err()
                .to_string()
                .contains("unknown Atlas profile: missing")
        );
        assert_eq!(pipe_lines("a|b||c|"), ["a", "b", "c"]);
        assert!(pipe_lines("").is_empty());
        assert!(contains("a b c", "b"));
        assert!(!contains("ab c", "b"));
        assert_eq!(snap().allowed_action_lines().len(), 6);
        assert_eq!(snap().out_of_scope_lines().len(), 5);
    }

    #[test]
    fn snapshot_round_trip_and_fallbacks() {
        let dir = std::env::temp_dir().join(format!("lcoat-scope-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fb = TargetInfo {
            target: "t".into(),
            address: "a".into(),
            label: "l".into(),
            ..Default::default()
        };
        let s = load_snapshot(&dir, &fb).unwrap();
        assert_eq!(
            (
                s.target.as_str(),
                s.target_address.as_str(),
                s.target_scope_status.as_str()
            ),
            ("t", "a", "unknown")
        );
        let p = load_profile(Path::new("/nonexistent"), "default").unwrap();
        let ti = TargetInfo {
            target: "astra".into(),
            address: "10.0.0.1".into(),
            label: "astra".into(),
            scope_status: "in-scope".into(),
            criticality: "low".into(),
            ..Default::default()
        };
        write_snapshot(&dir, &ti, &p).unwrap();
        let text = std::fs::read_to_string(snapshot_file(&dir)).unwrap();
        assert!(text.starts_with("SCOPE_PROFILE=default\n"));
        assert!(text.contains("\nSNAPSHOT_AT="));
        let s = load_snapshot(&dir, &fb).unwrap();
        assert_eq!(s.target_address, "10.0.0.1");
        assert_eq!(s.target_criticality, "low");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
