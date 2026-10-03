//! Target records, operation session records and the active-operation
//! pointer, in the shell build's layout.
//!
//! This is the loading side. Creating, resuming and closing operations is
//! the typestate lifecycle of phase 2 (`Operation<Active>` / `<Closed>`);
//! everything here takes `&` and writes nothing.

use std::path::{Path, PathBuf};

use lcoat_format::envfile::Record;
use lcoat_format::ids::slugify;
use lcoat_format::ndjson;

use crate::error::{Error, Result};
use crate::fail;
use crate::ledger;
use crate::root::{LabRoot, TOOL_NAME, file_exists};
use crate::scope::{self, Snapshot, TargetInfo};
use crate::tier::Tier;

/// A target registry record (`targets/<slug>.env`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Target {
    /// File stem.
    pub slug: String,
    /// `NAME`
    pub name: String,
    /// `ADDRESS`
    pub address: String,
    /// `SCOPE_STATUS`
    pub scope_status: String,
    /// `CRITICALITY`
    pub criticality: String,
    /// `TAGS`
    pub tags: String,
    /// `OWNER`
    pub owner: String,
    /// `NOTES`
    pub notes: String,
    /// `CREATED_AT`
    pub created_at: String,
    /// The record file.
    pub file: PathBuf,
}

impl Target {
    fn from_record(path: &Path, rec: &Record) -> Self {
        let slug = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            slug,
            name: rec.get("NAME").to_owned(),
            address: rec.get("ADDRESS").to_owned(),
            scope_status: rec.get("SCOPE_STATUS").to_owned(),
            criticality: rec.get("CRITICALITY").to_owned(),
            tags: rec.get("TAGS").to_owned(),
            owner: rec.get("OWNER").to_owned(),
            notes: rec.get("NOTES").to_owned(),
            created_at: rec.get("CREATED_AT").to_owned(),
            file: path.to_path_buf(),
        }
    }
}

/// The env path for a target name or slug.
pub fn target_file(root: &LabRoot, name: &str) -> PathBuf {
    root.targets_dir.join(format!("{}.env", slugify(name)))
}

/// Read a target record; `None` when it does not exist.
pub fn load_target(root: &LabRoot, name: &str) -> Result<Option<Target>> {
    let path = target_file(root, name);
    match Record::load(&path) {
        Ok(rec) => Ok(Some(Target::from_record(&path, &rec))),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(Error::Env(e)),
    }
}

/// Every target record in file-name order. A missing directory is empty.
pub fn list_targets(root: &LabRoot) -> Result<Vec<Target>> {
    let mut paths = Vec::new();
    match std::fs::read_dir(&root.targets_dir) {
        Ok(entries) => {
            for entry in entries {
                let p = entry?.path();
                if p.extension().is_some_and(|x| x == "env") && p.is_file() {
                    paths.push(p);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Io(e)),
    }
    paths.sort();
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let rec = Record::load(&p)?;
        out.push(Target::from_record(&p, &rec));
    }
    Ok(out)
}

fn or_unknown(s: &str) -> String {
    if s.is_empty() {
        "unknown".to_owned()
    } else {
        s.to_owned()
    }
}

/// `resolve_target_input`: a registered target supplies its metadata; any
/// other input is used verbatim with unknown status.
pub fn resolve_target(root: &LabRoot, input: &str) -> Result<TargetInfo> {
    let Some(t) = load_target(root, input)? else {
        return Ok(TargetInfo {
            target: input.to_owned(),
            address: input.to_owned(),
            label: input.to_owned(),
            scope_status: "unknown".into(),
            criticality: "unknown".into(),
            ..Default::default()
        });
    };
    let name = if t.name.is_empty() {
        input.to_owned()
    } else {
        t.name.clone()
    };
    let address = if t.address.is_empty() {
        name.clone()
    } else {
        t.address.clone()
    };
    Ok(TargetInfo {
        target: name.clone(),
        address,
        label: name,
        scope_status: or_unknown(&t.scope_status),
        criticality: or_unknown(&t.criticality),
        tags: t.tags,
        owner: t.owner,
    })
}

/// A loaded `session.env` for an atlas operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// `NAME`
    pub name: String,
    /// `SLUG`
    pub slug: String,
    /// `TARGET`
    pub target: String,
    /// `TARGET_ADDRESS` (falls back to the target).
    pub target_address: String,
    /// `TARGET_LABEL` (falls back to the target).
    pub target_label: String,
    /// `TARGET_SCOPE_STATUS` or `unknown`.
    pub scope_status: String,
    /// `TARGET_CRITICALITY` or `unknown`.
    pub criticality: String,
    /// `TARGET_TAGS`
    pub tags: String,
    /// `TARGET_OWNER`
    pub owner: String,
    /// `STATUS`: `active` or `closed`.
    pub status: String,
    /// `CREATED_AT`
    pub created_at: String,
    /// `CLOSED_AT`
    pub closed_at: String,
    /// `LAST_RESUMED_AT`
    pub last_resumed_at: String,
    /// `NOTES`
    pub notes: String,
    /// The session directory.
    pub dir: PathBuf,
    /// `session.env`
    pub file: PathBuf,
}

/// The session record file name.
pub const SESSION_FILE: &str = "session.env";

impl Operation {
    /// Load by name or slug, as `load_atlas_operation` does.
    pub fn load(root: &LabRoot, name: &str) -> Result<Self> {
        let slug = slugify(name);
        let dir = root.op_dir(&slug);
        let path = dir.join(SESSION_FILE);
        let rec = match Record::load(&path) {
            Ok(r) => r,
            Err(e) if e.is_not_found() => fail!("unknown operation: {slug}"),
            Err(e) => return Err(Error::Env(e)),
        };
        if rec.get("SOURCE_TOOL") != TOOL_NAME {
            fail!("not an atlas operation: {slug}");
        }
        if rec.get("MODE") != "operation" {
            fail!("invalid atlas operation record: {slug}");
        }
        let target = rec.get("TARGET").to_owned();
        let fallback = |key: &str| -> String {
            let v = rec.get(key);
            if v.is_empty() {
                target.clone()
            } else {
                v.to_owned()
            }
        };
        Ok(Self {
            name: rec.get("NAME").to_owned(),
            slug: rec.get("SLUG").to_owned(),
            target_address: fallback("TARGET_ADDRESS"),
            target_label: fallback("TARGET_LABEL"),
            target,
            scope_status: or_unknown(rec.get("TARGET_SCOPE_STATUS")),
            criticality: or_unknown(rec.get("TARGET_CRITICALITY")),
            tags: rec.get("TARGET_TAGS").to_owned(),
            owner: rec.get("TARGET_OWNER").to_owned(),
            status: rec.get("STATUS").to_owned(),
            created_at: rec.get("CREATED_AT").to_owned(),
            closed_at: rec.get("CLOSED_AT").to_owned(),
            last_resumed_at: rec.get("LAST_RESUMED_AT").to_owned(),
            notes: rec.get("NOTES").to_owned(),
            dir,
            file: path,
        })
    }

    /// The active operation slug, or `None` when none is set or the
    /// recorded operation no longer exists.
    pub fn active_slug(root: &LabRoot) -> Option<String> {
        let rec = Record::load(&root.active_file).ok()?;
        let slug = rec.get("ACTIVE_OPERATION");
        if slug.is_empty() || !file_exists(&root.op_dir(slug).join(SESSION_FILE)) {
            return None;
        }
        Some(slug.to_owned())
    }

    /// Load the active operation, or fail as the shell build does.
    pub fn load_active(root: &LabRoot) -> Result<Self> {
        match Self::active_slug(root) {
            Some(slug) => Self::load(root, &slug),
            None => fail!(
                "no active operation; use 'lcoat op start' or 'lcoat op resume', or name a closed operation where the command accepts one"
            ),
        }
    }

    /// Load `name` when given, else the active operation.
    pub fn load_named_or_active(root: &LabRoot, name: &str) -> Result<Self> {
        if name.is_empty() {
            Self::load_active(root)
        } else {
            Self::load(root, name)
        }
    }

    /// Whether `slug` is the active operation.
    pub fn is_active(root: &LabRoot, slug: &str) -> bool {
        Self::active_slug(root).as_deref() == Some(slug)
    }

    /// Every atlas operation in slug order; non-atlas session directories
    /// are skipped.
    pub fn list(root: &LabRoot) -> Result<Vec<Self>> {
        let mut slugs = Vec::new();
        match std::fs::read_dir(&root.sessions_dir) {
            Ok(entries) => {
                for entry in entries {
                    let p = entry?.path();
                    if p.join(SESSION_FILE).is_file()
                        && let Some(name) = p.file_name()
                    {
                        slugs.push(name.to_string_lossy().into_owned());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        slugs.sort();
        Ok(slugs
            .iter()
            .filter_map(|s| Self::load(root, s).ok())
            .collect())
    }

    /// The operation's target fields as snapshot fallbacks.
    pub fn target_info(&self) -> TargetInfo {
        TargetInfo {
            target: self.target.clone(),
            address: self.target_address.clone(),
            label: self.target_label.clone(),
            scope_status: self.scope_status.clone(),
            criticality: self.criticality.clone(),
            tags: self.tags.clone(),
            owner: self.owner.clone(),
        }
    }

    /// The operation's scope snapshot.
    pub fn snapshot(&self) -> Result<Snapshot> {
        scope::load_snapshot(&self.dir, &self.target_info())
    }

    /// The operation ledger path.
    pub fn ledger_file(&self) -> PathBuf {
        ledger::file(&self.dir)
    }

    /// The operation ledger events.
    pub fn events(&self) -> Result<Vec<ledger::Event>> {
        ledger::read(&self.dir)
    }

    /// `format_operation_target`: `target (label) -> address`, each part
    /// only when it adds information.
    pub fn format_target(&self) -> String {
        let mut rendered = self.target.clone();
        if self.target_label != self.target {
            rendered = format!("{} ({})", self.target, self.target_label);
        }
        if !self.target_address.is_empty() && self.target_address != self.target {
            return format!("{rendered} -> {}", self.target_address);
        }
        rendered
    }

    /// `operation_target_matches_identifier`.
    pub fn matches_identifier(&self, target: &str) -> bool {
        target == self.target
            || (!self.target_address.is_empty() && target == self.target_address)
            || (!self.target_label.is_empty() && target == self.target_label)
    }

    /// `atlas_approval_has_current` against `approvals.ndjson`: an approved
    /// record for this capability and target.
    pub fn has_approval(&self, capability: Tier, target: &str) -> bool {
        let Ok(recs) = ndjson::read_file(&self.dir.join("approvals.ndjson")) else {
            return false;
        };
        let cap = capability.capability();
        recs.iter().any(|r| {
            r.str("capability") == cap && r.str("target") == target && r.str("status") == "approved"
        })
    }

    /// Whether the record says `closed`.
    pub fn is_closed(&self) -> bool {
        self.status == "closed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> (LabRoot, PathBuf) {
        let dir = std::env::temp_dir().join(format!("lcoat-op-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (LabRoot::at(&dir).unwrap(), dir)
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn loads_and_lists_atlas_operations_only() {
        let (r, dir) = root("ops");
        write(
            &r.op_dir("astra-review").join(SESSION_FILE),
            "NAME=astra-review\nSLUG=astra-review\nTARGET=astra\nTARGET_ADDRESS=100.71.57.96\nTARGET_LABEL=astra\nTARGET_SCOPE_STATUS=in-scope\nSTATUS=closed\nSOURCE_TOOL=atlas\nMODE=operation\n",
        );
        write(
            &r.op_dir("other").join(SESSION_FILE),
            "NAME=other\nSOURCE_TOOL=labctl\n",
        );
        write(
            &r.op_dir("broken").join(SESSION_FILE),
            "NAME=b\nSOURCE_TOOL=atlas\nMODE=session\n",
        );
        let o = Operation::load(&r, "Astra Review").unwrap();
        assert_eq!(o.slug, "astra-review");
        assert_eq!(o.criticality, "unknown");
        assert_eq!(o.format_target(), "astra -> 100.71.57.96");
        assert!(o.matches_identifier("100.71.57.96"));
        assert!(!o.matches_identifier("elsewhere"));
        assert!(o.is_closed());
        assert!(o.events().unwrap().is_empty());
        assert!(
            Operation::load(&r, "other")
                .unwrap_err()
                .to_string()
                .contains("not an atlas operation: other")
        );
        assert!(
            Operation::load(&r, "broken")
                .unwrap_err()
                .to_string()
                .contains("invalid atlas operation record: broken")
        );
        assert!(
            Operation::load(&r, "nope")
                .unwrap_err()
                .to_string()
                .contains("unknown operation: nope")
        );
        let all = Operation::list(&r).unwrap();
        assert_eq!(all.len(), 1);

        // Active pointer: missing, dangling, present.
        assert!(Operation::active_slug(&r).is_none());
        assert!(
            Operation::load_active(&r)
                .unwrap_err()
                .to_string()
                .starts_with("no active operation")
        );
        write(&r.active_file, "ACTIVE_OPERATION=gone\n");
        assert!(Operation::active_slug(&r).is_none());
        write(&r.active_file, "ACTIVE_OPERATION=astra-review\n");
        assert_eq!(Operation::active_slug(&r).as_deref(), Some("astra-review"));
        assert!(Operation::is_active(&r, "astra-review"));
        assert_eq!(
            Operation::load_named_or_active(&r, "").unwrap().slug,
            "astra-review"
        );

        // Approvals.
        assert!(!o.has_approval(Tier::SafeValidation, "astra"));
        write(
            &o.dir.join("approvals.ndjson"),
            "{\"capability\":\"safe-validation\",\"target\":\"astra\",\"status\":\"approved\"}\n",
        );
        assert!(o.has_approval(Tier::SafeValidation, "astra"));
        assert!(!o.has_approval(Tier::SafeValidation, "elsewhere"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn targets_resolve_with_fallbacks() {
        let (r, dir) = root("targets");
        assert!(list_targets(&r).unwrap().is_empty());
        let t = resolve_target(&r, "10.0.0.5").unwrap();
        assert_eq!(
            (
                t.target.as_str(),
                t.address.as_str(),
                t.scope_status.as_str()
            ),
            ("10.0.0.5", "10.0.0.5", "unknown")
        );
        write(
            &target_file(&r, "Astra"),
            "NAME=astra\nADDRESS=100.71.57.96\nSCOPE_STATUS=in-scope\nCRITICALITY=\n",
        );
        let t = resolve_target(&r, "astra").unwrap();
        assert_eq!(
            (
                t.target.as_str(),
                t.address.as_str(),
                t.scope_status.as_str(),
                t.criticality.as_str()
            ),
            ("astra", "100.71.57.96", "in-scope", "unknown")
        );
        let all = list_targets(&r).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].slug, "astra");
        assert!(load_target(&r, "missing").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_target_variants() {
        let mut o = Operation::load_fixture("t", "t", "t");
        assert_eq!(o.format_target(), "t");
        o.target_label = "lbl".into();
        assert_eq!(o.format_target(), "t (lbl)");
        o.target_address = "1.2.3.4".into();
        assert_eq!(o.format_target(), "t (lbl) -> 1.2.3.4");
    }

    impl Operation {
        fn load_fixture(target: &str, address: &str, label: &str) -> Self {
            Self {
                name: target.into(),
                slug: target.into(),
                target: target.into(),
                target_address: address.into(),
                target_label: label.into(),
                scope_status: "unknown".into(),
                criticality: "unknown".into(),
                tags: String::new(),
                owner: String::new(),
                status: "active".into(),
                created_at: String::new(),
                closed_at: String::new(),
                last_resumed_at: String::new(),
                notes: String::new(),
                dir: PathBuf::new(),
                file: PathBuf::new(),
            }
        }
    }
}
