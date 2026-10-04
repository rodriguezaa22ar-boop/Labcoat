//! The lab root and the directory layout under it.
//!
//! Mirrors `lib/common.sh`: `LAB_ROOT` (or `LCOAT_ROOT`) names the root,
//! `etc/lab.env` under it may override each `LAB_*` directory, and each
//! `LAB_*` environment variable overrides both. Two deliberate differences
//! from Lite: an unset root is an error rather than a warning (the field
//! test showed lab data landing in `$HOME`), and nothing here creates
//! directories; read-only commands never touch the disk.

use std::path::{Path, PathBuf};

use lcoat_format::envfile::Record;

use crate::error::{Error, Result};

/// The value the shell build writes into `SOURCE_TOOL`; kept so the three
/// implementations recognise one another's operations.
pub const TOOL_NAME: &str = "atlas";

/// Resolved directories for one lab root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabRoot {
    /// The root itself.
    pub root: PathBuf,
    /// `state/`
    pub state_dir: PathBuf,
    /// `targets/`
    pub targets_dir: PathBuf,
    /// `sessions/`
    pub sessions_dir: PathBuf,
    /// `reports/`
    pub reports_dir: PathBuf,
    /// Scope profiles directory.
    pub profiles_dir: PathBuf,
    /// `state/atlas/`
    pub atlas_state: PathBuf,
    /// `state/atlas/active.env`
    pub active_file: PathBuf,
}

impl LabRoot {
    /// Resolve from the environment. `LAB_ROOT` wins over `LCOAT_ROOT`;
    /// neither set is an error.
    pub fn from_env() -> Result<Self> {
        let root = ["LAB_ROOT", "LCOAT_ROOT"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .find(|v| !v.is_empty());
        let Some(root) = root else {
            return Err(Error::user(
                "LCOAT_ROOT is not set; set it once: echo 'export LCOAT_ROOT=\"$HOME/lcoat-lab\"' >> ~/.bashrc",
            ));
        };
        Self::at(Path::new(&root))
    }

    /// Resolve for an explicit root (relative paths are made absolute
    /// against the current directory, without resolving symlinks).
    pub fn at(root: &Path) -> Result<Self> {
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()?.join(root)
        };

        let config_path = match std::env::var("LAB_CONFIG") {
            Ok(v) if !v.is_empty() => PathBuf::from(v),
            _ => root.join("etc").join("lab.env"),
        };
        let config = Record::load(&config_path).unwrap_or_default();
        let pick = |key: &str, fallback: PathBuf| -> PathBuf {
            if let Ok(v) = std::env::var(key)
                && !v.is_empty()
            {
                return PathBuf::from(v);
            }
            let c = config.get(key);
            if !c.is_empty() {
                return PathBuf::from(c);
            }
            fallback
        };

        let state_dir = pick("LAB_STATE_DIR", root.join("state"));
        let targets_dir = pick("LAB_TARGETS_DIR", root.join("targets"));
        let sessions_dir = pick("LAB_SESSIONS_DIR", root.join("sessions"));
        let reports_dir = pick("LAB_REPORTS_DIR", root.join("reports"));
        let mut profiles_dir = pick("ATLAS_SCOPE_PROFILES_DIR", PathBuf::new());
        if profiles_dir.as_os_str().is_empty() {
            let candidates = [
                root.join("tools").join("atlas").join("profiles"),
                root.join("profiles"),
            ];
            profiles_dir = candidates
                .iter()
                .find(|c| c.is_dir())
                .cloned()
                .unwrap_or_else(|| candidates[0].clone());
        }
        let atlas_state = state_dir.join("atlas");
        let active_file = atlas_state.join("active.env");
        Ok(Self {
            root,
            state_dir,
            targets_dir,
            sessions_dir,
            reports_dir,
            profiles_dir,
            atlas_state,
            active_file,
        })
    }

    /// The session directory for an operation slug.
    pub fn op_dir(&self, slug: &str) -> PathBuf {
        self.sessions_dir.join(slug)
    }

    /// Create the directories a mutating command expects (0700).
    pub fn ensure_layout(&self) -> Result<()> {
        for d in [
            &self.state_dir,
            &self.targets_dir,
            &self.sessions_dir,
            &self.reports_dir,
            &self.atlas_state,
        ] {
            mkdir_private(d)?;
        }
        Ok(())
    }
}

pub use lcoat_format::fsutil::{file_exists, mkdir_private};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_defaults_hang_off_root() {
        let r = LabRoot::at(Path::new("/tmp/lcoat-root-test")).unwrap();
        assert_eq!(
            r.sessions_dir,
            PathBuf::from("/tmp/lcoat-root-test/sessions")
        );
        assert_eq!(
            r.active_file,
            PathBuf::from("/tmp/lcoat-root-test/state/atlas/active.env")
        );
        assert_eq!(
            r.op_dir("x"),
            PathBuf::from("/tmp/lcoat-root-test/sessions/x")
        );
        assert_eq!(
            r.profiles_dir,
            PathBuf::from("/tmp/lcoat-root-test/tools/atlas/profiles")
        );
    }

    #[test]
    fn relative_root_is_made_absolute() {
        let r = LabRoot::at(Path::new("rel")).unwrap();
        assert!(r.root.is_absolute());
        assert!(r.root.ends_with("rel"));
    }
}
