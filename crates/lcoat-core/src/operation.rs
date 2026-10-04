//! Target records, operation session records and the active-operation
//! pointer, in the shell build's layout, with the lifecycle as types.
//!
//! [`Operation<AnyState>`] is what `load` returns and what every read-only
//! consumer (verifiers, readiness, the CLI's listing commands) takes.
//! [`Operation<Active>`] and [`Operation<Closed>`] are obtained by checking
//! the recorded `STATUS`, and the write side is split between them: new
//! evidence, findings, approvals and tool runs need `Active`; the closeout,
//! audit and archive packets need `Closed`; `close` and `resume` convert one
//! into the other. A caller holding the wrong state has no method to call,
//! so "add evidence to a closed operation" is a compile error here rather
//! than a runtime refusal.
//!
//! Every mutating method takes the operation lock (`<op dir>/.lock`) for its
//! duration and follows the transaction order in `docs/BLUEPRINT.md`.

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::envfile::{Record, upsert_file};
use lcoat_format::fsutil::{file_exists, mkdir_private};
use lcoat_format::ids::{is_safe_slug, slugify};

use crate::error::{Error, Result};
use crate::fail;
use crate::history;
use crate::ledger::{self, Event, Ledger};
use crate::lock::Lock;
use crate::root::{LabRoot, TOOL_NAME};
use crate::scope::{self, Decision, Profile, ScopedTarget, Snapshot, TargetInfo};
use crate::tier::Tier;

// --- targets --------------------------------------------------------------

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

/// Inputs to [`add_target`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewTarget {
    /// Display name; its slug is the file stem.
    pub name: String,
    /// Address.
    pub address: String,
    /// `unknown`, `review`, `in-scope`, `out-of-scope`.
    pub scope_status: String,
    /// `unknown`, `low`, `medium`, `high`, `critical`.
    pub criticality: String,
    /// Space-separated tags.
    pub tags: String,
    /// Owner.
    pub owner: String,
    /// Notes.
    pub notes: String,
}

/// Write a new target record in the shell build's key order; returns the
/// slug. Refuses an existing slug, an empty slug, or invalid enumerations.
pub fn add_target(root: &LabRoot, t: &NewTarget) -> Result<String> {
    let slug = slugify(&t.name);
    if !is_safe_slug(&slug) {
        fail!(
            "target name {:?} does not make a usable file name (slug {slug:?}); use letters or digits",
            t.name
        );
    }
    if !scope::valid_scope_status(&t.scope_status) {
        fail!(
            "expected target scope status unknown, review, in-scope, or out-of-scope; got: {}",
            t.scope_status
        );
    }
    if !scope::valid_criticality(&t.criticality) {
        fail!(
            "expected target criticality unknown, low, medium, high, or critical; got: {}",
            t.criticality
        );
    }
    let _lock = Lock::acquire(&root.atlas_state)?;
    let path = root.targets_dir.join(format!("{slug}.env"));
    if path.symlink_metadata().is_ok() {
        fail!("target already exists: {slug}");
    }
    mkdir_private(&root.targets_dir)?;
    let mut rec = Record::new();
    rec.upsert("NAME", t.name.as_str());
    rec.upsert("ADDRESS", t.address.as_str());
    rec.upsert("SCOPE_STATUS", t.scope_status.as_str());
    rec.upsert("CRITICALITY", t.criticality.as_str());
    rec.upsert("TAGS", t.tags.as_str());
    rec.upsert("OWNER", t.owner.as_str());
    rec.upsert("NOTES", t.notes.as_str());
    rec.upsert("CREATED_AT", clock::timestamp());
    rec.save(&path)?;
    Ok(slug)
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

// --- lifecycle states -----------------------------------------------------

mod sealed {
    pub trait Sealed {}
}

/// A lifecycle state marker. Sealed: only the three states below exist.
pub trait State: sealed::Sealed + Copy + std::fmt::Debug + Default + PartialEq + Eq {}

/// Loaded without checking `STATUS`; what every read-only API accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnyState;
/// `STATUS=active`: evidence, findings, approvals and tool runs are allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Active;
/// `STATUS=closed`: closeout, audit and archive packets are allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Closed;

impl sealed::Sealed for AnyState {}
impl sealed::Sealed for Active {}
impl sealed::Sealed for Closed {}
impl State for AnyState {}
impl State for Active {}
impl State for Closed {}

/// The session record file name.
pub const SESSION_FILE: &str = "session.env";

const OP_SUBDIRS: &[&str] = &[
    "loot",
    "pcaps",
    "notes",
    "logs",
    "tmp",
    "recon-runs",
    "action-sessions",
    "evidence",
    "findings",
    "validation-plans",
];

/// A loaded `session.env` for an atlas operation, tagged with its lifecycle
/// state. The fields are the record; the state is only in the type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation<S: State = AnyState> {
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
    /// The lab root the operation was loaded from.
    pub root: LabRoot,
    _state: PhantomData<S>,
}

/// An operation whose state has been read from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Loaded {
    /// `STATUS=active`
    Active(Operation<Active>),
    /// `STATUS=closed`
    Closed(Operation<Closed>),
}

impl Loaded {
    /// The state-erased view.
    pub fn any(&self) -> Operation<AnyState> {
        match self {
            Loaded::Active(o) => o.retag(),
            Loaded::Closed(o) => o.retag(),
        }
    }
}

// --- read side: every state -----------------------------------------------

impl<S: State> Operation<S> {
    fn retag<T: State>(&self) -> Operation<T> {
        Operation {
            name: self.name.clone(),
            slug: self.slug.clone(),
            target: self.target.clone(),
            target_address: self.target_address.clone(),
            target_label: self.target_label.clone(),
            scope_status: self.scope_status.clone(),
            criticality: self.criticality.clone(),
            tags: self.tags.clone(),
            owner: self.owner.clone(),
            status: self.status.clone(),
            created_at: self.created_at.clone(),
            closed_at: self.closed_at.clone(),
            last_resumed_at: self.last_resumed_at.clone(),
            notes: self.notes.clone(),
            dir: self.dir.clone(),
            file: self.file.clone(),
            root: self.root.clone(),
            _state: PhantomData,
        }
    }

    /// The state-erased view, for APIs that take `&Operation`.
    pub fn as_any(&self) -> Operation<AnyState> {
        self.retag()
    }

    /// Re-read `session.env` (after a mutation) and classify.
    pub fn reload(&self) -> Result<Loaded> {
        Operation::load(&self.root, &self.slug)?.classify()
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
    pub fn events(&self) -> Result<Vec<Event>> {
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

    /// Whether a current (approved, unexpired) approval exists for this
    /// capability and target. See [`crate::approval`].
    pub fn has_approval(&self, capability: Tier, target: &str) -> bool {
        crate::approval::current(&self.dir, capability, target, &clock::timestamp())
    }

    /// Whether the record says `closed`.
    pub fn is_closed(&self) -> bool {
        self.status == "closed"
    }

    /// Whether this is the active operation of its root.
    pub fn is_active(&self) -> bool {
        Operation::active_slug(&self.root).as_deref() == Some(self.slug.as_str())
    }

    /// Evaluate a preflight against the snapshot and record the decision as
    /// a `scope.preflight` ledger event (`allowed` or `denied`). Returns the
    /// decision; the caller surfaces the refusal. Recording the decision is
    /// a ledger append, which every state may do: a denied attempt against
    /// a closed operation is still worth a line in its trail.
    pub fn preflight(
        &self,
        capability: Tier,
        tool: &str,
        target: &str,
        reason: &str,
    ) -> Result<Decision> {
        let snap = self.snapshot()?;
        let d = snap.preflight(capability, target, reason, |c| {
            self.has_approval(c, &snap.target)
        });
        self.append_ledger(
            "scope.preflight",
            capability.capability(),
            tool,
            d.status(),
            &d.detail,
        )?;
        Ok(d)
    }

    /// Preflight `target` for `capability`, record the decision, and on
    /// success hand back the [`ScopedTarget`] the adapter runner requires.
    /// The address comes from the scope snapshot when the identifier matches
    /// the operation's target, so operator arguments never supply a host.
    pub fn scoped_target(
        &self,
        capability: Tier,
        tool: &str,
        target: &str,
        reason: &str,
    ) -> Result<ScopedTarget> {
        let snap = self.snapshot()?;
        self.preflight(capability, tool, target, reason)?
            .into_result()?;
        let address = if snap.target_matches(target) && !snap.target_address.is_empty() {
            snap.target_address.clone()
        } else {
            target.to_owned()
        };
        Ok(ScopedTarget::new(target, &address, capability))
    }

    /// `atlas_ledger_append_current`: append an event for this operation.
    /// Public for the adapter runner's `adapter.*` events; the detail is a
    /// [`MetadataOnly`] so nothing raw can be recorded through it.
    pub fn append_event(
        &self,
        event: &str,
        capability: Tier,
        tool: &str,
        status: &str,
        detail: &crate::metadata::MetadataOnly,
    ) -> Result<()> {
        self.append_ledger(
            event,
            capability.capability(),
            tool,
            status,
            detail.as_str(),
        )
    }

    pub(crate) fn append_ledger(
        &self,
        event: &str,
        capability: &str,
        tool: &str,
        status: &str,
        detail: &str,
    ) -> Result<()> {
        Ledger::of(&self.dir).append(Event {
            ts: String::new(),
            event: event.to_owned(),
            op: self.slug.clone(),
            target: self.target.clone(),
            capability: capability.to_owned(),
            tool: tool.to_owned(),
            status: status.to_owned(),
            detail: detail.to_owned(),
            line: 0,
        })
    }

    /// Take the operation lock for a mutating command.
    pub(crate) fn lock(&self) -> Result<Lock> {
        Lock::acquire(&self.dir)
    }
}

// --- loading ---------------------------------------------------------------

impl Operation<AnyState> {
    /// Load by name or slug, as `load_atlas_operation` does.
    pub fn load(root: &LabRoot, name: &str) -> Result<Self> {
        let slug = slugify(name);
        if !is_safe_slug(&slug) {
            fail!("unknown operation: {slug}");
        }
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
            root: root.clone(),
            _state: PhantomData,
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
    pub fn is_active_slug(root: &LabRoot, slug: &str) -> bool {
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

    /// Read the recorded state into the type.
    pub fn classify(self) -> Result<Loaded> {
        match self.status.as_str() {
            "active" => Ok(Loaded::Active(self.retag())),
            "closed" => Ok(Loaded::Closed(self.retag())),
            other => fail!("operation '{}' has an unknown status: {other:?}", self.slug),
        }
    }

    /// The operation as `Active`, or the shell build's refusal.
    pub fn into_active(self) -> Result<Operation<Active>> {
        match self.classify()? {
            Loaded::Active(o) => Ok(o),
            Loaded::Closed(o) => fail!(
                "operation '{}' is closed; resume it first with 'lcoat op resume {}'",
                o.slug,
                o.slug
            ),
        }
    }

    /// The operation as `Closed`, or a refusal naming what to do.
    pub fn into_closed(self) -> Result<Operation<Closed>> {
        match self.classify()? {
            Loaded::Closed(o) => Ok(o),
            Loaded::Active(o) => fail!(
                "operation '{}' is still active; close it first with 'lcoat op close'",
                o.slug
            ),
        }
    }
}

// --- write side: starting -------------------------------------------------

/// Inputs to [`Operation::start`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartParams {
    /// Operation name; its slug names the directory.
    pub name: String,
    /// Target name or address.
    pub target: String,
    /// Scope profile (`default` when empty).
    pub profile: String,
    /// Operator notes.
    pub notes: String,
}

fn set_active(root: &LabRoot, slug: &str) -> Result<()> {
    mkdir_private(&root.atlas_state)?;
    let mut rec = Record::new();
    rec.upsert("ACTIVE_OPERATION", slug);
    rec.upsert("SET_AT", clock::timestamp());
    rec.save(&root.active_file)?;
    Ok(())
}

fn clear_active(root: &LabRoot) -> Result<()> {
    match std::fs::remove_file(&root.active_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

impl Operation<Active> {
    /// `cmd_op_start`: resolve the target, refuse out-of-scope, load the
    /// profile, create the directory, write `session.env` and the scope
    /// snapshot, append `op.started`, record history, set active. The order
    /// is the shell's; an interruption before the ledger append leaves a
    /// directory `op list` shows and `op verify` reports as missing ledger.
    pub fn start(root: &LabRoot, p: &StartParams) -> Result<(Self, Profile)> {
        // Lab Coat is stricter than the shell here (field run 1): an
        // unregistered name would become its own "address" and a scan would
        // go wherever DNS sends it. The target must be declared first.
        if load_target(root, &p.target)?.is_none() {
            fail!(
                "unknown target: {}; declare it first: lcoat target add {} <address> --scope-status in-scope",
                p.target,
                p.target
            );
        }
        let target = resolve_target(root, &p.target)?;
        if target.scope_status == "out-of-scope" {
            return Err(scope::out_of_scope_error(&target.target));
        }
        let profile = scope::load_profile(&root.profiles_dir, &p.profile)?;
        let slug = slugify(&p.name);
        if !is_safe_slug(&slug) {
            fail!(
                "operation name {:?} does not make a usable directory name (slug {slug:?}); use letters or digits",
                p.name
            );
        }
        let _state_lock = Lock::acquire(&root.atlas_state)?;
        let dir = root.op_dir(&slug);
        if dir.symlink_metadata().is_ok() {
            fail!("operation already exists: {slug}");
        }
        for sub in OP_SUBDIRS {
            mkdir_private(&dir.join(sub))?;
        }
        let _op_lock = Lock::acquire(&dir)?;
        let mut rec = Record::new();
        rec.upsert("NAME", p.name.as_str());
        rec.upsert("SLUG", slug.as_str());
        rec.upsert("TARGET", target.target.as_str());
        rec.upsert("TARGET_ADDRESS", target.address.as_str());
        rec.upsert("TARGET_LABEL", target.label.as_str());
        rec.upsert("TARGET_SCOPE_STATUS", target.scope_status.as_str());
        rec.upsert("TARGET_CRITICALITY", target.criticality.as_str());
        rec.upsert("TARGET_TAGS", target.tags.as_str());
        rec.upsert("TARGET_OWNER", target.owner.as_str());
        rec.upsert("STATUS", "active");
        rec.upsert("CREATED_AT", clock::timestamp());
        rec.upsert("LAST_RESUMED_AT", clock::timestamp());
        rec.upsert("NOTES", p.notes.as_str());
        rec.upsert("SOURCE_TOOL", TOOL_NAME);
        rec.upsert("MODE", "operation");
        rec.save(&dir.join(SESSION_FILE))?;
        crate::crash::point("start.session");
        scope::write_snapshot(&dir, &target, &profile)?;
        crate::crash::point("start.snapshot");
        Ledger::of(&dir).append(Event {
            ts: String::new(),
            event: "op.started".into(),
            op: slug.clone(),
            target: target.target.clone(),
            capability: Tier::ReadOnly.capability().into(),
            tool: TOOL_NAME.into(),
            status: "ok".into(),
            detail: format!("profile={} notes={}", profile.name, p.notes),
            line: 0,
        })?;
        crate::crash::point("start.ledger");
        history::record(&dir, "start", &target.target)?;
        set_active(root, &slug)?;
        let op = Operation::load(root, &slug)?.into_active()?;
        Ok((op, profile))
    }

    /// `cmd_op_close`: set `STATUS`/`CLOSED_AT`, append the readiness and
    /// `op.closed` events, record history, clear the active pointer. The
    /// caller passes the readiness verdict and the `op.close.readiness`
    /// detail it computed (see [`crate::readiness::State::ledger_detail`]).
    pub fn close(self, readiness_status: &str, detail: &str) -> Result<Operation<Closed>> {
        let _lock = self.lock()?;
        upsert_file(&self.file, "STATUS", "closed")?;
        upsert_file(&self.file, "CLOSED_AT", &clock::timestamp())?;
        crate::crash::point("close.status");
        self.append_ledger(
            "op.close.readiness",
            Tier::ReadOnly.capability(),
            TOOL_NAME,
            readiness_status,
            detail,
        )?;
        crate::crash::point("close.readiness-event");
        self.append_ledger(
            "op.closed",
            Tier::ReadOnly.capability(),
            TOOL_NAME,
            "ok",
            &format!("{} {detail}", self.target),
        )?;
        crate::crash::point("close.closed-event");
        history::record(&self.dir, "close", &self.target)?;
        if self.is_active() {
            let _state_lock = Lock::acquire(&self.root.atlas_state)?;
            clear_active(&self.root)?;
        }
        Operation::load(&self.root, &self.slug)?.into_closed()
    }
}

impl Operation<Closed> {
    /// `cmd_op_resume`: reopen, set active, append `op.resumed`.
    pub fn resume(self) -> Result<Operation<Active>> {
        let _lock = self.lock()?;
        for (k, v) in [
            ("STATUS", "active"),
            ("LAST_RESUMED_AT", clock::timestamp().as_str()),
            ("CLOSED_AT", ""),
        ] {
            upsert_file(&self.file, k, v)?;
        }
        {
            let _state_lock = Lock::acquire(&self.root.atlas_state)?;
            set_active(&self.root, &self.slug)?;
        }
        self.append_ledger(
            "op.resumed",
            Tier::ReadOnly.capability(),
            TOOL_NAME,
            "ok",
            &self.target,
        )?;
        history::record(&self.dir, "resume", &self.target)?;
        Operation::load(&self.root, &self.slug)?.into_active()
    }
}

/// Resume by name from any recorded state (`op resume` accepts an operation
/// that is already active, as the shell does: it just re-marks it active).
pub fn resume(root: &LabRoot, name: &str) -> Result<Operation<Active>> {
    match Operation::load(root, name)?.classify()? {
        Loaded::Closed(o) => o.resume(),
        Loaded::Active(o) => {
            let _lock = o.lock()?;
            for (k, v) in [
                ("STATUS", "active"),
                ("LAST_RESUMED_AT", clock::timestamp().as_str()),
                ("CLOSED_AT", ""),
            ] {
                upsert_file(&o.file, k, v)?;
            }
            {
                let _state_lock = Lock::acquire(&o.root.atlas_state)?;
                set_active(&o.root, &o.slug)?;
            }
            o.append_ledger(
                "op.resumed",
                Tier::ReadOnly.capability(),
                TOOL_NAME,
                "ok",
                &o.target,
            )?;
            history::record(&o.dir, "resume", &o.target)?;
            Operation::load(&o.root, &o.slug)?.into_active()
        }
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
        assert_eq!(Operation::list(&r).unwrap().len(), 1);

        // State classification.
        assert!(matches!(o.clone().classify().unwrap(), Loaded::Closed(_)));
        assert!(
            o.clone()
                .into_active()
                .unwrap_err()
                .to_string()
                .contains("is closed; resume it first")
        );
        let closed = o.clone().into_closed().unwrap();
        assert_eq!(closed.as_any(), o);

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
        assert!(Operation::is_active_slug(&r, "astra-review"));
        assert!(o.is_active());
        assert_eq!(
            Operation::load_named_or_active(&r, "").unwrap().slug,
            "astra-review"
        );
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
        let slug = add_target(
            &r,
            &NewTarget {
                name: "Astra".into(),
                address: "100.71.57.96".into(),
                scope_status: "in-scope".into(),
                criticality: "unknown".into(),
                tags: "lab".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(slug, "astra");
        let text = std::fs::read_to_string(target_file(&r, "astra")).unwrap();
        assert!(text.starts_with("NAME=Astra\nADDRESS=100.71.57.96\nSCOPE_STATUS=in-scope\nCRITICALITY=unknown\nTAGS=lab\nOWNER=''\nNOTES=''\nCREATED_AT="), "{text}");
        assert!(
            add_target(
                &r,
                &NewTarget {
                    name: "astra".into(),
                    address: "x".into(),
                    scope_status: "unknown".into(),
                    criticality: "unknown".into(),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .to_string()
            .contains("already exists")
        );
        assert!(
            add_target(
                &r,
                &NewTarget {
                    name: "b".into(),
                    address: "x".into(),
                    scope_status: "maybe".into(),
                    criticality: "unknown".into(),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .to_string()
            .contains("scope status")
        );
        let t = resolve_target(&r, "astra").unwrap();
        assert_eq!(
            (
                t.target.as_str(),
                t.address.as_str(),
                t.scope_status.as_str(),
                t.criticality.as_str()
            ),
            ("Astra", "100.71.57.96", "in-scope", "unknown")
        );
        assert_eq!(list_targets(&r).unwrap().len(), 1);
        assert!(load_target(&r, "missing").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_close_resume_lifecycle() {
        let (r, dir) = root("lifecycle");
        add_target(
            &r,
            &NewTarget {
                name: "node".into(),
                address: "10.10.10.5".into(),
                scope_status: "in-scope".into(),
                criticality: "medium".into(),
                ..Default::default()
            },
        )
        .unwrap();
        add_target(
            &r,
            &NewTarget {
                name: "forbidden".into(),
                address: "10.10.10.6".into(),
                scope_status: "out-of-scope".into(),
                criticality: "unknown".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let err = Operation::start(
            &r,
            &StartParams {
                name: "x".into(),
                target: "forbidden".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("marked out-of-scope"));

        let (op, profile) = Operation::start(
            &r,
            &StartParams {
                name: "Full Op".into(),
                target: "node".into(),
                profile: String::new(),
                notes: "authorized".into(),
            },
        )
        .unwrap();
        assert_eq!(profile.name, "default");
        assert_eq!(op.slug, "full-op");
        assert_eq!(op.target_address, "10.10.10.5");
        assert!(op.is_active());
        assert!(op.dir.join("evidence").is_dir());
        assert!(op.dir.join(".lock").is_file());
        let events = op.events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "op.started");
        assert_eq!(events[0].detail, "profile=default notes=authorized");
        assert_eq!(history::read(&op.dir)[0].event, "start");
        assert!(
            Operation::start(
                &r,
                &StartParams {
                    name: "full-op".into(),
                    target: "node".into(),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .to_string()
            .contains("already exists")
        );

        // A preflight records its decision whatever the outcome.
        let d = op
            .preflight(Tier::ActiveRecon, "nmap", "elsewhere", "test")
            .unwrap();
        assert!(!d.allowed);
        let d = op
            .preflight(Tier::ActiveRecon, "nmap", "10.10.10.5", "test")
            .unwrap();
        assert!(d.allowed);
        let events = op.events().unwrap();
        assert_eq!(events[1].status, "denied");
        assert_eq!(events[2].status, "allowed");

        let closed = op
            .close("attention-required", "readiness=attention-required force=1")
            .unwrap();
        assert!(closed.is_closed());
        assert!(!closed.closed_at.is_empty());
        assert!(Operation::active_slug(&r).is_none());
        let events = closed.events().unwrap();
        assert_eq!(events[3].event, "op.close.readiness");
        assert_eq!(events[4].event, "op.closed");
        assert_eq!(
            events[4].detail,
            "node readiness=attention-required force=1"
        );
        assert!(
            Operation::load(&r, "full-op")
                .unwrap()
                .into_active()
                .is_err()
        );

        let again = closed.resume().unwrap();
        assert!(again.is_active());
        assert!(again.closed_at.is_empty());
        assert_eq!(again.events().unwrap()[5].event, "op.resumed");
        assert_eq!(
            history::read(&again.dir)
                .iter()
                .map(|e| e.event.as_str())
                .collect::<Vec<_>>(),
            ["start", "close", "resume"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_target_variants() {
        let (r, dir) = root("fmt");
        let mut o: Operation<AnyState> = Operation {
            name: "t".into(),
            slug: "t".into(),
            target: "t".into(),
            target_address: "t".into(),
            target_label: "t".into(),
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
            root: r,
            _state: PhantomData,
        };
        assert_eq!(o.format_target(), "t");
        o.target_label = "lbl".into();
        assert_eq!(o.format_target(), "t (lbl)");
        o.target_address = "1.2.3.4".into();
        assert_eq!(o.format_target(), "t (lbl) -> 1.2.3.4");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
