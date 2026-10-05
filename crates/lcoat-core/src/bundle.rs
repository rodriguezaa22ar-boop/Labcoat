//! Evidence bundles: a copy of an operation's shareable evidence with a
//! manifest a recipient can re-verify elsewhere (`lib/evidence.sh`,
//! `cmd_evidence_bundle`).
//!
//! Layout, as the shell build writes it, under
//! `<op>/evidence-bundles/<slug>/`:
//!
//! - `files/<id>-<included_as>-<name>`: one copy per eligible record;
//! - `manifest.ndjson`: one record per file, in the shell's field order;
//! - `README.md`: the shell's summary, plus how to verify.
//!
//! Eligibility is the shell's: a redacted record is bundled (its redacted
//! copy when one exists), a `public` one is bundled, anything else only with
//! `--include-unredacted`, and without the flag one such record refuses the
//! whole bundle.
//!
//! Lab Coat differences, all additive:
//!
//! - The source is re-hashed against its record before it is copied, so a
//!   bundle is never made from evidence that changed since capture; paths
//!   that leave the operation directory, and anything that is not a regular
//!   file, are refused.
//! - The bundle is staged in a hidden directory and renamed into place, so
//!   a half-written bundle never carries the final name.
//! - The ledger event adds `manifest_sha256=<sha>` to the shell's detail, so
//!   the hash-chained ledger anchors the manifest from the moment the bundle
//!   exists; the handoff, closeout and archive packets carry the same hash on
//!   an `Evidence bundle manifest:` line.
//! - [`verify_dir`] and [`verify_in_op`] re-check a bundle: every file
//!   against the manifest, no unlisted files, the manifest against its
//!   anchor, and (inside the operation) every source hash against the
//!   evidence index. The shell build has no bundle verifier.

use std::fs;
use std::path::{Component, Path, PathBuf};

use lcoat_format::clock;
use lcoat_format::fsutil::{copy_private_new, mkdir_private, write_private};
use lcoat_format::hash::Sha256Hex;
use lcoat_format::ids::{is_safe_slug, slugify};
use lcoat_format::json::{Object, Value};
use lcoat_format::ndjson;

use crate::error::Result;
use crate::evidence;
use crate::fail;
use crate::ledger;
use crate::operation::{Active, Operation, State};
use crate::root::TOOL_NAME;
use crate::tier::Tier;

/// The ledger event a bundle is recorded under.
pub const EVENT: &str = "evidence.bundle.generated";
/// Sub-directory of the operation that holds bundles.
pub const DIR: &str = "evidence-bundles";
/// The bundle's manifest file name.
pub const MANIFEST: &str = "manifest.ndjson";
/// The bundle's copied files live here.
pub const FILES: &str = "files";

/// `<op>/evidence-bundles`.
pub fn root_dir(op_dir: &Path) -> PathBuf {
    op_dir.join(DIR)
}

/// One manifest line, in the shell build's field order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Entry {
    pub id: String,
    pub operation: String,
    pub target: String,
    pub kind: String,
    pub classification: String,
    pub redacted: bool,
    pub original_path: String,
    pub original_sha256: String,
    /// `redacted`, `public` or `unredacted`.
    pub included_as: String,
    pub source_path: String,
    pub source_sha256: String,
    /// `files/<name>`, relative to the bundle directory.
    pub bundle_path: String,
    pub bundled_sha256: String,
    pub bundled_at: String,
}

impl Entry {
    /// Decode from a manifest object.
    pub fn from_object(o: &Object) -> Self {
        Self {
            id: o.str("id").to_owned(),
            operation: o.str("operation").to_owned(),
            target: o.str("target").to_owned(),
            kind: o.str("kind").to_owned(),
            classification: o.str("classification").to_owned(),
            redacted: o.bool("redacted"),
            original_path: o.str("original_path").to_owned(),
            original_sha256: o.str("original_sha256").to_owned(),
            included_as: o.str("included_as").to_owned(),
            source_path: o.str("source_path").to_owned(),
            source_sha256: o.str("source_sha256").to_owned(),
            bundle_path: o.str("bundle_path").to_owned(),
            bundled_sha256: o.str("bundled_sha256").to_owned(),
            bundled_at: o.str("bundled_at").to_owned(),
        }
    }

    /// Encode in the shell build's field order.
    pub fn to_object(&self) -> Object {
        let s = |v: &str| Value::String(v.to_owned());
        let mut o = Object::new();
        o.insert("id", s(&self.id));
        o.insert("operation", s(&self.operation));
        o.insert("target", s(&self.target));
        o.insert("kind", s(&self.kind));
        o.insert("classification", s(&self.classification));
        o.insert("redacted", Value::Bool(self.redacted));
        o.insert("original_path", s(&self.original_path));
        o.insert("original_sha256", s(&self.original_sha256));
        o.insert("included_as", s(&self.included_as));
        o.insert("source_path", s(&self.source_path));
        o.insert("source_sha256", s(&self.source_sha256));
        o.insert("bundle_path", s(&self.bundle_path));
        o.insert("bundled_sha256", s(&self.bundled_sha256));
        o.insert("bundled_at", s(&self.bundled_at));
        o
    }
}

/// What an evidence record contributes to a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Source {
    id: String,
    kind: String,
    classification: String,
    redacted: bool,
    original_path: String,
    original_sha256: String,
    included_as: &'static str,
    source_path: String,
    source_sha256: String,
}

/// `atlas_evidence_bundle_source`: which copy of a record is bundled, if any.
fn source_of(o: &Object, include_unredacted: bool) -> Option<(&'static str, String, String)> {
    let classification = if o.nonempty("classification") {
        o.str("classification")
    } else {
        "internal"
    };
    if o.bool("redacted") && o.nonempty("redacted_path") {
        Some((
            "redacted",
            o.str("redacted_path").to_owned(),
            o.str("redacted_sha256").to_owned(),
        ))
    } else if o.bool("redacted") {
        Some((
            "redacted",
            o.str("path").to_owned(),
            o.str("sha256").to_owned(),
        ))
    } else if classification == "public" {
        Some((
            "public",
            o.str("path").to_owned(),
            o.str("sha256").to_owned(),
        ))
    } else if include_unredacted {
        Some((
            "unredacted",
            o.str("path").to_owned(),
            o.str("sha256").to_owned(),
        ))
    } else {
        None
    }
}

/// The eligible records for the operation's target, oldest first by
/// `created_at` then `id`, and the number the flag would have to let in.
fn sources(op_dir: &Path, target: &str, include_unredacted: bool) -> Result<(Vec<Source>, usize)> {
    let ids = crate::scope::identifiers(op_dir, target);
    let mut recs: Vec<Object> = ndjson::latest(&ndjson::read_file(&evidence::index_file(op_dir))?)
        .into_iter()
        .filter(|o| ids.iter().any(|t| t == o.str("target")))
        .collect();
    recs.sort_by(|a, b| {
        a.str("created_at")
            .cmp(b.str("created_at"))
            .then_with(|| a.str("id").cmp(b.str("id")))
    });
    let mut out = Vec::new();
    let mut blocked = 0;
    for o in &recs {
        if source_of(o, false).is_none() {
            blocked += 1;
        }
        let Some((included_as, source_path, source_sha256)) = source_of(o, include_unredacted)
        else {
            continue;
        };
        out.push(Source {
            id: if o.nonempty("id") { o.str("id") } else { "?" }.to_owned(),
            kind: if o.nonempty("kind") {
                o.str("kind")
            } else {
                "?"
            }
            .to_owned(),
            classification: if o.nonempty("classification") {
                o.str("classification")
            } else {
                "internal"
            }
            .to_owned(),
            redacted: o.bool("redacted"),
            original_path: o.str("path").to_owned(),
            original_sha256: o.str("sha256").to_owned(),
            included_as,
            source_path,
            source_sha256,
        });
    }
    Ok((out, blocked))
}

/// Whether a recorded path stays inside the directory it is relative to:
/// not empty, not absolute, no `..` and no root or prefix component.
pub fn is_contained(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Whether a manifest `bundle_path` is `files/<one safe name>`.
pub fn is_bundle_path(path: &str) -> bool {
    path.strip_prefix("files/")
        .is_some_and(|name| !name.contains('/') && !name.contains('\\') && is_safe_slug(name))
}

/// A regular file that is not a symlink.
fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// `atlas_evidence_safe_name`: the slug of the base name, or `artifact`.
fn safe_name(path: &str) -> String {
    let base = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let s = slugify(&base);
    if s.is_empty() { "artifact".into() } else { s }
}

/// The recorded facts about one bundle, from its ledger event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// Event timestamp.
    pub at: String,
    /// Bundle slug.
    pub slug: String,
    /// `files=` count.
    pub files: String,
    /// `0` or `1`.
    pub include_unredacted: String,
    /// Format 1.1 `manifest_sha256=` (empty for a shell-written bundle).
    pub manifest_sha256: String,
}

impl Recorded {
    /// Parse an `evidence.bundle.generated` detail, as
    /// `atlas_handoff_latest_bundle_fields` does (unknown tokens ignored).
    pub fn parse(at: &str, detail: &str) -> Self {
        let mut r = Self {
            at: at.to_owned(),
            ..Self::default()
        };
        for part in detail.split_whitespace() {
            if let Some(v) = part.strip_prefix("bundle=") {
                v.clone_into(&mut r.slug);
            } else if let Some(v) = part.strip_prefix("files=") {
                v.clone_into(&mut r.files);
            } else if let Some(v) = part.strip_prefix("include_unredacted=") {
                v.clone_into(&mut r.include_unredacted);
            } else if let Some(v) = part.strip_prefix("manifest_sha256=") {
                v.clone_into(&mut r.manifest_sha256);
            }
        }
        r
    }

    /// `<op>/evidence-bundles/<slug>`, or `None` for a slug that would
    /// leave that directory.
    pub fn dir(&self, op_dir: &Path) -> Option<PathBuf> {
        is_safe_slug(&self.slug).then(|| root_dir(op_dir).join(&self.slug))
    }
}

/// The latest recorded bundle, if any.
pub fn latest_recorded(events: &[ledger::Event]) -> Option<Recorded> {
    ledger::latest(events, &[EVENT]).map(|e| Recorded::parse(&e.ts, &e.detail))
}

/// The latest recorded event for one slug.
fn recorded_for(events: &[ledger::Event], slug: &str) -> Option<Recorded> {
    events
        .iter()
        .rev()
        .filter(|e| e.event == EVENT)
        .map(|e| Recorded::parse(&e.ts, &e.detail))
        .find(|r| r.slug == slug)
}

/// A bundle that was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// Slug (directory name).
    pub slug: String,
    /// Absolute bundle directory.
    pub dir: PathBuf,
    /// Absolute manifest path.
    pub manifest: PathBuf,
    /// sha256 of the manifest, as recorded in the ledger.
    pub manifest_sha256: String,
    /// Number of bundled files.
    pub files: usize,
    /// Whether `--include-unredacted` was given.
    pub include_unredacted: bool,
}

/// `cmd_evidence_bundle`: select, re-hash, copy into a staging directory,
/// write the manifest and README, rename into place, append the ledger
/// event. Only an active operation is bundled (the shell's rule: a bundle
/// after close would be a ledger event the closeout does not allow).
pub fn write(op: &Operation<Active>, name: &str, include_unredacted: bool) -> Result<Bundle> {
    let index = evidence::index_file(&op.dir);
    if fs::metadata(&index).map(|m| m.len() == 0).unwrap_or(true) {
        fail!("no evidence recorded yet");
    }
    let _lock = op.lock()?;
    let (sources, blocked) = sources(&op.dir, &op.target, include_unredacted)?;
    if !include_unredacted && blocked > 0 {
        fail!(
            "redaction required before bundling: {blocked} non-public evidence record(s) are unredacted (pass --include-unredacted to bundle them as they are)"
        );
    }
    if sources.is_empty() {
        fail!("no bundle-eligible evidence records found");
    }
    let name = if name.is_empty() {
        format!("{}-evidence-bundle", op.slug)
    } else {
        name.to_owned()
    };
    let slug = slugify(&name);
    if slug.is_empty() {
        fail!("evidence bundle name produced an empty slug");
    }
    if !is_safe_slug(&slug) {
        fail!(
            "evidence bundle name {name:?} does not make a usable directory name (slug {slug:?})"
        );
    }
    let root = root_dir(&op.dir);
    let dir = root.join(&slug);
    if fs::symlink_metadata(&dir).is_ok() {
        fail!("evidence bundle already exists: {slug}");
    }

    // Every source is checked before anything is written.
    for s in &sources {
        if !is_contained(&s.source_path) {
            fail!(
                "evidence '{}' has a bundle source outside the operation directory: {}",
                s.id,
                s.source_path
            );
        }
        let abs = op.dir.join(&s.source_path);
        if !is_regular(&abs) {
            fail!(
                "missing bundle source for evidence '{}': {}",
                s.id,
                abs.display()
            );
        }
        if s.source_sha256.is_empty() {
            fail!(
                "evidence '{}' has no recorded sha256 for its bundle source",
                s.id
            );
        }
        let actual = Sha256Hex::of_file(&abs)?;
        if actual.as_str() != s.source_sha256 {
            fail!(
                "evidence '{}' changed since capture (expected_sha={} actual_sha={}); run 'lcoat evidence verify' before bundling",
                s.id,
                s.source_sha256,
                actual.as_str()
            );
        }
    }

    mkdir_private(&root)?;
    let staging = root.join(format!(".{slug}.{}.tmp", std::process::id()));
    if fs::symlink_metadata(&staging).is_ok() {
        fs::remove_dir_all(&staging)?;
    }
    let staged = stage(op, &staging, &sources, include_unredacted);
    let (manifest_sha256, files) = match staged {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    crate::crash::point("bundle.staged");
    if let Err(e) = fs::rename(&staging, &dir) {
        let _ = fs::remove_dir_all(&staging);
        return Err(e.into());
    }
    if let Ok(d) = fs::File::open(&root) {
        let _ = d.sync_all();
    }
    crate::crash::point("bundle.renamed");
    let include = if include_unredacted { "1" } else { "0" };
    op.append_ledger(
        EVENT,
        Tier::ReadOnly.capability(),
        TOOL_NAME,
        "ok",
        &format!(
            "bundle={slug} files={files} include_unredacted={include} manifest_sha256={manifest_sha256}"
        ),
    )?;
    Ok(Bundle {
        manifest: dir.join(MANIFEST),
        dir,
        slug,
        manifest_sha256,
        files,
        include_unredacted,
    })
}

/// Copy, hash and describe every source inside `staging`; returns the
/// manifest's sha256 and the file count.
fn stage(
    op: &Operation<Active>,
    staging: &Path,
    sources: &[Source],
    include_unredacted: bool,
) -> Result<(String, usize)> {
    mkdir_private(&staging.join(FILES))?;
    let mut manifest = Vec::new();
    let mut entries = Vec::new();
    for s in sources {
        let bundle_path = format!(
            "{FILES}/{}-{}-{}",
            s.id,
            s.included_as,
            safe_name(&s.source_path)
        );
        if !is_bundle_path(&bundle_path) {
            fail!(
                "evidence '{}' does not make a usable bundle file name: {bundle_path}",
                s.id
            );
        }
        let dst = staging.join(&bundle_path);
        copy_private_new(&op.dir.join(&s.source_path), &dst)?;
        let bundled = Sha256Hex::of_file(&dst)?;
        if bundled.as_str() != s.source_sha256 {
            fail!("bundle copy integrity check failed for evidence '{}'", s.id);
        }
        let e = Entry {
            id: s.id.clone(),
            operation: op.slug.clone(),
            target: op.target.clone(),
            kind: s.kind.clone(),
            classification: s.classification.clone(),
            redacted: s.redacted,
            original_path: s.original_path.clone(),
            original_sha256: s.original_sha256.clone(),
            included_as: s.included_as.to_owned(),
            source_path: s.source_path.clone(),
            source_sha256: s.source_sha256.clone(),
            bundle_path,
            bundled_sha256: bundled.as_str().to_owned(),
            bundled_at: clock::timestamp(),
        };
        manifest.extend(lcoat_format::canonical::compact(&Value::Object(
            e.to_object(),
        )));
        manifest.push(b'\n');
        entries.push(e);
    }
    write_private(&staging.join(MANIFEST), &manifest)?;
    let manifest_sha256 = Sha256Hex::of_bytes(&manifest).as_str().to_owned();
    write_private(
        &staging.join("README.md"),
        readme(op, &entries, include_unredacted, &manifest_sha256).as_bytes(),
    )?;
    Ok((manifest_sha256, entries.len()))
}

fn readme(
    op: &Operation<Active>,
    entries: &[Entry],
    include_unredacted: bool,
    manifest_sha256: &str,
) -> String {
    let mut b = String::new();
    b.push_str("# Atlas Evidence Bundle\n\n");
    b.push_str(&format!("Generated: {}\n", clock::timestamp()));
    b.push_str(&format!("Operation: {}\n", op.name));
    b.push_str(&format!("Operation ID: {}\n", op.slug));
    b.push_str(&format!("Target: {}\n", op.target));
    b.push_str(&format!(
        "Include unredacted: {}\n",
        u8::from(include_unredacted)
    ));
    b.push_str(&format!("Files: {}\n", entries.len()));
    b.push_str("\n## Files\n\n");
    for e in entries {
        b.push_str(&format!(
            "- {} / {} / {} / sha256={} / `{}`\n",
            e.id, e.included_as, e.classification, e.bundled_sha256, e.bundle_path
        ));
    }
    b.push_str("\n## Verify\n\n");
    b.push_str(&format!("- Manifest sha256: {manifest_sha256}\n"));
    b.push_str("- Compare it with the `Evidence bundle manifest:` line of the handoff, closeout or archive packet, then run `lcoat evidence bundle-verify <this directory> --manifest-sha256 <that hash>`.\n");
    b.push_str("- This README is a summary; the manifest and its anchored hash are what verify.\n");
    b
}

// --- verification ------------------------------------------------------------

/// One file row of a bundle verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCheck {
    /// Evidence id (or `-` for an unlisted file).
    pub id: String,
    /// `verified`, `changed`, `inconsistent`, `missing`, `not-a-file`,
    /// `unsafe-path`, `duplicate`, `unlisted`, `index-mismatch` or
    /// `not-in-index`.
    pub status: &'static str,
    /// `files/<name>` (as recorded, or as found for an unlisted file).
    pub path: String,
    /// Extra detail (hashes) for a failed check.
    pub detail: String,
}

/// The result of verifying one bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleVerify {
    /// The bundle directory.
    pub dir: String,
    /// The manifest's `operation`, else `-`.
    pub operation: String,
    /// The manifest's current sha256.
    pub manifest_sha256: String,
    /// The anchored sha256 the manifest was compared with, if any.
    pub expected_manifest_sha256: String,
    /// Where the anchor came from: `ledger`, `argument`, or `none`.
    pub anchor: &'static str,
    /// `verified`, `changed`, `unanchored` or `malformed`.
    pub manifest_status: &'static str,
    /// Manifest-level problems (operation mismatch, parse error), as text.
    pub manifest_problems: Vec<String>,
    /// One row per manifest line and per unlisted file.
    pub files: Vec<FileCheck>,
    /// Problems counted.
    pub problems: usize,
    /// `verified`, `unanchored` (consistent, but nothing to compare the
    /// manifest hash with) or `attention-required`.
    pub status: &'static str,
}

impl BundleVerify {
    /// Number of manifest rows checked (unlisted files excluded).
    pub fn checked(&self) -> usize {
        self.files.iter().filter(|f| f.status != "unlisted").count()
    }
}

/// Verify a bundle directory on its own, as a recipient would: every
/// listed file against the manifest, no unlisted files, and the manifest
/// against `expected` when one is given (from a packet's `Evidence bundle
/// manifest:` line). Needs no lab root.
pub fn verify_dir(dir: &Path, expected: &str) -> Result<BundleVerify> {
    let manifest_path = dir.join(MANIFEST);
    if !is_regular(&manifest_path) {
        fail!("not an evidence bundle (no {MANIFEST}): {}", dir.display());
    }
    let bytes = fs::read(&manifest_path)?;
    let actual = Sha256Hex::of_bytes(&bytes).as_str().to_owned();
    let mut v = BundleVerify {
        dir: dir.display().to_string(),
        operation: "-".into(),
        manifest_sha256: actual.clone(),
        expected_manifest_sha256: String::new(),
        anchor: "none",
        manifest_status: "unanchored",
        manifest_problems: Vec::new(),
        files: Vec::new(),
        problems: 0,
        status: "verified",
    };
    if !expected.is_empty() {
        v.anchor = "argument";
        v.expected_manifest_sha256 = expected.to_owned();
        if expected == actual {
            v.manifest_status = "verified";
        } else {
            v.manifest_status = "changed";
            v.problems += 1;
        }
    }
    let text = String::from_utf8_lossy(&bytes);
    let entries: Vec<Entry> = match ndjson::parse_lines(&text, MANIFEST) {
        Ok(objs) => objs.iter().map(Entry::from_object).collect(),
        Err(e) => {
            v.manifest_status = "malformed";
            v.manifest_problems.push(e.to_string());
            v.problems += 1;
            v.finish();
            return Ok(v);
        }
    };
    if entries.is_empty() {
        v.manifest_problems.push("manifest lists no files".into());
        v.problems += 1;
    }
    let mut ops: Vec<&str> = entries.iter().map(|e| e.operation.as_str()).collect();
    ops.sort_unstable();
    ops.dedup();
    match ops[..] {
        [] => {}
        [one] => one.clone_into(&mut v.operation),
        _ => {
            v.operation = ops.join(",");
            v.manifest_problems
                .push(format!("manifest names {} operations", ops.len()));
            v.problems += 1;
        }
    }

    let mut seen: Vec<String> = Vec::new();
    for e in &entries {
        let mut c = FileCheck {
            id: if e.id.is_empty() {
                "?".into()
            } else {
                e.id.clone()
            },
            status: "verified",
            path: e.bundle_path.clone(),
            detail: String::new(),
        };
        if seen.contains(&e.id) || seen.contains(&e.bundle_path) {
            c.status = "duplicate";
        } else if !is_bundle_path(&e.bundle_path) {
            c.status = "unsafe-path";
        } else {
            let full = dir.join(&e.bundle_path);
            if fs::symlink_metadata(&full).is_err() {
                c.status = "missing";
                c.detail = format!("expected_sha={}", or_unknown(&e.bundled_sha256));
            } else if !is_regular(&full) {
                c.status = "not-a-file";
            } else {
                let got = Sha256Hex::of_file(&full)?;
                if got.as_str() != e.bundled_sha256 {
                    c.status = "changed";
                    c.detail = format!(
                        "expected_sha={} actual_sha={}",
                        or_unknown(&e.bundled_sha256),
                        got.as_str()
                    );
                } else if !e.source_sha256.is_empty() && e.source_sha256 != e.bundled_sha256 {
                    // The copy matches its line, but the line says the copy
                    // differs from its source: the manifest contradicts itself.
                    c.status = "inconsistent";
                    c.detail = format!(
                        "source_sha={} bundled_sha={}",
                        e.source_sha256, e.bundled_sha256
                    );
                }
            }
        }
        seen.push(e.id.clone());
        seen.push(e.bundle_path.clone());
        if c.status != "verified" {
            v.problems += 1;
        }
        v.files.push(c);
    }

    // Anything in files/ the manifest does not list.
    let files_dir = dir.join(FILES);
    if let Ok(rd) = fs::read_dir(&files_dir) {
        let mut extra: Vec<String> = rd
            .filter_map(std::result::Result::ok)
            .map(|d| format!("{FILES}/{}", d.file_name().to_string_lossy()))
            .filter(|p| !entries.iter().any(|e| &e.bundle_path == p))
            .collect();
        extra.sort();
        for p in extra {
            v.problems += 1;
            v.files.push(FileCheck {
                id: "-".into(),
                status: "unlisted",
                path: p,
                detail: String::new(),
            });
        }
    }
    v.finish();
    Ok(v)
}

impl BundleVerify {
    fn finish(&mut self) {
        self.status = if self.problems > 0 {
            "attention-required"
        } else if self.manifest_status == "verified" {
            "verified"
        } else {
            "unanchored"
        };
    }
}

fn or_unknown(s: &str) -> &str {
    if s.is_empty() { "unknown" } else { s }
}

/// Resolve a bundle of an operation: the latest recorded one when `name`
/// is empty, else a slug (or name) under `evidence-bundles/`.
pub fn resolve<S: State>(op: &Operation<S>, name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        let events = ledger::read(&op.dir)?;
        let Some(r) = latest_recorded(&events) else {
            fail!(
                "no evidence bundle recorded for operation '{}'; run 'lcoat evidence bundle' first",
                op.slug
            );
        };
        let Some(dir) = r.dir(&op.dir) else {
            fail!("recorded evidence bundle has an unusable name: {}", r.slug);
        };
        return Ok(dir);
    }
    let slug = slugify(name);
    if !is_safe_slug(&slug) {
        fail!(
            "unknown evidence bundle for operation '{}': {name}",
            op.slug
        );
    }
    let dir = root_dir(&op.dir).join(&slug);
    if !dir.is_dir() {
        fail!(
            "unknown evidence bundle for operation '{}': {name}",
            op.slug
        );
    }
    Ok(dir)
}

/// Verify a bundle inside its operation: everything [`verify_dir`] checks,
/// with the manifest anchored by the ledger event that recorded it (and by
/// `expected` too when given), the manifest's operation checked, and every
/// source hash compared with the evidence index.
pub fn verify_in_op<S: State>(
    op: &Operation<S>,
    dir: &Path,
    expected: &str,
) -> Result<BundleVerify> {
    let mut v = verify_dir(dir, expected)?;
    let slug = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let events = ledger::read(&op.dir)?;
    match recorded_for(&events, &slug) {
        Some(r) if !r.manifest_sha256.is_empty() => {
            if v.manifest_status != "malformed" && r.manifest_sha256 != v.manifest_sha256 {
                if v.manifest_status != "changed" {
                    v.problems += 1;
                }
                v.manifest_status = "changed";
            } else if v.anchor == "none" && v.manifest_status != "malformed" {
                v.manifest_status = "verified";
            }
            if v.expected_manifest_sha256.is_empty() {
                v.expected_manifest_sha256 = r.manifest_sha256;
            }
            v.anchor = if v.anchor == "argument" {
                "argument+ledger"
            } else {
                "ledger"
            };
        }
        Some(_) => {}
        None => {
            v.manifest_problems.push(format!(
                "no {EVENT} event records this bundle (interrupted write?)"
            ));
            v.problems += 1;
        }
    }
    if v.operation != "-" && v.operation != op.slug {
        v.manifest_problems.push(format!(
            "manifest belongs to '{}', not '{}'",
            v.operation, op.slug
        ));
        v.problems += 1;
    }

    // Each source hash must still be the one the evidence index records.
    let index = ndjson::latest(&ndjson::read_file(&evidence::index_file(&op.dir))?);
    let manifest = ndjson::read_file(&dir.join(MANIFEST)).unwrap_or_default();
    for (row, e) in v
        .files
        .iter_mut()
        .zip(manifest.iter().map(Entry::from_object))
    {
        if row.status != "verified" {
            continue;
        }
        let Some(rec) = index.iter().find(|o| o.str("id") == e.id) else {
            row.status = "not-in-index";
            v.problems += 1;
            continue;
        };
        let want = match source_of(rec, true) {
            Some((_, _, sha)) => sha,
            None => String::new(),
        };
        if want != e.source_sha256 {
            row.status = "index-mismatch";
            row.detail = format!(
                "index_sha={} manifest_sha={}",
                or_unknown(&want),
                or_unknown(&e.source_sha256)
            );
            v.problems += 1;
        }
    }
    v.finish();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_must_stay_inside() {
        assert!(is_contained("evidence/ev_1/a.txt"));
        assert!(is_contained("./evidence/a"));
        for bad in ["", "/etc/passwd", "../x", "evidence/../../x"] {
            assert!(!is_contained(bad), "{bad}");
        }
        assert!(is_bundle_path("files/ev_1-public-a.txt"));
        for bad in [
            "files/",
            "files/.hidden",
            "files/a/b",
            "files/..",
            "other/a",
            "/files/a",
            "files/a\\b",
        ] {
            assert!(!is_bundle_path(bad), "{bad}");
        }
    }

    #[test]
    fn eligibility_follows_the_shell() {
        let obj = |json: &str| match Value::parse(json).unwrap() {
            Value::Object(o) => o,
            _ => unreachable!(),
        };
        let public = obj(r#"{"classification":"public","redacted":false,"path":"p","sha256":"s"}"#);
        assert_eq!(source_of(&public, false).unwrap().0, "public");
        let internal = obj(r#"{"redacted":false,"path":"p","sha256":"s"}"#);
        assert!(source_of(&internal, false).is_none());
        assert_eq!(source_of(&internal, true).unwrap().0, "unredacted");
        let redacted = obj(
            r#"{"redacted":true,"path":"p","sha256":"s","redacted_path":"r","redacted_sha256":"rs"}"#,
        );
        assert_eq!(
            source_of(&redacted, false).unwrap(),
            ("redacted", "r".to_owned(), "rs".to_owned())
        );
        let redacted_in_place = obj(r#"{"redacted":true,"path":"p","sha256":"s"}"#);
        assert_eq!(
            source_of(&redacted_in_place, false).unwrap(),
            ("redacted", "p".to_owned(), "s".to_owned())
        );
    }

    #[test]
    fn recorded_detail_parses_known_tokens() {
        let r = Recorded::parse(
            "t",
            "bundle=demo-evidence-bundle files=2 include_unredacted=0 manifest_sha256=abc extra=1",
        );
        assert_eq!(r.slug, "demo-evidence-bundle");
        assert_eq!(r.files, "2");
        assert_eq!(r.include_unredacted, "0");
        assert_eq!(r.manifest_sha256, "abc");
        assert!(
            Recorded::parse("t", "bundle=.. files=1")
                .dir(Path::new("/op"))
                .is_none()
        );
    }

    #[test]
    fn standalone_verify_catches_edits_injections_and_forged_anchors() {
        let dir = std::env::temp_dir().join(format!("lcoat-bundle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(FILES)).unwrap();
        fs::write(dir.join("files/ev_1-public-a.txt"), b"hello\n").unwrap();
        let sum = Sha256Hex::of_bytes(b"hello\n");
        let e = Entry {
            id: "ev_1".into(),
            operation: "demo".into(),
            included_as: "public".into(),
            source_sha256: sum.as_str().into(),
            bundle_path: "files/ev_1-public-a.txt".into(),
            bundled_sha256: sum.as_str().into(),
            ..Entry::default()
        };
        let mut line = lcoat_format::canonical::compact(&Value::Object(e.to_object()));
        line.push(b'\n');
        fs::write(dir.join(MANIFEST), &line).unwrap();
        let msha = Sha256Hex::of_bytes(&line).as_str().to_owned();

        let v = verify_dir(&dir, "").unwrap();
        assert_eq!((v.status, v.problems, v.checked()), ("unanchored", 0, 1));
        assert_eq!(v.manifest_sha256, msha);
        assert_eq!(v.operation, "demo");
        let v = verify_dir(&dir, &msha).unwrap();
        assert_eq!(v.status, "verified");
        let v = verify_dir(&dir, &"0".repeat(64)).unwrap();
        assert_eq!(
            (v.status, v.manifest_status),
            ("attention-required", "changed")
        );

        fs::write(dir.join("files/extra.txt"), b"x").unwrap();
        let v = verify_dir(&dir, &msha).unwrap();
        assert_eq!(v.files[1].status, "unlisted");
        fs::remove_file(dir.join("files/extra.txt")).unwrap();

        fs::write(dir.join("files/ev_1-public-a.txt"), b"edited\n").unwrap();
        let v = verify_dir(&dir, &msha).unwrap();
        assert_eq!(v.files[0].status, "changed");
        fs::remove_file(dir.join("files/ev_1-public-a.txt")).unwrap();
        let v = verify_dir(&dir, &msha).unwrap();
        assert_eq!(v.files[0].status, "missing");

        fs::write(dir.join(MANIFEST), b"{not json\n").unwrap();
        let v = verify_dir(&dir, "").unwrap();
        assert_eq!(
            (v.status, v.manifest_status),
            ("attention-required", "malformed")
        );
        assert!(verify_dir(&dir.join(FILES), "").is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
