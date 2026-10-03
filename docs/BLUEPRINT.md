# Lab Coat (Rust) Blueprint

As-of 2026-10-02. The living copy is the Claude doc of the same name; this file tracks it.

## Summary

Lab Coat is the production build of the control plane prototyped as Atlas (shell) and proven as Lab Coat Lite (Go). It is written in Rust so the two rules Lite could only test for, *metadata only* and *in scope*, become things the compiler enforces. The binary keeps the name `lcoat`, picks up at version 0.2.0, and reads every operation the shell and Go builds ever wrote.

The strategy in one line: **upgrade the formats additively, so the shell build stays the oracle.** Every file Lab Coat writes is still accepted by the shell and Go verifiers; the extra fields and manifests it adds are what let its own verifiers catch what theirs cannot. Three implementations verifying each other's output is the exit check for the whole build.

Inputs: the Lite blueprint and go/no-go memo in `GO-project/docs`, the Go conformance fixtures (`learning-op-001`, the demo-site receipt chain, the nmap sample), the shell build pinned at `23ba2d2`, and the two field operations on the Fedora lab server that showed where Lite fell short.

## Goals and non-goals

**Goals**

- Full lifecycle parity with Lite, plus the parts Lite deferred: finding status changes, evidence bundles and manifests, the Tier 3 approval plane, release packets, and a `v1 status` split into *toolchain installed* and *trust artifacts sound*.
- Compile-time enforcement of the two invariants: nothing but scanned metadata reaches a packet or receipt, and nothing runs against a target that is not in the operation's scope.
- A ledger whose entries are chained by hash, so a verifier can point at the exact event that was altered.
- Evidence artifact hashes anchored inside the packets, closing the gap found in the first field test.
- Builds for Linux (amd64, arm64) and macOS, so a scan can run from a second vantage point and the record says which one.
- Lite's field-found bugs fixed by construction: an unset lab root is an error; a missing target cannot shift arguments; adapter timeouts are per adapter.

**Non-goals**

- Rewriting wiremap, vector or intelctl, or any scanner.
- Anything above Tier 3. Tier 4 and 5 stay refused outright.
- A GUI, a server, or a database. Plain files under the lab root remain the store.
- Renaming the `atlas.*` schema IDs. Reserved for a 1.0 decision.

## Compatibility strategy: additive formats

Two facts checked in the Go and shell code make upgrades possible without losing the oracle:

- Both verifiers decode NDJSON into generic objects and ignore unknown keys. Extra fields on a ledger line are invisible to them, and the whole-file SHA-256 they anchor still holds.
- The shell's closeout and archive packets already carry an `Evidence manifest:` slot. Lite wrote `none` there (hence two `unverifiable` gaps in `op verify`). A build that fills the slot is verified by the shell's own `archive-verify`.

So Lab Coat writes **format 1.1**: everything Lite wrote, byte for byte, plus additive fields and the manifests the format already had room for.

| Level | Meaning | Checked by |
| --- | --- | --- |
| Read v1 | Lab Coat verifies every shell/Lite operation with identical verdicts | Golden and tamper fixtures from `GO-project` |
| Write v1-compatible | Shell and Lite verifiers accept every packet Lab Coat writes | Three-way cross-check |
| Verify v1.1 | Lab Coat's verifiers use the additive data to catch what v1 cannot | Rust-only tamper fixtures |

A Lite operation continued by Lab Coat gets chain fields from that point on; its verifier reports the chain as `partial`, never as broken. The `atlas.*` schema IDs and the `jq -cS` canonical hashing stay exactly as they are.

## Architecture

```text
 lcoat (bin)            CLI: argument parsing, exit codes, output rendering. No logic.
   |
   +--> lcoat-adapters  nmap, script, later nuclei/zap. Typed argument parsers,
   |      |             subprocess runner. The only crate that executes anything.
   |      v
   +--> lcoat-core      scope, ledger, evidence, findings, packets, verifiers,
          |             receipts, approvals. Owns MetadataOnly and the operation
          |             typestate. Never spawns a process.
          v
        lcoat-format    strict JSON, canonical (jq -cS), SHA-256, NDJSON, envfile
                        (bash %q), second-resolution IDs. Pure functions.
```

- `lcoat-format` is where every byte-compatibility rule lives; the Go fixtures test it hardest.
- `lcoat-core` takes a `LabRoot` (never the current directory) and exposes the lifecycle as types. Public, auditable.
- `lcoat-adapters` is behind the `adapters` Cargo feature (default on). Building without it yields a verify-only binary.
- `lcoat` maps commands to core calls; a command that would break the packet order does not compile.

Read-only commands take `&Operation<_>`; writing commands take `&mut`. The borrow checker is the "read-only stays read-only" test Lite wrote by hand.

## What Rust buys: invariants as types

1. **Metadata only.** Packet and receipt writers accept only `MetadataOnly`, whose only constructor is the forbidden-content scanner.
2. **In scope.** `AdapterRunner::run` takes a `ScopedTarget`, which only `Scope::preflight` can produce.
3. **Lifecycle and packet order.** `Operation<Active>` / `Operation<Closed>` typestate; each packet constructor requires the previous packet by reference.
4. **Tiers and arguments.** `Tier` is an enum; nmap arguments parse into `enum NmapArg`, so unknown flags fail to parse and positionals have no variant.
5. **Append-only ledger.** `Ledger::append` is the only write; the file is `O_APPEND` under an exclusive lock, private to the type.
6. **Lab root.** `LabRoot::from_env()` returns `Err(RootUnset)` instead of a warning.
7. **Read-only commands.** Verifiers take shared references.

Types cannot prove the scanner's patterns are complete or that a hash covered the right bytes; those stay as tests, property tests and fuzzing.

## Format upgrades (all additive)

| Upgrade | On disk | Fixes | v1 verifiers |
| --- | --- | --- | --- |
| Ledger hash chain | `prev_hash`, `event_hash` per event (SHA-256 of canonical event without those fields + previous `event_hash`; first `prev_hash` null) | names the altered event | ignore the fields |
| Evidence manifest | `evidence/manifest.ndjson`; closeout/archive fill the `Evidence manifest:` slot | edited/deleted artifacts caught by the packet chain | shell already checks the slot |
| Finding lifecycle | `finding resolve/accept/reopen` append a record with the same id; `finding.updated` ledger event | status after `add` | latest-record-per-id readers |
| Scan vantage | `vantage=<hostname>` and `vantage_addr` on adapter evidence and `adapter.started` | self-scan vs external scan distinguishable | extra tokens ignored |
| Approval records | `approvals.ndjson`; `approval.granted` event | Tier 3 under a recorded grant | same file the shell uses |
| Receipt signatures | optional `signature` (ed25519 over `receipt_hash`) + key id | receipts tied to an operator key | unknown keys ignored |

Unchanged: env quoting, NDJSON field order, Markdown packet layouts, canonical form, IDs with `_02` suffixes, `atlas.*` schema IDs.

## Command surface

Every Lite command keeps its name, arguments and output. New: `finding resolve / accept / reopen`, `evidence bundle`, `approval grant / list / revoke`, `ledger chain-verify`, `receipt sign` and `receipt verify --require-signature`, `v1 status` (split `toolchain` / `trust`), `release packet / verify / replay / manifest`, `lcoat doctor`. Not planned: `web`, `flow`, `advisor`.

Two deliberate behaviour changes: an unset lab root is an error; a missing `<target>` is reported before any argument is read.

## Dependencies, toolchain and supply chain

**Default: the library crates use the standard library only, as Lite used Go's.** Lite's zero-dependency supply chain was a strength, and the environment this scaffold was built in has no crates.io access, so anything built on external crates could not have been compiled before hand-over. The formats are small and ours; std has file locking (1.89); SHA-256 and strict JSON are about 200 lines each with exact test vectors. Phase 0 shipped them and they reproduce every golden hash.

Fallback list if a hand-written piece proves costly (adopt with a one-line reason; `cargo deny` keeps the allowlist): `serde`/`serde_json`, `sha2`/`hex`, `regex`, `clap`, `time`, `rustix`, `ed25519-dalek` (phase 4); dev: `proptest`, `assert_cmd`, `trybuild`, `cargo-fuzz`. `#![forbid(unsafe_code)]` everywhere regardless.

- **Toolchain:** stable Rust, MSRV 1.89, edition 2024, `rust-toolchain.toml`. CI: fmt, clippy `-D warnings`, tests with and without adapters, cargo-deny, MSRV build.
- **Builds:** static `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `aarch64-apple-darwin`; `--locked`, stripped, `SHA256SUMS` per release.
- **Nix: dropped for this repo.** An asset for the shell build (exact `bash`/`jq`/coreutils); with zero dependencies and a pinned toolchain Cargo is already reproducible, so Nix would add a contributor requirement without adding assurance. May return in phase 4 for bit-for-bit reproducible release binaries (linker and libc pinning), a build-server concern.

## Conformance

1. **Pinned oracles:** shell `23ba2d2`; Lite `v0.1.4` (`f4039fb`). Fixtures copied read-only into `fixtures/golden/`.
1. **Tamper verdicts recorded first.** `conformance/tamper.sh record` builds a closed operation with the shell build, applies eight cases and writes the shell's verdicts to `fixtures/tamper/*.expect`; `tamper.sh check <bin>` diffs another implementation against them. Done in phase 0; Lite matches on all eight. Notably the shell passes an edited artifact (all verifiers `verified`), which is the gap format 1.1 closes.
2. **Golden hashes first:** ledger file hash (18 events), head event and closeout prefix hashes, artifact hash, all three receipts' `event_hash`/`receipt_hash`. Done in phase 0.
3. **Three-way scenario:** one frozen-clock scenario through shell, Go and Rust; normalized diff; every verifier on every root (9 combinations, 27 runs).
4. **Tamper fixtures, two tiers:** Lite's five must fail identically in all three; two Rust-only (rewritten middle event with file hash recomputed; artifact edited after `evidence bundle`) must fail only in Rust.
5. **Property tests** over canonical JSON, envfile round trip, scanner.
6. **Fuzzing** of envfile, NDJSON, packet anchor and nmap XML parsers. `cargo-fuzz` needs nightly, so it runs as a separate CI job on nightly; local builds and every other job stay on stable.
7. **Compile-fail tests** (`trybuild`) for the type-level claims.
8. **Field validation:** re-run the Fedora lab assessment with Lab Coat; Lite verifies the result; the case study gets a third column.

## Eight-week plan

| Weeks | Phase | Deliverable | Exit check |
| --- | --- | --- | --- |
| 0 | Prepare (done) | Workspace, CI, fixtures, canonical JSON + hashing, `MetadataOnly`, this blueprint | `cargo test` reproduces the golden ledger, artifact and receipt hashes |
| 1–2 | Read and verify v1 | envfile, NDJSON, ledger reader, packet verifiers, `receipt verify/replay`, `op trust-chain`, `evidence verify`; **tamper cases first, verifiers second** | `tamper.sh check target/debug/lcoat LCOAT_ROOT` prints TAMPER OK; identical verdicts on every golden fixture; `receipt verify --json` byte-identical |
| 3–4 | Write v1-compatible | targets, operations, scope, evidence, findings, report, packets, `adapter run`; typestate; `MetadataOnly` on every writer | three-way cross-check clean in all nine directions; compile-fail suite passes |
| 5–6 | Format 1.1 | ledger chain, `evidence bundle`, finding lifecycle, vantage, `ledger chain-verify`, `doctor`; musl + macOS builds | shell and Lite still verify Rust output; Rust-only tamper fixtures fail only in Rust; Mac scan records vantage |
| 7–8 | Trust plane and release | approval plane, `v1 status` split, receipt signatures, release packets; field re-run; 0.2.0 | field operation verified by all three builds; `v0.2.0` tagged with SHA256SUMS |

Schedule risk sits in weeks 3–4. If the typestate fights the format, the format wins and the type gets a documented exception.

## Open decisions

- [x] **Repo:** `rodriguezaa22ar-boop/Labcoat-`, Apache-2.0.
- [x] **Binary name and version.** `lcoat`, 0.2.0 onward. Lite is retired when 0.2.0 ships; `GO-project` stays pinned at v0.1.4 as the oracle, security fixes only.
- [ ] **Public/private split.** Default: one public repo, adapters behind a feature flag.
- [ ] **Edition and MSRV.** Default: 2024 / 1.89, stable only.
- [ ] **Signature scheme.** Default: ed25519, keys in `$LCOAT_ROOT/keys/`. Decide in phase 4.
- [x] **Nix.** Dropped (see Dependencies).
- [ ] **Schema IDs.** Default: keep `atlas.*` through 0.x.
- [ ] **Second vantage.** Default: the Mac build over Tailscale.
- [x] **Ledger event hash definition.** Frozen in `lcoat-core::chain`: `sha256(canonical(event without prev_hash/event_hash) + "\n" + prev_hash_hex_or_empty + "\n")`, first `prev_hash` null. Two test vectors computed independently with `jq -cS` and `sha256sum` pin it.

## Threat model

See `docs/THREAT_MODEL.md`: what a verified operation proves (records unaltered, order, scope checked before every run, metadata only, receipt pins an archive), what it does not (completeness, tool correctness, operator honesty, authorization, firewall behaviour from a self-scan), the adversaries considered, and the known weak points in priority order.

## What is prepared today

Phase-0 scaffold: builds with zero dependencies, clippy-clean under `-D warnings`, 40 tests pass including the day-0 exit check and the frozen chain vectors. `fixtures/tamper/` holds the shell oracle's verdicts for eight tamper cases, and Lite matches all of them. See the README for the crate table and build commands, `fixtures/README.md` for the pinned values, and `conformance/cross_check.sh` for the three-way harness (stages not yet implemented report NOT YET). To pick up phase 1: `lcoat-format::envfile` and `ndjson` against `fixtures/golden/learning-op-001/`, then the packet anchor parser, with `GO-project/internal/{envfile,ndjson,packet}` as the reference.
