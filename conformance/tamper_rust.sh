#!/usr/bin/env bash
# Tamper cases that only format 1.1 can catch.
#
# conformance/tamper.sh replays the shell oracle's eight verdicts; this script
# covers what the oracle cannot say. Each case builds a fresh closed operation
# with the Rust binary (frozen clock), tampers with it in place, and checks the
# verdict lines of the verifiers that exist only here: `evidence verify`, the
# `Evidence Artifacts` and `Ledger Chain` lines of `op trust-chain`, and
# `ledger chain-verify`. When ATLAS_REPO points at the shell build (23ba2d2),
# the same tampered root is also run through the shell's verifiers to show
# the gap: every shell verdict stays `verified`.
#
#   conformance/tamper_rust.sh [rust-bin]        default: target/debug/lcoat
#
# No fixture is written; the expected lines are pinned below. The project
# rule this enforces: a trust gate is only real if it can fail correctly.
set -eu   # no pipefail: the verifiers under test are expected to exit 1 inside the pipelines below

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$HERE/target/debug/lcoat}"
case "$BIN" in /*) ;; *) BIN="$PWD/$BIN" ;; esac
[ -x "$BIN" ] || { echo "not executable: $BIN (cargo build -p lcoat first)" >&2; exit 2; }
export LCOAT_NOW="${LCOAT_NOW:-2026-10-02T07:40:00Z}"
export LCOAT_OPERATOR=tester
unset LAB_ROOT

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; FAIL=1; }

# expect <label> <needle> <<< output
expect() {
  local label="$1" needle="$2" out
  out="$(cat)"
  if grep -qF -- "$needle" <<<"$out"; then pass "$label"; else
    fail "$label: expected '$needle', got:"; sed 's/^/        /' <<<"$out"; fi
}
# expect_exit <label> <code> <cmd...>
expect_exit() {
  local label="$1" want="$2"; shift 2
  local got=0; "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" = "$want" ]; then pass "$label (exit $want)"; else fail "$label: exit $got, wanted $want"; fi
}

# fresh_root <name>: a closed operation with one artifact, one resolved
# finding, report, handoff, closeout, audit and archive packets.
fresh_root() {
  local root="$WORK/$1"; mkdir -p "$root"
  export LCOAT_ROOT="$root"   # for this subshell; callers set it again
  "$BIN" target add node 10.10.10.5 --scope-status in-scope --criticality medium >/dev/null
  "$BIN" op start demo node authorized lab >/dev/null
  printf 'PORT 22 open ssh\n' >"$root/recon.txt"
  "$BIN" evidence add "$root/recon.txt" --kind scan-output --classification public >/dev/null
  "$BIN" finding add "SSH exposed" --level observed --severity low >/dev/null
  local fid; fid="$("$BIN" finding list | awk 'NR==1{print $1}')"
  "$BIN" finding resolve "$fid" --note firewalled >/dev/null
  "$BIN" op report >/dev/null; "$BIN" op handoff >/dev/null
  "$BIN" op close >/dev/null
  "$BIN" op closeout demo >/dev/null; "$BIN" op audit-packet demo >/dev/null; "$BIN" op archive-packet demo >/dev/null
  # Sanity: everything verifies before the tamper.
  "$BIN" op verify demo >/dev/null; "$BIN" op audit-verify demo >/dev/null; "$BIN" op archive-verify demo >/dev/null
  "$BIN" op trust-chain demo --strict >/dev/null; "$BIN" evidence verify demo >/dev/null; "$BIN" ledger chain-verify demo >/dev/null
  echo "$root"
}

ARTIFACT="sessions/demo/evidence/ev_20261002T074000Z/recon.txt"
LEDGER="sessions/demo/ledger.ndjson"

# The shell's verifiers on the same root, when the oracle is available.
shell_says_verified() {
  local root="$1" label="$2"
  [ -n "${ATLAS_REPO:-}" ] || return 0
  [ -x "$ATLAS_REPO/tools/atlas/bin/atlas" ] || { echo "  note  ATLAS_REPO has no tools/atlas/bin/atlas; shell comparison skipped"; return 0; }
  # The shell build runs from inside its lab root (as cross_check.sh does).
  cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$root/"
  local out
  out="$(cd "$root" && for c in verify archive-verify trust-chain; do LAB_ROOT="$root" "$root/tools/atlas/bin/atlas" op $c demo 2>&1 || true; done)"
  if grep -q "Verification Status: verified" <<<"$out" && grep -q "Trust Chain Status: current" <<<"$out" && ! grep -q "attention-required" <<<"$out"; then
    pass "$label: shell verifiers still say verified/current (the gap this build closes)"
  else
    fail "$label: expected the shell to miss this tamper; it said:"; sed 's/^/        /' <<<"$out"
  fi
}

# Lab Coat Lite (Go) on the same root, when GO_PROJECT is set: Lite has
# `evidence verify` but no hash chain, so it catches artifact edits and
# misses ledger rewrites.
GO_BIN=""
if [ -n "${GO_PROJECT:-}" ]; then
  GO_BIN="$WORK/lcoat-go"; ( cd "$GO_PROJECT" && go build -o "$GO_BIN" ./cmd/lcoat ) || { echo "  note  Lite did not build; comparison skipped"; GO_BIN=""; }
fi
lite_says() { # <label> <needle> <args...>
  [ -n "$GO_BIN" ] || return 0
  local label="$1" needle="$2"; shift 2
  "$GO_BIN" "$@" 2>&1 | expect "Lite: $label" "$needle"
}

echo "case 1: edit an evidence artifact after capture"
root="$(fresh_root edit_artifact)"; export LCOAT_ROOT="$root"
printf 'tampered\n' >>"$root/$ARTIFACT"
"$BIN" evidence verify demo 2>&1 | expect "evidence verify names the artifact" "ev_20261002T074000Z        changed"
"$BIN" evidence verify demo 2>&1 | expect "evidence verify status" "Verification Status: attention-required"
expect_exit "evidence verify" 1 "$BIN" evidence verify demo
"$BIN" op trust-chain demo 2>&1 | expect "trust-chain line" "Evidence Artifacts: attention-required checked=1 problems=1"
"$BIN" op trust-chain demo 2>&1 | expect "trust-chain status" "Trust Chain Status: attention-required"
expect_exit "trust-chain --strict" 1 "$BIN" op trust-chain demo --strict
# The shell-shaped verifiers do not re-hash artifacts, in any implementation.
"$BIN" op archive-verify demo 2>&1 | expect "archive-verify alone cannot see it" "Verification Status: verified"
shell_says_verified "$root" "edit_artifact"
lite_says "evidence verify also catches it" "Verification Status: attention-required" evidence verify demo

echo "case 2: edit the manifest and index to hide the artifact edit"
root="$(fresh_root edit_manifest)"; export LCOAT_ROOT="$root"
printf 'tampered\n' >>"$root/$ARTIFACT"
new="$(sha256sum "$root/$ARTIFACT" | cut -d' ' -f1)"
old="$(grep -o '"sha256":"[0-9a-f]*"' "$root/sessions/demo/evidence/manifest.ndjson" | head -1 | cut -d'"' -f4)"
sed -i "s/$old/$new/" "$root/sessions/demo/evidence/manifest.ndjson" "$root/sessions/demo/evidence.ndjson"
"$BIN" evidence verify demo 2>&1 | expect "evidence verify now agrees with the forged index" "Verification Status: verified"
# ...but the manifest's hash is anchored in the closeout and archive packets.
"$BIN" op verify demo 2>&1 | expect "op verify catches the manifest" "Evidence Manifest    changed"
expect_exit "op verify" 1 "$BIN" op verify demo
"$BIN" op archive-verify demo 2>&1 | expect "archive-verify catches the manifest" "Evidence Manifest"
expect_exit "archive-verify" 1 "$BIN" op archive-verify demo
# The index edit also breaks the ledger's record of the artifact hash.
"$BIN" op trust-chain demo 2>&1 | expect "trust-chain status" "Trust Chain Status: attention-required"

echo "case 3: delete an evidence artifact"
root="$(fresh_root delete_artifact)"; export LCOAT_ROOT="$root"
rm "$root/$ARTIFACT"
"$BIN" evidence verify demo 2>&1 | expect "evidence verify" "ev_20261002T074000Z        missing"
expect_exit "evidence verify" 1 "$BIN" evidence verify demo
shell_says_verified "$root" "delete_artifact"

echo "case 4: rewrite a ledger event in an operation that has no packets yet"
root="$(fresh_root rewrite_event)"; export LCOAT_ROOT="$root"
"$BIN" op resume demo >/dev/null
# Before close there is no packet anchoring the ledger hash; only the chain can tell.
sed -i '3s/"status":"ok"/"status":"edited"/' "$root/$LEDGER"
grep -q '"status":"edited"' "$root/$LEDGER" || { fail "tamper did not apply"; }
"$BIN" ledger chain-verify demo 2>&1 | expect "chain-verify" "Chain Status: broken at event 3 (event_hash does not match event content)"
expect_exit "chain-verify" 1 "$BIN" ledger chain-verify demo
"$BIN" ledger verify "$root/$LEDGER" 2>&1 | expect "shell-shaped ledger verify sees a well-formed ledger" "ledger: ok"
"$BIN" op trust-chain demo 2>&1 | expect "trust-chain line" "Ledger Chain: broken"
lite_says "has no chain and accepts the rewritten ledger (the gap this build closes)" "ledger: ok" ledger verify "$root/$LEDGER"

echo "case 5: splice out a ledger event (prev_hash no longer matches)"
root="$(fresh_root splice_event)"; export LCOAT_ROOT="$root"
"$BIN" op resume demo >/dev/null
sed -i '3d' "$root/$LEDGER"
"$BIN" ledger chain-verify demo 2>&1 | expect "chain-verify" "Chain Status: broken at event 3 (prev_hash does not match previous event_hash)"
expect_exit "chain-verify" 1 "$BIN" ledger chain-verify demo

echo "case 6: truncate the ledger tail (documented limit: needs a checkpoint)"
root="$(fresh_root truncate_tail)"; export LCOAT_ROOT="$root"
"$BIN" op resume demo >/dev/null
before="$("$BIN" ledger checkpoint "$root/$LEDGER" | awk '/^head_event_hash:/{print $2}')"
sed -i '$d' "$root/$LEDGER"
# A hash chain cannot see its own tail removed; the chain still verifies.
"$BIN" ledger chain-verify demo 2>&1 | expect "chain-verify alone cannot see truncation" "Chain Status: verified"
after="$("$BIN" ledger checkpoint "$root/$LEDGER" | awk '/^head_event_hash:/{print $2}')"
if [ "$before" != "$after" ] && [ -n "$before" ]; then
  pass "a recorded checkpoint head ($before) no longer matches ($after): truncation caught by the checkpoint"
else
  fail "checkpoint head did not change after truncation"
fi

echo
if [ "$FAIL" = 0 ]; then echo "TAMPER-RUST OK"; else echo "TAMPER-RUST FAILED"; exit 1; fi
