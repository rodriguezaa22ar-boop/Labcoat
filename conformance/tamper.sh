#!/usr/bin/env bash
# Tamper fixtures: record what the ORACLE says before any verifier is written.
#
# Builds one closed operation with the Atlas shell build in a temp root, then
# applies each tamper case to a fresh copy and runs the shell verifiers on it.
# The verdicts are written to fixtures/tamper/<case>.expect. A Rust (or Go)
# verifier is conformant when it produces the same verdict lines.
#
#   record mode:  conformance/tamper.sh record        (re)writes the .expect files
#   check mode:   conformance/tamper.sh check <bin> <rootvar>
#                 runs the same cases through another implementation and diffs
#                 e.g. conformance/tamper.sh check target/debug/lcoat LCOAT_ROOT
#
# Requires ATLAS_REPO (shell build pinned at 23ba2d2). The project rule this
# enforces: a trust gate is only real if it can fail correctly.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout}"
MODE="${1:-record}"
BIN="${2:-}"; VAR="${3:-LAB_ROOT}"
OUT="$HERE/fixtures/tamper"
export LCOAT_NOW="${LCOAT_NOW:-2026-10-02T07:40:00Z}"

# Frozen clock, as in cross_check.sh.
shim="$(mktemp -d)"
cat >"$shim/date" <<'SHIM'
#!/usr/bin/env bash
now="${LCOAT_NOW:-2026-10-02T07:40:00Z}"
y=${now:0:4}; mo=${now:5:2}; d=${now:8:2}; h=${now:11:2}; mi=${now:14:2}; s=${now:17:2}
for a in "$@"; do
  case "$a" in
    +%Y-%m-%dT%H:%M:%SZ) printf '%s-%s-%sT%s:%s:%sZ\n' "$y" "$mo" "$d" "$h" "$mi" "$s"; exit 0 ;;
    +%Y%m%dT%H%M%SZ)     printf '%s%s%sT%s%s%sZ\n' "$y" "$mo" "$d" "$h" "$mi" "$s"; exit 0 ;;
    +%F)                 printf '%s-%s-%s\n' "$y" "$mo" "$d"; exit 0 ;;
  esac
done
exec /usr/bin/date "$@"
SHIM
chmod +x "$shim/date"; export PATH="$shim:$PATH"

# Build one clean, closed operation with the shell build into a fresh root.
# Packets embed absolute paths and hashes of each other, so a root cannot be
# copied; under the frozen clock every build is byte-identical anyway.
build_root() {
  local root; root="$(mktemp -d)"
  cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$root/"
  printf 'nmap scan output\nPORT 22 open ssh\n' >"$root/recon.txt"
  local atlas="$root/tools/atlas/bin/atlas" eid prev A
  ( cd "$root"
    export LAB_ROOT="$root"
    "$atlas" target add demo-node 10.10.10.5 --scope-status in-scope --criticality medium --tag prototype >/dev/null
    "$atlas" op start --profile htb-starting-point full-op demo-node authorized full lifecycle >/dev/null
    eid=$("$atlas" evidence add "$root/recon.txt" --kind scan-output --classification public | awk -F': ' '$1=="id"{print $2}')
    "$atlas" finding add "SSH exposed" --level observed --severity low --confidence high --evidence "$eid" >/dev/null
    "$atlas" op report full-op >/dev/null; "$atlas" op handoff full-op >/dev/null
    "$atlas" op close full-op --force >/dev/null
    "$atlas" op closeout full-op >/dev/null; "$atlas" op audit-packet full-op >/dev/null; "$atlas" op archive-packet full-op >/dev/null
    A="$root/sessions/full-op/archive/full-op-archive.md"
    "$atlas" receipt create --action demo.archived --actor tester --subject-type atlas-operation --subject operation://full-op \
      --artifact-ref "$A=$(sha256sum "$A" | cut -d' ' -f1)" --out "$root/r1.json" >/dev/null
    prev=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["event_hash"])' "$root/r1.json")
    "$atlas" receipt create --action demo.reviewed --actor tester --subject-type atlas-operation --subject operation://full-op \
      --prev-hash "$prev" --out "$root/r2.json" >/dev/null
  )
  echo "$root"
}

# Each case: a function that mutates $ROOT in place. Keep them minimal and
# describable in one line; the description is the first line of the .expect.
tamper_edit_artifact()   { sed -i 's/PORT 22 open ssh/PORT 22 closed/' "$ROOT"/sessions/full-op/evidence/*/recon.txt; }
tamper_late_ledger()     { printf '{"ts":"2026-10-02T07:41:00Z","event":"finding.recorded","op":"full-op","target":"demo-node","capability":"read-only","tool":"atlas","status":"ok","detail":"tampered"}\n' >>"$ROOT/sessions/full-op/ledger.ndjson"; }
tamper_rewrite_middle()  { sed -i '2s/"status":"\([a-z]*\)"/"status":"tampered"/' "$ROOT/sessions/full-op/ledger.ndjson"; }
tamper_stale_report()    { echo "edited after handoff" >>"$ROOT"/reports/full-op-report.md; }
tamper_delete_closeout() { rm -f "$ROOT"/sessions/full-op/closeout/*.md; }
tamper_receipt_prev()    { sed -i 's/"prev_hash": "[0-9a-f]\{4\}/"prev_hash": "0000/' "$ROOT/r2.json"; }
tamper_receipt_secret()  { sed -i 's/"action": "demo.reviewed"/"action": "token=abcdefabcdefabcdefabcdef"/' "$ROOT/r2.json"; }

CASES=(edit_artifact late_ledger rewrite_middle stale_report delete_closeout receipt_prev receipt_secret)
DESC_edit_artifact="Edit an evidence artifact after evidence add"
DESC_late_ledger="Append a disallowed ledger event after closeout"
DESC_rewrite_middle="Rewrite a middle ledger event in place (whole-file hash changes; v1.1 chain must name the event)"
DESC_stale_report="Edit the report after the handoff was generated"
DESC_delete_closeout="Delete the closeout manifest"
DESC_receipt_prev="Hand-edit a receipt's prev_hash"
DESC_receipt_secret="Insert a credential marker into a receipt field"

# Run every verifier and print verdict lines in a fixed, implementation-neutral shape.
verdicts() { # bin var root
  local bin="$1" var="$2" root="$3" v s
  for v in verify audit-verify archive-verify; do
    s=$(env "$var=$root" "$bin" op "$v" full-op 2>&1 | awk -F': ' '$1=="Verification Status"{print $2}' || true); echo "op $v: ${s:-error}"
  done
  s=$(env "$var=$root" "$bin" op trust-chain full-op 2>&1 | awk -F': ' '$1=="Trust Chain Status"{print $2}' || true); echo "op trust-chain: ${s:-error}"
  if env "$var=$root" "$bin" receipt verify "$root/r2.json" >/dev/null 2>&1; then echo "receipt verify r2: ok"; else echo "receipt verify r2: error"; fi
  if env "$var=$root" "$bin" receipt replay "$root/r1.json" "$root/r2.json" >/dev/null 2>&1; then echo "receipt replay: ok"; else echo "receipt replay: error"; fi
}

mkdir -p "$OUT"; fail=0
for c in clean "${CASES[@]}"; do
  ROOT="$(build_root)"
  fingerprint() { (cd "$1" && find sessions reports r1.json r2.json -type f -exec sha256sum {} + | sort | sha256sum); }
  before="$(fingerprint "$ROOT")"
  [ "$c" = clean ] || "tamper_$c"
  if [ "$c" != clean ] && [ "$before" = "$(fingerprint "$ROOT")" ]; then echo "BUG: tamper $c changed nothing"; exit 2; fi
  desc="${c/clean/Untampered baseline}"; [ "$c" = clean ] || { d="DESC_$c"; desc="${!d}"; }
  if [ "$MODE" = record ]; then
    { echo "# $desc"; verdicts "$ROOT/tools/atlas/bin/atlas" LAB_ROOT "$ROOT"; } >"$OUT/$c.expect"
    echo "recorded $c"; sed 's/^/    /' "$OUT/$c.expect"
  else
    [ -n "$BIN" ] || { echo "check mode needs <bin>"; exit 2; }
    got="$(verdicts "$BIN" "$VAR" "$ROOT")"
    if diff <(tail -n +2 "$OUT/$c.expect") <(echo "$got") >/dev/null; then echo "  ok   $c"; else echo "  DIFF $c"; diff <(tail -n +2 "$OUT/$c.expect") <(echo "$got") | sed 's/^/       /'; fail=1; fi
  fi
done
[ "$MODE" = record ] || { [ "$fail" -eq 0 ] && echo "TAMPER OK" || { echo "TAMPER FAILED"; exit 1; }; }
