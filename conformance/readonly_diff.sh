#!/usr/bin/env bash
# Read-only conformance: every phase-1 command, run by the shell build, Lab
# Coat Lite (Go) and Lab Coat (Rust) against ONE root the shell build wrote,
# diffed byte for byte.
#
# The root is the tamper harness's scenario (closed operation, three packets,
# two chained receipts) built under the frozen clock. Lines that legitimately
# differ between implementations are normalized before the diff and listed
# in `norm` below; everything else must match exactly.
#
#   ATLAS_REPO=... GO_PROJECT=... conformance/readonly_diff.sh [rust-bin]
#
# Exit 0 and "READONLY OK" when every command agrees.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout (pinned 23ba2d2)}"
GO_PROJECT="${GO_PROJECT:?set GO_PROJECT to the GO-project checkout (Lite v0.1.4)}"
RS="${1:-}"
export LCOAT_NOW="${LCOAT_NOW:-2026-10-02T07:40:00Z}"

if [ -z "$RS" ]; then
  RS="$(mktemp -d)/lcoat"; ( cd "$HERE" && cargo build --quiet -p lcoat && cp target/debug/lcoat "$RS" )
else
  RS="$(cd "$(dirname "$RS")" && pwd)/$(basename "$RS")"
fi
GO="$(mktemp -d)/lcoat-go"; ( cd "$GO_PROJECT" && go build -o "$GO" ./cmd/lcoat )

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

ROOT="$(mktemp -d)"
cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$ROOT/"
printf 'nmap scan output\nPORT 22 open ssh\n' >"$ROOT/recon.txt"
SH="$ROOT/tools/atlas/bin/atlas"
( cd "$ROOT"
  export LAB_ROOT="$ROOT"
  "$SH" target add demo-node 10.10.10.5 --scope-status in-scope --criticality medium --tag prototype >/dev/null
  "$SH" op start --profile htb-starting-point full-op demo-node authorized full lifecycle >/dev/null
  eid=$("$SH" evidence add "$ROOT/recon.txt" --kind scan-output --classification public | awk -F': ' '$1=="id"{print $2}')
  "$SH" finding add "SSH exposed" --level observed --severity low --confidence high --evidence "$eid" >/dev/null
  "$SH" op report full-op >/dev/null; "$SH" op handoff full-op >/dev/null
  "$SH" op close full-op --force >/dev/null
  "$SH" op closeout full-op >/dev/null; "$SH" op audit-packet full-op >/dev/null; "$SH" op archive-packet full-op >/dev/null
  A="$ROOT/sessions/full-op/archive/full-op-archive.md"
  "$SH" receipt create --action demo.archived --actor tester --subject-type atlas-operation --subject operation://full-op \
    --artifact-ref "$A=$(sha256sum "$A" | cut -d' ' -f1)" --out "$ROOT/r1.json" >/dev/null
  prev=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["event_hash"])' "$ROOT/r1.json")
  "$SH" receipt create --action demo.reviewed --actor tester --subject-type atlas-operation --subject operation://full-op \
    --prev-hash "$prev" --out "$ROOT/r2.json" >/dev/null
)
L="$ROOT/sessions/full-op/ledger.ndjson"

# Known, documented divergences (docs/BLUEPRINT.md, "Read-only conformance"):
#  - V1 Readiness: the shell evaluates its v1 toolchain pillars; Lab Coat and
#    Lite do not ship them and say so. The verdict word is not compared.
#  - Next Trust Step when current: the shell says "Trust chain is current.",
#    Lab Coat "Metadata trust chain is current." (it certifies metadata only).
#  - Business Flow Evidence: a shell-only subsystem; its block is dropped.
#  - Evidence Artifacts: the Lite/Lab Coat re-hash line the shell lacks.
#  - ledger checkpoint: timestamp and checkpoint id depend on the clock/file.
norm() {
  awk '
    /^Business Flow Evidence$/ { skip=1; next }
    skip && /^-{60}$/ { skip=0; next }
    skip { next }
    /^Evidence Artifacts: / { next }
    { print }
  ' | sed -E \
    -e 's/^(V1 Readiness: ).*/\1<implementation-specific>/' \
    -e 's/^(Next Trust Step: )(Metadata trust chain is current\.|Trust chain is current\.).*/\1<current>/' \
    -e 's/"timestamp":"[^"]*"/"timestamp":"T"/' \
    -e 's/"checkpoint_id":"checkpoint_[0-9a-f]+"/"checkpoint_id":"C"/'
}

run() { # label var bin args...
  local label="$1" var="$2" bin="$3"; shift 3
  ( cd "$ROOT" && env "$var=$ROOT" "$bin" "$@" 2>&1; echo "exit=$?" ) | norm
}

# The shell build is the oracle: Rust must match it byte for byte after
# normalization. Lite is reported for information; where it simplified the
# shell's output (verifier tables, replay JSON, pretty receipts) it differs
# from both, and that is Lite's known shortfall, not a Rust failure.
fail=0; checked=0; lite_diffs=0
compare() { # name shell-args... -- lite/rust args...
  local name="$1"; shift
  local sh_args=() rest=()
  while [ $# -gt 0 ]; do [ "$1" = "--" ] && { shift; break; }; sh_args+=("$1"); shift; done
  rest=("$@")
  local a b c
  a="$(run shell LAB_ROOT "$SH" "${sh_args[@]}")"
  b="$(run lite LCOAT_ROOT "$GO" "${rest[@]}")"
  c="$(run rust LCOAT_ROOT "$RS" "${rest[@]}")"
  checked=$((checked+1))
  if [ "$a" != "$c" ]; then echo "  DIFF shell vs rust: $name"; diff <(echo "$a") <(echo "$c") | sed 's/^/       /' | head -40 || true; fail=1
  elif [ "$b" != "$c" ]; then echo "  ok   $name (shell == rust; lite differs)"; lite_diffs=$((lite_diffs+1))
  else echo "  ok   $name (all three)"; fi
}

compare_lite_rust() { # name args...  (commands the shell build does not have)
  local name="$1"; shift
  local b c
  b="$(run lite LCOAT_ROOT "$GO" "$@")"
  c="$(run rust LCOAT_ROOT "$RS" "$@")"
  checked=$((checked+1))
  if [ "$b" != "$c" ]; then echo "  DIFF lite vs rust: $name"; diff <(echo "$b") <(echo "$c") | sed 's/^/       /' | head -40 || true; fail=1; else echo "  ok   $name (lite/rust)"; fi
}

echo "== read-only commands on a shell-built root =="
compare "op readiness"        op readiness full-op      -- op readiness full-op
compare "op verify"           op verify full-op         -- op verify full-op
compare "op audit-verify"     op audit-verify full-op   -- op audit-verify full-op
compare "op archive-verify"   op archive-verify full-op -- op archive-verify full-op
compare "op trust-chain"      op trust-chain full-op    -- op trust-chain full-op
compare "ledger verify"       ledger verify "$L" --json -- ledger verify "$L" --json
compare "ledger verify text"  ledger verify "$L"        -- ledger verify "$L"
compare "ledger checkpoint"   ledger checkpoint "$L" --json -- ledger checkpoint "$L" --json
compare "receipt verify"      receipt verify "$ROOT/r2.json" --json -- receipt verify "$ROOT/r2.json" --json
compare "receipt verify text" receipt verify "$ROOT/r2.json" -- receipt verify "$ROOT/r2.json"
compare "receipt replay"      receipt replay "$ROOT/r1.json" "$ROOT/r2.json" --json -- receipt replay "$ROOT/r1.json" "$ROOT/r2.json" --json
compare "receipt replay text" receipt replay "$ROOT/r1.json" "$ROOT/r2.json" -- receipt replay "$ROOT/r1.json" "$ROOT/r2.json"
compare_lite_rust "op list"           op list
compare_lite_rust "scope status"      scope status full-op
compare_lite_rust "evidence list"     evidence list full-op
compare_lite_rust "evidence verify"   evidence verify full-op
compare_lite_rust "finding list"      finding list full-op

echo "== receipt create (frozen clock, same inputs) =="
mk() { # var bin out
  ( cd "$ROOT" && env "$1=$ROOT" "$2" receipt create --action demo.created --actor tester --subject-type atlas-operation \
      --subject operation://full-op --prev-hash "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["event_hash"])' "$ROOT/r2.json")" \
      --evidence-ref ev_x --artifact-ref "$L=$(sha256sum "$L" | cut -d' ' -f1)" --out "$3" >/dev/null )
}
mk LAB_ROOT "$SH" "$ROOT/c-sh.json"; mk LCOAT_ROOT "$GO" "$ROOT/c-go.json"; mk LCOAT_ROOT "$RS" "$ROOT/c-rs.json"
checked=$((checked+1))
if cmp -s "$ROOT/c-sh.json" "$ROOT/c-rs.json"; then
  if cmp -s "$ROOT/c-go.json" "$ROOT/c-rs.json"; then echo "  ok   receipt create file is byte-identical (all three)"
  else echo "  ok   receipt create file is byte-identical (shell == rust; lite writes the compact form)"; lite_diffs=$((lite_diffs+1)); fi
else
  echo "  DIFF receipt create (shell vs rust)"; diff "$ROOT/c-sh.json" "$ROOT/c-rs.json" | head -20 || true; fail=1
fi
# Whatever the serialization, every build must accept every build's receipt.
for made in c-sh c-go c-rs; do
  for v in "$SH" "$GO" "$RS"; do case "$v" in "$SH") var=LAB_ROOT;; *) var=LCOAT_ROOT;; esac
    ( cd "$ROOT" && env "$var=$ROOT" "$v" receipt replay "$ROOT/r1.json" "$ROOT/r2.json" "$ROOT/$made.json" >/dev/null 2>&1 ) || { echo "  FAIL: $v cannot replay the chain ending in $made.json"; fail=1; }
  done
done
echo "  ok   every build replays every build's three-receipt chain (9 runs)"

echo
echo "checked: $checked commands; lite differs from the shell on $lite_diffs of them (known)"
if [ "$fail" -eq 0 ]; then echo "READONLY OK"; else echo "READONLY FAILED"; exit 1; fi
