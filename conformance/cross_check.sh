#!/usr/bin/env bash
# Three-way conformance check: Atlas shell build, Lab Coat Lite (Go) and
# Lab Coat (Rust).
#
# Stages, each of which can fail:
#   0. golden: `cargo test` reproduces the fixture hashes            (phase 0)
#   1. read:   Rust verifiers agree with shell + Go on golden/tamper (phase 1)
#   2. write:  one frozen-clock scenario through all three builds;
#              normalized diff; every verifier on every root         (phase 2)
#
# Stages whose commands the Rust binary does not implement yet are reported
# as NOT YET, not as failures, so the script is honest about progress.
#
# Usage:
#   ATLAS_REPO=/path/to/atlas-trust-infrastructure \
#   GO_PROJECT=/path/to/GO-project \
#   conformance/cross_check.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout (pinned 23ba2d2)}"
GO_PROJECT="${GO_PROJECT:?set GO_PROJECT to the GO-project checkout (Lite v0.1.4)}"
export LCOAT_NOW="${LCOAT_NOW:-2026-10-02T07:40:00Z}"

fail=0
notyet=0
has() { "$RS" "$@" --help >/dev/null 2>&1 || "$RS" "$@" >/dev/null 2>&1; }

echo "== stage 0: golden hashes (cargo test) =="
( cd "$HERE" && cargo test --workspace --quiet 2>&1 | tail -1 ) || fail=1

echo "== build the three implementations =="
RS="$(mktemp -d)/lcoat"; ( cd "$HERE" && cargo build --quiet -p lcoat && cp target/debug/lcoat "$RS" )
GO="$(mktemp -d)/lcoat-go"; ( cd "$GO_PROJECT" && go build -o "$GO" ./cmd/lcoat )
SHELL_BIN="$ATLAS_REPO/tools/atlas/bin/atlas"
echo "  rust:  $("$RS" version)"
echo "  go:    $("$GO" version)"
echo "  shell: $(git -C "$ATLAS_REPO" rev-parse --short HEAD)"

# Frozen date shim so all three builds agree on timestamps and IDs.
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

echo "== stage 1: Rust verifiers on golden fixtures =="
if "$RS" op verify --help >/dev/null 2>&1; then
  G="$HERE/fixtures/golden"
  for v in verify audit-verify archive-verify; do
    s=$(LCOAT_ROOT="$G" "$RS" op "$v" learning-op-001 2>&1 | awk -F': ' '$1=="Verification Status"{print $2}')
    echo "  rust op $v -> $s"; [ "$s" = verified ] || fail=1
  done
  for r in boundary packet replay; do
    "$RS" receipt verify "$G/demo-site-receipts/demo-site-$r.json" >/dev/null && echo "  rust receipt verify $r -> ok" || { echo "  rust receipt verify $r -> FAIL"; fail=1; }
  done
else
  echo "  NOT YET (phase 1): op verify / receipt verify not implemented in Rust"; notyet=1
fi

echo "== stage 2: three-way scenario =="
if "$RS" op start --help >/dev/null 2>&1; then
  roots=(); names=(sh go rs)
  for n in "${names[@]}"; do r="$(mktemp -d)"; roots+=("$r"); cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$r/"; printf 'nmap scan output\nPORT 22 open ssh\n' >"$r/recon.txt"; done
  scenario() { # VAR bin root
    local V="$1" bin="$2" root="$3" eid
    env "$V=$root" "$bin" target add demo-node 10.10.10.5 --scope-status in-scope --criticality medium --tag prototype >/dev/null
    env "$V=$root" "$bin" op start --profile htb-starting-point full-op demo-node authorized full lifecycle >/dev/null
    eid=$(env "$V=$root" "$bin" evidence add "$root/recon.txt" --kind scan-output --classification public | awk -F': ' '$1=="id"{print $2}')
    env "$V=$root" "$bin" finding add "SSH exposed" --level observed --severity low --confidence high --evidence "$eid" >/dev/null
    for c in report handoff; do env "$V=$root" "$bin" op $c full-op >/dev/null; done
    env "$V=$root" "$bin" op close full-op --force >/dev/null
    for c in closeout audit-packet archive-packet; do env "$V=$root" "$bin" op $c full-op >/dev/null; done
  }
  ( cd "${roots[0]}" && scenario LAB_ROOT "${roots[0]}/tools/atlas/bin/atlas" "${roots[0]}" )
  ( cd "${roots[1]}" && scenario LCOAT_ROOT "$GO" "${roots[1]}" )
  ( cd "${roots[2]}" && scenario LCOAT_ROOT "$RS" "${roots[2]}" )
  norm() { sed -e "s#$1#ROOT#g" -e 's/[0-9a-f]\{64\}/HASH/g' "$2"; }
  echo "  -- structural diff (shell vs rust; shell vs go) --"
  while IFS= read -r rel; do
    for i in 1 2; do
      f="${roots[$i]}/$rel"
      if [ ! -f "$f" ]; then echo "  MISSING in ${names[$i]}: $rel"; fail=1; continue; fi
      diff <(norm "${roots[0]}" "${roots[0]}/$rel") <(norm "${roots[$i]}" "$f") >/dev/null || { echo "  DIFF ${names[$i]}: $rel"; fail=1; }
    done
  done < <(cd "${roots[0]}" && find sessions targets reports -type f | sort)
  echo "  -- every verifier on every root --"
  for i in 0 1 2; do for j in 0 1 2; do
    case $j in 0) bin="${roots[$i]}/tools/atlas/bin/atlas"; var=LAB_ROOT;; 1) bin="$GO"; var=LCOAT_ROOT;; 2) bin="$RS"; var=LCOAT_ROOT;; esac
    for v in verify audit-verify archive-verify; do
      s=$(env "$var=${roots[$i]}" "$bin" op "$v" full-op 2>&1 | awk -F': ' '$1=="Verification Status"{print $2}')
      [ "$s" = verified ] || { echo "  ${names[$j]} verifier on ${names[$i]} root: op $v -> $s"; fail=1; }
    done
  done; done
  echo "  all 27 verifier runs checked"
else
  echo "  NOT YET (phase 2): lifecycle commands not implemented in Rust"; notyet=1
fi

echo
if [ "$fail" -ne 0 ]; then echo "CONFORMANCE FAILED"; exit 1; fi
if [ "$notyet" -ne 0 ]; then echo "CONFORMANCE OK (completed stages only; later stages NOT YET)"; else echo "CONFORMANCE OK"; fi
