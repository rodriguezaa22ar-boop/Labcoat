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

echo "== stage 0: golden hashes (cargo test) =="
( cd "$HERE" && out="$(cargo test --workspace --features lcoat/test-support 2>&1)" && echo "  $(echo "$out" | grep -c 'test result: ok') suites ok, $(echo "$out" | grep -oE '^test result: ok\. [0-9]+' | awk '{s+=$4} END {print s}') tests" ) || fail=1

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

echo "== stage 1: read-only conformance (tamper verdicts + byte-identical output) =="
if "$RS" help 2>/dev/null | grep -q "^  lcoat op verify"; then
  ( cd "$HERE" && ATLAS_REPO="$ATLAS_REPO" conformance/tamper.sh check "$RS" LCOAT_ROOT 2>&1 | tail -1 ) || fail=1
  ( cd "$HERE" && ATLAS_REPO="$ATLAS_REPO" GO_PROJECT="$GO_PROJECT" conformance/readonly_diff.sh "$RS" 2>&1 | tail -2 ) || fail=1
  # Format 1.1 tamper cases: what this build catches that the oracle and Lite cannot.
  if "$RS" help 2>/dev/null | grep -q "^  lcoat op start"; then
    ( cd "$HERE" && ATLAS_REPO="$ATLAS_REPO" GO_PROJECT="$GO_PROJECT" conformance/tamper_rust.sh "$RS" 2>&1 | tail -1 ) || fail=1
  fi
else
  echo "  NOT YET (phase 1): read-only commands not implemented in Rust"; notyet=1
fi

echo "== stage 2: three-way scenario =="
if "$RS" help 2>/dev/null | grep -q "^  lcoat op start"; then
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
  # Normalize paths and hashes, then the format 1.1 additions Lab Coat makes
  # (docs/BLUEPRINT.md, "Format 1.1 details"): rel= tokens, ledger chain
  # fields, and the Evidence manifest slot the shell leaves as `none`.
  norm() {
    sed -e "s#$1#ROOT#g" -e 's/[0-9a-f]\{64\}/HASH/g' \
        -e 's/ rel=[^ ]*//g' \
        -e 's/,"prev_hash":\(null\|"HASH"\),"event_hash":"HASH"//' \
        -e 's/^- Evidence manifest: .*/- Evidence manifest: <v1.1 slot>/' "$2"
  }
  echo "  -- structural diff (shell vs rust; shell vs go) --"
  while IFS= read -r rel; do
    for i in 1 2; do
      f="${roots[$i]}/$rel"
      if [ ! -f "$f" ]; then echo "  MISSING in ${names[$i]}: $rel"; fail=1; continue; fi
      diff <(norm "${roots[0]}" "${roots[0]}/$rel") <(norm "${roots[$i]}" "$f") >/dev/null || { echo "  DIFF ${names[$i]}: $rel"; fail=1; }
    done
  done < <(cd "${roots[0]}" && find sessions targets reports -type f | sort)
  echo "  -- files only the Rust root has (expected: format 1.1 manifest, lock files) --"
  extra="$(comm -13 <(cd "${roots[0]}" && find sessions targets reports -type f | sort) <(cd "${roots[2]}" && find sessions targets reports -type f | sort))"
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    case "$rel" in
      */evidence/manifest.ndjson|*/.lock) echo "  ok   $rel" ;;
      *) echo "  UNEXPECTED extra file: $rel"; fail=1 ;;
    esac
  done <<<"$extra"
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
