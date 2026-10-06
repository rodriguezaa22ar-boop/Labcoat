#!/usr/bin/env bash
# Finding resolution and approvals: the shell build is the oracle.
#
# The three-way scenario in cross_check.sh covers what all three builds
# share; Lite has no `finding resolve`, `finding accept` or approvals, so
# those are compared here between the shell build and Lab Coat only. One
# frozen-clock scenario runs through both:
#   finding add x2, evidence add, finding resolve (evidence and note),
#   finding accept, approval grant, then op status, approval list,
#   op report, op readiness;
# and the outputs, the finding index, the approvals file and the ledger's
# event sequence must match after normalization, and each build must read
# the other's root the same way. The one normalized
# difference is the approval expiry Lab Coat adds (format 1.1): the shell's
# `approval grant` takes no expiry, Lab Coat's requires one.
#
#   ATLAS_REPO=... conformance/lifecycle_diff.sh [rust-bin]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout (pinned 23ba2d2)}"
RS="${1:-$HERE/target/debug/lcoat}"
case "$RS" in /*) ;; *) RS="$PWD/$RS" ;; esac
export LCOAT_NOW=2026-10-04T05:15:00Z ATLAS_TODAY=2026-10-04 LCOAT_OPERATOR=anthony ATLAS_OPERATOR=anthony
unset LAB_ROOT

WORK="$(mktemp -d)"; [ -n "${KEEP:-}" ] || trap 'rm -rf "$WORK"' EXIT; [ -n "${KEEP:-}" ] && echo "work: $WORK"
# Frozen clock for the shell's `date`, passing date arithmetic (-d) through.
mkdir -p "$WORK/shim"
cat >"$WORK/shim/date" <<'SHIM'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = "-d" ] && exec /usr/bin/date "$@"; done
now="${LCOAT_NOW}"
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
chmod +x "$WORK/shim/date"; export PATH="$WORK/shim:$PATH"

scenario() { # VAR bin root grant-args...
  local V="$1" bin="$2" root="$3" f1 f2 eid; shift 3
  run() { env "$V=$root" "$bin" "$@"; }
  printf 'PORT 22 open ssh\n' >"$root/recon.txt"
  run target add local-vm 127.0.0.1 --scope-status in-scope --criticality medium >/dev/null
  run op start local-baseline local-vm authorized lab >/dev/null
  eid=$(run evidence add "$root/recon.txt" --kind scan-output --classification public | awk -F': ' '$1=="id"{print $2}')
  f1=$(run finding add "ssh on loopback" --severity low --evidence "$eid" | awk -F': ' '$1=="id"{print $2}')
  f2=$(run finding add "second risk" --severity medium | awk -F': ' '$1=="id"{print $2}')
  run finding resolve "$f1" --evidence "$eid" --note "bound to loopback" >"$root/resolve.out" 2>&1
  run finding accept "$f2" --reason "lab only" --owner anthony --expires 2027-01-02 >"$root/accept.out" 2>&1
  run approval grant "$@" >"$root/grant.out" 2>&1
  # `finding list` follows Lite's format, not the shell's (readonly_diff.sh
  # compares it with Lite), so it is not compared here.
  for c in "op status" "approval list" "op report" "op readiness"; do
    # shellcheck disable=SC2086
    run $c >"$root/$(tr ' ' _ <<<"$c").out" 2>&1; echo "exit=$?" >>"$root/$(tr ' ' _ <<<"$c").out"
  done
}
for n in sh rs; do mkdir -p "$WORK/$n"; cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$WORK/$n/"; done
SH="$WORK/sh/tools/atlas/bin/atlas"
( cd "$WORK/sh" && scenario LAB_ROOT "$SH" "$WORK/sh" safe-validation lab window )
( cd "$WORK/rs" && scenario LCOAT_ROOT "$RS" "$WORK/rs" safe-validation --reason "lab window" --expires 2026-10-05 )

norm() {
  sed -e "s#$WORK/\(sh\|rs\)#ROOT#g" -e 's/ rel=[^ ]*//g' -e 's/[0-9a-f]\{64\}/HASH/g' \
      -e 's/,"expires_at":"[^"]*"//' -e '/^expires_at: /d' -e 's/ expires_at=[0-9TZ:-]*//'
}
FAIL=0
same() { # label shell-file rust-file
  if diff <(norm <"$2") <(norm <"$3") >"$WORK/d"; then echo "  ok    $1"; else echo "  FAIL  $1"; sed 's/^/        /' "$WORK/d"; FAIL=1; fi
}
for o in resolve accept grant op_status approval_list op_readiness op_report; do
  same "$o output" "$WORK/sh/$o.out" "$WORK/rs/$o.out"
done
OP=sessions/local-baseline
same "findings.ndjson" "$WORK/sh/$OP/findings.ndjson" "$WORK/rs/$OP/findings.ndjson"
same "approvals.ndjson" "$WORK/sh/$OP/approvals.ndjson" "$WORK/rs/$OP/approvals.ndjson"
# The ledger without the format 1.1 chain fields Lab Coat adds.
unchain() { sed -e 's/,"prev_hash":\(null\|"[0-9a-f]*"\),"event_hash":"[0-9a-f]*"//' "$1"; }
same "ledger events" <(unchain "$WORK/sh/$OP/ledger.ndjson") <(unchain "$WORK/rs/$OP/ledger.ndjson")
same "report body" "$WORK/sh/reports/local-baseline-report.md" "$WORK/rs/reports/local-baseline-report.md"

# Each build reads the other's root and says what the root's own build said.
( cd "$WORK/sh" && LCOAT_ROOT="$WORK/sh" "$RS" op readiness >"$WORK/rs-on-sh.out" 2>&1; echo "exit=$?" >>"$WORK/rs-on-sh.out" )
( cd "$WORK/rs" && LAB_ROOT="$WORK/rs" "$WORK/rs/tools/atlas/bin/atlas" op readiness >"$WORK/sh-on-rs.out" 2>&1; echo "exit=$?" >>"$WORK/sh-on-rs.out" )
same "Lab Coat reads the shell root" "$WORK/sh/op_readiness.out" "$WORK/rs-on-sh.out"
same "the shell reads the Lab Coat root" "$WORK/rs/op_readiness.out" "$WORK/sh-on-rs.out"

if [ "$FAIL" = 0 ]; then echo "LIFECYCLE OK"; else echo "LIFECYCLE FAILED"; exit 1; fi
