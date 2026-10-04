#!/usr/bin/env bash
# Accepted-risk review packets: the shell build is the oracle.
#
# One frozen-clock scenario (two accepted risks: one current, one due soon)
# through the shell build and Lab Coat; `finding review-queue`,
# `finding review-packet`, `finding review-verify` and the packet body must
# match byte for byte after path/hash normalization; each build must verify
# the other's packet; and after a finding changes, both verifiers must give
# the same attention-required verdict.
#
#   ATLAS_REPO=... conformance/review_diff.sh [rust-bin]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout (pinned 23ba2d2)}"
RS="${1:-$HERE/target/debug/lcoat}"
case "$RS" in /*) ;; *) RS="$PWD/$RS" ;; esac
export LCOAT_NOW=2026-10-04T05:15:00Z ATLAS_TODAY=2026-10-04 LCOAT_OPERATOR=anthony ATLAS_OPERATOR=anthony
unset LAB_ROOT

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
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

scenario() { # VAR bin root
  local V="$1" bin="$2" root="$3" f1 f2
  env "$V=$root" "$bin" target add local-vm 127.0.0.1 --scope-status in-scope >/dev/null
  env "$V=$root" "$bin" op start local-baseline local-vm >/dev/null
  f1=$(env "$V=$root" "$bin" finding add "ssh on loopback" --severity low | awk -F': ' '$1=="id"{print $2}')
  env "$V=$root" "$bin" finding accept "$f1" --reason "lab loopback only" --owner anthony --expires 2027-01-02 >/dev/null
  f2=$(env "$V=$root" "$bin" finding add "second risk" --severity medium | awk -F': ' '$1=="id"{print $2}')
  env "$V=$root" "$bin" finding accept "$f2" --reason "due soon" --expires 2026-10-20 >/dev/null
  env "$V=$root" "$bin" finding review-queue --within 30 >"$root/queue.out" 2>&1
  env "$V=$root" "$bin" finding review-packet >"$root/packet.out" 2>&1
  env "$V=$root" "$bin" finding review-verify >"$root/verify.out" 2>&1; echo "exit=$?" >>"$root/verify.out"
  echo "$f1" >"$root/f1"
}
for n in sh rs; do mkdir -p "$WORK/$n"; cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$WORK/$n/"; done
SH="$WORK/sh/tools/atlas/bin/atlas"
( cd "$WORK/sh" && scenario LAB_ROOT "$SH" "$WORK/sh" )
( cd "$WORK/rs" && scenario LCOAT_ROOT "$RS" "$WORK/rs" )

norm() { sed -e "s#$WORK/\(sh\|rs\)#ROOT#g" -e 's/ rel=[^ ]*//g' -e 's/sha256=[0-9a-f]\{64\}/sha256=HASH/g' -e 's/_sha=[0-9a-f]\{64\}/_sha=HASH/g'; }
FAIL=0
same() { # label shell-file rust-file
  if diff <(norm <"$2") <(norm <"$3") >"$WORK/d"; then echo "  ok    $1"; else echo "  FAIL  $1"; sed 's/^/        /' "$WORK/d"; FAIL=1; fi
}
PKT=sessions/local-baseline/findings/review-packets/local-baseline-accepted-risk-review.md
same "review-queue output" "$WORK/sh/queue.out" "$WORK/rs/queue.out"
same "review-packet output" "$WORK/sh/packet.out" "$WORK/rs/packet.out"
same "review-verify output" "$WORK/sh/verify.out" "$WORK/rs/verify.out"
same "packet body" "$WORK/sh/$PKT" "$WORK/rs/$PKT"

cross() { # label VAR bin root
  local out; out="$(cd "$4" && env "$2=$4" "$3" finding review-verify 2>&1)"
  if grep -q "Verification Status: verified" <<<"$out"; then echo "  ok    $1"; else echo "  FAIL  $1"; sed "s/^/        /" <<<"$out" | tail -8; FAIL=1; fi
}
cross "shell verifies the Lab Coat root" LAB_ROOT "$WORK/rs/tools/atlas/bin/atlas" "$WORK/rs"
cross "Lab Coat verifies the shell root" LCOAT_ROOT "$RS" "$WORK/sh"

# A finding changes after the review: both say attention-required, identically.
( cd "$WORK/sh" && LAB_ROOT="$WORK/sh" "$SH" finding update "$(cat "$WORK/sh/f1")" --note "changed after review" >/dev/null
  LAB_ROOT="$WORK/sh" "$SH" finding review-verify >"$WORK/sh/tamper.out" 2>&1; echo "exit=$?" >>"$WORK/sh/tamper.out" )
( cd "$WORK/rs" && LCOAT_ROOT="$WORK/rs" "$RS" finding update "$(cat "$WORK/rs/f1")" --note "changed after review" >/dev/null 2>&1 || LCOAT_ROOT="$WORK/rs" "$RS" finding note "$(cat "$WORK/rs/f1")" "changed after review" >/dev/null
  LCOAT_ROOT="$WORK/rs" "$RS" finding review-verify >"$WORK/rs/tamper.out" 2>&1; echo "exit=$?" >>"$WORK/rs/tamper.out" )
same "tamper verdict after a finding changes" "$WORK/sh/tamper.out" "$WORK/rs/tamper.out"
grep -q 'attention-required' "$WORK/rs/tamper.out" || { echo "  FAIL  tamper not detected"; FAIL=1; }

if [ "$FAIL" = 0 ]; then echo "REVIEW OK"; else echo "REVIEW FAILED"; exit 1; fi
