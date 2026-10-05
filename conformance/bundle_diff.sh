#!/usr/bin/env bash
# Evidence bundles: the shell build is the oracle.
#
# One frozen-clock scenario (a public and an internal artifact; a refused
# bundle, then one with --include-unredacted; then report, handoff, close,
# closeout, audit and archive) through the shell build and Lab Coat. After
# path/hash normalization the refusal, the bundle output, the bundle's
# manifest, README and files, and the handoff, closeout and archive bodies
# must match; each build's packet verifiers must pass on the other's root;
# and Lab Coat's bundle-verify must accept the shell's bundle (consistent,
# but unanchored: the shell's ledger event records no manifest hash).
#
# Normalized on purpose (docs/BLUEPRINT.md, "Evidence bundles"): the
# `manifest_sha256` and `next:` lines Lab Coat prints, the
# `manifest_sha256=` token it adds to the ledger detail, the README's
# Verify section, and the packets' manifest lines (the shell names the
# bundle manifest `Evidence manifest`; Lab Coat keeps that slot for the
# format 1.1 artifact manifest and adds `Evidence bundle manifest`).
#
#   ATLAS_REPO=... conformance/bundle_diff.sh [rust-bin]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout (pinned 23ba2d2)}"
RS="${1:-$HERE/target/debug/lcoat}"
case "$RS" in /*) ;; *) RS="$PWD/$RS" ;; esac
export LCOAT_NOW=2026-10-02T07:40:00Z LCOAT_OPERATOR=tester ATLAS_OPERATOR=tester
unset LAB_ROOT

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
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
  local V="$1" bin="$2" root="$3"
  printf 'PORT 22 open ssh\n' >"$root/recon.txt"; printf 'internal notes\n' >"$root/int.txt"
  env "$V=$root" "$bin" target add node 10.10.10.5 --scope-status in-scope >/dev/null
  env "$V=$root" "$bin" op start demo node >/dev/null
  env "$V=$root" "$bin" evidence add "$root/recon.txt" --kind scan-output --classification public >/dev/null
  env "$V=$root" "$bin" evidence add "$root/int.txt" >/dev/null
  env "$V=$root" "$bin" evidence bundle >"$root/refused.out" 2>&1; echo "exit=$?" >>"$root/refused.out"
  env "$V=$root" "$bin" evidence bundle --include-unredacted >"$root/bundle.out" 2>&1; echo "exit=$?" >>"$root/bundle.out"
  env "$V=$root" "$bin" op readiness demo >"$root/readiness.out" 2>&1
  for c in report handoff; do env "$V=$root" "$bin" op $c demo >/dev/null; done
  env "$V=$root" "$bin" op close demo --force >/dev/null
  for c in closeout audit-packet archive-packet; do env "$V=$root" "$bin" op $c demo >/dev/null; done
}
for n in sh rs; do mkdir -p "$WORK/$n"; cp -r "$ATLAS_REPO/lib" "$ATLAS_REPO/tools" "$ATLAS_REPO/bin" "$WORK/$n/"; done
SH="$WORK/sh/tools/atlas/bin/atlas"
( cd "$WORK/sh" && scenario LAB_ROOT "$SH" "$WORK/sh" )
( cd "$WORK/rs" && scenario LCOAT_ROOT "$RS" "$WORK/rs" )

norm() {
  sed -e "s#$WORK/\(sh\|rs\)#ROOT#g" -e 's/ rel=[^ ]*//g' -e 's/[0-9a-f]\{64\}/HASH/g' \
      -e 's/^error: \(.*\) (pass --include-unredacted.*)$/error: \1/' \
      -e '/^manifest_sha256: /d' -e '/^next: lcoat /d' -e 's/ manifest_sha256=HASH//g' \
      -e '/^- Evidence manifest: `ROOT\/sessions\/demo\/evidence\/manifest.ndjson`/d' \
      -e 's/^- Evidence bundle manifest: /- Evidence manifest: /' |
    awk '/^## Verify$/ { exit } { line[n++] = $0 } END { while (n > 0 && line[n-1] == "") n--; for (i = 0; i < n; i++) print line[i] }'
}
FAIL=0
same() { # label shell-file rust-file
  if diff <(norm <"$2") <(norm <"$3") >"$WORK/d"; then echo "  ok    $1"; else echo "  FAIL  $1"; sed 's/^/        /' "$WORK/d"; FAIL=1; fi
}
B=sessions/demo/evidence-bundles/demo-evidence-bundle
same "refusal without --include-unredacted" "$WORK/sh/refused.out" "$WORK/rs/refused.out"
same "bundle output" "$WORK/sh/bundle.out" "$WORK/rs/bundle.out"
same "readiness after the bundle" "$WORK/sh/readiness.out" "$WORK/rs/readiness.out"
same "bundle manifest" "$WORK/sh/$B/manifest.ndjson" "$WORK/rs/$B/manifest.ndjson"
same "bundle README (before Lab Coat's Verify section)" "$WORK/sh/$B/README.md" "$WORK/rs/$B/README.md"
if diff <(cd "$WORK/sh/$B/files" && ls && cat ./*) <(cd "$WORK/rs/$B/files" && ls && cat ./*) >/dev/null; then echo "  ok    bundled files"; else echo "  FAIL  bundled files differ"; FAIL=1; fi
for p in handoff/demo-handoff.md closeout/demo-closeout.md archive/demo-archive.md; do
  same "packet body: $p" "$WORK/sh/sessions/demo/$p" "$WORK/rs/sessions/demo/$p"
done

cross() { # label VAR bin root
  local out v ok=1; for v in verify audit-verify archive-verify; do
    out="$(cd "$4" && env "$2=$4" "$3" op "$v" demo 2>&1)"
    grep -q "Verification Status: verified" <<<"$out" || { ok=0; echo "  FAIL  $1: op $v"; sed "s/^/        /" <<<"$out" | tail -12; }
  done
  [ "$ok" = 1 ] && echo "  ok    $1" || FAIL=1
}
cross "shell verifiers on the Lab Coat root" LAB_ROOT "$WORK/rs/tools/atlas/bin/atlas" "$WORK/rs"
cross "Lab Coat verifiers on the shell root" LCOAT_ROOT "$RS" "$WORK/sh"

out="$(LCOAT_ROOT="$WORK/sh" "$RS" evidence bundle-verify --op demo 2>&1)"; code=$?
if [ "$code" = 0 ] && grep -q "Verification Status: unanchored" <<<"$out" && grep -q "Files Checked: 2" <<<"$out"; then
  echo "  ok    Lab Coat checks the shell's bundle (unanchored: no hash in the shell's event)"
else echo "  FAIL  bundle-verify on the shell's bundle (exit $code)"; sed 's/^/        /' <<<"$out"; FAIL=1; fi
out="$(LCOAT_ROOT="$WORK/rs" "$RS" evidence bundle-verify --op demo 2>&1)"
if grep -q "Verification Status: verified" <<<"$out"; then echo "  ok    Lab Coat's own bundle verifies against its ledger anchor"
else echo "  FAIL  bundle-verify on Lab Coat's bundle"; sed 's/^/        /' <<<"$out"; FAIL=1; fi

if [ "$FAIL" = 0 ]; then echo "BUNDLE OK"; else echo "BUNDLE FAILED"; exit 1; fi
