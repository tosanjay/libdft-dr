#!/usr/bin/env bash
#
# tests/run_smoke.sh -- libdft-dr CI smoke test.
#
# Drives:
#   1. synthetic_unit -- 15 assertions on the tag model API (must print "OK").
#   2. vuzzer_cmp_sink -- runs against tests/sut/magic_check on tests/seeds/tiny.bin
#      and checks the emitted cmp.out tag SET contains the expected offsets.
#
# The expected-tag-SET check is compiler/ASLR/PC-agnostic: it ignores PCs
# and exact values, looking only at the per-byte taint labels.
#
# Usage: DR_ROOT=/path/to/dynamorio-10.0 tests/run_smoke.sh
#
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DR_ROOT="${DR_ROOT:?DR_ROOT must point at the DynamoRIO 10.0 install}"

BUILD="$REPO/build"
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

PASS=0; FAIL=0
log() { printf '[smoke] %s\n' "$*"; }
ok()  { PASS=$((PASS+1)); printf '  PASS %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$*"; }

# ---------- (1) synthetic_unit ----------
log "1. synthetic_unit"
SU="$BUILD/clients/synthetic_unit/libdft-synthetic-unit-dr.so"
[[ -f "$SU" ]] || { bad "synthetic_unit .so missing at $SU"; exit 1; }
SU_OUT="$("$DR_ROOT/bin64/drrun" -c "$SU" -- /bin/true 2>&1 || true)"
if grep -q "synthetic_unit\] OK" <<< "$SU_OUT"; then
    ok "15 assertions"
else
    bad "synthetic_unit did not print OK"
    echo "$SU_OUT" | grep -E "synthetic_unit|FAIL" >&2
fi

# ---------- (2) vuzzer_cmp_sink + magic_check ----------
log "2. vuzzer_cmp_sink + magic_check SUT"
VCS="$BUILD/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so"
SUT="$TMPD/magic_check"
SEED="$REPO/tests/seeds/tiny.bin"
[[ -f "$VCS" ]] || { bad "vuzzer_cmp_sink .so missing"; exit 1; }
[[ -f "$SEED" ]] || { bad "tiny.bin seed missing"; exit 1; }

cc -O0 -o "$SUT" "$REPO/tests/sut/magic_check.c"

"$DR_ROOT/bin64/drrun" -c "$VCS" \
    -o "$TMPD/cmp.out" -leao "$TMPD/lea.out" \
    -filename "$SEED" -- "$SUT" "$SEED" >/dev/null

if [[ ! -s "$TMPD/cmp.out" ]]; then
    bad "cmp.out is empty"
    exit 1
fi

# Extract unique taint labels (just the digit offsets, deduped).
got="$(grep -ohE '\{[0-9,]+\}' "$TMPD/cmp.out" \
       | tr -d '{}' | tr ',' '\n' | grep -v '^$' | sort -un)"

# Expected: bytes 0,1,2,3 are CMP'd against constants in magic_check.c.
# We require that all four labels appear; the SUT may also drag bytes 4-7
# into reads (fread loads 8 bytes), so we allow a superset.
for need in 0 1 2 3; do
    if ! grep -qx "$need" <<< "$got"; then
        bad "expected tag offset $need not in cmp.out (got: $(tr '\n' ',' <<< "$got"))"
        FAIL=$((FAIL+1))
    fi
done
if [[ $FAIL -eq 0 ]]; then
    ok "cmp.out tag-set covers offsets {0,1,2,3} (full: $(tr '\n' ',' <<< "$got"))"
fi

# ---------- summary ----------
log "$PASS pass, $FAIL fail"
[[ $FAIL -eq 0 ]]
