#!/usr/bin/env bash
#
# tests/run_smoke.sh -- libdft-dr CI smoke test.
#
# Drives:
#   1. synthetic_unit -- 15 assertions on the tag model API (must print "OK").
#   2. vuzzer_cmp_sink -- runs against tests/sut/magic_check on tests/seeds/tiny.bin
#      and checks the emitted cmp.out tag SET contains the expected offsets.
#
# Both tests use a tiny in-repo SUT (compiled here from
# tests/sut/magic_check.c) rather than /bin/true. The /bin/true on
# Ubuntu 24.04 (glibc 2.39) has a static-PIE-ish startup that DR 10.0
# doesn't always finish gracefully -- the client exit event sometimes
# doesn't fire and synthetic_unit's OK line never reaches stderr.
# A self-compiled tiny SUT sidesteps the issue and is more deterministic
# anyway.
#
# The expected-tag-SET check is compiler/ASLR/PC-agnostic: it ignores PCs
# and exact values, looking only at the per-byte taint labels.
#
# Usage: DR_ROOT=/path/to/dynamorio-11.3.0 tests/run_smoke.sh
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

# Compile the shared tiny SUT once. Used by both tests below.
SUT="$TMPD/magic_check"
SEED="$REPO/tests/seeds/tiny.bin"
[[ -f "$SEED" ]] || { bad "tiny.bin seed missing"; exit 1; }
cc -O0 -o "$SUT" "$REPO/tests/sut/magic_check.c"

# ---------- (1) synthetic_unit ----------
log "1. synthetic_unit"
SU="$BUILD/clients/synthetic_unit/libdft-synthetic-unit-dr.so"
[[ -f "$SU" ]] || { bad "synthetic_unit .so missing at $SU"; exit 1; }
SU_OUT_FILE="$TMPD/synthetic_unit.out"
set +e
"$DR_ROOT/bin64/drrun" -c "$SU" -- "$SUT" "$SEED" >"$SU_OUT_FILE" 2>&1
SU_RC=$?
set -e
SU_OUT="$(cat "$SU_OUT_FILE")"
if grep -q "synthetic_unit\] OK" <<< "$SU_OUT"; then
    ok "15 assertions"
else
    bad "synthetic_unit did not print OK (rc=$SU_RC)"
    echo "--- full drrun output (truncated to 200 lines) ---" >&2
    echo "$SU_OUT" | head -200 >&2
    echo "--- end output ---" >&2
fi

# ---------- (2) vuzzer_cmp_sink + magic_check ----------
log "2. vuzzer_cmp_sink + magic_check SUT"
VCS="$BUILD/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so"
[[ -f "$VCS" ]] || { bad "vuzzer_cmp_sink .so missing"; exit 1; }

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
