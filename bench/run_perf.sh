#!/usr/bin/env bash
#
# bench/run_perf.sh -- libdft-dr v0.1 perf benchmark.
#
# Methodology:
#   For each (target, arm) pair: run BENCH_ITERS+1 iterations, discard the
#   first (cold-cache warmup), report mean ± stdev of the remaining ones.
#   Wallclock is `time -p` real-time.
#
#   Arms: native (no instrumentation), libdft-dr (this work, via the
#   vuzzer_cmp_sink reference client), Pin libdft64 (the canonical baseline,
#   skipped gracefully if PIN_ROOT or LIBDFT_PIN_SO are unset/missing).
#
#   Bench unit is ONE SUT invocation. No fuzzer loop; no GA mutation; no
#   .pkl/.names static-analysis files.
#
# Reproducibility:
#   ASLR must be disabled (sudo sysctl -w kernel.randomize_va_space=0)
#   for the Pin arm to behave identically to its baseline. The libdft-dr
#   and native arms tolerate ASLR but timings are noisier.
#
# Output:
#   $BENCH_OUT (default: bench/results.md) -- markdown tables, one per target.
#
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

# --- knobs (env-overridable) ----------------------------------------------
BENCH_ITERS="${BENCH_ITERS:-5}"
BENCH_OUT="${BENCH_OUT:-$REPO/bench/results.md}"
DR_ROOT="${DR_ROOT:?DR_ROOT must point at the DynamoRIO 11.3 install}"
PIN_ROOT="${PIN_ROOT:-}"   # optional; if unset/empty, the Pin arm is skipped
LIBDFT_DR_SO="${LIBDFT_DR_SO:-$REPO/build/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so}"
LIBDFT_PIN_SO="${LIBDFT_PIN_SO:-}"   # optional; required only with PIN_ROOT

# --- per-target config -----------------------------------------------------
# Each target needs: SUT binary, seed file, optional LD_LIBRARY_PATH for
# bundled SUT libs, and the SUT command template (where %SEED% / %OUT% are
# substituted at run time). Output path is %OUT%; sized for one invocation.
#
# The default paths point at the sibling vuzzer64-v2 dev-tree layout used
# during libdft-dr development. External users will override these via
# the per-target env vars (see "Reproducing" in bench/BENCHMARKS.md).
VV2="${VV2:-$REPO/../vuzzer64-v2/bin}"

declare -A SUT_BIN SUT_SEED SUT_LDPATH SUT_INVOKE
SUT_BIN[tiffcp]="$VV2/libtiff/tiffcp"
SUT_SEED[tiffcp]="$VV2/libtiff/seeds_tiffcp/2.tif"
SUT_LDPATH[tiffcp]="$VV2/libtiff"
SUT_INVOKE[tiffcp]='%SEED% %OUT%/out.tif'

SUT_BIN[xmllint]="$VV2/libxml2/xmllint"
SUT_SEED[xmllint]="$VV2/libxml2/seeds_xmllint/tutorA.rng"
SUT_LDPATH[xmllint]="$VV2/libxml2"
SUT_INVOKE[xmllint]='%SEED%'

SUT_BIN[pdfimages]="$VV2/poppler/pdfimages"
SUT_SEED[pdfimages]="$VV2/poppler/seeds/issue1985.pdf"
SUT_LDPATH[pdfimages]="$VV2/poppler"
SUT_INVOKE[pdfimages]='%SEED% %OUT%/pdfimg'

TARGETS=(tiffcp xmllint pdfimages)

# --- helpers ---------------------------------------------------------------
log() { printf '[bench] %s\n' "$*" >&2; }

time_one() {
    # $1: cmd to run (already has env vars + redirects baked in).
    # Use python's perf_counter for ms-precision wallclock (bash builtin
    # `time -p` rounds to 10ms which loses native-arm sub-100ms runs).
    python3 -c '
import subprocess, sys, time
t = time.perf_counter()
subprocess.run(["bash", "-c", sys.argv[1]],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"{time.perf_counter() - t:.4f}")
' "$1"
}

# mean and stdev (sample) over stdin (one number per line).
stats() {
    awk '
        { x[NR]=$1; s+=$1 }
        END {
            if (NR == 0) { print "0 0"; exit }
            mean = s / NR
            if (NR > 1) {
                ss = 0
                for (i=1; i<=NR; i++) ss += (x[i]-mean)^2
                sd = sqrt(ss / (NR-1))
            } else {
                sd = 0
            }
            printf "%.4f %.4f\n", mean, sd
        }'
}

build_cmd() {
    # $1: target, $2: arm (native|dr|pin), $3: tmpdir
    local tgt="$1" arm="$2" tmpd="$3"
    local bin="${SUT_BIN[$tgt]}" seed="${SUT_SEED[$tgt]}"
    local ld="${SUT_LDPATH[$tgt]}" inv="${SUT_INVOKE[$tgt]}"
    local sut_args="${inv//%SEED%/$seed}"
    sut_args="${sut_args//%OUT%/$tmpd}"
    case "$arm" in
        native)
            echo "LD_LIBRARY_PATH='$ld' '$bin' $sut_args"
            ;;
        dr)
            echo "LD_LIBRARY_PATH='$ld' '$DR_ROOT/bin64/drrun' -c '$LIBDFT_DR_SO' \
                -o '$tmpd/cmp.out' -leao '$tmpd/lea.out' \
                -filename '$seed' -- '$bin' $sut_args"
            ;;
        pin)
            echo "LD_LIBRARY_PATH='$ld' '$PIN_ROOT/pin' -t '$LIBDFT_PIN_SO' \
                -o '$tmpd/cmp.out' -leao '$tmpd/lea.out' \
                -filename '$seed' -- '$bin' $sut_args"
            ;;
    esac
}

# --- prereq checks ---------------------------------------------------------
[[ -x "$DR_ROOT/bin64/drrun" ]] || { log "ERROR: drrun not at $DR_ROOT/bin64/drrun"; exit 1; }
[[ -f "$LIBDFT_DR_SO" ]] || { log "ERROR: libdft-dr .so not at $LIBDFT_DR_SO; build first"; exit 1; }

HAVE_PIN=0
if [[ -x "$PIN_ROOT/pin" && -f "$LIBDFT_PIN_SO" ]]; then
    HAVE_PIN=1
    log "Pin baseline available ($LIBDFT_PIN_SO)"
else
    log "Pin baseline UNAVAILABLE (PIN_ROOT=$PIN_ROOT, LIBDFT_PIN_SO=$LIBDFT_PIN_SO) -- skipping pin arm"
fi

# --- bench loop ------------------------------------------------------------
RESULTS_TMP="$(mktemp)"
trap 'rm -f "$RESULTS_TMP"' EXIT

ARMS=(native dr)
[[ $HAVE_PIN -eq 1 ]] && ARMS+=(pin)

for tgt in "${TARGETS[@]}"; do
    [[ -x "${SUT_BIN[$tgt]}" ]] || { log "WARN: skipping $tgt -- binary missing"; continue; }
    [[ -f "${SUT_SEED[$tgt]}" ]] || { log "WARN: skipping $tgt -- seed missing"; continue; }
    log "=== target: $tgt ==="
    seed_sha="$(sha256sum "${SUT_SEED[$tgt]}" | awk '{print $1}')"
    seed_size="$(stat -c %s "${SUT_SEED[$tgt]}")"
    echo "## $tgt" >> "$RESULTS_TMP"
    echo "" >> "$RESULTS_TMP"
    echo "- seed: \`$(basename "${SUT_SEED[$tgt]}")\` (${seed_size} B, sha256 \`$seed_sha\`)" >> "$RESULTS_TMP"
    echo "- SUT: \`$(basename "${SUT_BIN[$tgt]}")\`" >> "$RESULTS_TMP"
    echo "" >> "$RESULTS_TMP"
    echo "| arm | mean (s) | stdev (s) | × native |" >> "$RESULTS_TMP"
    echo "|---|---|---|---|" >> "$RESULTS_TMP"

    declare -A means
    for arm in "${ARMS[@]}"; do
        tmpd="$(mktemp -d)"
        cmd="$(build_cmd "$tgt" "$arm" "$tmpd")"
        log "  arm=$arm  warmup..."
        time_one "$cmd" >/dev/null || { log "    FAIL warmup; skipping"; rm -rf "$tmpd"; continue; }
        log "  arm=$arm  iters=$BENCH_ITERS"
        samples_file="$(mktemp)"
        for ((i=1; i<=BENCH_ITERS; i++)); do
            t="$(time_one "$cmd")"
            echo "$t" >> "$samples_file"
            log "    iter $i: ${t}s"
        done
        read -r mean sd < <(stats < "$samples_file")
        means[$arm]="$mean"
        ratio="-"
        if [[ -n "${means[native]:-}" && "$arm" != "native" ]]; then
            ratio="$(awk -v a="$mean" -v n="${means[native]}" 'BEGIN{ printf "%.1f×", a/n }')"
        elif [[ "$arm" == "native" ]]; then
            ratio="1.0×"
        fi
        printf '| %-12s | %s | %s | %s |\n' "$arm" "$mean" "$sd" "$ratio" >> "$RESULTS_TMP"
        rm -f "$samples_file"
        rm -rf "$tmpd"
    done

    # libdft-dr / Pin ratio if both ran
    if [[ -n "${means[dr]:-}" && -n "${means[pin]:-}" ]]; then
        echo "" >> "$RESULTS_TMP"
        spd="$(awk -v p="${means[pin]}" -v d="${means[dr]}" 'BEGIN{ printf "%.2f×", p/d }')"
        echo "**libdft-dr speedup over Pin libdft64:** $spd" >> "$RESULTS_TMP"
    fi
    echo "" >> "$RESULTS_TMP"
    unset means
done

# --- finalize --------------------------------------------------------------
{
    echo "# libdft-dr v0.1 perf benchmarks"
    echo ""
    echo "Generated: $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    echo "Host: $(uname -srm), $(nproc) cores"
    if command -v lscpu >/dev/null 2>&1; then
        cpu="$(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
        [[ -n "$cpu" ]] && echo "CPU: $cpu"
    fi
    echo "DR: $("$DR_ROOT/bin64/drrun" -version 2>/dev/null | head -1)"
    if [[ $HAVE_PIN -eq 1 ]]; then
        echo "Pin: $(basename "$(dirname "$PIN_ROOT")")/$(basename "$PIN_ROOT")"
    fi
    echo "Iterations per (target, arm): $BENCH_ITERS (+1 warmup discarded)"
    echo ""
    echo "Methodology and caveats: see bench/BENCHMARKS.md."
    echo ""
    cat "$RESULTS_TMP"
} > "$BENCH_OUT"

log "wrote $BENCH_OUT"
