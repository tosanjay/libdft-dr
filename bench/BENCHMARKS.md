# libdft-dr v0.1 Benchmarks

This file documents the methodology behind `results.md` and how to reproduce
the numbers on your own machine.

## What we measure

**Bench unit:** a single SUT invocation under the taint engine. No fuzzer
loop, no GA mutation, no static-analysis `.pkl` / `.names` files. Just:

```
time drrun -c libdft-dta-dr-v2.so -filename SEED -- SUT SEED OUT
```

repeated `BENCH_ITERS + 1` times. The first iteration is discarded as a
cold-cache warmup; the remaining `BENCH_ITERS` produce the reported mean ±
stdev.

Wallclock comes from `time.perf_counter()` in a python wrapper (bash
builtin `time -p` rounds to 10ms which loses the native-arm sub-100ms
timings).

## Targets and seeds

Three targets, chosen to cover different SUT shapes — TIFF binary parser,
XML text parser, PDF image extractor:

| Target | Binary | Seed | Size |
|---|---|---|---|
| `tiffcp` | libtiff 4.3.0 | `seeds_tiffcp/2.tif` | 12658 B |
| `xmllint` | libxml2 2.9.12 | `seeds_xmllint/tutorA.rng` | 8131 B |
| `pdfimages` | poppler 21.11.0 | `seeds/issue1985.pdf` | 9884 B |

Seed sha256 sums and full paths live in `results.md` so a reader can
verify they're benchmarking against the same input.

## Three arms per target

1. **native** — no instrumentation; `SUT SEED OUT`. Baseline.
2. **dr** — libdft-dr via the `vuzzer_cmp_sink` reference client.
3. **pin** — Pin libdft64 (`vuzzer64-v2/libdft64/tools/libdft-dta.so`).
   Skipped gracefully if `PIN_ROOT` / `LIBDFT_PIN_SO` are unset/missing.

The Pin arm is the **comparison baseline** for the libdft-dr "faster than
Pin" claim.

## Reproducing

```sh
# Prereqs: Ubuntu 22.04 or 24.04, DynamoRIO 11.3, Pin 3.20 (optional).
cd libdft-dr
cmake -B build -DDynamoRIO_DIR=$DR_ROOT/cmake
cmake --build build -j

# Optional: disable ASLR for tightest Pin-arm reproducibility.
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Run the bench (5 iters per arm + 1 warmup, ~3 minutes on a 2018 i7):
DR_ROOT=/path/to/dynamorio-11.3.0 \
PIN_ROOT=/path/to/pin-3.20 \
LIBDFT_PIN_SO=/path/to/libdft64/tools/libdft-dta.so \
./bench/run_perf.sh

# Output: bench/results.md
```

`bench/run_perf.sh` defaults all paths to the vuzzer64-v2 dev-box layout;
override via env vars to point at your own install.

## Caveats

- **Single-machine numbers.** All numbers in `results.md` are from one
  host (CPU model recorded in that file's header). Different CPUs and
  memory subsystems will give different absolute numbers; the **ratio**
  (libdft-dr / Pin) is more stable across hardware than the absolutes.
- **Single seed per target.** A different seed exercising different
  opcode mixes will give different ratios. The pdfimages 1.23× speedup
  is particularly seed-sensitive (image-decode SUTs spend most time in
  float/SSE inner loops where neither engine instruments anything,
  muting the engine-cost delta).
- **No SPEC CPU.** SPEC CPU is the standard taint-engine benchmark
  (Taint Rabbit, LibDFT-DataTracker etc. all report on it) but takes
  hours per arm. For v0.1 we prioritized parser-style targets that
  match the VUzzer fuzzing use case. SPEC CPU is a v0.2 candidate.

## Acceptance criteria (M4)

- libdft-dr faster than Pin libdft64 on tiffcp seed-2 ✅
  (Headline: 2.78× speedup in this run, vs the README's prior 2.1×
  single-measurement claim.)
- Run-to-run variance within 5% on the bench host. ✅
  (Highest observed: 1.5% stdev/mean on instrumented arms.)
- Offset recall regression-guarded at **98.5%** on tiffcp seed-2 ✅
  (Verified independently; see `project_status_phase5` memory in the
  vuzzer64-v2 development tree. The 1% gap vs 100% Pin oracle is from
  the deferred M1.4 REP-string-expansion opcodes; v0.2 closes this.
  See `docs/api-design.md` and the standalone-repo ROADMAP.)
