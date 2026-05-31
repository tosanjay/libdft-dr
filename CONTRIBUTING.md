# Contributing to libdft-dr

Thanks for considering a contribution. v0.1 is in private development;
once the repo flips public, this file is the entry point for external
PRs.

---

## Quick build

Prereqs: Ubuntu 22.04 or 24.04, GCC ≥ 11, CMake ≥ 3.10, and a
DynamoRIO 10.0 install with development headers.

```sh
# Install DynamoRIO 10.0 (one-time):
curl -fLO https://github.com/DynamoRIO/dynamorio/releases/download/release_10.0.0/DynamoRIO-Linux-10.0.0.tar.gz
tar xzf DynamoRIO-Linux-10.0.0.tar.gz
export DR_ROOT=$PWD/DynamoRIO-Linux-10.0.0

# Build libdft-dr + all 4 reference clients:
git clone https://github.com/tosanjay/libdft-dr
cd libdft-dr
cmake -B build -DDynamoRIO_DIR="$DR_ROOT/cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Expected outputs:

```
build/liblibdft-dr.a                                       # the static lib
build/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so          # client #1
build/clients/file_introspect/libdft-introspect-dr.so      # client #2
build/clients/egress_sanitizer/libdft-egress-dr.so         # client #3
build/clients/synthetic_unit/libdft-synthetic-unit-dr.so   # client #4
```

## Running tests

The CI workflow that runs on every PR is in
`.github/workflows/ci.yml`. To replicate it locally:

```sh
DR_ROOT=/path/to/DynamoRIO-Linux-10.0.0 ./tests/run_smoke.sh
```

This runs two checks:

1. **`synthetic_unit`** — 15 assertions over the public tag-model API
   (`tag_t`, `combine`, `enumerate`, `get_mem_tag`, etc.). Must print
   `[synthetic_unit] OK`.
2. **`vuzzer_cmp_sink` tag-set check** — compiles `tests/sut/magic_check.c`,
   runs it through the client with `tests/seeds/tiny.bin` as the taint
   source, and asserts the emitted `cmp.out` contains tag labels
   `{0,1,2,3}`. This is a compiler / ASLR / PC-agnostic regression
   guard: it ignores PCs and exact values, looking only at the per-byte
   taint labels.

## Running the perf benchmark

Local only — Pin requires an EULA-gated download, so the bench isn't
in CI.

```sh
export DR_ROOT=/path/to/DynamoRIO-Linux-10.0.0
export PIN_ROOT=/path/to/pin-3.20                                # optional
export LIBDFT_PIN_SO=/path/to/libdft64/tools/libdft-dta.so       # optional
./bench/run_perf.sh
```

Output lands at `bench/results.md`. If `PIN_ROOT` or `LIBDFT_PIN_SO`
are unset / missing, the Pin arm is skipped gracefully — you get
`native` + `dr` only.

Default seed and SUT paths point at the vuzzer64-v2 dev-tree layout;
override with the env vars defined at the top of
`bench/run_perf.sh` if your setup differs.

See [bench/BENCHMARKS.md](bench/BENCHMARKS.md) for methodology and the
reproducibility caveats.

## The parity gate

The non-negotiable correctness contract for v0.1:

> The `vuzzer_cmp_sink` client must produce `cmp.out` / `lea.out`
> byte-identical to the legacy single-shot tool on tiffcp seed-2,
> modulo the run-randomized value column (last field; stack canaries
> and pointer values vary per process).

Any PR that touches the taint propagation, sink registry, or tag-map
representation must re-run the parity gate. The standard check:

```sh
# Generate cmp.out under both the new client and the legacy tool.
LD_LIBRARY_PATH=<seed-bin-dir> \
$DR_ROOT/bin64/drrun -c build/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so \
    -o /tmp/cmp.new -leao /tmp/lea.new -filename <seed> \
    -- <SUT> <seed> <out>

LD_LIBRARY_PATH=<seed-bin-dir> \
$DR_ROOT/bin64/drrun -c build/libdft-dta-dr.so \
    -o /tmp/cmp.old -leao /tmp/lea.old -filename <seed> \
    -- <SUT> <seed> <out>

# Strip the run-randomized value column and diff.
awk '{NF--; print}' /tmp/cmp.new > /tmp/cmp.new.nv
awk '{NF--; print}' /tmp/cmp.old > /tmp/cmp.old.nv
diff -q /tmp/cmp.new.nv /tmp/cmp.old.nv
diff -q /tmp/lea.new /tmp/lea.old
```

Both diffs should be empty.

If the diff is non-empty, **don't paper over it** — investigate. Common
sources (from the v0.1 development history):

- A handler missed a register-shadow write site → the gap appears in
  cmp.out as missing tag labels.
- An init-order change disturbed DR's BB-instrumentation pipeline →
  manifests as a small constant drop in cmp.out line count
  (~10 lines) that's run-to-run stable. See the
  `project_libdft_dr_release.md` memory entry on
  "Parity-gate note" — the 18008-vs-17997 environmental discrepancy
  is the canonical example.

## Code style

- Match the surrounding style — there's no formal style guide.
- C++17, no exceptions in the hot path. `std::string` / `vector` / `map`
  are fine; iostream and C stdio are **not** (DR's private loader
  unmaps them — use `dr_open_file` / `dr_fprintf` instead).
- Public headers go in `include/libdft_dr/`. Internal headers go in
  the repo root (or `src/` for newer ones). The convention is
  documented in `docs/api-design.md`.
- Comments explain *why*, not *what*. Naming and structure should
  carry *what*.

## Commits

- One logical change per commit.
- Commit messages explain *why* the change is needed and *what*
  invariant it preserves; bulleted summaries of files-changed are
  fine but not the whole story.
- **No author names in commit trailers** — skip `Co-Authored-By:` lines.
  (Project convention; comes from the upstream development workflow.)
- Commit `bench/results.md` only when re-running the bench as part of
  the change; do not commit it for code-only PRs (the numbers go
  stale instantly).

## PRs

- If your change affects taint output (propagation, sink registry,
  tag-map, source painting): include the parity-gate diff result in
  the PR description.
- If your change affects perf: include a `bench/results.md` excerpt
  showing the before/after numbers on at least tiffcp seed-2. CI
  doesn't enforce a perf threshold, but unreviewed perf regressions
  will be reverted.
- If your change adds a new public symbol: update
  `docs/api-design.md` and (if appropriate) the
  `include/libdft_dr/libdft64_compat.h` mapping.
- Reference clients live in `clients/`. Adding a new one is welcome
  if it covers a pattern not represented by the four existing
  clients; smaller variations belong in your own repo linking
  libdft-dr.

## Reporting issues

Open an issue with:

- A minimal reproducer (a SUT + a seed file are usually enough).
- The exact command line used to invoke `drrun -c ...`.
- DR version (`drrun -version`) and Ubuntu version (`lsb_release -a`).
- For correctness issues: include both Pin libdft64 output and
  libdft-dr output if possible. The point of comparison matters.

For DR-level issues (DR itself crashing the client at startup, not
libdft-dr behavior), file upstream at
[dynamorio/dynamorio](https://github.com/DynamoRIO/dynamorio/issues) —
their tracker is much more responsive for engine bugs.

## Roadmap pointers

- v0.1 deferred items and v0.2 plans: [ROADMAP.md](ROADMAP.md).
- The full release plan (private to vuzzer64-v2 right now):
  `vuzzer64-v2/docs/libdft-dr-release-plan.md`.
