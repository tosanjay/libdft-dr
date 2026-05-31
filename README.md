# libdft-dr

A DynamoRIO-native dynamic taint analysis (DTA) library for x86_64. Re-implements
the [libdft64](https://github.com/AngoraFuzzer/libdft64) data-flow model (per-byte
shadow memory, per-instruction propagation, syscall-based source painting, CMP/LEA
sinks) on top of DynamoRIO instead of Intel Pin.

**Status:** v0.1 in private development. Not yet released.

## Why

libdft64 has been Pin-only since its 2018 release. Pin is closed-source,
commercial, and ships approximately yearly. DynamoRIO is open-source, BSD-licensed,
and on a multi-release-per-year cadence. `libdft-dr` exists so DTA tooling can
move off the Pin dependency without abandoning the libdft data-flow model.

## What's in this repo

| Component | Purpose |
|---|---|
| `tagmap.{h,cpp}` | Per-byte shadow memory + interned-label tag representation |
| `libdft_api_dr.{h,cpp}` | drmgr/drreg setup, per-thread VCPU context, syscall events |
| `libdft_core_dr.{h,cpp}` | Opcode propagation (MOV, CMP, binary, MOVZX/SX, LEA, PUSH/POP, CMPS, LEAVE, BSF/BSR, CWD/CDQ, MUL/DIV/IMUL, XCHG, CMOVcc, shifts, MOVBE/BSWAP, CMPXCHG, XADD, MOVS/STOS/LODS) |
| `mnt_consumer_dr.{h,cpp}` | Static module-skip ("MNT") for libc/etc. — optional perf optimization |
| `sdft_hook_dr.{h,cpp}` | Function-summary hooks via drsym + drwrap — optional |
| `syscall_desc_dr.{h,cpp}` | File-descriptor-based source painting (read, open, mmap, ...) |
| `tools/` | Reference clients (libdft-dta-dr.so produces VUzzer64-compatible cmp.out / lea.out) |

## Build

Requires DynamoRIO ≥ 10.0 with development headers; CMake ≥ 3.7.

```sh
export DR_ROOT=/path/to/dynamorio
mkdir build && cd build
cmake .. -DDynamoRIO_DIR="$DR_ROOT/cmake"
make -j$(nproc)
```

Output: `build/libdft-dta-dr.so` — load with `drrun -c build/libdft-dta-dr.so -- <target>`.

## Reference numbers

Mean ± stdev wallclock from 5 iterations per arm (single-machine, see
`bench/BENCHMARKS.md` for methodology and reproduction instructions):

| Target | Seed | native | libdft-dr | Pin libdft64 | dr / pin |
|---|---|---|---|---|---|
| tiffcp    | seeds_tiffcp/2.tif (12.7 KB)        | 0.012 ± 0.020 s | **1.25 ± 0.01 s**  | 3.48 ± 0.04 s  | **2.78× faster** |
| xmllint   | seeds_xmllint/tutorA.rng (8.1 KB)   | 0.003 ± 0.000 s | **1.60 ± 0.01 s**  | 4.57 ± 0.05 s  | **2.85× faster** |
| pdfimages | seeds/issue1985.pdf (9.9 KB)        | 0.009 ± 0.000 s | **8.25 ± 0.06 s**  | 10.12 ± 0.01 s | **1.23× faster** |

Correctness (independent of perf bench; tiffcp seed-2 with Pin libdft64
output as the oracle):

| Property | Pin libdft64 (2018) | libdft-dr v0.1 |
|---|---|---|
| False-positive offsets | n/a (oracle) | **0** (strict subset) |
| Offset recall | 100 % | 98.5 % (gap = deferred REP-string-expansion opcodes; v0.2 closes this) |

The pdfimages speedup is smaller than the parser targets because image-
decode SUTs spend most of their cycles in float/SSE inner loops where
neither engine instruments anything, muting the engine-cost delta.

The speed advantage over Pin libdft64 has two compounding sources: DR's
lower per-instruction instrumentation overhead vs Pin's
`IARG_FAST_ANALYSIS_CALL`, and a small optimization in the per-byte tag
map data structure (see `tagmap.cpp`).

## License

3-clause BSD, inherited from libdft64. See `LICENSE`.
