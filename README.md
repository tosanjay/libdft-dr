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

Validated on `tiffcp` from libtiff with a 14 KB seed (`cmp.out` byte-equivalence
against Pin libdft64 as the oracle):

| Property | Pin libdft64 (2018) | libdft-dr |
|---|---|---|
| Speed (tiffcp seed-2, sdft off) | 4.02 s | **1.92 s** (~2.1× faster) |
| False-positive offsets | n/a (oracle) | **0** (strict subset) |
| Offset recall | 100% | 98.5% (v0.1; v0.2 targets ≥99.5%) |

The speed delta has two compounding sources: DR's lower per-instruction
instrumentation overhead vs Pin's `IARG_FAST_ANALYSIS_CALL`, and a small
optimization in the per-byte tag map data structure (see `tagmap.cpp`).

## License

3-clause BSD, inherited from libdft64. See `LICENSE`.
