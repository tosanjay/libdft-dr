# libdft-dr — DynamoRIO port of libdft64

DR-idiomatic reimplementation of the VUzzer64 taint engine, tracked in
`c4_dr_port_plan.md`. The Pin tree (`../libdft64/`) stays the canonical A/B
baseline and is **not** modified by this port.

**Status: Phase 0** — scaffold only. `tools/libdft-dta-dr.cpp` is a no-op DR
client that stands up the drmgr/drreg lifecycle and emits empty `cmp.out` /
`lea.out`. No taint propagation yet.

## Prerequisites

- DynamoRIO 10.0.0 at `/home/sanjay/san-home/tools/dynamorio-10.0` (install via
  `../bin/install_dynamorio_10.sh`).
- CMake ≥ 3.10, a C++ compiler.

## Build

```sh
export DR_ROOT=/home/sanjay/san-home/tools/dynamorio-10.0
cmake -B build -DDynamoRIO_DIR=$DR_ROOT/cmake
cmake --build build -j
```

Output: `build/libdft-dta-dr.so`.

## Run (standalone smoke)

```sh
$DR_ROOT/bin64/drrun -c build/libdft-dta-dr.so -o cmp.out -leao lea.out \
    -filename input.bin -- /path/to/sut input.bin
```

From the fuzzer, this is driven by `runfuzzer.py --mode dr` (see
`fuzzer-code/config.py` `DRTNTCMD`).
