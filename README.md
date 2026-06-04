# libdft-dr

A DynamoRIO-native dynamic taint analysis (DTA) library for x86_64.
Re-implements the [libdft64](https://github.com/AngoraFuzzer/libdft64)
data-flow model — per-byte shadow memory, per-instruction propagation,
syscall-based source painting, CMP/LEA sinks — on top of DynamoRIO instead
of Intel Pin.

**~4× faster than Pin libdft64** on parser benchmarks (tiffcp, xmllint);
byte-equivalent `cmp.out` / `lea.out` output for VUzzer64-style fuzzers.

**Status:** v0.1 — first public release. See [ROADMAP.md](ROADMAP.md) for
deferred items and v0.2 plans.

---

## Why

| | Pin libdft64 (2018) | libdft-dr (this work) |
|---|---|---|
| DBI framework | Intel Pin (closed, commercial) | DynamoRIO (open, BSD-licensed) |
| Architecture | x86_64 | x86_64 |
| Release cadence | ~yearly (Pin) | multi-release-per-year (DR) |
| Tag representation | per-byte EWAH bitmap | per-byte interned-set 32-bit ID |
| Build system | Pin's GNU make | CMake (DR-native) |
| Speed vs Pin libdft64 (tiffcp seed-2) | 1.0× (oracle) | **~4.54×** |
| Recall vs Pin oracle (tiffcp seed-2) | 100 % | 98.5 % (v0.1) |
| False-positive offsets | n/a (oracle) | **0** (strict subset) |
| Generic taint policies | byte-set (fixed) | byte-set (fixed); user-defined sinks |
| User-defined sinks | source-edit only | three patterns: opcode-class, PC-range, function-entry |

libdft64 has been Pin-only since its 2018 release. Pin is closed-source,
commercial, EULA-gated. DynamoRIO is open-source BSD and on a multi-release
cadence. `libdft-dr` exists so DTA tooling can move off the Pin dependency
without abandoning the libdft data-flow model.

## Quick start

Requires DynamoRIO ≥ 11.3 with development headers and CMake ≥ 3.10.

```sh
export DR_ROOT=/path/to/dynamorio-11.3.0
cmake -B build -DDynamoRIO_DIR="$DR_ROOT/cmake"
cmake --build build -j

# VUzzer-compatible CMP/LEA dump on a target binary:
$DR_ROOT/bin64/drrun \
  -c build/clients/vuzzer_cmp_sink/libdft-dta-dr-v2.so \
  -o cmp.out -leao lea.out -filename input.tif \
  -- /usr/bin/tiffcp input.tif /tmp/out.tif

# In-process tag-model self-test (15 assertions, takes <1s):
$DR_ROOT/bin64/drrun \
  -c build/clients/synthetic_unit/libdft-synthetic-unit-dr.so \
  -- /bin/true
```

## Hello-world client

A minimal client paints an input file as a taint source and dumps the tag
of any memory comparison the target performs:

```cpp
#include "dr_api.h"
#include "libdft_dr/lifecycle.h"
#include "libdft_dr/sources.h"
#include "libdft_dr/sinks.h"
#include "libdft_dr/tag.h"

static void on_cmp(const libdft_dr::sink_context_t &ctx) {
    if (!ctx.has_tainted_operand()) return;
    libdft_dr::tag_t t = ctx.operand_union();
    dr_fprintf(STDERR, "[hello] CMP at %p tainted by %s\n",
               ctx.pc, libdft_dr::to_string(t).c_str());
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    libdft_dr::init({});

    libdft_dr::file_source_options_t f;
    f.filename = "/path/to/input.txt";  // substring match on opened files
    libdft_dr::register_file_source(f);

    libdft_dr::register_sink(libdft_dr::opcode_class::CMP, on_cmp);
}
```

Build alongside the library as a DR client (see
`clients/vuzzer_cmp_sink/CMakeLists.txt` for the canonical CMake recipe).
Run it the same way as the reference clients above.

## Reference clients

Four reference clients under `clients/` cover the four canonical patterns
laid out in [docs/api-design.md](docs/api-design.md):

| Client | .so name | Pattern | Use case |
|---|---|---|---|
| `vuzzer_cmp_sink` | `libdft-dta-dr-v2.so` | opcode-class sink | VUzzer-compatible `cmp.out` + `lea.out` |
| `file_introspect` | `libdft-introspect-dr.so` | PC-range sink | "what input bytes fed this PC?" |
| `egress_sanitizer` | `libdft-egress-dr.so` | function-entry sink | alert on tainted `write()` |
| `synthetic_unit` | `libdft-synthetic-unit-dr.so` | direct tag I/O | unit-test the tag model |

## Public API

Five headers under `include/libdft_dr/`:

| Header | Layer | What it provides |
|---|---|---|
| `lifecycle.h` | 1 | `init({...opts})`, `shutdown()` |
| `tag.h` | 2 | `tag_t`, `make_tag`, `combine`, `enumerate`, memory + register shadow I/O |
| `sources.h` | 3a | `register_file_source`, custom `register_pre/post_syscall_hook` |
| `sinks.h` | 3b | `register_sink(opcode_class, cb)`, `register_pc_range_sink`, `register_func_sink` |
| `libdft64_compat.h` | — | 12-entry source-compat shim for existing libdft64 clients |

Full API rationale and worked examples: [docs/api-design.md](docs/api-design.md).

## Reference numbers

Mean ± stdev wallclock from 5 iterations per arm; methodology and seed
sha256 manifest in [bench/BENCHMARKS.md](bench/BENCHMARKS.md):

| Target | Seed | native | libdft-dr | Pin libdft64 | dr / pin |
|---|---|---|---|---|---|
| tiffcp    | seeds_tiffcp/2.tif (12.7 KB)        | 0.003 ± 0.000 s | **0.75 ± 0.01 s**  | 3.40 ± 0.02 s  | **4.54× faster** |
| xmllint   | seeds_xmllint/tutorA.rng (8.1 KB)   | 0.003 ± 0.000 s | **1.08 ± 0.01 s**  | 4.55 ± 0.02 s  | **4.20× faster** |
| pdfimages | seeds/issue1985.pdf (9.9 KB)        | 0.009 ± 0.000 s | **4.60 ± 0.07 s**  | 10.11 ± 0.00 s | **2.20× faster** |

The pdfimages speedup is smaller than the parser targets because image-
decode SUTs spend most cycles in float/SSE inner loops where neither
engine instruments anything, muting the engine-cost delta.

The speed advantage over Pin libdft64 has two compounding sources: DR's
lower per-instruction instrumentation overhead vs Pin's
`IARG_FAST_ANALYSIS_CALL`, and a small optimization in the per-byte tag
map data structure (see [DESIGN.md](DESIGN.md) and `tagmap.cpp`).

## Documentation

- [DESIGN.md](DESIGN.md) — why this exists, how it's built, perf profile,
  opcode coverage matrix.
- [docs/api-design.md](docs/api-design.md) — full API rationale, worked
  examples, version-evolution notes.
- [ROADMAP.md](ROADMAP.md) — what's deferred from v0.1; v0.2 plans (DFPG,
  multi-thread, language bindings).
- [bench/BENCHMARKS.md](bench/BENCHMARKS.md) — perf methodology and
  reproduction instructions.
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test, parity-gate workflow,
  PR conventions.
  
## Acknowledgement

CC + Opus 4.7 has been my co-pilot in the development of this project. 
My take: If one knows what they want to build and have good understanding of the nitty-gritty of the stuff, this human-AI colab works well! 

## License

3-clause BSD, inherited from libdft64. See [LICENSE](LICENSE).
