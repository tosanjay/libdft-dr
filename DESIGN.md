# libdft-dr — Design Notes

A self-contained "why + how" for the library. For the *public API*
specifically, see [docs/api-design.md](docs/api-design.md). For perf
methodology, see [bench/BENCHMARKS.md](bench/BENCHMARKS.md).

---

## 1. Why DR? Why now?

The reference implementation we're replacing — `libdft64` — has been
Pin-only since its 2018 release. Profiling a Pin-based VUzzer setup
on `pdfimages` showed ~71–85 % of per-execution wallclock was being
spent *inside the Pin runtime itself* (pinbin, Pin's libc/STLport,
libxed) — ~5 s of a 6.7 s execution. The opcode handlers and the
tag-map data structure were a minority of the cost. Optimizing libdft
further on Pin yields a small slice of a small slice.

DynamoRIO has materially lower per-instruction instrumentation
overhead than Pin and is BSD-licensed and open-source on a
multi-release-per-year cadence. Porting the libdft data-flow model
across DBI frameworks is the lever that actually moves the needle:
this work delivers **~4× speedup over Pin libdft64** on parser
benchmarks (see §7) while preserving the data-flow semantics existing
clients depend on.

## 2. Design philosophy

**DR-native, not Pin-clone.** Where Pin and DR differ architecturally,
we follow DR's grain rather than emulate Pin's. The opcode router
switches on DR's own `OP_*` enum (no XED→DR translation table).
Operands come from DR's `opnd_*` API; memory EAs from
`drutil_insert_get_mem_addr`. Function-summary intercepts use `drwrap`
(entry-PC wrap) rather than mimicking Pin's `RTN_InsertCall`
(function-body instrumentation). The two models diverge by ~10 % on
"intercepted-RTN counts" — that divergence is correctness-neutral; the
data flowing through the libc summaries is identical, validated at the
output-byte level on the parity gate.

**Selective inline + clean calls, not trace-all.** DR's `drmemtrace`
records every retired instruction and memory access unconditionally;
taint after MNT-skip + libc summaries touches only a small fraction.
A trace-all engine would be heavier, not lighter, for the fuzzing
workload. We instrument at CMP/LEA sites directly, just like libdft.

**Correctness first, perf second.** The Phase-5 propagation handlers
landed as clean calls (full register save/restore per dynamic
instruction). That's expensive — a clean call costs ~50 ns of wall
time. The plan was to promote hot opcodes to inline `drreg`/`drx`
patterns afterwards. Profiling the clean-call build (§6) overturned
the premise: dispatch was only ~3 % of cycles; the tag-map data
structure was ~34 %. Replacing the tag representation, not inlining
dispatch, was the speedup. **Profile the actual target before
committing to an optimization plan** — the most expensive single
lesson of the port.

## 3. Architecture

```
                      ┌──────────────────────────────────────┐
                      │  Public API (libdft_dr:: namespace)  │
                      │  lifecycle / tag / sources / sinks   │
                      └────────────────┬─────────────────────┘
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            │                                                     │
   ┌────────▼─────────┐                                ┌──────────▼──────────┐
   │  Source painting │                                │  Sink registries    │
   │  syscall_desc_dr │                                │  api_sinks.cpp      │
   │  open/read/mmap  │                                │  opcode / pc / func │
   └────────┬─────────┘                                └──────────▲──────────┘
            │                                                     │
            ▼                                                     │
   ┌──────────────────────────────────────────────────────────────┴──────────┐
   │  Tag map (shadow memory)                                                │
   │  3-level page table, per-byte cell = 32-bit interned-set ID             │
   │  combine() = O(1) memoized; sprint() = rare, sink-time                  │
   └──────────────────────────────────────────────────────────────────────────┘
            ▲
            │  (per-instruction reads / writes)
            │
   ┌────────┴─────────────────────────────────────────────────────────────────┐
   │  Opcode propagation (libdft_core_dr.cpp, drmgr BB event → clean calls)   │
   │  MOV · CMP · ADD/SUB/AND/OR/XOR/SBB · MOVZX · MOVSX · LEA · PUSH/POP     │
   │  CMPS · LEAVE · BSF/BSR · CWD/CDQ · MUL/DIV/IMUL · XCHG · CMOVcc         │
   │  shifts (no-op, matches libdft) · MOVBE · BSWAP · CMPXCHG · XADD         │
   │  MOVS/STOS/LODS                                                          │
   └──────────────────────────────────────────────────────────────────────────┘
            ▲
            │
   ┌────────┴─────────────┐         ┌─────────────────────────────────────┐
   │  MNT consumer        │         │  sdft_hook (function summaries)     │
   │  static module skip  │         │  drwrap entry-PC; IFUNC-correct via │
   │  for libc / etc.     │         │  dr_get_proc_address-by-name        │
   └──────────────────────┘         └─────────────────────────────────────┘
```

## 4. The DR-native instrumentation pattern

**Lifecycle.** `libdft_dr::init({...})` calls `drmgr_init` / `drreg_init`,
reserves a per-thread TLS slot for the VCPU shadow + syscall context,
allocates the tag-map, and registers DR events: thread init/exit, pre/
post-syscall, BB instrumentation, module load/unload.

**BB instrumentation.** Registered via
`drmgr_register_bb_instrumentation_event`. For each app instruction in
each BB, the opcode router (`ins_inspect_dr`) classifies the instruction
and inserts the appropriate clean call to the matching propagation
handler. The router skips instructions in MNT-marked modules (libc,
etc.) — taint flows over those via syscall hooks and `sdft_hook`
function summaries, not per-instruction propagation.

**Operand handling.** DR's `opnd_*` API exposes operand kind (reg,
memory, immediate), size, and the components of memory EAs (base,
index, scale, displacement). Memory EAs are materialized at runtime
via `drutil_insert_get_mem_addr` into a scratch register reserved by
`drreg`. The handler reads / writes shadow memory at that EA.

**Clean-call arg discipline.** `dr_insert_clean_call` corrupts state
when handed a sub-register value operand (`AX`/`AL`/`EAX`/...). The
rule throughout is: **always pass the pointer-sized parent register
as a clean-call value, and mask to the operand width inside the
handler**. The width mask was already needed for the `cmp.out` value
field, so this is free at the handler boundary.

**Safe memory reads.** Pin's `file_cmp_*` handlers dereference app
memory directly (`*(uint64_t*)ea`). Under DR a racy or unmapped EA
would fault the client. We read the value with `dr_safe_read` (returns
0 on failure) — same emitted bytes for real comparisons, DR-safe on
edge cases.

**Function summaries (`sdft_hook`).** Optional; loaded only when a
`libc_summaries.conf` is provided. For each named function in the
config, we call `dr_get_proc_address(module, name)` per loaded module
and `drwrap`-wrap the resolved entry. Going through the dynamic loader
returns the **IFUNC-resolved implementation address** (e.g.
`__memcpy_avx_unaligned_erms`), not the exported stub, fixing a class
of misses where Pin's `RTN_InsertCall` happens to find the resolved
RTN by execution coincidence.

**File descriptor source painting (`syscall_desc_dr`).** Pre/post
syscall events for `open` / `openat` / `read` / `pread64` / `dup*` /
`close` / `mmap` / `munmap`. An opened path matching the
`register_file_source` substring is added to `fdset`. Subsequent reads
on those fds paint the destination buffer byte-by-byte with
`make_tag(file_offset + i)`.

## 5. Opcode coverage

| Family | Status | Notes |
|---|---|---|
| MOV (reg/mem/imm) | ✅ | r2r / m2r / r2m / imm-clear |
| CMP family (r2r / m2r / i2r / r2m / i2m / m2m) | ✅ | emits `cmp.out` records |
| Binary RMW (ADD, SUB, AND, OR, XOR, SBB, ADC) | ✅ | width-generic; same-reg XOR/SUB detected as clear |
| MOVZX | ✅ | principled zero-extend (libdft's per-size handlers have stale-byte bugs; see §10) |
| MOVSX, MOVSXD | ✅ | sign-fill semantics: low bytes copy source tags, extension region gets the top source byte's tag |
| LEA | ✅ | `dst[i] = combine(base[i], index[i])`; index taint logged to `lea.out` |
| PUSH / POP (reg) | ✅ | reuses MOV mem/reg handlers |
| PUSH / POP (mem) | ⚠️ partial | needs the m2m primitive; low-frequency on tested targets |
| LEAVE | ✅ |  |
| BSF / BSR | ✅ | grouped with MOV in libdft; same here |
| CWD / CDQ / CQO / CBW / CWDE / CDQE | ✅ | in-place accumulator sign-extend |
| MUL / DIV / IDIV | ✅ | ternary combine into RDX:RAX |
| IMUL (1/2/3-op) | ✅ | 1-op → RDX:RAX combine; 2-op binary; 3-op approximated as binary |
| XCHG (r↔r, r↔m) | ✅ | byte-tag swap |
| CMOVcc | ✅ | predicate evaluated at runtime via `dr_get_mcontext(DR_MC_CONTROL)` — taint moves only when condition holds; preserves zero-false-offset property |
| Shifts (SHL/SHR/SAR/ROL/ROR/SHLD/SHRD/RCL/RCR) | ✅ | no-op — matches libdft (which doesn't propagate through shifts) |
| MOVBE | ✅ | byte-reverse semantics |
| BSWAP | ✅ | byte-reverse semantics |
| CMPXCHG, XADD | ✅ | over-conservative union of all operand bytes |
| MOVS / STOS / LODS (non-REP) | ✅ | reuses m2m / r2m / m2r handlers |
| REP-prefixed string ops | ⚠️ deferred to v0.2 | needs `drutil_expand_rep_string`; investigation hit a libc-startup SIGSEGV that survives the canonical fixes; see [ROADMAP.md](ROADMAP.md) |
| x87 FPU | ❌ | out of scope for v0.1 |
| SSE / AVX | ❌ | out of scope for v0.1 |

Validation: on tiffcp seed-2, the DR port captures **1082 of Pin
libdft64's 1098 input-byte offsets**, with **zero false-positive
offsets** (strict subset of Pin's set). The 16-offset gap is the
REP-string deferral; closing it is the v0.2 M1.4 milestone.

## 6. Per-byte tag map

The tag-map is the perf-critical data structure. It's a three-level
page table indexed by app virtual address; each leaf holds 4096
per-byte tag cells.

**The naïve port** (Phase 5.1) used a per-byte `EWAHBoolArray` — a
compressed bitmap of input file offsets, identical to libdft64's
representation. This made every taint MOV/store a heap-allocating
deep-copy of the EWAH structure. Profiling showed
`EWAHBoolArray::operator= → std::vector::operator= →
std::copy/memmove/alloc` consuming **~34 % of cycles** on tiffcp.
DR's own clean-call dispatch machinery was only ~3 %.

**The fix** is an interned-label representation: each per-byte cell is
a 4-byte `uint32` ID into a global table that maps `id →
EWAHBoolArray`. id 0 is the empty set. A taint MOV/store becomes a
single 4-byte copy (inlinable in principle). `combine(a, b)` is a
memoized 2-label lookup against `g_combine[a<<32 | b]`; on a miss it
materializes the union, interns it, and remembers the answer. Set
*materialization* (string-formatting the offset set) happens only at
the rare cmp.out / lea.out sink emissions.

> *This optimization was developed jointly with Cristiano Giuffrida.*

**Result.** On the original DR 10.0 build the tiffcp seed-2 wallclock
dropped 9.32 s → 1.92 s (sdft off) from this change alone, making DR
~2.1× faster than Pin libdft64 (4.02 s) and meeting the project's
≤ 2.0 s wallclock target. The current published numbers (§7) compose
that improvement with the move to DR 11.3, which delivered a further
~1.7× on the same workload — net 4.54× speedup over Pin. Offset
oracle preserved exactly (1082 / 1098, 0 false) across both
transitions. Residual EWAH cost is ~2-5 %, in the intern dedup-key
build; a v0.2 optimization keys `g_intern` on a hash of the EWAH
buffer instead of its serialized string.

The public tag-map API (`tag_combine`, `tag_dir_setb`, etc.) is
unchanged from the EWAH version — the representation swap is internal,
and the public `libdft_dr::tag_t` is a 4-byte opaque handle either way.

## 7. Performance

Mean ± stdev wallclock from 5 iterations per arm; full table and
reproduction instructions in
[bench/BENCHMARKS.md](bench/BENCHMARKS.md):

| Target | Seed | libdft-dr | Pin libdft64 | speedup |
|---|---|---|---|---|
| tiffcp    | 12.7 KB TIFF  | **0.75 ± 0.01 s** | 3.40 ± 0.02 s  | **4.54×** |
| xmllint   | 8.1 KB XML    | **1.08 ± 0.01 s** | 4.55 ± 0.02 s  | **4.20×** |
| pdfimages | 9.9 KB PDF    | **4.60 ± 0.07 s** | 10.11 ± 0.00 s | **2.20×** |

The speed delta has two compounding sources: DR's lower per-instruction
instrumentation overhead vs Pin's `IARG_FAST_ANALYSIS_CALL`, and the
interned-label tag-map (§6). The pdfimages speedup is smaller because
image-decode SUTs spend most cycles in float/SSE inner loops where
neither engine instruments anything — the absolute engine cost is
similar, but the native runtime is large enough to mute the ratio.

## 8. Public API

Four layers covered in detail in [docs/api-design.md](docs/api-design.md):

1. **Lifecycle** — `init({opts})`, `shutdown()`.
2. **Tag model** — `tag_t` opaque handle, mem/reg shadow I/O, label
   enumeration.
3. **Extension points** — built-in file source, custom syscall hooks,
   sink callbacks (opcode-class / PC-range / function-entry).
4. **Reference clients** — four shipped under `clients/`, demonstrating
   the four canonical patterns (VUzzer-compatible CMP/LEA dump, file-
   byte introspection, egress sanitization, synthetic tag-model unit
   tests).

A `libdft64_compat.h` shim provides a 12-entry source-compat layer so
existing libdft64 clients port by changing the include path only.

## 9. Limitations & deferred work

See [ROADMAP.md](ROADMAP.md) for the full list. The headline items:

- **REP-string expansion (M1.4)** — `drutil_expand_rep_string`
  integration hit a libc-startup SIGSEGV that survives every documented
  workaround. Recall stays at 98.5 % until v0.2 closes it.
- **Custom propagation primitives** — v0.1 is fixed byte-set semantics;
  per-opcode user-defined propagation (the Dytan / Taint Rabbit
  generic-policy story) is v0.2+.
- **Multi-thread** — v0.1 assumes a single-threaded target. The
  interned-tag table is lock-free; a multi-threaded SUT would need an
  RW lock or a sharded variant.
- **x87 / SSE / AVX** — propagation through floating-point and vector
  arithmetic is out of scope for v0.1.
- **Architectures** — x86_64 only; ARM64 / RISC-V would be a substantial
  port (DR supports them, but the opcode router and reg-shadow span
  logic are x86_64-specific).

## 10. Engineering lessons worth recording

These cost real time during the port; documenting them so the next
person doesn't repeat the work.

**DR's private loader makes C++ iostream and C stdio unsafe in a client.**
A global `std::ofstream` crashed deterministically at init (glibc stdio /
locale state, `0xfbad` FILE magic). `std::cerr` and `FILE*` failed
similarly. The fix is to use DR's file API (`dr_open_file`,
`dr_fprintf`, `dr_read_file`) for everything. `std::string` / `vector` /
`map` globals are fine; only iostream / stdio are not.

**Clean-call value args must be pointer-sized.** Passing a sub-register
operand (`AL`, `AX`, `EAX`) to `dr_insert_clean_call` corrupts state
on the way in. Always pass the parent (`RAX`), mask to width inside the
handler. The crash is at *insertion* time, not in the handler — bisecting
this took most of a day.

**Adding a propagation handler can *shrink* cmp.out** as easily as
inflate it. Before the LEA handler was wired, registers used as LEA
destinations retained stale taint from their previous role, which leaked
into later comparisons as false offsets. Correctly recomputing
`dst = base ⊕ index` (usually clears the register, since most pointer
math is untainted) removes that false taint and shrinks cmp.out from
~41.7 k → ~16.9 k records on tiffcp. Lesson: **cmp.out volume is not
monotonic in handler coverage**.

**libdft64's MOVZX handlers have stale-byte bugs.** Several size-
specialized `_movzx_*` handlers don't clear the zero-extension region
(e.g. `_movzx_r2r_opqb_u` writes only `dst[0..1]` of an 8-byte qword
destination, leaving `dst[2..7]` stale). A correct implementation has
"low bytes = source, rest = cleared" per x86-64 semantics. The DR port
implements the principled version; the consequence is that strict byte-
parity with Pin will diverge on MOVZX-heavy paths, and the divergence
is in DR's favor (fewer false offsets).

**Base normalization for parity.** DR loads PIE binaries at different
runtime bases than Pin. Any cross-arm parity comparison must use
image-base-relative offsets (subtract the module base reported in
`imageOffset.txt`), never raw runtime PCs. We caught this with the
canary-value-stripped cmp.out diff after seeing 14 lines vary across
runs of the same binary.

## 11. Acknowledgements

The libdft64 codebase by Vasileios Kemerlis and contributors is the
reference implementation this work re-implements; the data-flow model,
syscall hook semantics, and `cmp.out` / `lea.out` wire formats are
preserved across the port. See [LICENSE](LICENSE) for the
BSD-3-Clause inheritance.
