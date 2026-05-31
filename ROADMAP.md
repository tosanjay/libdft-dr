# libdft-dr Roadmap

This file enumerates what's intentionally **not** in v0.1, and what's on
deck for v0.2 and beyond. Each item points back to its rationale in the
[DESIGN.md](DESIGN.md) or [docs/api-design.md](docs/api-design.md).

---

## v0.1 (current)

The shipping scope, recapped for context:

- DR-native libdft64 port; per-byte shadow memory, per-instruction
  propagation, syscall source painting, CMP/LEA sinks.
- Interned-label tag-map representation; **~2.78× faster than Pin
  libdft64** on tiffcp seed-2 ([bench/BENCHMARKS.md](bench/BENCHMARKS.md)).
- Public `libdft_dr::` API: lifecycle, tag model, sources, sinks
  (opcode-class + PC-range + function-entry).
- 4 reference clients: `vuzzer_cmp_sink`, `file_introspect`,
  `egress_sanitizer`, `synthetic_unit`.
- `libdft64_compat.h` source-compat shim.
- CI (Ubuntu 22.04 + 24.04 matrix).

---

## Deferred from v0.1

These are intentional gaps. Each is documented in
[DESIGN.md](DESIGN.md) §9 (limitations) and/or
[docs/api-design.md](docs/api-design.md) §11.

### Recall: REP-string expansion (M1.4 — gates v0.1 recall at 98.5 %)

Pin libdft64 propagates taint through `REP MOVS` / `REP STOS` /
`REP LODS` via XED's loop expansion. The DR equivalent is
`drutil_expand_rep_string`. Wiring it on hit a libc-startup SIGSEGV
that survives every documented workaround (priority ordering,
`drutil_instr_is_stringop_loop` filter, `drmgr_orig_app_instr_for_operands`,
`DR_EMIT_STORE_TRANSLATIONS` vs `DR_EMIT_DEFAULT`). The crash fires on
the first expanded BB even with every per-instruction handler disabled,
so the interaction is with `drutil_expand_rep_string` and one of the
init paths (drwrap, drreg's 4-slot config, syscall hooks) rather than
our propagation code. Closing this gap brings recall from 98.5 % →
≥ 99.5 % on tiffcp seed-2.

**Status:** scheduled for v0.2 as the headline correctness milestone
(see `vuzzer64-v2/docs/libdft-dr-release-plan.md` M1.4 follow-up).

### Custom propagation primitives

v0.1 ships byte-set propagation with fixed semantics. Some clients want
to override how a specific opcode propagates (e.g. "for ADD, also union
the carry flag's source" — the Dytan / Taint Rabbit "generic taint"
story). The opcode router in `libdft_core_dr.cpp` is structured to
support this — handlers are dispatch-table entries, and a public
extension point is technically feasible. But it's a sharp tool that few
clients reach for, and it would significantly complicate the v0.1 API
surface. See [docs/api-design.md](docs/api-design.md) §5.4.

**Status:** v0.2 candidate, lower priority than DFPG and REP-string.

### Multi-threaded targets

v0.1 is single-thread only. The per-thread VCPU shadow already lives in
a `drmgr` TLS slot, so the registration side is multi-thread-clean. The
interned-tag table (`g_sets` / `g_intern` / `g_combine`) is process-
global and unlocked — valid for single-threaded CLI parsers, **not safe
under a multi-threaded SUT**.

**Status:** v0.2 candidate. Closes via either a reader-writer lock on
the intern table (simplest) or a sharded variant (better scaling under
contention). The `init_options_t::single_threaded` field is already
present to gate behavior at init.

### Custom tag types

v0.1 fixes `tag_t` to the interned-set representation. The
implementation is template-ready — `dft_label::id` is the only point of
contact with the set table — so a future `tag<Provenance>` parameterized
on the application's label type is a localized change. Useful for
Undangle-style pointer-provenance tracking and composite labels.

**Status:** v0.2 candidate. See [docs/api-design.md](docs/api-design.md)
§4 "Custom tag types".

### Non-x86_64 architectures

x86_64 only. ARM64 and RISC-V would be substantial ports — DR supports
them, but the opcode router and `reg_shadow_span` logic are
x86_64-specific (register-numbering table, sub-register aliasing rules,
flag-touching opcodes, calling convention).

**Status:** v0.2+. Probably ARM64 first given mobile / Apple Silicon
demand; would need a co-maintainer with ARM expertise.

### Language bindings

C++ only. Python / Rust bindings would let DTA tooling outside the C++
ecosystem (think static-analysis frontends, fuzz-mutation scripts) talk
to the library.

**Status:** v0.2+. Python via pybind11 is the cheapest first cut and
covers the largest user community.

---

## v0.2 plans

### M7: Dynamic Fast Path Generation (DFPG) via `drbbdup` — headline v0.2 feature

Most BBs in fuzzed parsers touch zero tainted bytes; instrumenting them
is wasted work. The Taint Rabbit paper (Galea & Kroening, ASIA CCS '20)
demonstrated a 2-3× speedup on parsing benchmarks by using DR's
`drbbdup` extension (which they upstreamed) to JIT specialized BB
copies — an uninstrumented "no taint" variant for the common case, and
an instrumented variant when the BB-entry register taint mask says
otherwise.

Adopting this in libdft-dr would put us in the same league as Taint
Rabbit's reported 1.7× generic overhead, while preserving v0.1's
correctness contract and public API surface.

**Prep work landed in v0.1:** `libdft_compute_gpr_mask(tc)` in
`libdft_api_dr.h` is the rebuild-from-truth helper, and a
`gpr_mask_cached` field is reserved in `thread_ctx_t` for the
incremental cached path. The dispatcher will use both.

**Expected scope:**
- `drbbdup` variant registration to replace `event_bb_insn`.
- Truncation: split BBs at runtime-computed-EA points so the entry
  encoder has a static input set.
- PC-range sink coexistence: a BB overlapping a registered PC-range
  sink still takes the instrumented path even on a zero-taint mask.
- Paranoid validation mode (`LIBDFT_DR_VALIDATE_DFPG`): runs both
  variants and diffs the output per-BB, catching the over-approx-mask
  staleness bug class before it ships.

Full scope, acceptance criteria, and risks are in
`vuzzer64-v2/docs/libdft-dr-release-plan.md` M7.

### M1.4 follow-up: close the REP-string-expansion gap

Goal: recall ≥ 99.5 % on tiffcp seed-2. Approach: revisit
`drutil_expand_rep_string` with a focused reproducer, likely landing on
either a DR-upstream fix or an alternative (e.g. emit MOVS / STOS / LODS
as unrolled inline propagation at instrument time for short rep counts,
fall back to a clean call for long ones).

### Lock the interned-tag table for multi-thread

Either an RW lock on `g_intern` / `g_combine` (simple, low contention
since most ops are read-only after warmup) or a sharded variant
(8 shards keyed on label id, locked independently). Benchmark on a
multi-threaded SUT after landing.

### Custom-tag-type templating

`tag<Provenance>` with `Provenance` = the application's label payload
(uint32 by default; user can substitute richer types). Library API stays
generic via concepts.

---

## v0.3+ wishlist (no schedule)

- **Python bindings** (pybind11) for the `libdft_dr::` API.
- **ARM64 port**.
- **SPEC CPU 2017 benchmark suite** in `bench/` — taint-engine standard
  benchmark; useful for side-by-side with Taint Rabbit / DataTracker /
  Triton numbers.
- **Custom propagation primitives** (Dytan / Taint Rabbit generic-policy
  story). Lower priority than the items above.
- **x87 / SSE / AVX propagation** — out of scope for v0.1; needed for
  taint analysis of media-decoding paths where SIMD is the main carrier.
- **Live register analysis** for `drreg` to skip dead-reg spills
  (Taint Rabbit's other modest optimization, orthogonal to DFPG).
