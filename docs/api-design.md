# libdft-dr Public API — v0.1 Design

**Status:** draft for sign-off. Implementation (M3.2) follows once this is locked.

**Scope:** propose the public C++ API surface for v0.1. The headline goal,
per the M0 scoping decision (release plan §6 Q4), is *user-facing API
flexibility* — the library should support a range of DTA client patterns
beyond "produce VUzzer's cmp.out". Speed and recall are already secured;
this milestone decides what users can *do* with the library.

This document is intentionally opinionated. The goal is to converge to a
locked surface, not enumerate every alternative. Open questions are flagged
in §10 for explicit decision before M3.2.

---

## 1. Client patterns we're designing for

These are the four concrete client shapes the library must support. We will
ship a reference client for each (M3.3).

### 1A — File-byte introspection ("what fed this assert?")
A reverse-engineering tool wants to know: "when the program asserted at PC
0x4011a0 with `assert(buf[10] == buf[14])`, which bytes of the input file
were ultimately compared?" Client paints the input on `read()`, runs the
target, and at the assertion sinks the per-byte tag of the two memory
addresses being compared.

### 1B — Egress sanitizer ("did secrets just leave the box?")
A security tool wants to flag any `write()`-to-socket whose buffer contains
tags from `/etc/passwd`. Client paints a custom source (a manual call
saying "the next N bytes of this fd should be tagged 'SECRET'"), registers
a sink on the `write()` syscall, and inspects the buffer's tags inside the
sink callback.

### 1C — VUzzer-style CMP-sink dump
The historical libdft64 client (and our reference vuzzer64-v2 client):
paint the input file on `read()`/`open()`/`mmap()`, sink on every CMP and
LEA instruction with at least one tainted operand byte, emit the
VUzzer-specific text format. The library should make this client a
~200-LOC plug-in, not a hard-coded behavior.

### 1D — Synthetic-input unit tester
A unit test wants to programmatically paint a byte at register/memory
address X with label N, run a synthetic instruction sequence, and assert
that address Y has the expected tag afterward. No syscalls, no real input
file, no instrumentation registration. Used by the M4 test suite.

Five-client mental checklist (a derivative of 1C, included for completeness
because it's a separate Pattern in libdft's design space):

### 1E — Cross-process / cross-input tagging
A multi-process or fork-server fuzzer wants per-byte tags to identify
*which* of several inputs fed a value. Solved by the tag type being rich
enough to encode label provenance (current `dft_label` representation
already supports this via the interned offset-set).

---

## 2. Conceptual layers

The API is organized into four layers, each consumable independently:

```
┌──────────────────────────────────────────────────────────┐
│  4. Reference clients (clients/*)                        │
│     ─ vuzzer_cmp_sink, file_introspect, egress_sanitizer │
├──────────────────────────────────────────────────────────┤
│  3. Client extension points                              │
│     ─ source-painting hooks    ─ sink callback registry  │
│     ─ tag-introspection API    ─ propagation overrides   │
├──────────────────────────────────────────────────────────┤
│  2. Tag model                                            │
│     ─ tag_t opaque handle      ─ tag_combine / tag_test  │
│     ─ tag I/O (mem + reg)      ─ tag enumeration         │
├──────────────────────────────────────────────────────────┤
│  1. Lifecycle                                            │
│     ─ libdft_init(opts)        ─ libdft_exit()           │
│     ─ thread events            ─ exception handling      │
└──────────────────────────────────────────────────────────┘
```

Layer 4 is built on layer 3 only. A client that only needs taint *queries*
(layer 2 + layer 1) can ignore layers 3-4 entirely.

---

## 3. Layer 1 — Lifecycle

**Public header:** `<libdft_dr/lifecycle.h>`

```cpp
namespace libdft_dr {

struct init_options_t {
    /* Per-thread VCPU shadow-register storage. v0.1 supports single-threaded
     * targets only; ignored if app spawns threads. v0.2 adds multi-thread. */
    bool single_threaded = true;

    /* If non-empty, treat module basenames matching any entry as opaque
     * boundaries (taint flows over them via syscall hooks, not per-insn
     * propagation). Equivalent to the existing C.2 "MNT" feature; an
     * optional performance optimization, not a correctness requirement. */
    std::vector<std::string> opaque_modules = {};

    /* Override the default per-thread shadow register count (DFT_REG_NUM).
     * Most users never touch this. */
    size_t reg_file_size = 0;  /* 0 = library default */
};

bool init(const init_options_t &opts);
void exit();

/* Drmgr/drreg are initialized internally; clients DO NOT call drmgr_init
 * themselves. If a client already initialized drmgr (e.g. for an unrelated
 * pass), `init()` is a no-op for those subsystems and just registers our
 * events. Detected at init-time, logged on stderr. */

}  // namespace libdft_dr
```

**What clients do not see:** drmgr/drreg/drutil setup, drwrap discovery,
TLS-slot reservation, the event handler signatures themselves. All hidden.

**Failure modes:** `init()` returns `false` on hard failure (logged to
stderr); client should bail. Soft failures (e.g. an opaque-module entry
that matches no loaded module) log a warning and continue.

---

## 4. Layer 2 — Tag model

**Public header:** `<libdft_dr/tag.h>`

```cpp
namespace libdft_dr {

/* Opaque tag handle. Internally an interned-set id; clients treat as an
 * opaque uint32-sized value. Two tag_t values compare equal iff they
 * represent the same underlying offset set. */
class tag_t {
public:
    constexpr tag_t() noexcept;          // empty tag
    constexpr bool empty() const noexcept;
    constexpr bool operator==(tag_t) const noexcept;
    constexpr bool operator!=(tag_t) const noexcept;

    /* Hash, comparable, copy/movable. Trivially destructible. */
private:
    uint32_t id_;
};
static_assert(sizeof(tag_t) == 4);
static_assert(std::is_trivially_copyable_v<tag_t>);

/* Construct a "singleton" tag from a single label id (e.g. an input-file
 * byte offset). Caller-defined label semantics; library treats labels as
 * opaque uint32_t. */
tag_t make_tag(uint32_t label);

/* Union two tags. (Implemented as memoized set union — O(1) amortized.) */
tag_t combine(tag_t a, tag_t b);

/* Enumerate the labels in a tag. The callback may return false to stop
 * iteration early. Order is unspecified but deterministic across calls. */
using label_visitor = std::function<bool(uint32_t label)>;
void enumerate(tag_t t, const label_visitor &fn);

/* Convenience: serialize a tag to a string ("{1,4,7}" or "{}"). */
std::string to_string(tag_t t);

/* ---- Memory shadow I/O ---- */

tag_t get_mem_tag(uintptr_t addr);
void  set_mem_tag(uintptr_t addr, tag_t t);
void  clear_mem(uintptr_t addr, size_t n);

/* Bulk: union the tags of n consecutive bytes. Used by sinks to ask
 * "what tag does this memory region carry as a whole?". */
tag_t get_mem_tag_range(uintptr_t addr, size_t n);

/* ---- Register shadow I/O (must be called from within instrumentation
 * callbacks; reads the current thread's VCPU). ---- */

tag_t get_reg_tag(reg_id_t reg);                // first byte; sized form below
tag_t get_reg_tag_byte(reg_id_t reg, size_t byte_idx);
void  set_reg_tag(reg_id_t reg, tag_t t);       // applies to all bytes of reg
void  set_reg_tag_byte(reg_id_t reg, size_t byte_idx, tag_t t);
tag_t get_reg_tag_range(reg_id_t reg);          // union across all bytes

}  // namespace libdft_dr
```

**Custom tag types (Q4 follow-on):** v0.1 fixes `tag_t` to the
interned-set representation. The implementation is template-ready (the
`dft_label::id` field is the only point of contact for the set table),
so v0.2 can introduce `tag<Provenance>` parameterized on the application's
label type. Documented in ROADMAP.md.

---

## 5. Layer 3 — Client extension points

### 5.1 Source-painting

**Public header:** `<libdft_dr/sources.h>`

Two source patterns are supported.

**(a) Built-in file-source.** The library ships a turnkey "paint file
bytes by offset" source. The client tells it which filenames matter; the
library hooks `open/openat/read/pread/mmap/dup*/close` and paints each
input byte with `make_tag(file_offset)`.

```cpp
namespace libdft_dr {

struct file_source_options_t {
    /* Filename or basename pattern. Substring match on resolved path. */
    std::string filename;
    /* If true, also paint reads from any fd `dup()`d from a hit fd. */
    bool track_dups = true;
    /* Optional: cap total bytes painted across the entire run. 0 = unlimited. */
    size_t max_bytes = 0;
};

void register_file_source(const file_source_options_t &opts);

}  // namespace libdft_dr
```

**(b) Client-defined source.** The client registers callbacks on
arbitrary syscalls; the callback can paint whatever shadow it wants.
Use for sources outside the file model (`recv()` from a socket,
shared-memory writes, mmap'd hardware buffers).

```cpp
namespace libdft_dr {

using pre_syscall_cb  = std::function<void(syscall_args_t &)>;
using post_syscall_cb = std::function<void(syscall_args_t &, ssize_t result)>;

struct syscall_args_t {
    int sysno;
    uintptr_t arg[6];
    /* Helpers for common patterns: */
    void paint_range(uintptr_t addr, size_t n, uint32_t label);
    /* ... */
};

void register_pre_syscall_hook(int sysno, const pre_syscall_cb &cb);
void register_post_syscall_hook(int sysno, const post_syscall_cb &cb);

}  // namespace libdft_dr
```

### 5.2 Sink callbacks

**Public header:** `<libdft_dr/sinks.h>`

Two granularities:

**(a) Opcode-class callbacks** — fire on every dynamic execution of an
instruction matching a class, *after* taint propagation, *only if* at
least one operand byte is tainted.

```cpp
namespace libdft_dr {

enum class opcode_class {
    CMP,            // covers CMP, CMPS
    LEA,
    MEM_LOAD,       // any read from memory (broad)
    MEM_STORE,      // any write to memory (broad)
    BRANCH,         // conditional branches (Jcc family)
    CALL,
    RET,
    /* future: APP_DEFINED */
};

struct sink_context_t {
    void *drcontext;        // for DR API calls if needed
    instr_t *instr;         // the original app instruction
    app_pc pc;
    /* Operand accessors that already check for non-empty tags: */
    bool has_tainted_operand() const;
    tag_t operand_union() const;  // union of all operand byte-tags
    /* Detailed per-operand iteration; for low-level clients. */
    template <typename F> void for_each_operand_tag(F &&f) const;
};

using sink_cb = std::function<void(const sink_context_t &)>;

void register_sink(opcode_class cls, sink_cb cb);

}  // namespace libdft_dr
```

**(b) PC-range callbacks** — fire on every dynamic execution of any
instruction whose PC falls in `[lo, hi)`. Used by the "stop at this
assert and dump tags" pattern (client 1A).

```cpp
namespace libdft_dr {

void register_pc_range_sink(app_pc lo, app_pc hi, sink_cb cb);

}  // namespace libdft_dr
```

**Threading note:** sink callbacks fire on the application's thread,
inside the DR clean-call path. Heavy work (file I/O, mutex acquisition)
is the client's responsibility to keep cheap; v0.1 single-thread
assumption means no library-side locking, but client callbacks that
themselves block can still freeze the app.

### 5.3 Tag introspection (no callback)

Already covered in layer 2 (`get_mem_tag_range` etc.). A client that
only does post-hoc inspection from inside its own sink callback doesn't
need to register anything beyond a sink.

### 5.4 Propagation overrides (out of scope for v0.1)

A client might want to override how a specific opcode propagates (e.g.
"for ADD, also union the carry flag's source"). This is technically
feasible — the opcode router in `libdft_core_dr.cpp` could be made
extensible — but it's a sharp tool that few clients will reach for and
that complicates the v0.1 API surface significantly. **Deferred to
v0.2**, called out explicitly in ROADMAP.md.

---

## 6. Layer 4 — Reference clients

Ship four under `clients/` (matches §1 patterns):

| Directory | Pattern | LOC estimate | Demonstrates |
|---|---|---|---|
| `clients/file_introspect/` | 1A | ~150 | `register_pc_range_sink`, `get_mem_tag_range`, `enumerate` |
| `clients/egress_sanitizer/` | 1B | ~200 | custom `register_post_syscall_hook`, conditional alerts |
| `clients/vuzzer_cmp_sink/` | 1C | ~250 | `register_file_source` + `register_sink(CMP)` + VUzzer text format. **Byte-equivalent anchor for vuzzer64-v2.** |
| `clients/synthetic_unit/` | 1D | ~100 | Direct `set_reg_tag` / `get_mem_tag` from a non-DR harness for unit tests |

Each client has its own `CMakeLists.txt`, `README.md`, and one example
invocation in the top-level README.

---

## 7. Sink output format

**Library-side:** none. The library passes structured `sink_context_t`
objects to callbacks; clients format as they wish.

**Reference-client-side:** the `vuzzer_cmp_sink` client emits the
historical VUzzer text format (`cmp.out` + `lea.out`). Its README links
to the format spec. Future clients are free to emit JSON, protobuf,
SQLite rows, network packets — whatever fits.

This is a deliberate change from the current libdft-dr internal API,
which has `out` and `out_lea` as public globals. Those go away.

---

## 8. Build-time integration

**For library consumers:**

```cmake
find_package(libdft-dr REQUIRED)
add_dynamorio_client(my_client my_client.cpp)
target_link_libraries(my_client PRIVATE libdft-dr::libdft-dr)
```

A client's source has `#include <libdft_dr/lifecycle.h>` etc. and calls
`libdft_dr::init({...})` from its `dr_client_main`.

**Backwards-compat shim** for libdft64-style code:
`<libdft_dr/libdft64_compat.h>` re-exports `tag_combine(tag_t&, tag_t&)`,
`tagmap_setb_with_tag(addr, tag)`, `file_tag_testb(addr)`, etc. as inline
wrappers that bridge to the namespaced API. Goal: an existing libdft64
client should compile by just changing the include path. Best-effort
(not all libdft64 quirks will translate); documented.

---

## 9. Threading

**v0.1:** single-threaded targets only. Library does not lock the
register file or the interned-tag table. Clients should not call
library APIs from non-app threads (e.g. their own helper threads).

**v0.2:** multi-thread support via per-thread VCPU TLS (already
partially implemented in libdft_api_dr.cpp). The interned-tag table
will need a reader-writer lock or a sharded variant.

---

## 10. Open questions for sign-off

**Q-API.1 — Reference-client count for v0.1.**
Plan said 3-5. §6 currently lists 4. Are all four in scope, or trim to
3 (drop 1D synthetic-unit, since it's really a unit-test harness)?

**Q-API.2 — `sink_context_t` operand walker.**
The `for_each_operand_tag` template is more flexible than
`operand_union()` but adds a header-only template surface (clients see
implementation details). Keep both? Just one? Recommendation: keep both;
80% of clients use `operand_union()`, the 20% with custom needs reach
for the walker.

**Q-API.3 — libdft64 compat shim scope.**
§8 promises a best-effort header. Concrete bar: should the shim cover
just the half-dozen functions vuzzer64-v2 uses, or the full libdft64
public surface? Recommendation: just the functions actually used by
the original libdft64 reference clients (looking at AngoraFuzzer's
example, that's ~10 functions). Documented mapping table.

**Q-API.4 — Namespace.**
Currently `libdft_dr::` everywhere. Some clients may prefer `libdft::`
(shorter) or no namespace at all (libdft64-style). Recommendation: keep
`libdft_dr::`, ship the compat header for the no-namespace style.

**Q-API.5 — Build artifact.**
Currently one `.so` (`libdft-dta-dr.so` = lib + the VUzzer client).
For the standalone release this needs to split:
- `libdft-dr.so` — the library itself
- `clients/vuzzer_cmp_sink/libdft-dta-dr.so` — the reference client

Plus optional: a CMake config so clients can `find_package(libdft-dr)`.
Recommendation: yes, split. ~30 min of CMake refactoring.

---

## 11. What's NOT in v0.1 (recorded for ROADMAP.md)

- Custom tag types beyond the interned-set `dft_label`.
- Propagation hooks / per-opcode overrides (§5.4).
- Multi-thread / locking (§9).
- REP-string-op expansion (M1.4 — closes the recall gap to ≥99.5%).
- Non-x86_64 architectures.
- Language bindings (Python, Rust).

---

## 12. Sign-off checklist (M3.1 close)

Before M3.2 starts, the user explicitly approves:
- [ ] Layer split (§2)
- [ ] `tag_t` opaque-handle design (§4)
- [ ] Two source patterns: built-in file + custom syscall (§5.1)
- [ ] Two sink patterns: opcode-class + PC-range (§5.2)
- [ ] Propagation overrides deferred to v0.2 (§5.4)
- [ ] Four reference clients (§6)
- [ ] No library-side output format (§7)
- [ ] libdft64 compat shim included (§8)
- [ ] Single-threaded for v0.1 (§9)
- [ ] Answers to Q-API.1 through Q-API.5 (§10)
