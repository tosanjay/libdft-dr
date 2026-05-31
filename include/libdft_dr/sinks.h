/* libdft_dr/sinks.h -- Layer 3 sink callback registry.
 *
 * Three sink patterns:
 *   (a) opcode-class -- "fire on every CMP/LEA/... with tainted operand"
 *   (b) PC-range     -- "fire on every insn in [lo, hi)"
 *   (c) function-entry -- "fire on every call to named func, with taint-aware
 *                         arg accessors"
 * See docs/api-design.md §5.2.
 */
#ifndef LIBDFT_DR_SINKS_H_
#define LIBDFT_DR_SINKS_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "dr_api.h"

#include "libdft_dr/tag.h"

namespace libdft_dr {

/* ---- (a) Opcode-class sinks ---- */

enum class opcode_class {
    CMP,         /* CMP family (CMP, CMPS) */
    LEA,
    MEM_LOAD,    /* any read from memory */
    MEM_STORE,   /* any write to memory */
    BRANCH,      /* conditional Jcc */
    CALL,
    RET,
};

struct sink_context_t {
    void    *drcontext;
    instr_t *instr;        /* original app instruction; may be NULL in v0.1
                            * for clean-call-dispatched sinks (CMP/LEA) */
    app_pc   pc;

    /* True if at least one operand byte carries a non-empty tag. */
    bool  has_tainted_operand() const;

    /* Union of every operand byte's tag (memory + register operands). */
    tag_t operand_union() const;

    /* Iterate per-operand tags.
     *   visitor signature: bool(int operand_idx, bool is_dst, tag_t t)
     * Visitor may return false to stop early. v0.1 reports is_dst=false for
     * all CMP/LEA operands (both sides are read-only semantically). */
    using operand_visitor =
        std::function<bool(int operand_idx, bool is_dst, tag_t t)>;
    void for_each_operand_tag(const operand_visitor &fn) const;

    /* Pre-formatted libdft64-compatible record (21 fields for CMP, 10 for LEA;
     * empty for other classes in v0.1). Used by the vuzzer_cmp_sink reference
     * client for byte-equivalent cmp.out / lea.out output. New clients should
     * prefer the raw tag accessors above. The vector is owned by the dispatch
     * payload and only valid for the duration of the callback. */
    const std::vector<std::string> &legacy_record() const;

    /* Opaque dispatch payload pointer; clients must not touch. */
    void *_internal;
};

using sink_cb = std::function<void(const sink_context_t &)>;

/* Sinks are additive: multiple sinks on the same class all fire. */
void register_sink(opcode_class cls, sink_cb cb);

/* ---- (b) PC-range sinks ---- */

void register_pc_range_sink(app_pc lo, app_pc hi, sink_cb cb);

/* ---- (c) Function-entry sinks ---- */

struct func_sink_context_t {
    void  *drcontext;
    app_pc entry_pc;

    /* Raw argument value (uintptr-sized, mirrors drwrap_get_arg). */
    std::uintptr_t arg(unsigned idx) const;

    /* Tag of the register/stack slot holding the arg (8 bytes). Use for
     * scalar args (int, fd, size). */
    tag_t arg_tag(unsigned idx) const;

    /* Tag of *(arg+0 .. arg+n-1). For pointer args. Returns empty if n == 0
     * or arg is null. */
    tag_t arg_pointed_tag(unsigned idx, std::size_t n) const;

    /* Convenience: "is ANY of the first n pointed-to bytes tainted?". */
    bool arg_pointed_is_tainted(unsigned idx, std::size_t n) const;

    /* Walk per-arg scalar tags.
     *   visitor signature: bool(unsigned arg_idx, tag_t t)
     * Visitor may return false to stop early. */
    using arg_visitor = std::function<bool(unsigned arg_idx, tag_t t)>;
    void for_each_arg_tag(unsigned n_args, const arg_visitor &fn) const;
};

using func_sink_cb = std::function<void(const func_sink_context_t &)>;

/* Resolve `func_name` in `module_basename` (e.g. "libc.so.6"); empty
 * module_basename = any loaded module. Returns false if the symbol can't
 * be resolved at load time (logged to stderr). Registration is durable:
 * if the module isn't loaded yet, the wrap is applied when it loads. */
bool register_func_sink(const std::string &func_name,
                        const std::string &module_basename,
                        func_sink_cb cb);

/* For clients that already resolved the PC (e.g. via static analysis). */
void register_func_sink_pc(app_pc entry_pc, func_sink_cb cb);

}  // namespace libdft_dr

#endif  /* LIBDFT_DR_SINKS_H_ */
