/* api_sinks.cpp -- libdft_dr layer-3 sink registry.
 *
 * Three registries:
 *   - opcode-class:   register_sink(opcode_class, cb)            -- CMP, LEA, ...
 *   - PC range:       register_pc_range_sink(lo, hi, cb)         -- step 5 (stub)
 *   - function entry: register_func_sink(name, module, cb)       -- step 5 (stub)
 *
 * libdft_core_dr.cpp builds a sink_payload at each emit point and calls
 * libdft_dr_internal::dispatch_sink(). Public sink_context_t accessors
 * downcast _internal to sink_payload.
 *
 * Concurrency: g_opcode_sinks is built at client init time (single-thread
 * dr_client_main) and read-only thereafter, so no lock on the dispatch path.
 * If v0.2 adds runtime registration, this becomes RCU/copy-on-write.
 */
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "dr_api.h"
#include "drwrap.h"

#include "libdft_dr/sinks.h"
#include "libdft_dr/tag.h"

#include "sink_internal.h"
#include "tagmap.h"

namespace libdft_dr_internal {

namespace {
std::map<libdft_dr::opcode_class, std::vector<libdft_dr::sink_cb>> g_opcode_sinks;

struct pc_range_entry { app_pc lo; app_pc hi; libdft_dr::sink_cb cb; };
std::vector<pc_range_entry> g_pc_ranges;

std::vector<pending_func_sink> g_pending_func_sinks;
}  // namespace

bool has_sink(libdft_dr::opcode_class cls) {
    auto it = g_opcode_sinks.find(cls);
    return it != g_opcode_sinks.end() && !it->second.empty();
}

void dispatch_sink(libdft_dr::opcode_class cls,
                   void *drcontext, instr_t *instr, app_pc pc,
                   sink_payload &pl) {
    auto it = g_opcode_sinks.find(cls);
    if (it == g_opcode_sinks.end()) return;
    libdft_dr::sink_context_t ctx;
    ctx.drcontext = drcontext;
    ctx.instr     = instr;
    ctx.pc        = pc;
    ctx._internal = &pl;
    for (auto &cb : it->second) cb(ctx);
}

bool has_pc_range_sink_at(app_pc pc) {
    for (auto &e : g_pc_ranges)
        if (pc >= e.lo && pc < e.hi) return true;
    return false;
}

void dispatch_pc_range_sink(app_pc pc) {
    sink_payload pl;  /* operand_tags empty -- PC-range sinks have no operand
                       * info; clients use libdft_dr::get_mem_tag_range etc.
                       * to inspect whatever they care about. */
    libdft_dr::sink_context_t ctx;
    ctx.drcontext = dr_get_current_drcontext();
    ctx.instr     = NULL;
    ctx.pc        = pc;
    ctx._internal = &pl;
    for (auto &e : g_pc_ranges)
        if (pc >= e.lo && pc < e.hi)
            e.cb(ctx);
}

const std::vector<pending_func_sink> &func_sinks() {
    return g_pending_func_sinks;
}

}  // namespace libdft_dr_internal

namespace libdft_dr {

void register_sink(opcode_class cls, sink_cb cb) {
    libdft_dr_internal::g_opcode_sinks[cls].push_back(std::move(cb));
}

/* ---- sink_context_t accessors ---- */

namespace {
inline libdft_dr_internal::sink_payload *pl_of(const sink_context_t *c) {
    return static_cast<libdft_dr_internal::sink_payload *>(c->_internal);
}
}  // namespace

bool sink_context_t::has_tainted_operand() const {
    auto *pl = pl_of(this);
    for (auto &t : pl->operand_tags)
        if (!t.empty()) return true;
    return false;
}

tag_t sink_context_t::operand_union() const {
    auto *pl = pl_of(this);
    tag_t acc;
    for (auto &t : pl->operand_tags)
        acc = combine(acc, t);
    return acc;
}

void sink_context_t::for_each_operand_tag(const operand_visitor &fn) const {
    auto *pl = pl_of(this);
    for (std::size_t i = 0; i < pl->operand_tags.size(); ++i) {
        /* v0.1: is_dst=false for all (CMP/LEA operands are semantically reads). */
        if (!fn((int)i, false, pl->operand_tags[i]))
            return;
    }
}

const std::vector<std::string> &sink_context_t::legacy_record() const {
    return pl_of(this)->legacy_fields;
}

/* ---- PC-range sinks ---- */

void register_pc_range_sink(app_pc lo, app_pc hi, sink_cb cb) {
    if (lo >= hi) {
        dr_fprintf(STDERR, "[libdft_dr] register_pc_range_sink: empty range "
                           "[%p,%p) -- ignoring\n", lo, hi);
        return;
    }
    libdft_dr_internal::g_pc_ranges.push_back({lo, hi, std::move(cb)});
}

/* ---- Function-entry sinks ----
 *
 * Registration just enqueues; the actual drsym + drwrap work happens in
 * libdft_core_dr.cpp's module-load handler (after libdft_setup wires the
 * module event). For PC-direct registration the wrap can be applied
 * immediately. */

namespace {
inline void *wrapcxt_of(const func_sink_context_t *c) {
    return c->_internal;
}
}  // namespace

std::uintptr_t func_sink_context_t::arg(unsigned idx) const {
    return (std::uintptr_t)drwrap_get_arg(wrapcxt_of(this), (int)idx);
}

tag_t func_sink_context_t::arg_tag(unsigned idx) const {
    /* The argument value occupies a register or stack slot. We don't know
     * which without walking the mcontext; v0.1 returns the tag of the first
     * byte of the arg-as-uintptr (matches libdft's "scalar arg tag" notion
     * for the common case of a register-passed arg). For pointer args, use
     * arg_pointed_tag instead. */
    (void)idx;
    return tag_t{};  /* v0.1 placeholder: full impl requires mcontext walk */
}

tag_t func_sink_context_t::arg_pointed_tag(unsigned idx, std::size_t n) const {
    if (n == 0) return tag_t{};
    std::uintptr_t p = arg(idx);
    if (p == 0) return tag_t{};
    ::tag_t acc; acc.id = 0;
    for (std::size_t i = 0; i < n; ++i) {
        ::tag_t b = ::file_tagmap_getb((ADDRINT)(p + i));
        acc = ::tag_combine(acc, b);
    }
    return tag_t::from_raw(acc.id);
}

bool func_sink_context_t::arg_pointed_is_tainted(unsigned idx, std::size_t n) const {
    if (n == 0) return false;
    std::uintptr_t p = arg(idx);
    if (p == 0) return false;
    for (std::size_t i = 0; i < n; ++i) {
        ::tag_t b = ::file_tagmap_getb((ADDRINT)(p + i));
        if (b.id != 0) return true;
    }
    return false;
}

void func_sink_context_t::for_each_arg_tag(unsigned n_args,
                                           const arg_visitor &fn) const {
    for (unsigned i = 0; i < n_args; ++i)
        if (!fn(i, arg_tag(i))) return;
}

bool register_func_sink(const std::string &func_name,
                        const std::string &module_basename,
                        func_sink_cb cb) {
    if (func_name.empty()) {
        dr_fprintf(STDERR, "[libdft_dr] register_func_sink: empty name\n");
        return false;
    }
    libdft_dr_internal::g_pending_func_sinks.push_back(
        {func_name, module_basename, nullptr, std::move(cb)});
    return true;
}

void register_func_sink_pc(app_pc entry_pc, func_sink_cb cb) {
    libdft_dr_internal::g_pending_func_sinks.push_back(
        {"", "", entry_pc, std::move(cb)});
}

}  // namespace libdft_dr
