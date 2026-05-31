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

#include "libdft_dr/sinks.h"
#include "libdft_dr/tag.h"

#include "sink_internal.h"

namespace libdft_dr_internal {

namespace {
std::map<libdft_dr::opcode_class, std::vector<libdft_dr::sink_cb>> g_opcode_sinks;
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

/* ---- PC-range sinks (stub: step 5) ---- */

void register_pc_range_sink(app_pc, app_pc, sink_cb) {
    dr_fprintf(STDERR, "[libdft_dr] register_pc_range_sink: stub (v0.1 M3.2 step 5)\n");
}

/* ---- Function-entry sinks (stub: step 5) ---- */

std::uintptr_t func_sink_context_t::arg(unsigned) const { return 0; }
tag_t func_sink_context_t::arg_tag(unsigned) const { return tag_t{}; }
tag_t func_sink_context_t::arg_pointed_tag(unsigned, std::size_t) const { return tag_t{}; }
bool func_sink_context_t::arg_pointed_is_tainted(unsigned, std::size_t) const { return false; }
void func_sink_context_t::for_each_arg_tag(unsigned, const arg_visitor &) const {}

bool register_func_sink(const std::string &, const std::string &, func_sink_cb) {
    dr_fprintf(STDERR, "[libdft_dr] register_func_sink: stub (v0.1 M3.2 step 5)\n");
    return false;
}

void register_func_sink_pc(app_pc, func_sink_cb) {
    dr_fprintf(STDERR, "[libdft_dr] register_func_sink_pc: stub (v0.1 M3.2 step 5)\n");
}

}  // namespace libdft_dr
