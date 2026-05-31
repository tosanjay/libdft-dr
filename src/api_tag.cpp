/* api_tag.cpp -- libdft_dr layer-2 (tag model).
 *
 * Thin wrappers over tagmap.{h,cpp}. The public libdft_dr::tag_t and the
 * internal dft_label both hold a single uint32 interned-set id; we round-
 * trip via tag_t::raw()/from_raw to keep the type boundary explicit (no
 * reinterpret_cast).
 */
#include <cstdint>
#include <string>

#include "dr_api.h"

#include "libdft_dr/tag.h"

#include "libdft_api_dr.h"
#include "tagmap.h"

namespace libdft_dr {

/* ---- internal helpers: public tag_t <-> internal dft_label round-trip ---- */

static inline ::tag_t to_internal(tag_t t) {
    ::tag_t out;
    out.id = t.raw();
    return out;
}

static inline tag_t to_public(::tag_t t) {
    return tag_t::from_raw(t.id);
}

/* DR reg_id_t -> DFT VCPU register-file row + (start_byte, n_bytes) span.
 * Duplicated from libdft_core_dr.cpp; the two mappings must stay in sync.
 * Returns false for non-GPR regs (caller treats as empty/no-op). */
static bool reg_span(reg_id_t reg, std::size_t *row,
                     std::size_t *start, std::size_t *n) {
    if (!reg_is_gpr(reg))
        return false;
    reg_id_t full = reg_to_pointer_sized(reg);
    std::size_t idx;
    switch (full) {
        case DR_REG_RDI: idx = DFT_REG_RDI; break;
        case DR_REG_RSI: idx = DFT_REG_RSI; break;
        case DR_REG_RBP: idx = DFT_REG_RBP; break;
        case DR_REG_RSP: idx = DFT_REG_RSP; break;
        case DR_REG_RAX: idx = DFT_REG_RAX; break;
        case DR_REG_RBX: idx = DFT_REG_RBX; break;
        case DR_REG_RCX: idx = DFT_REG_RCX; break;
        case DR_REG_RDX: idx = DFT_REG_RDX; break;
        case DR_REG_R8:  idx = DFT_REG_R8;  break;
        case DR_REG_R9:  idx = DFT_REG_R9;  break;
        case DR_REG_R10: idx = DFT_REG_R10; break;
        case DR_REG_R11: idx = DFT_REG_R11; break;
        case DR_REG_R12: idx = DFT_REG_R12; break;
        case DR_REG_R13: idx = DFT_REG_R13; break;
        case DR_REG_R14: idx = DFT_REG_R14; break;
        case DR_REG_R15: idx = DFT_REG_R15; break;
        default: return false;
    }
    *row = idx;
    if (reg == DR_REG_AH || reg == DR_REG_BH ||
        reg == DR_REG_CH || reg == DR_REG_DH) {
        *start = 1; *n = 1;
    } else {
        *start = 0;
        *n = (std::size_t)opnd_size_in_bytes(reg_get_size(reg));
    }
    return true;
}

/* ---- factory / op / introspect ---- */

tag_t make_tag(std::uint32_t label) {
    ::tag_t t;
    t.id = 0;
    t.set(label);
    return to_public(t);
}

tag_t combine(tag_t a, tag_t b) {
    ::tag_t l = to_internal(a);
    ::tag_t r = to_internal(b);
    return to_public(::tag_combine(l, r));
}

void enumerate(tag_t t, const label_visitor &fn) {
    struct ctx { const label_visitor *fn; } c{ &fn };
    ::tag_walk(to_internal(t),
        [](std::uint32_t label, void *user) -> bool {
            auto *cc = static_cast<ctx *>(user);
            return (*cc->fn)(label);
        }, &c);
}

std::string to_string(tag_t t) {
    ::tag_t i = to_internal(t);
    return ::tag_sprint(i);
}

/* ---- memory shadow ---- */

tag_t get_mem_tag(std::uintptr_t addr) {
    return to_public(::file_tagmap_getb((ADDRINT)addr));
}

void set_mem_tag(std::uintptr_t addr, tag_t t) {
    ::tag_t i = to_internal(t);
    ::tagmap_setb_with_tag((size_t)addr, i);
}

void clear_mem(std::uintptr_t addr, std::size_t n) {
    ::file_tagmap_clrn((ADDRINT)addr, (UINT32)n);
}

tag_t get_mem_tag_range(std::uintptr_t addr, std::size_t n) {
    ::tag_t acc; acc.id = 0;
    for (std::size_t i = 0; i < n; ++i) {
        ::tag_t b = ::file_tagmap_getb((ADDRINT)(addr + i));
        acc = ::tag_combine(acc, b);
    }
    return to_public(acc);
}

/* ---- register shadow ---- */

static thread_ctx_t *cur_ctx() {
    return libdft_get_thread_ctx(dr_get_current_drcontext());
}

tag_t get_reg_tag(reg_id_t reg) {
    std::size_t row, start, n;
    if (!reg_span(reg, &row, &start, &n)) return tag_t{};
    thread_ctx_t *tc = cur_ctx();
    if (!tc) return tag_t{};
    return to_public(tc->vcpu.gpr_file[row][start]);
}

tag_t get_reg_tag_byte(reg_id_t reg, std::size_t byte_idx) {
    std::size_t row, start, n;
    if (!reg_span(reg, &row, &start, &n)) return tag_t{};
    if (byte_idx >= n) return tag_t{};
    thread_ctx_t *tc = cur_ctx();
    if (!tc) return tag_t{};
    return to_public(tc->vcpu.gpr_file[row][start + byte_idx]);
}

void set_reg_tag(reg_id_t reg, tag_t t) {
    std::size_t row, start, n;
    if (!reg_span(reg, &row, &start, &n)) return;
    thread_ctx_t *tc = cur_ctx();
    if (!tc) return;
    ::tag_t i = to_internal(t);
    for (std::size_t k = 0; k < n; ++k)
        tc->vcpu.gpr_file[row][start + k] = i;
}

void set_reg_tag_byte(reg_id_t reg, std::size_t byte_idx, tag_t t) {
    std::size_t row, start, n;
    if (!reg_span(reg, &row, &start, &n)) return;
    if (byte_idx >= n) return;
    thread_ctx_t *tc = cur_ctx();
    if (!tc) return;
    tc->vcpu.gpr_file[row][start + byte_idx] = to_internal(t);
}

tag_t get_reg_tag_range(reg_id_t reg) {
    std::size_t row, start, n;
    if (!reg_span(reg, &row, &start, &n)) return tag_t{};
    thread_ctx_t *tc = cur_ctx();
    if (!tc) return tag_t{};
    ::tag_t acc; acc.id = 0;
    for (std::size_t k = 0; k < n; ++k)
        acc = ::tag_combine(acc, tc->vcpu.gpr_file[row][start + k]);
    return to_public(acc);
}

}  // namespace libdft_dr
