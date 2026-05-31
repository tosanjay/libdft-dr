/*
 * libdft_core_dr.cpp -- DR port of libdft64/libdft_core (C.4 Phase 5).
 *
 * Phase 5.0: BB-instrumentation backbone + C.2 MNT skip + opcode router.
 * Phase 5.1: propagation handlers as clean calls, correctness first; hot
 * families promoted to inline drx/drreg in 5.2.
 *   5.1a: register-shadow foundation + MOV reg/imm.
 *   5.1b (this): MOV mem<->reg (m2r/r2m) via drutil mem-EA + drreg, and the
 *        CMP family (OP_cmp r2r/m2r/i2r/r2m/i2m) emitting the byte-exact
 *        21-field cmp.out the GA consumes.
 *
 * DESIGN NOTE (DR-native, not a Pin transliteration): the opcode router
 * switches on DR's own OP_* (no XED->DR table); operands come from DR's
 * opnd API; memory EAs from drutil_insert_get_mem_addr; scratch from drreg;
 * memory VALUES are read with dr_safe_read (Pin deref'd raw app memory).
 * What IS faithfully mirrored from libdft is the cmp.out *wire format* and
 * the print_log "> limit_offset" drop rule -- those are a contract with the
 * downstream Python parsers (read_taint/read_lea), not a Pin-parity goal.
 *
 * One deliberate divergence from libdft64's register model: libdft's
 * REG_INDX() aliases the legacy high-byte regs (AH/BH/CH/DH) onto byte 0 of
 * their parent row, i.e. it reads/writes them as if they were the low byte.
 * reg_shadow_span() below models them correctly at byte 1. The only
 * observable cmp.out difference vs Pin is therefore a tainted CMP involving a
 * high-byte register (vanishingly rare in compiler output; ~0 on tiffcp).
 */
#include "libdft_core_dr.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"

#include "dr_compat.h"
#include "libdft_api_dr.h"
#include "tagmap.h"
#include "mnt_consumer_dr.h"

#include "libdft_dr/sinks.h"
#include "src/sink_internal.h"

/* ---------- register-shadow foundation ---------- */

/* DR reg_id_t -> DFT VCPU register-file index (row in gpr_file). */
static size_t
reg_indx_dr(reg_id_t reg)
{
    reg_id_t full = reg_is_gpr(reg) ? reg_to_pointer_sized(reg) : reg;
    switch (full) {
        case DR_REG_RDI: return DFT_REG_RDI;
        case DR_REG_RSI: return DFT_REG_RSI;
        case DR_REG_RBP: return DFT_REG_RBP;
        case DR_REG_RSP: return DFT_REG_RSP;
        case DR_REG_RAX: return DFT_REG_RAX;
        case DR_REG_RBX: return DFT_REG_RBX;
        case DR_REG_RCX: return DFT_REG_RCX;
        case DR_REG_RDX: return DFT_REG_RDX;
        case DR_REG_R8:  return DFT_REG_R8;
        case DR_REG_R9:  return DFT_REG_R9;
        case DR_REG_R10: return DFT_REG_R10;
        case DR_REG_R11: return DFT_REG_R11;
        case DR_REG_R12: return DFT_REG_R12;
        case DR_REG_R13: return DFT_REG_R13;
        case DR_REG_R14: return DFT_REG_R14;
        case DR_REG_R15: return DFT_REG_R15;
        default:         return GRP_NUM;  /* unhandled (XMM/ST/seg) -> 5.x */
    }
}

/* Shadow span of a GPR operand: (row, start_byte, n_bytes).
 * Returns false for non-GPR regs (handled in a later increment). */
static bool
reg_shadow_span(reg_id_t reg, uint *row, uint *start, uint *n)
{
    if (!reg_is_gpr(reg))
        return false;
    size_t idx = reg_indx_dr(reg);
    if (idx == GRP_NUM)
        return false;
    *row = (uint)idx;
    if (reg == DR_REG_AH || reg == DR_REG_BH ||
        reg == DR_REG_CH || reg == DR_REG_DH) {
        *start = 1;
        *n = 1;
    } else {
        *start = 0;
        *n = (uint)opnd_size_in_bytes(reg_get_size(reg));
    }
    return true;
}

/* Pointer-sized parent of a GPR, for passing a register VALUE to a clean call:
 * dr_insert_clean_call corrupts state when handed a sub-register value operand,
 * so we always pass the 64-bit parent and mask to the operand width inside the
 * handler. (The legacy high-byte regs AH/BH/CH/DH collapse to the low byte of
 * the value here -- the same rare, documented divergence as reg_shadow_span.) */
static opnd_t
reg_val_opnd(reg_id_t reg)
{
    return opnd_create_reg(reg_is_gpr(reg) ? reg_to_pointer_sized(reg) : reg);
}

/* ---------- cmp.out formatting helpers (the parser contract) ---------- */

/* Pin StringFromAddrint / hexstr both render as "0x%lx". */
static std::string
hexstr_u(uint64_t v)
{
    char b[32];
    snprintf(b, sizeof(b), "0x%lx", (unsigned long)v);
    return std::string(b);
}

/* Pin INT2STR(x): decimal. */
static std::string
int2str(int v)
{
    char b[16];
    snprintf(b, sizeof(b), "%d", v);
    return std::string(b);
}

/* Pin's print_log filter splits each tag field on ',' and drops the whole
 * line if any byte carries more than limit_offset offsets. split() yields
 * (#commas + 1) tokens; replicate that count exactly. */
static int
comma_tokens(const std::string &s)
{
    int n = 1;
    for (char c : s)
        if (c == ',')
            n++;
    return n;
}

/* legacy_write_cmp: filter fields [3..18], then write all 21 fields
 * space-separated (trailing space after each field, like Pin) + '\n'.
 * Used only when no client registered a CMP sink (transitional fallback). */
static void
legacy_write_cmp(const std::vector<std::string> &o)
{
    if (out == INVALID_FILE)
        return;
    for (int i = 3; i < 19; i++) {
        if (comma_tokens(o[i]) > limit_offset)
            return;  /* loop-noise cut */
    }
    std::string line;
    for (int i = 0; i < 21; i++) {
        line += o[i];
        line += ' ';
    }
    line += '\n';
    dr_write_file(out, line.data(), line.size());
}

/* legacy_write_lea: 10 fields, filter [2..9], same trailing-space + '\n'
 * layout. Field [0]=width, [1]="baseidx", [2..9]=index-byte tags. (libdft
 * writes the ins address to [2] but immediately clobbers it with the i=0
 * index tag, so it never appears -- we omit it, matching the on-disk format
 * read_lea expects.) Used only when no client registered a LEA sink. */
static void
legacy_write_lea(const std::vector<std::string> &o)
{
    if (out_lea == INVALID_FILE)
        return;
    for (int i = 2; i < 10; i++) {
        if (comma_tokens(o[i]) > limit_offset)
            return;
    }
    std::string line;
    for (int i = 0; i < 10; i++) {
        line += o[i];
        line += ' ';
    }
    line += '\n';
    dr_write_file(out_lea, line.data(), line.size());
}

/* emit_cmp / emit_lea: dispatch to registered sinks if any (M3.2 step 4), or
 * fall through to the legacy `out`/`out_lea` write for backward compat with
 * the old monolithic tools/libdft-dta-dr.cpp client. CMP operands are passed
 * as dest_tags then src_tags (concatenated into sink_payload.operand_tags);
 * LEA passes its index tags as `optags`. */
static void
emit_cmp(std::vector<std::string> &o, ptr_uint_t ins,
         const std::vector<tag_t> &dest_tags,
         const std::vector<tag_t> &src_tags)
{
    if (libdft_dr_internal::has_sink(libdft_dr::opcode_class::CMP)) {
        libdft_dr_internal::sink_payload pl;
        pl.legacy_fields = std::move(o);
        pl.operand_tags.reserve(dest_tags.size() + src_tags.size());
        for (const auto &t : dest_tags)
            pl.operand_tags.push_back(libdft_dr::tag_t::from_raw(t.id));
        for (const auto &t : src_tags)
            pl.operand_tags.push_back(libdft_dr::tag_t::from_raw(t.id));
        libdft_dr_internal::dispatch_sink(libdft_dr::opcode_class::CMP,
            dr_get_current_drcontext(), NULL, (app_pc)(uintptr_t)ins, pl);
        return;
    }
    legacy_write_cmp(o);
}

static void
emit_lea(std::vector<std::string> &o, ptr_uint_t ins,
         const std::vector<tag_t> &optags)
{
    if (libdft_dr_internal::has_sink(libdft_dr::opcode_class::LEA)) {
        libdft_dr_internal::sink_payload pl;
        pl.legacy_fields = std::move(o);
        pl.operand_tags.reserve(optags.size());
        for (const auto &t : optags)
            pl.operand_tags.push_back(libdft_dr::tag_t::from_raw(t.id));
        libdft_dr_internal::dispatch_sink(libdft_dr::opcode_class::LEA,
            dr_get_current_drcontext(), NULL, (app_pc)(uintptr_t)ins, pl);
        return;
    }
    legacy_write_lea(o);
}

/* read `size` byte-tags from a register span into v (size guaranteed <= 8). */
static void
fill_reg_tags(thread_ctx_t *tc, uint row, uint start, uint size,
              std::vector<tag_t> &v)
{
    for (uint i = 0; i < size; i++)
        v[i] = tc->vcpu.gpr_file[row][start + i];
}

/* read `size` byte-tags from shadow memory. */
static void
fill_mem_tags(ADDRINT addr, uint size, std::vector<tag_t> &v)
{
    for (uint i = 0; i < size; i++)
        v[i] = file_tagmap_getb(addr + i);
}

/* read up to 8 bytes of application memory for the cmp.out value field.
 * DR-safe (Pin deref'd raw); a faulting EA yields 0 rather than crashing. */
static uint64_t
read_mem_val(ADDRINT addr, uint size)
{
    uint64_t val = 0;
    if (!dr_safe_read((void *)addr, size, &val, NULL))
        val = 0;
    return val;
}

/* ---------- MOV propagation handlers (clean calls, 5.1) ---------- */

/* reg -> reg byte-tag copy (MOV reg,reg and width-preserving moves). */
static void
r2r_xfer(uint dst_row, uint dst_start, uint src_row, uint src_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[dst_row][dst_start + i] =
            tc->vcpu.gpr_file[src_row][src_start + i];
}

/* clear a register's shadow span (MOV reg,imm -- immediate carries no taint). */
static void
r_clr(uint row, uint start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[row][start + i] = tag_traits<tag_t>::cleared_val;
}

/* mem -> reg (MOV reg,[mem]): load shadow memory into the register span. */
static void
mov_m2r(uint row, uint start, ADDRINT addr, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[row][start + i] = file_tagmap_getb(addr + i);
}

/* reg -> mem (MOV [mem],reg): store the register span into shadow memory
 * (overwrite semantics -- a cleared reg byte clears the mem byte). */
static void
mov_r2m(ADDRINT addr, uint row, uint start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tagmap_setb_with_tag(addr + i, tc->vcpu.gpr_file[row][start + i]);
}

/* imm -> mem (MOV [mem],imm): clear the mem span. */
static void
mov_clr_mem(ADDRINT addr, uint n)
{
    file_tagmap_clrn(addr, n);
}

/* mem -> mem byte-tag copy (PUSH/POP with a memory operand). */
static void
m2m_xfer(ADDRINT dst_addr, ADDRINT src_addr, uint n)
{
    for (uint i = 0; i < n; i++)
        tagmap_setb_with_tag(dst_addr + i, file_tagmap_getb(src_addr + i));
}

/* ---------- ternary combine (MUL/DIV/IDIV/IMUL 1-operand form) ----------
 * RDX:RAX (or AX for byte) <- accumulator (combined) op the single operand.
 * Taint: combine the operand's byte tags into both RAX and RDX over the width
 * (byte form: into RAX[0],RAX[1] only -- AX = AL * src8). */
static void
ternary_combine(thread_ctx_t *tc, const tag_t *src, uint n)
{
    if (n == 1) {
        tc->vcpu.gpr_file[DFT_REG_RAX][0] =
            tag_combine(tc->vcpu.gpr_file[DFT_REG_RAX][0], const_cast<tag_t &>(src[0]));
        tc->vcpu.gpr_file[DFT_REG_RAX][1] =
            tag_combine(tc->vcpu.gpr_file[DFT_REG_RAX][1], const_cast<tag_t &>(src[0]));
        return;
    }
    for (uint i = 0; i < n; i++) {
        tc->vcpu.gpr_file[DFT_REG_RDX][i] =
            tag_combine(tc->vcpu.gpr_file[DFT_REG_RDX][i], const_cast<tag_t &>(src[i]));
        tc->vcpu.gpr_file[DFT_REG_RAX][i] =
            tag_combine(tc->vcpu.gpr_file[DFT_REG_RAX][i], const_cast<tag_t &>(src[i]));
    }
}

static void
ternary_r2r(uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    tag_t src[8];
    for (uint i = 0; i < n && i < 8; i++)
        src[i] = tc->vcpu.gpr_file[s_row][s_start + i];
    ternary_combine(tc, src, n);
}

static void
ternary_m2r(ADDRINT addr, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    tag_t src[8];
    for (uint i = 0; i < n && i < 8; i++)
        src[i] = file_tagmap_getb(addr + i);
    ternary_combine(tc, src, n);
}

/* ---------- XCHG (swap byte-tags) ---------- */
static void
xchg_r2r(uint a_row, uint a_start, uint b_row, uint b_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t t = tc->vcpu.gpr_file[a_row][a_start + i];
        tc->vcpu.gpr_file[a_row][a_start + i] = tc->vcpu.gpr_file[b_row][b_start + i];
        tc->vcpu.gpr_file[b_row][b_start + i] = t;
    }
}

static void
xchg_m2r(ADDRINT addr, uint row, uint start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t r = tc->vcpu.gpr_file[row][start + i];
        tc->vcpu.gpr_file[row][start + i] = file_tagmap_getb(addr + i);
        tagmap_setb_with_tag(addr + i, r);
    }
}

/* ---------- CMOVcc (predicated transfer) ----------
 * Taint moves only when the condition holds (Pin uses InsertPredicatedCall);
 * we evaluate the DR predicate against the app's saved EFLAGS so we never add
 * taint on the not-taken path (preserves the zero-false-offset property). */
static bool
cond_triggered(int pred, reg_t flags)
{
    bool cf = (flags >> 0) & 1, pf = (flags >> 2) & 1, zf = (flags >> 6) & 1,
         sf = (flags >> 7) & 1, of = (flags >> 11) & 1;
    switch (pred) {
        case DR_PRED_O:   return of;
        case DR_PRED_NO:  return !of;
        case DR_PRED_B:   return cf;
        case DR_PRED_NB:  return !cf;
        case DR_PRED_Z:   return zf;
        case DR_PRED_NZ:  return !zf;
        case DR_PRED_BE:  return cf || zf;
        case DR_PRED_NBE: return !cf && !zf;
        case DR_PRED_S:   return sf;
        case DR_PRED_NS:  return !sf;
        case DR_PRED_P:   return pf;
        case DR_PRED_NP:  return !pf;
        case DR_PRED_L:   return sf != of;
        case DR_PRED_NL:  return sf == of;
        case DR_PRED_LE:  return zf || (sf != of);
        case DR_PRED_NLE: return !zf && (sf == of);
        default:          return false;  /* unknown -> don't propagate (safe) */
    }
}

static bool
cmov_taken(void *dc, int pred)
{
    dr_mcontext_t mc;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL;  /* xflags */
    dr_get_mcontext(dc, &mc);
    return cond_triggered(pred, mc.xflags);
}

static void
cmov_r2r(int pred, uint d_row, uint d_start, uint s_row, uint s_start, uint n)
{
    void *dc = dr_get_current_drcontext();
    if (!cmov_taken(dc, pred))
        return;
    thread_ctx_t *tc = libdft_get_thread_ctx(dc);
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] = tc->vcpu.gpr_file[s_row][s_start + i];
}

static void
cmov_m2r(int pred, uint d_row, uint d_start, ADDRINT addr, uint n)
{
    void *dc = dr_get_current_drcontext();
    if (!cmov_taken(dc, pred))
        return;
    thread_ctx_t *tc = libdft_get_thread_ctx(dc);
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] = file_tagmap_getb(addr + i);
}

/* ---------- binary combine handlers (ADD/AND/OR/XOR/SBB/SUB) ----------
 * Arithmetic/logical RMW mixes operand taint: dst[i] = combine(dst[i], src[i])
 * (EWAH union). The immediate-source forms carry no taint and are not
 * instrumented; the XOR/SUB/SBB same-register zeroing idiom is turned into a
 * clear at instrument time (see insert_binary). */
static void
binary_r2r(uint d_row, uint d_start, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] =
            tag_combine(tc->vcpu.gpr_file[d_row][d_start + i],
                        tc->vcpu.gpr_file[s_row][s_start + i]);
}

/* dst reg, src mem (e.g. ADD reg,[mem]). */
static void
binary_m2r(uint d_row, uint d_start, ADDRINT addr, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t m = file_tagmap_getb(addr + i);
        tc->vcpu.gpr_file[d_row][d_start + i] =
            tag_combine(tc->vcpu.gpr_file[d_row][d_start + i], m);
    }
}

/* dst mem, src reg (e.g. ADD [mem],reg). */
static void
binary_r2m(ADDRINT addr, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t cur = file_tagmap_getb(addr + i);
        tag_t s = tc->vcpu.gpr_file[s_row][s_start + i];
        tagmap_setb_with_tag(addr + i, tag_combine(cur, s));
    }
}

/* ---------- MOVZX (zero-extend) ----------
 * Principled semantics: copy the source byte-tags, then CLEAR the
 * zero-extension region. (libdft's size-specialized _movzx_* handlers are
 * buggy -- several leave the extension bytes uncleared, producing stale/false
 * taint; the DR port fixes this. See arch-doc D27.) */
static void
movzx_r2r(uint d_row, uint s_row, uint s_start, uint srcn, uint dstn)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < srcn; i++)
        tc->vcpu.gpr_file[d_row][i] = tc->vcpu.gpr_file[s_row][s_start + i];
    for (uint i = srcn; i < dstn; i++)
        tc->vcpu.gpr_file[d_row][i] = tag_traits<tag_t>::cleared_val;
}

static void
movzx_m2r(uint d_row, ADDRINT addr, uint srcn, uint dstn)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    for (uint i = 0; i < srcn; i++)
        tc->vcpu.gpr_file[d_row][i] = file_tagmap_getb(addr + i);
    for (uint i = srcn; i < dstn; i++)
        tc->vcpu.gpr_file[d_row][i] = tag_traits<tag_t>::cleared_val;
}

/* ---------- MOVSX/MOVSXD (sign-extend) ----------
 * Principled semantics (arch-doc D27, user decision): copy the source byte
 * tags, then fill the sign-extension region with the TOP source byte's tag
 * (the byte whose sign bit drives the extension). Differs from libdft's quirky
 * source-pattern tiling. */
static void
movsx_r2r(uint d_row, uint s_row, uint s_start, uint srcn, uint dstn)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || srcn == 0)
        return;
    for (uint i = 0; i < srcn; i++)
        tc->vcpu.gpr_file[d_row][i] = tc->vcpu.gpr_file[s_row][s_start + i];
    tag_t sign = tc->vcpu.gpr_file[s_row][s_start + srcn - 1];
    for (uint i = srcn; i < dstn; i++)
        tc->vcpu.gpr_file[d_row][i] = sign;
}

static void
movsx_m2r(uint d_row, ADDRINT addr, uint srcn, uint dstn)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || srcn == 0)
        return;
    for (uint i = 0; i < srcn; i++)
        tc->vcpu.gpr_file[d_row][i] = file_tagmap_getb(addr + i);
    tag_t sign = file_tagmap_getb(addr + srcn - 1);
    for (uint i = srcn; i < dstn; i++)
        tc->vcpu.gpr_file[d_row][i] = sign;
}

/* ---------- LEA (taint base+index into dst; log index taint to lea.out) ----
 * dst[i] = combine(base[i], index[i]); a NULL base/index maps to the always-
 * clear spare row GRP_NUM. lea.out records the INDEX taint only (the value
 * VUzzer uses to find offsets that index into tainted structures). */
static void
lea_prop(ptr_uint_t ins, uint dst_row, uint base_row, uint base_start,
         uint idx_row, uint idx_start, uint size)
{
    (void)ins;
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;

    std::vector<std::string> o(10, "{}");
    o[0] = int2str((int)size * 8);
    o[1] = "baseidx";
    int fl = 0;
    std::vector<tag_t> idx_tags(size);
    for (uint i = 0; i < size; i++) {
        tag_t it = tc->vcpu.gpr_file[idx_row][idx_start + i];
        idx_tags[i] = it;
        if (tag_count(it))
            fl = 1;
        o[i + 2] = tag_sprint(it);
    }
    if (fl)
        emit_lea(o, ins, idx_tags);

    for (uint i = 0; i < size; i++) {
        tag_t b = tc->vcpu.gpr_file[base_row][base_start + i];
        tag_t x = tc->vcpu.gpr_file[idx_row][idx_start + i];
        tc->vcpu.gpr_file[dst_row][i] = tag_combine(b, x);
    }
}

/* ---------- CMP -> cmp.out handlers (clean calls) ---------- */

static void
cmp_r2r(ptr_uint_t ins, uint d_row, uint d_start, ptr_uint_t dval,
        uint s_row, uint s_start, ptr_uint_t sval, uint size)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    std::vector<tag_t> dest(size), src(size);
    fill_reg_tags(tc, d_row, d_start, size, dest);
    fill_reg_tags(tc, s_row, s_start, size, src);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        if (tag_count(dest[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
        if (tag_count(src[i])) { o[2] = hexstr_u(ins); fl = 1; }
        o[i + 11] = tag_sprint(src[i]);
    }
    if (fl) {
        switch (size) {
            case 8: o[19] = hexstr_u(dval);            o[20] = hexstr_u(sval);            break;
            case 4: o[19] = hexstr_u((uint32_t)dval);  o[20] = hexstr_u((uint32_t)sval);  break;
            case 2: o[19] = hexstr_u((uint16_t)dval);  o[20] = hexstr_u((uint16_t)sval);  break;
            case 1: o[19] = hexstr_u((uint8_t)dval);   o[20] = hexstr_u((uint8_t)sval);   break;
        }
        o[0] = int2str((int)size * 8);
        o[1] = "reg reg";
        emit_cmp(o, ins, dest, src);
    }
}

static void
cmp_m2r(ptr_uint_t ins, uint d_row, uint d_start, ptr_uint_t dval,
        ADDRINT src_addr, uint size)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    std::vector<tag_t> dest(size), src(size);
    fill_reg_tags(tc, d_row, d_start, size, dest);
    if (!file_tag_testb(src_addr))
        return;
    fill_mem_tags(src_addr, size, src);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        if (tag_count(dest[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
        if (tag_count(src[i])) { o[2] = hexstr_u(ins); fl = 1; }
        o[i + 11] = tag_sprint(src[i]);
    }
    if (fl) {
        uint64_t mv = read_mem_val(src_addr, size);
        switch (size) {
            case 8: o[19] = hexstr_u(dval);            o[20] = hexstr_u(mv);            break;
            case 4: o[19] = hexstr_u((uint32_t)dval);  o[20] = hexstr_u((uint32_t)mv);  break;
            case 2: o[19] = hexstr_u((uint16_t)dval);  o[20] = hexstr_u((uint16_t)mv);  break;
            case 1: o[19] = hexstr_u((uint8_t)dval);   o[20] = hexstr_u((uint8_t)mv);   break;
        }
        o[0] = int2str((int)size * 8);
        o[1] = "reg mem";
        emit_cmp(o, ins, dest, src);
    }
}

static void
cmp_i2r(ptr_uint_t ins, uint d_row, uint d_start, ptr_uint_t dval,
        uint32_t imm, uint size)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    std::vector<tag_t> dest(size);
    fill_reg_tags(tc, d_row, d_start, size, dest);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        if (tag_count(dest[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
    }
    if (fl) {
        switch (size) {
            case 8:
            case 4: o[19] = hexstr_u((uint32_t)dval);  o[20] = hexstr_u((uint32_t)imm);  break;
            case 2: o[19] = hexstr_u((uint16_t)dval);  o[20] = hexstr_u((uint16_t)imm);  break;
            case 1: o[19] = hexstr_u((uint8_t)dval);   o[20] = hexstr_u((uint8_t)imm);   break;
        }
        o[0] = int2str((int)size * 8);
        o[1] = "reg imm";
        emit_cmp(o, ins, dest, std::vector<tag_t>{});
    }
}

static void
cmp_r2m(ptr_uint_t ins, ADDRINT dest_addr, uint s_row, uint s_start,
        ptr_uint_t sval, uint size)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL)
        return;
    if (!file_tag_testb(dest_addr))
        return;
    std::vector<tag_t> dest(size), src(size);
    fill_mem_tags(dest_addr, size, dest);
    fill_reg_tags(tc, s_row, s_start, size, src);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        if (tag_count(dest[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
        if (tag_count(src[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 11] = tag_sprint(src[i]);
    }
    if (fl) {
        uint64_t mv = read_mem_val(dest_addr, size);
        switch (size) {
            case 8: o[19] = hexstr_u(mv);            o[20] = hexstr_u(sval);            break;
            case 4: o[19] = hexstr_u((uint32_t)mv);  o[20] = hexstr_u((uint32_t)sval);  break;
            case 2: o[19] = hexstr_u((uint16_t)mv);  o[20] = hexstr_u((uint16_t)sval);  break;
            case 1: o[19] = hexstr_u((uint8_t)mv);   o[20] = hexstr_u((uint8_t)sval);   break;
        }
        o[0] = int2str((int)size * 8);
        o[1] = "mem reg";
        emit_cmp(o, ins, dest, src);
    }
}

static void
cmp_i2m(ptr_uint_t ins, ADDRINT dest_addr, uint32_t imm, uint size)
{
    if (!file_tag_testb(dest_addr))
        return;
    std::vector<tag_t> dest(size);
    fill_mem_tags(dest_addr, size, dest);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        if (tag_count(dest[i])) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
    }
    if (fl) {
        switch (size) {
            case 8:
            case 4: o[19] = hexstr_u((uint32_t)read_mem_val(dest_addr, 4)); break;
            case 2: o[19] = hexstr_u((uint16_t)read_mem_val(dest_addr, 2)); break;
            case 1: o[19] = hexstr_u((uint8_t)read_mem_val(dest_addr, 1));  break;
        }
        o[20] = hexstr_u(imm);
        o[0] = int2str((int)size * 8);
        o[1] = "mem imm";
        emit_cmp(o, ins, dest, std::vector<tag_t>{});
    }
}

/* CMPS (string compare): both operands are memory. Mirrors libdft file_cmp_m2m
 * -- gate each byte on numberOfOnes in (0, limit_offset], value field uses a
 * 4-byte read for the 8/4 cases (as libdft does). */
static void
cmp_m2m(ptr_uint_t ins, ADDRINT dest_addr, ADDRINT src_addr, uint size)
{
    if (!file_tag_testb(dest_addr) || !file_tag_testb(src_addr))
        return;
    std::vector<tag_t> dest(size), src(size);
    fill_mem_tags(dest_addr, size, dest);
    fill_mem_tags(src_addr, size, src);

    std::vector<std::string> o(21, "{}");
    int fl = 0;
    for (uint i = 0; i < size; i++) {
        size_t dn = dest[i].numberOfOnes();
        if (dn > 0 && dn <= (size_t)limit_offset) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 3] = tag_sprint(dest[i]);
        size_t sn = src[i].numberOfOnes();
        if (sn > 0 && sn <= (size_t)limit_offset) {
            if (fl == 0) { o[2] = hexstr_u(ins); fl = 1; }
        }
        o[i + 11] = tag_sprint(src[i]);
    }
    if (fl) {
        switch (size) {
            case 8:
            case 4:
                o[19] = hexstr_u((uint32_t)read_mem_val(dest_addr, 4));
                o[20] = hexstr_u((uint32_t)read_mem_val(src_addr, 4));
                break;
            case 2:
                o[19] = hexstr_u((uint16_t)read_mem_val(dest_addr, 2));
                o[20] = hexstr_u((uint16_t)read_mem_val(src_addr, 2));
                break;
            case 1:
                o[19] = hexstr_u((uint8_t)read_mem_val(dest_addr, 1));
                o[20] = hexstr_u((uint8_t)read_mem_val(src_addr, 1));
                break;
        }
        o[0] = int2str((int)size * 8);
        o[1] = "mem mem";
        emit_cmp(o, ins, dest, src);
    }
}

/* ---------- instrumentation inserters ---------- */

static void
insert_r2r_xfer(void *drcontext, instrlist_t *bb, instr_t *instr,
                reg_id_t dst, reg_id_t src)
{
    uint dr_row, dr_start, dr_n, sr_row, sr_start, sr_n;
    if (!reg_shadow_span(dst, &dr_row, &dr_start, &dr_n))
        return;
    if (!reg_shadow_span(src, &sr_row, &sr_start, &sr_n))
        return;
    uint n = (dr_n < sr_n) ? dr_n : sr_n;
    dr_insert_clean_call(drcontext, bb, instr, (void *)r2r_xfer, false, 5,
                         OPND_CREATE_INT32(dr_row), OPND_CREATE_INT32(dr_start),
                         OPND_CREATE_INT32(sr_row), OPND_CREATE_INT32(sr_start),
                         OPND_CREATE_INT32(n));
}

static void
insert_r_clr(void *drcontext, instrlist_t *bb, instr_t *instr, reg_id_t dst)
{
    uint row, start, n;
    if (!reg_shadow_span(dst, &row, &start, &n))
        return;
    dr_insert_clean_call(drcontext, bb, instr, (void *)r_clr, false, 3,
                         OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                         OPND_CREATE_INT32(n));
}

/* Reserve aflags + two scratch regs and materialize a memory operand's EA
 * into addr_reg. Returns true on success; on success the caller MUST call
 * release_mem_addr() after inserting its clean call. */
struct mem_ea {
    reg_id_t addr;
    reg_id_t scratch;
};

static bool
acquire_mem_addr(void *dc, instrlist_t *bb, instr_t *where, opnd_t mem,
                 mem_ea *out_ea)
{
    out_ea->addr = DR_REG_NULL;
    out_ea->scratch = DR_REG_NULL;
    if (drreg_reserve_aflags(dc, bb, where) != DRREG_SUCCESS)
        return false;
    if (drreg_reserve_register(dc, bb, where, NULL, &out_ea->addr) != DRREG_SUCCESS) {
        drreg_unreserve_aflags(dc, bb, where);
        return false;
    }
    if (drreg_reserve_register(dc, bb, where, NULL, &out_ea->scratch) != DRREG_SUCCESS) {
        drreg_unreserve_register(dc, bb, where, out_ea->addr);
        drreg_unreserve_aflags(dc, bb, where);
        return false;
    }
    if (!drutil_insert_get_mem_addr(dc, bb, where, mem, out_ea->addr,
                                    out_ea->scratch)) {
        drreg_unreserve_register(dc, bb, where, out_ea->scratch);
        drreg_unreserve_register(dc, bb, where, out_ea->addr);
        drreg_unreserve_aflags(dc, bb, where);
        return false;
    }
    return true;
}

static void
release_mem_addr(void *dc, instrlist_t *bb, instr_t *where, mem_ea *ea)
{
    drreg_unreserve_register(dc, bb, where, ea->scratch);
    drreg_unreserve_register(dc, bb, where, ea->addr);
    drreg_unreserve_aflags(dc, bb, where);
}

/* Two memory EAs at once (m2m: CMPS, PUSH/POP mem). addr1/addr2 hold the EAs;
 * one shared scratch is reused for both drutil computations. */
struct mem_ea2 {
    reg_id_t addr1;
    reg_id_t addr2;
    reg_id_t scratch;
};

static bool
acquire_mem_addr2(void *dc, instrlist_t *bb, instr_t *where, opnd_t m1, opnd_t m2,
                  mem_ea2 *out)
{
    out->addr1 = out->addr2 = out->scratch = DR_REG_NULL;
    if (drreg_reserve_aflags(dc, bb, where) != DRREG_SUCCESS)
        return false;
    bool ok = drreg_reserve_register(dc, bb, where, NULL, &out->addr1) == DRREG_SUCCESS &&
              drreg_reserve_register(dc, bb, where, NULL, &out->addr2) == DRREG_SUCCESS &&
              drreg_reserve_register(dc, bb, where, NULL, &out->scratch) == DRREG_SUCCESS &&
              drutil_insert_get_mem_addr(dc, bb, where, m1, out->addr1, out->scratch) &&
              drutil_insert_get_mem_addr(dc, bb, where, m2, out->addr2, out->scratch);
    if (!ok) {
        if (out->scratch != DR_REG_NULL)
            drreg_unreserve_register(dc, bb, where, out->scratch);
        if (out->addr2 != DR_REG_NULL)
            drreg_unreserve_register(dc, bb, where, out->addr2);
        if (out->addr1 != DR_REG_NULL)
            drreg_unreserve_register(dc, bb, where, out->addr1);
        drreg_unreserve_aflags(dc, bb, where);
        return false;
    }
    return true;
}

static void
release_mem_addr2(void *dc, instrlist_t *bb, instr_t *where, mem_ea2 *ea)
{
    drreg_unreserve_register(dc, bb, where, ea->scratch);
    drreg_unreserve_register(dc, bb, where, ea->addr2);
    drreg_unreserve_register(dc, bb, where, ea->addr1);
    drreg_unreserve_aflags(dc, bb, where);
}

static void
insert_mov_m2r(void *dc, instrlist_t *bb, instr_t *instr, reg_id_t dst,
               opnd_t mem)
{
    uint row, start, n;
    if (!reg_shadow_span(dst, &row, &start, &n))
        return;
    mem_ea ea;
    if (!acquire_mem_addr(dc, bb, instr, mem, &ea))
        return;
    dr_insert_clean_call(dc, bb, instr, (void *)mov_m2r, false, 4,
                         OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                         opnd_create_reg(ea.addr), OPND_CREATE_INT32(n));
    release_mem_addr(dc, bb, instr, &ea);
}

static void
insert_mov_r2m(void *dc, instrlist_t *bb, instr_t *instr, opnd_t mem,
               reg_id_t src)
{
    uint row, start, n;
    if (!reg_shadow_span(src, &row, &start, &n))
        return;
    mem_ea ea;
    if (!acquire_mem_addr(dc, bb, instr, mem, &ea))
        return;
    dr_insert_clean_call(dc, bb, instr, (void *)mov_r2m, false, 4,
                         opnd_create_reg(ea.addr), OPND_CREATE_INT32(row),
                         OPND_CREATE_INT32(start), OPND_CREATE_INT32(n));
    release_mem_addr(dc, bb, instr, &ea);
}

static void
insert_mov_clr_mem(void *dc, instrlist_t *bb, instr_t *instr, opnd_t mem)
{
    uint n = (uint)opnd_size_in_bytes(opnd_get_size(mem));
    if (n == 0)
        return;
    mem_ea ea;
    if (!acquire_mem_addr(dc, bb, instr, mem, &ea))
        return;
    dr_insert_clean_call(dc, bb, instr, (void *)mov_clr_mem, false, 2,
                         opnd_create_reg(ea.addr), OPND_CREATE_INT32(n));
    release_mem_addr(dc, bb, instr, &ea);
}

/* the data destination of an RMW op (first GPR or memory dst, skipping eflags) */
static bool
find_data_dst(instr_t *instr, opnd_t *out)
{
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t o = instr_get_dst(instr, k);
        if (opnd_is_memory_reference(o) ||
            (opnd_is_reg(o) && reg_is_gpr(opnd_get_reg(o)))) {
            *out = o;
            return true;
        }
    }
    return false;
}

/* whether a source operand is the same datum as the RMW destination (so it can
 * be skipped when locating the "other" operand that contributes taint). */
static bool
same_data_opnd(opnd_t a, opnd_t b)
{
    if (opnd_is_reg(a) && opnd_is_reg(b))
        return opnd_get_reg(a) == opnd_get_reg(b);
    if (opnd_is_memory_reference(a) && opnd_is_memory_reference(b))
        return true;
    return false;
}

static void
insert_binary(void *dc, instrlist_t *bb, instr_t *instr, int opcode)
{
    opnd_t op0;
    if (!find_data_dst(instr, &op0))
        return;

    /* the taint-source operand = first src that isn't the RMW dst-as-src */
    opnd_t op1 = op0;
    bool have1 = false;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_immed(s)) { op1 = s; have1 = true; break; }
        if (same_data_opnd(s, op0))
            continue;
        op1 = s; have1 = true; break;
    }
    (void)have1;  /* !have1 => same-register operand (op1 == op0) */

    if (opnd_is_immed(op1))
        return;  /* immediate carries no taint */

    /* XOR/SUB/SBB reg,reg same register => zeroing idiom => clear dst. */
    if ((opcode == OP_xor || opcode == OP_sub || opcode == OP_sbb) &&
        opnd_is_reg(op0) && opnd_is_reg(op1) &&
        opnd_get_reg(op0) == opnd_get_reg(op1)) {
        insert_r_clr(dc, bb, instr, opnd_get_reg(op0));
        return;
    }

    if (opnd_is_reg(op0)) {
        uint d_row, d_start, d_n;
        if (!reg_shadow_span(opnd_get_reg(op0), &d_row, &d_start, &d_n))
            return;
        if (opnd_is_reg(op1)) {
            uint s_row, s_start, s_n;
            if (!reg_shadow_span(opnd_get_reg(op1), &s_row, &s_start, &s_n))
                return;
            uint n = (d_n < s_n) ? d_n : s_n;
            dr_insert_clean_call(dc, bb, instr, (void *)binary_r2r, false, 5,
                                 OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                                 OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                                 OPND_CREATE_INT32(n));
        } else if (opnd_is_memory_reference(op1)) {
            mem_ea ea;
            if (!acquire_mem_addr(dc, bb, instr, op1, &ea))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)binary_m2r, false, 4,
                                 OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                                 opnd_create_reg(ea.addr), OPND_CREATE_INT32(d_n));
            release_mem_addr(dc, bb, instr, &ea);
        }
    } else if (opnd_is_memory_reference(op0)) {
        if (!opnd_is_reg(op1))
            return;
        uint s_row, s_start, s_n;
        if (!reg_shadow_span(opnd_get_reg(op1), &s_row, &s_start, &s_n))
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, op0, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)binary_r2m, false, 4,
                             opnd_create_reg(ea.addr), OPND_CREATE_INT32(s_row),
                             OPND_CREATE_INT32(s_start), OPND_CREATE_INT32(s_n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

/* MOVZX (sign=false) / MOVSX/MOVSXD (sign=true): same shape, different handler. */
static void
insert_extend(void *dc, instrlist_t *bb, instr_t *instr, bool sign)
{
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d))
        return;
    uint d_row, d_start, d_n;
    if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
        return;
    opnd_t s = instr_get_src(instr, 0);
    if (opnd_is_reg(s)) {
        uint s_row, s_start, s_n;
        if (!reg_shadow_span(opnd_get_reg(s), &s_row, &s_start, &s_n))
            return;
        dr_insert_clean_call(dc, bb, instr,
                             sign ? (void *)movsx_r2r : (void *)movzx_r2r, false, 5,
                             OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(s_row),
                             OPND_CREATE_INT32(s_start), OPND_CREATE_INT32(s_n),
                             OPND_CREATE_INT32(d_n));
    } else if (opnd_is_memory_reference(s)) {
        uint srcn = (uint)opnd_size_in_bytes(opnd_get_size(s));
        if (srcn == 0)
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, s, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr,
                             sign ? (void *)movsx_m2r : (void *)movzx_m2r, false, 4,
                             OPND_CREATE_INT32(d_row), opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(srcn), OPND_CREATE_INT32(d_n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

static bool
is_stack_ptr_reg(reg_id_t r)
{
    return r == DR_REG_RSP || r == DR_REG_ESP || r == DR_REG_SP;
}

/* mem -> mem byte-tag copy: emit the two-EA acquire + m2m_xfer clean call. */
static void
insert_m2m_xfer(void *dc, instrlist_t *bb, instr_t *instr, opnd_t dst_mem,
                opnd_t src_mem, uint n)
{
    if (n == 0)
        return;
    mem_ea2 ea;
    if (!acquire_mem_addr2(dc, bb, instr, dst_mem, src_mem, &ea))
        return;
    dr_insert_clean_call(dc, bb, instr, (void *)m2m_xfer, false, 3,
                         opnd_create_reg(ea.addr1), opnd_create_reg(ea.addr2),
                         OPND_CREATE_INT32(n));
    release_mem_addr2(dc, bb, instr, &ea);
}

/* PUSH reg -> stack slot (r2m); PUSH imm -> clear stack; PUSH mem -> m2m. */
static void
insert_push(void *dc, instrlist_t *bb, instr_t *instr)
{
    opnd_t mem;
    bool havemem = false;
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t o = instr_get_dst(instr, k);
        if (opnd_is_memory_reference(o)) { mem = o; havemem = true; break; }
    }
    if (!havemem)
        return;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_reg(s)) {
            reg_id_t r = opnd_get_reg(s);
            if (is_stack_ptr_reg(r))
                continue;
            insert_mov_r2m(dc, bb, instr, mem, r);
            return;
        }
        if (opnd_is_immed(s)) {
            insert_mov_clr_mem(dc, bb, instr, mem);
            return;
        }
        if (opnd_is_memory_reference(s)) {
            insert_m2m_xfer(dc, bb, instr, mem, s,
                            (uint)opnd_size_in_bytes(opnd_get_size(mem)));
            return;
        }
    }
}

/* POP -> reg (m2r from stack slot); POP mem -> m2m. */
static void
insert_pop(void *dc, instrlist_t *bb, instr_t *instr)
{
    opnd_t mem;
    bool havemem = false;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_memory_reference(s)) { mem = s; havemem = true; break; }
    }
    if (!havemem)
        return;
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t o = instr_get_dst(instr, k);
        if (opnd_is_reg(o) && reg_is_gpr(opnd_get_reg(o)) &&
            !is_stack_ptr_reg(opnd_get_reg(o))) {
            insert_mov_m2r(dc, bb, instr, opnd_get_reg(o), mem);
            return;
        }
        if (opnd_is_memory_reference(o)) {
            insert_m2m_xfer(dc, bb, instr, o, mem,
                            (uint)opnd_size_in_bytes(opnd_get_size(o)));
            return;
        }
    }
}

/* CMPS (string compare): both operands memory. Match libdft's dest/src:
 * dest = ES:[rdi], src = DS:[rsi] (keyed off the base register, robust to DR's
 * src ordering). */
static void
insert_cmps(void *dc, instrlist_t *bb, instr_t *instr)
{
    opnd_t m[2];
    int nm = 0;
    for (int k = 0; k < instr_num_srcs(instr) && nm < 2; k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_memory_reference(s))
            m[nm++] = s;
    }
    if (nm != 2)
        return;
    opnd_t dst_mem = m[0], src_mem = m[1];
    /* dest = the [rdi] operand, src = the [rsi] operand. */
    reg_id_t b0 = opnd_get_base(m[0]);
    if (b0 == DR_REG_RSI || b0 == DR_REG_ESI) {
        dst_mem = m[1];
        src_mem = m[0];
    }
    uint size = (uint)opnd_size_in_bytes(opnd_get_size(dst_mem));
    if (size == 0)
        return;
    mem_ea2 ea;
    if (!acquire_mem_addr2(dc, bb, instr, dst_mem, src_mem, &ea))
        return;
    app_pc pc = instr_get_app_pc(instr);
    dr_insert_clean_call(dc, bb, instr, (void *)cmp_m2m, false, 4,
                         OPND_CREATE_INTPTR((ptr_int_t)pc),
                         opnd_create_reg(ea.addr1), opnd_create_reg(ea.addr2),
                         OPND_CREATE_INT32(size));
    release_mem_addr2(dc, bb, instr, &ea);
}

/* LEAVE = (mov rsp,rbp ; pop rbp): rsp gets rbp's taint, then rbp gets the
 * stack slot's taint ([old rbp]). */
static void
insert_leave(void *dc, instrlist_t *bb, instr_t *instr)
{
    insert_r2r_xfer(dc, bb, instr, DR_REG_RSP, DR_REG_RBP);
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_memory_reference(s)) {
            insert_mov_m2r(dc, bb, instr, DR_REG_RBP, s);
            return;
        }
    }
}

/* BSF/BSR: libdft treats these as a plain MOV (dst reg <- src reg/mem). */
static void
insert_xfer(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d))
        return;
    opnd_t s = instr_get_src(instr, 0);
    if (opnd_is_reg(s))
        insert_r2r_xfer(dc, bb, instr, opnd_get_reg(d), opnd_get_reg(s));
    else if (opnd_is_memory_reference(s))
        insert_mov_m2r(dc, bb, instr, opnd_get_reg(d), s);
}

/* fixed-register byte-span copy (sign-extend accumulator ops CBW..CQO). */
static void
insert_fixed_xfer(void *dc, instrlist_t *bb, instr_t *instr, uint d_row,
                  uint d_start, uint s_row, uint s_start, uint n)
{
    dr_insert_clean_call(dc, bb, instr, (void *)r2r_xfer, false, 5,
                         OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                         OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                         OPND_CREATE_INT32(n));
}

/* CBW/CWDE/CDQE (DR OP_cwde): sign-extend the accumulator in place. The dst
 * width (2/4/8) selects which: copy RAX[0..half-1] -> RAX[half..size-1]. */
static void
insert_cwde_family(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || !opnd_is_reg(instr_get_dst(instr, 0)))
        return;
    uint size = (uint)opnd_size_in_bytes(opnd_get_size(instr_get_dst(instr, 0)));
    if (size < 2)
        return;
    uint half = size / 2;
    insert_fixed_xfer(dc, bb, instr, DFT_REG_RAX, half, DFT_REG_RAX, 0, half);
}

/* CWD/CDQ/CQO (DR OP_cdq): RDX <- sign of rAX at the operand width. */
static void
insert_cdq_family(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || !opnd_is_reg(instr_get_dst(instr, 0)))
        return;
    uint size = (uint)opnd_size_in_bytes(opnd_get_size(instr_get_dst(instr, 0)));
    if (size == 0)
        return;
    insert_fixed_xfer(dc, bb, instr, DFT_REG_RDX, 0, DFT_REG_RAX, 0, size);
}

/* the single explicit reg/mem operand of MUL/DIV/IDIV (skip the implicit
 * RAX/RDX). Returns false if only the accumulator is involved. */
static bool
find_explicit_operand(instr_t *instr, opnd_t *out)
{
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t o = instr_get_src(instr, k);
        if (opnd_is_memory_reference(o)) { *out = o; return true; }
        if (opnd_is_reg(o)) {
            reg_id_t full = reg_to_pointer_sized(opnd_get_reg(o));
            if (full != DR_REG_RAX && full != DR_REG_RDX) { *out = o; return true; }
        }
    }
    return false;
}

/* MUL/DIV/IDIV (1-operand): RDX:RAX combine with the explicit operand. */
static void
insert_muldiv(void *dc, instrlist_t *bb, instr_t *instr)
{
    opnd_t e;
    if (!find_explicit_operand(instr, &e))
        return;
    if (opnd_is_reg(e)) {
        uint row, start, n;
        if (!reg_shadow_span(opnd_get_reg(e), &row, &start, &n))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)ternary_r2r, false, 3,
                             OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                             OPND_CREATE_INT32(n));
    } else if (opnd_is_memory_reference(e)) {
        uint n = (uint)opnd_size_in_bytes(opnd_get_size(e));
        if (n == 0)
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, e, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)ternary_m2r, false, 2,
                             opnd_create_reg(ea.addr), OPND_CREATE_INT32(n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

/* IMUL: 1-operand form (RDX:RAX dsts) -> ternary; 2-operand form -> binary
 * combine (handled by insert_binary). 3-operand (dst,src,imm) is approximated
 * by insert_binary as well (over-combines into dst -- acceptable). */
static void
insert_imul(void *dc, instrlist_t *bb, instr_t *instr)
{
    bool has_rax = false, has_rdx = false;
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t o = instr_get_dst(instr, k);
        if (opnd_is_reg(o) && reg_is_gpr(opnd_get_reg(o))) {
            reg_id_t full = reg_to_pointer_sized(opnd_get_reg(o));
            if (full == DR_REG_RAX) has_rax = true;
            if (full == DR_REG_RDX) has_rdx = true;
        }
    }
    if (has_rax && has_rdx)
        insert_muldiv(dc, bb, instr);   /* 1-operand form */
    else
        insert_binary(dc, bb, instr, OP_imul);
}

/* XCHG: swap byte-tags (reg<->reg or reg<->mem). */
static void
insert_xchg(void *dc, instrlist_t *bb, instr_t *instr)
{
    opnd_t r0, r1, mem;
    int nreg = 0, nmem = 0;
    /* collect the two data operands from the dst list (XCHG writes both). */
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t o = instr_get_dst(instr, k);
        if (opnd_is_reg(o) && reg_is_gpr(opnd_get_reg(o))) {
            if (nreg == 0) r0 = o; else r1 = o;
            nreg++;
        } else if (opnd_is_memory_reference(o)) {
            mem = o; nmem++;
        }
    }
    if (nmem == 0 && nreg >= 2) {
        uint a_row, a_start, a_n, b_row, b_start, b_n;
        if (!reg_shadow_span(opnd_get_reg(r0), &a_row, &a_start, &a_n) ||
            !reg_shadow_span(opnd_get_reg(r1), &b_row, &b_start, &b_n))
            return;
        uint n = (a_n < b_n) ? a_n : b_n;
        dr_insert_clean_call(dc, bb, instr, (void *)xchg_r2r, false, 5,
                             OPND_CREATE_INT32(a_row), OPND_CREATE_INT32(a_start),
                             OPND_CREATE_INT32(b_row), OPND_CREATE_INT32(b_start),
                             OPND_CREATE_INT32(n));
    } else if (nmem == 1 && nreg >= 1) {
        uint row, start, n;
        if (!reg_shadow_span(opnd_get_reg(r0), &row, &start, &n))
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, mem, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)xchg_m2r, false, 4,
                             opnd_create_reg(ea.addr), OPND_CREATE_INT32(row),
                             OPND_CREATE_INT32(start), OPND_CREATE_INT32(n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

/* (row,start) for an address register, mapping NULL/non-GPR to the clear row. */
static void
addr_reg_span(reg_id_t reg, uint *row, uint *start)
{
    uint r, s, n;
    if (reg != DR_REG_NULL && reg_shadow_span(reg, &r, &s, &n)) {
        *row = r;
        *start = s;
    } else {
        *row = GRP_NUM;
        *start = 0;
    }
}

static void
insert_lea(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d))
        return;
    uint d_row, d_start, d_n;
    if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
        return;
    opnd_t mem = instr_get_src(instr, 0);
    if (!opnd_is_base_disp(mem))
        return;
    uint b_row, b_start, i_row, i_start;
    addr_reg_span(opnd_get_base(mem), &b_row, &b_start);
    addr_reg_span(opnd_get_index(mem), &i_row, &i_start);
    app_pc pc = instr_get_app_pc(instr);
    dr_insert_clean_call(dc, bb, instr, (void *)lea_prop, false, 7,
                         OPND_CREATE_INTPTR((ptr_int_t)pc),
                         OPND_CREATE_INT32(d_row),
                         OPND_CREATE_INT32(b_row), OPND_CREATE_INT32(b_start),
                         OPND_CREATE_INT32(i_row), OPND_CREATE_INT32(i_start),
                         OPND_CREATE_INT32(d_n));
}

/* CMOVcc: predicated reg<-reg/mem transfer; the predicate (instr_get_predicate)
 * is evaluated at runtime in the handler. */
static void
insert_cmov(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d))
        return;
    reg_id_t dst = opnd_get_reg(d);
    uint d_row, d_start, d_n;
    if (!reg_shadow_span(dst, &d_row, &d_start, &d_n))
        return;
    int pred = (int)instr_get_predicate(instr);

    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_memory_reference(s)) {
            mem_ea ea;
            if (!acquire_mem_addr(dc, bb, instr, s, &ea))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)cmov_m2r, false, 5,
                                 OPND_CREATE_INT32(pred), OPND_CREATE_INT32(d_row),
                                 OPND_CREATE_INT32(d_start), opnd_create_reg(ea.addr),
                                 OPND_CREATE_INT32(d_n));
            release_mem_addr(dc, bb, instr, &ea);
            return;
        }
        if (opnd_is_reg(s) && reg_is_gpr(opnd_get_reg(s)) &&
            opnd_get_reg(s) != dst) {
            uint s_row, s_start, s_n;
            if (!reg_shadow_span(opnd_get_reg(s), &s_row, &s_start, &s_n))
                return;
            uint n = (d_n < s_n) ? d_n : s_n;
            dr_insert_clean_call(dc, bb, instr, (void *)cmov_r2r, false, 6,
                                 OPND_CREATE_INT32(pred), OPND_CREATE_INT32(d_row),
                                 OPND_CREATE_INT32(d_start), OPND_CREATE_INT32(s_row),
                                 OPND_CREATE_INT32(s_start), OPND_CREATE_INT32(n));
            return;
        }
    }
}

static void
insert_cmp(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_srcs(instr) < 2)
        return;
    app_pc pc = instr_get_app_pc(instr);
    opnd_t op0 = instr_get_src(instr, 0);
    opnd_t op1 = instr_get_src(instr, 1);

    if (opnd_is_reg(op0)) {
        reg_id_t r0 = opnd_get_reg(op0);
        uint row, start, n;
        if (!reg_shadow_span(r0, &row, &start, &n))
            return;
        uint size = (uint)opnd_size_in_bytes(reg_get_size(r0));

        if (opnd_is_reg(op1)) {
            reg_id_t r1 = opnd_get_reg(op1);
            uint s_row, s_start, s_n;
            if (!reg_shadow_span(r1, &s_row, &s_start, &s_n))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)cmp_r2r, false, 8,
                                 OPND_CREATE_INTPTR((ptr_int_t)pc),
                                 OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                                 reg_val_opnd(r0),
                                 OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                                 reg_val_opnd(r1), OPND_CREATE_INT32(size));
        } else if (opnd_is_memory_reference(op1)) {
            mem_ea ea;
            if (!acquire_mem_addr(dc, bb, instr, op1, &ea))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)cmp_m2r, false, 6,
                                 OPND_CREATE_INTPTR((ptr_int_t)pc),
                                 OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                                 reg_val_opnd(r0), opnd_create_reg(ea.addr),
                                 OPND_CREATE_INT32(size));
            release_mem_addr(dc, bb, instr, &ea);
        } else if (opnd_is_immed(op1)) {
            uint32_t imm = (uint32_t)opnd_get_immed_int(op1);
            dr_insert_clean_call(dc, bb, instr, (void *)cmp_i2r, false, 6,
                                 OPND_CREATE_INTPTR((ptr_int_t)pc),
                                 OPND_CREATE_INT32(row), OPND_CREATE_INT32(start),
                                 reg_val_opnd(r0), OPND_CREATE_INT32((int)imm),
                                 OPND_CREATE_INT32(size));
        }
    } else if (opnd_is_memory_reference(op0)) {
        uint size = (uint)opnd_size_in_bytes(opnd_get_size(op0));
        if (size == 0)
            return;
        if (opnd_is_reg(op1)) {
            reg_id_t r1 = opnd_get_reg(op1);
            uint s_row, s_start, s_n;
            if (!reg_shadow_span(r1, &s_row, &s_start, &s_n))
                return;
            mem_ea ea;
            if (!acquire_mem_addr(dc, bb, instr, op0, &ea))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)cmp_r2m, false, 6,
                                 OPND_CREATE_INTPTR((ptr_int_t)pc),
                                 opnd_create_reg(ea.addr),
                                 OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                                 reg_val_opnd(r1), OPND_CREATE_INT32(size));
            release_mem_addr(dc, bb, instr, &ea);
        } else if (opnd_is_immed(op1)) {
            uint32_t imm = (uint32_t)opnd_get_immed_int(op1);
            mem_ea ea;
            if (!acquire_mem_addr(dc, bb, instr, op0, &ea))
                return;
            dr_insert_clean_call(dc, bb, instr, (void *)cmp_i2m, false, 4,
                                 OPND_CREATE_INTPTR((ptr_int_t)pc),
                                 opnd_create_reg(ea.addr),
                                 OPND_CREATE_INT32((int)imm), OPND_CREATE_INT32(size));
            release_mem_addr(dc, bb, instr, &ea);
        }
    }
}

/* ---------- shifts: SHL/SHR/SAR/ROL/ROR/RCL/RCR + SHLD/SHRD ----------
 *
 * D-doc Q5 decision: shift-amount-conservative pass-through.
 *
 * A naive "no-op" (libdft's choice) preserves tags pinned to their original
 * byte positions, which is a false-negative whenever the shift moves bits
 * across byte boundaries (e.g. `shl rax, 8` makes ah depend on what was in
 * al, but ah's shadow stays untouched). At per-byte tag granularity the
 * principled fix is per-bit modelling, which is heavy and rarely worth it
 * for offset-coverage DTA (VUzzer's use case).
 *
 * The coarsening we do: collect the union of all data-operand byte tags
 * and write that union to every dst byte. Conservative on the over-tainting
 * side (a 1-bit shift now claims all dst bytes depend on the original
 * data), but eliminates the false-negative class. For SHLD/SHRD the union
 * spans both source registers (dst's current bytes + the funnel source);
 * the count operand (imm or `cl`) is *ignored* per Q5 so a tainted count
 * register doesn't pollute downstream reach. */
static void
shift_r(uint d_row, uint d_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    tag_t u = tc->vcpu.gpr_file[d_row][d_start];
    for (uint i = 1; i < n; i++)
        u = tag_combine(u, tc->vcpu.gpr_file[d_row][d_start + i]);
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] = u;
}

static void
shift_m(ADDRINT addr, uint n)
{
    if (n == 0)
        return;
    tag_t u = file_tagmap_getb(addr);
    for (uint i = 1; i < n; i++) {
        tag_t b = file_tagmap_getb(addr + i);
        u = tag_combine(u, b);
    }
    for (uint i = 0; i < n; i++)
        tagmap_setb_with_tag(addr + i, u);
}

/* SHLD/SHRD: union dst bytes + src reg bytes, write to all dst bytes. */
static void
shld_r2r(uint d_row, uint d_start, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    tag_t u = tc->vcpu.gpr_file[d_row][d_start];
    for (uint i = 1; i < n; i++)
        u = tag_combine(u, tc->vcpu.gpr_file[d_row][d_start + i]);
    for (uint i = 0; i < n; i++)
        u = tag_combine(u, tc->vcpu.gpr_file[s_row][s_start + i]);
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] = u;
}

static void
insert_shift(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (opnd_is_reg(d)) {
        if (!reg_is_gpr(opnd_get_reg(d)))
            return;
        uint row, start, n;
        if (!reg_shadow_span(opnd_get_reg(d), &row, &start, &n))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)shift_r, false, 3,
                             OPND_CREATE_INT32(row),
                             OPND_CREATE_INT32(start),
                             OPND_CREATE_INT32(n));
    } else if (opnd_is_memory_reference(d)) {
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, d, &ea))
            return;
        uint n = opnd_size_in_bytes(opnd_get_size(d));
        dr_insert_clean_call(dc, bb, instr, (void *)shift_m, false, 2,
                             opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

static void
insert_shld_shrd(void *dc, instrlist_t *bb, instr_t *instr)
{
    /* SHLD/SHRD form: dst reg, src reg, count (imm or cl). */
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 2)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d) || !reg_is_gpr(opnd_get_reg(d)))
        return;
    uint d_row, d_start, d_n;
    if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
        return;
    /* Find the 2nd reg source (the funnel source); skip the count operand
     * (imm or `cl`) per Q5. */
    reg_id_t dst_reg = opnd_get_reg(d);
    bool found = false;
    uint s_row = 0, s_start = 0, s_n = 0;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_reg(s) && reg_is_gpr(opnd_get_reg(s))
            && opnd_get_reg(s) != dst_reg) {
            if (reg_shadow_span(opnd_get_reg(s), &s_row, &s_start, &s_n)) {
                found = true;
                break;
            }
        }
    }
    if (!found) {
        /* Degenerate (count is the only "other" operand and it's an imm):
         * fall back to the in-place coarsening. */
        dr_insert_clean_call(dc, bb, instr, (void *)shift_r, false, 3,
                             OPND_CREATE_INT32(d_row),
                             OPND_CREATE_INT32(d_start),
                             OPND_CREATE_INT32(d_n));
        return;
    }
    uint n = (d_n < s_n) ? d_n : s_n;
    dr_insert_clean_call(dc, bb, instr, (void *)shld_r2r, false, 5,
                         OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                         OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                         OPND_CREATE_INT32(n));
}

/* ---------- BSWAP + MOVBE: byte-order ops ----------
 *
 * BSWAP reverses the bytes of a 32/64-bit register in place; the per-byte
 * tags must reverse with the data so a tag attached to byte 0 follows the
 * byte to its new position N-1. MOVBE is a load/store with byte-swap: same
 * idea, but cross-operand. Both are missing from libdft64 entirely; the DR
 * port adds them generically. */
static void
bswap_reg(uint d_row, uint d_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n < 2)
        return;
    for (uint i = 0; i < n / 2; i++) {
        tag_t tmp = tc->vcpu.gpr_file[d_row][d_start + i];
        tc->vcpu.gpr_file[d_row][d_start + i] =
            tc->vcpu.gpr_file[d_row][d_start + n - 1 - i];
        tc->vcpu.gpr_file[d_row][d_start + n - 1 - i] = tmp;
    }
}

static void
movbe_m2r(uint d_row, uint d_start, ADDRINT addr, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++)
        tc->vcpu.gpr_file[d_row][d_start + i] = file_tagmap_getb(addr + n - 1 - i);
}

static void
movbe_r2m(ADDRINT addr, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++)
        tagmap_setb_with_tag(addr + i, tc->vcpu.gpr_file[s_row][s_start + n - 1 - i]);
}

static void
insert_bswap(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_reg(d) || !reg_is_gpr(opnd_get_reg(d)))
        return;
    uint row, start, n;
    if (!reg_shadow_span(opnd_get_reg(d), &row, &start, &n))
        return;
    if (n < 2)
        return;  /* BSWAP undefined for 16-bit; nothing to swap for 8-bit. */
    dr_insert_clean_call(dc, bb, instr, (void *)bswap_reg, false, 3,
                         OPND_CREATE_INT32(row),
                         OPND_CREATE_INT32(start),
                         OPND_CREATE_INT32(n));
}

static void
insert_movbe(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    opnd_t s = instr_get_src(instr, 0);
    if (opnd_is_reg(d) && opnd_is_memory_reference(s)) {
        /* MOVBE r, m */
        if (!reg_is_gpr(opnd_get_reg(d)))
            return;
        uint d_row, d_start, d_n;
        if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, s, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)movbe_m2r, false, 4,
                             OPND_CREATE_INT32(d_row),
                             OPND_CREATE_INT32(d_start),
                             opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(d_n));
        release_mem_addr(dc, bb, instr, &ea);
    } else if (opnd_is_memory_reference(d) && opnd_is_reg(s)) {
        /* MOVBE m, r */
        if (!reg_is_gpr(opnd_get_reg(s)))
            return;
        uint s_row, s_start, s_n;
        if (!reg_shadow_span(opnd_get_reg(s), &s_row, &s_start, &s_n))
            return;
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, d, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)movbe_r2m, false, 4,
                             opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(s_row),
                             OPND_CREATE_INT32(s_start),
                             OPND_CREATE_INT32(s_n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

/* ---------- CMPXCHG + XADD: read-modify-write families ----------
 *
 * Both have data-dependent semantics that would need a runtime predicate
 * check for fully-precise tags. We coarsen to a binary-style union on the
 * grounds that (a) it is correct (no false negatives), (b) over-tainting
 * is acceptable for offset-coverage DTA, and (c) it is much cheaper than
 * inserting a runtime ZF check on every dynamic instruction. Same design
 * philosophy as libdft64's binary-op handlers. */

/* CMPXCHG mem, src_reg:
 *   mem ← union(mem, src_reg, accum); accum ← union(mem, src_reg, accum).
 * Both outputs receive the full union — over-conservative but safe. */
static void
cmpxchg_mem(ADDRINT addr, uint src_row, uint src_start,
            uint accum_row, uint accum_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t m = file_tagmap_getb(addr + i);
        tag_t s = tc->vcpu.gpr_file[src_row][src_start + i];
        tag_t a = tc->vcpu.gpr_file[accum_row][accum_start + i];
        tag_t u = tag_combine(m, s);
        u = tag_combine(u, a);
        tagmap_setb_with_tag(addr + i, u);
        tc->vcpu.gpr_file[accum_row][accum_start + i] = u;
    }
}

static void
cmpxchg_reg(uint d_row, uint d_start, uint src_row, uint src_start,
            uint accum_row, uint accum_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t d = tc->vcpu.gpr_file[d_row][d_start + i];
        tag_t s = tc->vcpu.gpr_file[src_row][src_start + i];
        tag_t a = tc->vcpu.gpr_file[accum_row][accum_start + i];
        tag_t u = tag_combine(d, s);
        u = tag_combine(u, a);
        tc->vcpu.gpr_file[d_row][d_start + i] = u;
        tc->vcpu.gpr_file[accum_row][accum_start + i] = u;
    }
}

/* XADD dst, src: real semantics are src←old_dst, dst←old_dst+src. We coarsen
 * to: both outputs receive union(dst, src). Over-taints src; acceptable. */
static void
xadd_r2r(uint d_row, uint d_start, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t d = tc->vcpu.gpr_file[d_row][d_start + i];
        tag_t s = tc->vcpu.gpr_file[s_row][s_start + i];
        tag_t u = tag_combine(d, s);
        tc->vcpu.gpr_file[d_row][d_start + i] = u;
        tc->vcpu.gpr_file[s_row][s_start + i] = u;
    }
}

static void
xadd_m2r(ADDRINT addr, uint s_row, uint s_start, uint n)
{
    thread_ctx_t *tc = libdft_get_thread_ctx(dr_get_current_drcontext());
    if (tc == NULL || n == 0)
        return;
    for (uint i = 0; i < n; i++) {
        tag_t m = file_tagmap_getb(addr + i);
        tag_t s = tc->vcpu.gpr_file[s_row][s_start + i];
        tag_t u = tag_combine(m, s);
        tagmap_setb_with_tag(addr + i, u);
        tc->vcpu.gpr_file[s_row][s_start + i] = u;
    }
}

/* CMPXCHG instrumenter. Operands include the implicit accumulator (RAX family
 * sized to the op width: AL / AX / EAX / RAX). DR exposes it explicitly in the
 * src/dst lists; we find it by `reg_to_pointer_sized == DR_REG_RAX`. CMPXCHG8B
 * / CMPXCHG16B (which touch EDX:EAX:ECX:EBX) are intentionally not handled
 * here — they appear in atomic lock-free code, not parsing hot paths. */
static void
insert_cmpxchg(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    /* Find the explicit src reg (not the accumulator, not the dst-as-src)
     * and the accumulator (RAX-family sized to op). */
    reg_id_t src_reg = DR_REG_NULL, accum_reg = DR_REG_NULL;
    reg_id_t dst_reg = opnd_is_reg(d) ? opnd_get_reg(d) : DR_REG_NULL;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (!opnd_is_reg(s) || !reg_is_gpr(opnd_get_reg(s)))
            continue;
        reg_id_t r = opnd_get_reg(s);
        if (reg_to_pointer_sized(r) == DR_REG_RAX) {
            if (accum_reg == DR_REG_NULL)
                accum_reg = r;
        } else if (r != dst_reg) {
            if (src_reg == DR_REG_NULL)
                src_reg = r;
        }
    }
    if (src_reg == DR_REG_NULL || accum_reg == DR_REG_NULL)
        return;
    uint s_row, s_start, s_n;
    if (!reg_shadow_span(src_reg, &s_row, &s_start, &s_n))
        return;
    uint a_row, a_start, a_n;
    if (!reg_shadow_span(accum_reg, &a_row, &a_start, &a_n))
        return;
    uint n = opnd_size_in_bytes(opnd_get_size(d));
    if (n == 0) n = s_n;
    if (opnd_is_memory_reference(d)) {
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, d, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)cmpxchg_mem, false, 6,
                             opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                             OPND_CREATE_INT32(a_row), OPND_CREATE_INT32(a_start),
                             OPND_CREATE_INT32(n));
        release_mem_addr(dc, bb, instr, &ea);
    } else if (opnd_is_reg(d) && reg_is_gpr(opnd_get_reg(d))) {
        uint d_row, d_start, d_n;
        if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)cmpxchg_reg, false, 7,
                             OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                             OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                             OPND_CREATE_INT32(a_row), OPND_CREATE_INT32(a_start),
                             OPND_CREATE_INT32(n));
    }
}

/* XADD: dst[0] = dst (mem or reg), dst[1] = src reg. */
static void
insert_xadd(void *dc, instrlist_t *bb, instr_t *instr)
{
    if (instr_num_dsts(instr) < 2)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    opnd_t s = instr_get_dst(instr, 1);
    if (!opnd_is_reg(s) || !reg_is_gpr(opnd_get_reg(s)))
        return;
    uint s_row, s_start, s_n;
    if (!reg_shadow_span(opnd_get_reg(s), &s_row, &s_start, &s_n))
        return;
    if (opnd_is_reg(d) && reg_is_gpr(opnd_get_reg(d))) {
        uint d_row, d_start, d_n;
        if (!reg_shadow_span(opnd_get_reg(d), &d_row, &d_start, &d_n))
            return;
        uint n = (d_n < s_n) ? d_n : s_n;
        dr_insert_clean_call(dc, bb, instr, (void *)xadd_r2r, false, 5,
                             OPND_CREATE_INT32(d_row), OPND_CREATE_INT32(d_start),
                             OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                             OPND_CREATE_INT32(n));
    } else if (opnd_is_memory_reference(d)) {
        mem_ea ea;
        if (!acquire_mem_addr(dc, bb, instr, d, &ea))
            return;
        dr_insert_clean_call(dc, bb, instr, (void *)xadd_m2r, false, 4,
                             opnd_create_reg(ea.addr),
                             OPND_CREATE_INT32(s_row), OPND_CREATE_INT32(s_start),
                             OPND_CREATE_INT32(s_n));
        release_mem_addr(dc, bb, instr, &ea);
    }
}

/* ---------- string ops: MOVS / STOS / LODS ----------
 *
 * REP-prefixed string ops iterate over `RCX` elements. We register an
 * app2app pass below (`event_bb_app2app`) that calls
 * `drutil_expand_rep_string`, which rewrites `REP MOVSB` into a synthetic
 * inner loop containing a bare `MOVSB`. After that the per-instruction
 * insert event fires once per iteration with the real MOVS/STOS/LODS
 * inside the loop, and we reuse the existing m2m / r2m / m2r byte-tag
 * helpers. (libdft64 didn't model these; this closes a known recall gap.)
 *
 * SCAS is intentionally NOT instrumented for cmp.out — the existing
 * libdft writers (CMP/CMPS only) define the sink-set; adding SCAS would
 * change the wire format.
 */
static void
insert_movs(void *dc, instrlist_t *bb, instr_t *instr)
{
    /* dst[0] = [RDI], src[0] = [RSI]. After rep-expansion, this fires
     * once per iteration with the element size on the operand. */
    if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    opnd_t s = instr_get_src(instr, 0);
    if (!opnd_is_memory_reference(d) || !opnd_is_memory_reference(s))
        return;
    uint n = opnd_size_in_bytes(opnd_get_size(d));
    if (n == 0)
        return;
    insert_m2m_xfer(dc, bb, instr, d, s, n);
}

static void
insert_stos(void *dc, instrlist_t *bb, instr_t *instr)
{
    /* dst[0] = [RDI], src reg = AL/AX/EAX/RAX. */
    if (instr_num_dsts(instr) < 1)
        return;
    opnd_t d = instr_get_dst(instr, 0);
    if (!opnd_is_memory_reference(d))
        return;
    reg_id_t accum = DR_REG_NULL;
    for (int k = 0; k < instr_num_srcs(instr); k++) {
        opnd_t s = instr_get_src(instr, k);
        if (opnd_is_reg(s) && reg_is_gpr(opnd_get_reg(s))
            && reg_to_pointer_sized(opnd_get_reg(s)) == DR_REG_RAX) {
            accum = opnd_get_reg(s);
            break;
        }
    }
    if (accum == DR_REG_NULL)
        return;
    insert_mov_r2m(dc, bb, instr, d, accum);
}

static void
insert_lods(void *dc, instrlist_t *bb, instr_t *instr)
{
    /* dst reg = AL/AX/EAX/RAX, src[0] = [RSI]. */
    if (instr_num_srcs(instr) < 1)
        return;
    opnd_t s = instr_get_src(instr, 0);
    if (!opnd_is_memory_reference(s))
        return;
    reg_id_t accum = DR_REG_NULL;
    for (int k = 0; k < instr_num_dsts(instr); k++) {
        opnd_t d = instr_get_dst(instr, k);
        if (opnd_is_reg(d) && reg_is_gpr(opnd_get_reg(d))
            && reg_to_pointer_sized(opnd_get_reg(d)) == DR_REG_RAX) {
            accum = opnd_get_reg(d);
            break;
        }
    }
    if (accum == DR_REG_NULL)
        return;
    insert_mov_m2r(dc, bb, instr, accum, s);
}

/* ---------- opcode router ---------- */

void
ins_inspect_dr(void *drcontext, instrlist_t *bb, instr_t *instr)
{
    int op = instr_get_opcode(instr);
    switch (op) {
        case OP_mov_ld: {
            /* dst = reg; src = reg (r2r) or mem (m2r). */
            if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
                break;
            opnd_t d = instr_get_dst(instr, 0);
            opnd_t s = instr_get_src(instr, 0);
            if (!opnd_is_reg(d))
                break;
            if (opnd_is_reg(s))
                insert_r2r_xfer(drcontext, bb, instr,
                                opnd_get_reg(d), opnd_get_reg(s));
            else if (opnd_is_memory_reference(s))
                insert_mov_m2r(drcontext, bb, instr, opnd_get_reg(d), s);
            break;
        }
        case OP_mov_st: {
            /* dst = mem or reg; src = reg (r2m/r2r) or imm (clear). */
            if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
                break;
            opnd_t d = instr_get_dst(instr, 0);
            opnd_t s = instr_get_src(instr, 0);
            if (opnd_is_memory_reference(d)) {
                if (opnd_is_reg(s))
                    insert_mov_r2m(drcontext, bb, instr, d, opnd_get_reg(s));
                else if (opnd_is_immed(s))
                    insert_mov_clr_mem(drcontext, bb, instr, d);
            } else if (opnd_is_reg(d)) {
                if (opnd_is_reg(s))
                    insert_r2r_xfer(drcontext, bb, instr,
                                    opnd_get_reg(d), opnd_get_reg(s));
                else if (opnd_is_immed(s))
                    insert_r_clr(drcontext, bb, instr, opnd_get_reg(d));
            }
            break;
        }
        case OP_mov_imm: {
            /* dst = reg; src = immediate -> clear dst shadow. */
            if (instr_num_dsts(instr) < 1)
                break;
            opnd_t d = instr_get_dst(instr, 0);
            if (opnd_is_reg(d))
                insert_r_clr(drcontext, bb, instr, opnd_get_reg(d));
            break;
        }
        case OP_cmp:
            insert_cmp(drcontext, bb, instr);
            break;
        case OP_add:
        case OP_and:
        case OP_or:
        case OP_xor:
        case OP_sub:
        case OP_sbb:
            insert_binary(drcontext, bb, instr, op);
            break;
        case OP_movzx:
            insert_extend(drcontext, bb, instr, false);
            break;
        case OP_movsx:
        case OP_movsxd:
            insert_extend(drcontext, bb, instr, true);
            break;
        case OP_lea:
            insert_lea(drcontext, bb, instr);
            break;
        case OP_push:
            insert_push(drcontext, bb, instr);
            break;
        case OP_pop:
            insert_pop(drcontext, bb, instr);
            break;
        case OP_cmps:
            insert_cmps(drcontext, bb, instr);
            break;
        case OP_leave:
            insert_leave(drcontext, bb, instr);
            break;
        case OP_bsf:
        case OP_bsr:
            insert_xfer(drcontext, bb, instr);  /* libdft: MOV-like transfer */
            break;
        case OP_cwde: /* CBW/CWDE/CDQE: RAX sign-extend in place */
            insert_cwde_family(drcontext, bb, instr);
            break;
        case OP_cdq:  /* CWD/CDQ/CQO: RDX <- sign of rAX */
            insert_cdq_family(drcontext, bb, instr);
            break;
        case OP_mul:
        case OP_div:
        case OP_idiv:
            insert_muldiv(drcontext, bb, instr);
            break;
        case OP_imul:
            insert_imul(drcontext, bb, instr);
            break;
        case OP_xchg:
            insert_xchg(drcontext, bb, instr);
            break;
        case OP_cmovo:  case OP_cmovno:
        case OP_cmovb:  case OP_cmovnb:
        case OP_cmovz:  case OP_cmovnz:
        case OP_cmovbe: case OP_cmovnbe:
        case OP_cmovs:  case OP_cmovns:
        case OP_cmovp:  case OP_cmovnp:
        case OP_cmovl:  case OP_cmovnl:
        case OP_cmovle: case OP_cmovnle:
            insert_cmov(drcontext, bb, instr);  /* predicate evaluated at runtime */
            break;
        /* Shifts + rotates (Q5: shift-amount-conservative pass-through).
         * RCL/RCR include the carry-flag implicitly; we coarsen the same way
         * (carry-bit modelling is out of scope for byte-granularity tags). */
        case OP_shl:
        case OP_shr:
        case OP_sar:
        case OP_rol:
        case OP_ror:
        case OP_rcl:
        case OP_rcr:
            insert_shift(drcontext, bb, instr);
            break;
        case OP_shld:
        case OP_shrd:
            insert_shld_shrd(drcontext, bb, instr);
            break;
        case OP_bswap:
            insert_bswap(drcontext, bb, instr);
            break;
        case OP_movbe:
            insert_movbe(drcontext, bb, instr);
            break;
        case OP_cmpxchg:
            insert_cmpxchg(drcontext, bb, instr);
            break;
        case OP_xadd:
            insert_xadd(drcontext, bb, instr);
            break;
        case OP_movs:
            insert_movs(drcontext, bb, instr);
            break;
        case OP_stos:
            insert_stos(drcontext, bb, instr);
            break;
        case OP_lods:
            insert_lods(drcontext, bb, instr);
            break;
        /* deferred (REP/sdft-covered or conditional-RMW): CMPXCHG, XADD,
         * string MOVS/STOS/LODS/SCAS. */
        default:
            break;  /* no propagation yet */
    }
}

/* ---------- BB instrumentation event ---------- */

static dr_emit_flags_t
event_bb_insn(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
              bool for_trace, bool translating, void *user_data)
{
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    app_pc pc = instr_get_app_pc(instr);
    if (pc != NULL && mnt::is_mnt((ADDRINT)pc))
        return DR_EMIT_DEFAULT;  /* C.2 skip */

    ins_inspect_dr(drcontext, bb, instr);

    /* M3.2 step 5: PC-range sinks. Inserted AFTER ins_inspect_dr so the
     * propagation handlers reach drreg first (avoids slot exhaustion seen
     * pre-ins_inspect). Cheap per-insn check; clean call only fires for
     * matched ranges. */
    if (pc != NULL && libdft_dr_internal::has_pc_range_sink_at(pc)) {
        dr_insert_clean_call(drcontext, bb, instr,
            (void *)libdft_dr_internal::dispatch_pc_range_sink, false, 1,
            OPND_CREATE_INTPTR(pc));
    }
    return DR_EMIT_DEFAULT;
}

/* ---------- Function-entry sinks: module-load resolution + drwrap ---------- */

static void
func_sink_pre(void *wrapcxt, OUT void **user_data)
{
    auto *entry = (const libdft_dr_internal::pending_func_sink *)
                  drwrap_get_func(wrapcxt);
    /* Above is a lookup-by-PC; drwrap returns the original wrap target's
     * func pc. We stored the entry pointer as user_data at wrap time, but
     * drwrap_wrap doesn't carry a user_data through to pre_cb; we instead
     * use drwrap_get_drcontext + walk the registered list. For v0.1 the
     * pending list is short (handful of entries) so a linear scan is fine. */
    (void)entry;
    void *dc = drwrap_get_drcontext(wrapcxt);
    app_pc pc = (app_pc)drwrap_get_func(wrapcxt);
    libdft_dr::func_sink_context_t ctx;
    ctx.drcontext = dc;
    ctx.entry_pc  = pc;
    ctx._internal = wrapcxt;
    for (const auto &e : libdft_dr_internal::func_sinks()) {
        if (e.pc != 0 && e.pc == pc) e.cb(ctx);
        /* For name-resolved entries we set e.pc once we wrap them (see
         * module-load handler) -- after that they hit the pc-match branch. */
    }
    (void)user_data;
}

static void
func_sink_on_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    (void)drcontext; (void)loaded;
    if (info == NULL) return;
    /* For each pending name-based entry whose module filter matches this
     * loaded module, look up the symbol via drsym and drwrap_wrap it.
     * v0.1: drsym lookup is synchronous; for very large stripped binaries
     * this could be slow on first load but typical clients wrap O(10) names. */
    const char *path = info->full_path;
    if (path == NULL) path = "";
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    auto &pending = const_cast<std::vector<libdft_dr_internal::pending_func_sink>&>(
        libdft_dr_internal::func_sinks());
    for (auto &e : pending) {
        if (!e.func_name.empty() && e.pc == 0) {
            if (!e.module_basename.empty() && e.module_basename != base)
                continue;
            size_t modoffs = 0;
            drsym_error_t r = drsym_lookup_symbol(path, e.func_name.c_str(),
                                                  &modoffs, DRSYM_DEMANGLE);
            if (r == DRSYM_SUCCESS && modoffs != 0) {
                app_pc wrap_pc = info->start + modoffs;
                if (drwrap_wrap(wrap_pc, func_sink_pre, NULL)) {
                    e.pc = wrap_pc;  /* mark resolved so pre_cb fires the right entry */
                    dr_fprintf(STDERR,
                        "[libdft_dr] func_sink: wrapped %s!%s @ %p\n",
                        base, e.func_name.c_str(), wrap_pc);
                }
            }
        }
    }
}

void
libdft_core_init(void)
{
    drutil_init();
    /* TODO M1.4 follow-up: enable drutil_expand_rep_string app2app pass.
     * Investigation 2026-05-31 hit a libc-startup SIGSEGV that survives all
     * the canonical fixes from DR's `memtrace_simple` sample (priority
     * ordering, app2app filter via drutil_instr_is_stringop_loop,
     * drmgr_orig_app_instr_for_operands for instr lookup, DR_EMIT_DEFAULT
     * vs DR_EMIT_STORE_TRANSLATIONS). The crash fires on the FIRST expanded
     * BB (ld-linux dynamic resolver) even with ALL of our per-instruction
     * handlers fully disabled -- suggesting an interaction between
     * drutil_expand_rep_string and one of our existing init paths
     * (sdft_hook's drwrap, drreg's 4-slot config, or syscall hooks).
     * Needs DR-list-quality investigation; defer to v0.2 of the libdft-dr
     * release. The MOVS/STOS/LODS router cases STILL fire on non-REP
     * forms, so the handlers earn their keep even without expansion. */
    drmgr_register_bb_instrumentation_event(NULL /*analysis*/, event_bb_insn,
                                            NULL);

    /* M3.2 step 5: function-entry sink resolution. Pre-registered PC entries
     * (register_func_sink_pc) are wrapped immediately; name-based entries
     * (register_func_sink) are resolved at module-load time.
     *
     * drwrap/drsym are also init'd by sdft_hook::init(), but that fails
     * silently when the sdft conf is missing (typical for non-vuzzer
     * clients). Init them explicitly here -- both are reference-counted in
     * DR 10 so a second init is a no-op. Skip the whole module-load
     * registration when no func_sinks are pending (avoids touching the BB
     * pipeline on existing parity gates). */
    if (!libdft_dr_internal::func_sinks().empty()) {
        drsym_init(0);
        drwrap_init();
        drmgr_register_module_load_event(func_sink_on_module_load);
        for (auto &e : const_cast<std::vector<libdft_dr_internal::pending_func_sink>&>(
                           libdft_dr_internal::func_sinks())) {
            if (e.pc != 0 && e.func_name.empty()) {
                if (drwrap_wrap(e.pc, func_sink_pre, NULL))
                    dr_fprintf(STDERR, "[libdft_dr] func_sink: wrapped PC %p\n", e.pc);
            }
        }
    }
}
