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
#include <string>
#include <vector>

#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"

#include "dr_compat.h"
#include "libdft_api_dr.h"
#include "tagmap.h"
#include "mnt_consumer_dr.h"

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

/* print_log: filter fields [3..18], then write all 21 fields space-separated
 * (trailing space after each field, like Pin) + '\n'. */
static void
emit_cmp(std::vector<std::string> &o)
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

/* print_lea_log: 10 fields, filter [2..9], same trailing-space + '\n' layout.
 * Field [0]=width, [1]="baseidx", [2..9]=index-byte tags. (libdft writes the
 * ins address to [2] but immediately clobbers it with the i=0 index tag, so it
 * never appears -- we omit it, matching the on-disk format read_lea expects.) */
static void
emit_lea(std::vector<std::string> &o)
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
    for (uint i = 0; i < size; i++) {
        tag_t it = tc->vcpu.gpr_file[idx_row][idx_start + i];
        if (tag_count(it))
            fl = 1;
        o[i + 2] = tag_sprint(it);
    }
    if (fl)
        emit_lea(o);

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
        emit_cmp(o);
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
        emit_cmp(o);
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
        emit_cmp(o);
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
        emit_cmp(o);
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
        emit_cmp(o);
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
        emit_cmp(o);
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
        /* deferred (predicated/conditional -> false-positive risk, or REP/
         * sdft-covered): CMOV*, CMPXCHG, XADD, string MOVS/STOS/LODS/SCAS.
         * No-op in libdft too: shift/rotate family. */
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
    return DR_EMIT_DEFAULT;
}

void
libdft_core_init(void)
{
    drutil_init();
    drmgr_register_bb_instrumentation_event(NULL /*analysis*/, event_bb_insn,
                                            NULL);
}
