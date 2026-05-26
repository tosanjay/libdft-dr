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
        /* 5.1 next: OP_cmps (m2m), OP_movzx/movsx, OP_add/sub/and/or/xor,
         * OP_push/pop, OP_lea (lea.out). */
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
