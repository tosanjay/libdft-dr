/*
 * libdft_core_dr.cpp -- DR port of libdft64/libdft_core (C.4 Phase 5).
 *
 * Phase 5.0: BB-instrumentation backbone + C.2 MNT skip + opcode router.
 * Phase 5.1 (in progress): propagation handlers as clean calls, correctness
 * first; hot families promoted to inline drx/drreg in 5.2.
 *
 * Register-shadow model (ported from libdft64): the per-thread VCPU shadow is
 * gpr_file[reg_index][byte], 16 byte-tags per register. A register operand maps
 * to (reg_index, start_byte, n_bytes): low/word/dword/qword start at byte 0;
 * the legacy high-byte regs (AH/BH/CH/DH) start at byte 1. We collapse Pin's
 * exhaustive REG_INDX switch using DR's reg_to_pointer_sized().
 */
#include "libdft_core_dr.h"

#include "drmgr.h"

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

/* ---------- clean-call propagation handlers (5.1) ---------- */

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

/* ---------- opcode router ---------- */

void
ins_inspect_dr(void *drcontext, instrlist_t *bb, instr_t *instr)
{
    int op = instr_get_opcode(instr);
    switch (op) {
        case OP_mov_ld: {
            /* dst = reg; src = reg or mem. Reg->reg copy handled here; the
             * mem->reg (m2r) load lands in the next increment (drutil mem
             * address + tagmap read). */
            if (instr_num_dsts(instr) < 1 || instr_num_srcs(instr) < 1)
                break;
            opnd_t d = instr_get_dst(instr, 0);
            opnd_t s = instr_get_src(instr, 0);
            if (opnd_is_reg(d) && opnd_is_reg(s))
                insert_r2r_xfer(drcontext, bb, instr,
                                opnd_get_reg(d), opnd_get_reg(s));
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
        /* 5.1 next: OP_mov_ld (mem src/m2r), OP_mov_st (r2m), OP_movzx/movsx,
         * OP_add/sub/and/or/xor/adc/sbb, OP_push/pop, OP_lea, OP_cmp (cmp.out). */
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
    drmgr_register_bb_instrumentation_event(NULL /*analysis*/, event_bb_insn,
                                            NULL);
}
