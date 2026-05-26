/*
 * libdft_core_dr.cpp -- DR port of libdft64/libdft_core (C.4 Phase 5).
 * Phase 5.0 backbone: BB-instrumentation event + C.2 MNT skip + opcode router.
 * Propagation handlers land in 5.1 (clean calls) / 5.2 (inline). See the header.
 */
#include "libdft_core_dr.h"

#include "drmgr.h"

#include "dr_compat.h"
#include "libdft_api_dr.h"
#include "tagmap.h"
#include "mnt_consumer_dr.h"

/*
 * Per-application-instruction opcode router. Empty in 5.0 -- every opcode falls
 * through to "no propagation," which is the correct conservative default under
 * VUzzer's optimistic policy (an un-handled instruction simply does not move
 * taint; correctness is only lost for opcodes we have not yet ported, and those
 * are added family-by-family in 5.1). Switching on DR OP_* directly.
 */
void
ins_inspect_dr(void *drcontext, instrlist_t *bb, instr_t *instr)
{
    int op = instr_get_opcode(instr);
    switch (op) {
        /* 5.1 will add: OP_mov family, OP_add/sub/and/or/xor/adc/sbb,
         * OP_push/pop, OP_lea, OP_cmp (cmp.out), then the long tail. */
        default:
            break;  /* no propagation yet */
    }
    (void)drcontext;
    (void)bb;
}

/*
 * BB insertion event: for each application instruction, apply the C.2 static
 * MNT skip (PCs proven by static analysis never to carry input-derived taint),
 * else route by opcode. This is the first code path that exercises Phase 3's
 * mnt::is_mnt() at runtime.
 */
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
