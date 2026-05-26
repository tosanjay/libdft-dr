/*
 * libdft_core_dr.h -- DR port of libdft64/libdft_core (C.4 Phase 5).
 *
 * Opcode-level taint propagation. Mirrors the Pin engine's trace_inspect +
 * ins_inspect: a drmgr BB-instrumentation event walks each application
 * instruction, applies the C.2 static MNT skip (mnt::is_mnt), and routes the
 * instruction by opcode to a propagation handler.
 *
 * Build order (see arch-doc D23 + task #50):
 *   5.0 backbone: BB event + is_mnt skip + opcode router skeleton (this file).
 *   5.1 handlers as clean calls (correctness-first; gate G5 cmp.out parity).
 *   5.2 promote hot families (MOV/ADD/...) to inline drx/drreg for speed.
 *
 * We switch on DR's own OP_* opcodes (instr_get_opcode) rather than building a
 * XED->DR translation table.
 */
#ifndef LIBDFT_CORE_DR_H
#define LIBDFT_CORE_DR_H

#include "dr_api.h"

/* Register the BB-instrumentation event. Call once from libdft_setup() AFTER
 * mnt::init() (the router consults mnt::is_mnt). */
void libdft_core_init(void);

/* Per-application-instruction routing (opcode switch). Called from the BB
 * insertion event for every non-MNT app instruction. */
void ins_inspect_dr(void *drcontext, instrlist_t *bb, instr_t *instr);

#endif /* LIBDFT_CORE_DR_H */
