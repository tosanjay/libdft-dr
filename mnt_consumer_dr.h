/*
 * mnt_consumer_dr.h -- DR port of libdft64/mnt_consumer.h (C.4 Phase 3).
 *
 * Reader for the static MNT (Must-Not-Tainted) analyzer output
 * (fuzzer-code/mnt/ghidra_mnt_step12_proto.py). Loads a per-module .mnt.bin
 * at module-load time and provides a fast is_mnt(pc) check that the Phase 5
 * trace dispatch uses to skip instrumentation at PCs proven by static
 * analysis to never carry input-derived taint (C.2 of the Option-C plan).
 *
 * Logic is identical to the Pin consumer; only the host bindings change:
 *   - Pin IMG load/unload hooks  -> drmgr module load/unload events
 *   - FILE* stdio                -> DR file API (dr_open_file/dr_read_file)
 *   - std::cerr logging          -> dr_fprintf(STDERR, ...)
 *
 * Policy via env: VUZZER_MNT_POLICY = "lean" (default) | "sound" | "v2_perpc"
 *                 | "off". Search order for <imgbase>.mnt.bin:
 *   1. $VUZZER_MNT_DIR/<imgbase>.mnt.bin
 *   2. <dirname-of-image>/<imgbase>.mnt.bin
 *   3. <fuzzer cwd>/bin/_test/<imgbase>.mnt.bin
 * Missing files are not fatal (that image is simply not MNT-skippable).
 */
#ifndef MNT_CONSUMER_DR_H
#define MNT_CONSUMER_DR_H

#include "dr_api.h"
#include "dr_compat.h"

namespace mnt {

/* Initialize the MNT subsystem: read VUZZER_MNT_POLICY and register the
 * module load/unload events. Call once from libdft_setup(). Always safe;
 * if disabled, is_mnt() returns 0 for every PC. Returns 0 on success. */
int init(void);

/* Module-load event: load <imgbase>.mnt.bin and build the per-image MNT set
 * under the selected policy. Registered by init(). */
void on_module_load(void *drcontext, const module_data_t *info, bool loaded);

/* Module-unload event: free per-image state. */
void on_module_unload(void *drcontext, const module_data_t *info);

/* Hot path: is `pc` MNT for whichever image contains it? 1 = skip, 0 = keep. */
int is_mnt(ADDRINT pc);

/* Register a runtime MNT range [low, high) -- used by sdft_hook (Phase 4) to
 * mark summarized libc/stdc++ RTN bodies skippable. Not thread-safe. */
void add_rtn_range(ADDRINT low, ADDRINT high);

/* Diagnostics: print loaded MNT data + lookup stats. */
void log_summary(void);

}  // namespace mnt

#endif  /* MNT_CONSUMER_DR_H */
