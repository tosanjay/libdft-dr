/*
 * sdft_hook_dr.h -- DR port of libdft64/sdft_hook.h (C.4 Phase 4).
 *
 * Applies static libdft function summaries (C.3) at libc/libstdc++ function
 * entry instead of running per-instruction shadow propagation through their
 * bodies. Where Pin used RTN_AddInstrumentFunction + RTN_InsertCall, the DR
 * port enumerates module symbols (drsym) at module-load time and installs an
 * entry callback per matched function via drwrap.
 *
 * Public API:
 *   int  init(const std::string &conf_path)
 *       drsym_init + drwrap_init, load summaries, register the module-load
 *       symbol-enumeration event. Call once from libdft_setup() AFTER
 *       mnt::init(). Returns 0 on success.
 *   void log_summary(void)   Diagnostic counts.
 *   void shutdown(void)      drwrap_exit + drsym_exit (no-op if not inited).
 */
#ifndef SDFT_HOOK_DR_H
#define SDFT_HOOK_DR_H

#include <string>

namespace sdft_hook {

int  init(const std::string &conf_path);
void log_summary(void);
void shutdown(void);

}  // namespace sdft_hook

#endif  // SDFT_HOOK_DR_H
