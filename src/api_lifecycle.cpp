/* api_lifecycle.cpp -- libdft_dr::init / shutdown.
 *
 * Thin wrapper over libdft_setup()/libdft_die() in libdft_api_dr.cpp. The
 * internal setup already registers drmgr/drreg, the per-thread TLS slot, the
 * syscall events, the optional MNT/sdft subsystems, and the opcode router.
 * v0.1 reuses all of that verbatim; init_options_t maps to the existing env-
 * var knobs.
 */
#include <cstdlib>
#include <cstring>
#include <string>

#include "dr_api.h"

#include "libdft_dr/lifecycle.h"

#include "libdft_api_dr.h"   /* libdft_setup, libdft_die */

namespace libdft_dr {

static bool g_initialized = false;

bool init(const init_options_t &opts) {
    if (g_initialized) {
        dr_fprintf(STDERR, "[libdft_dr] init() called twice -- ignoring\n");
        return true;
    }

    /* single_threaded is currently advisory: the engine does not lock the
     * interned-tag table or reg file. Multi-thread is v0.2. Log if a client
     * asks for multi-thread so the limitation is visible. */
    if (!opts.single_threaded) {
        dr_fprintf(STDERR, "[libdft_dr] init: multi-thread requested but "
                           "v0.1 is single-thread only; proceeding\n");
    }

    /* opaque_modules: forward to the existing MNT subsystem by setting its
     * env-var knob iff the client passed something. If the env var is
     * already set by the user, we don't override. Empty list = leave MNT
     * at its default (off unless VUZZER_MNT_POLICY is already set). */
    if (!opts.opaque_modules.empty()) {
        const char *existing = std::getenv("VUZZER_MNT_POLICY");
        if (existing == nullptr || std::strlen(existing) == 0) {
            std::string joined = "on:";
            for (size_t i = 0; i < opts.opaque_modules.size(); ++i) {
                if (i) joined += ",";
                joined += opts.opaque_modules[i];
            }
            setenv("VUZZER_MNT_POLICY", joined.c_str(), 0);
        }
    }

    /* reg_file_size is ignored in v0.1 (TAGS_PER_GPR + GRP_NUM are compile-
     * time constants in libdft_api_dr.h). Log if the client requests a
     * different size so we can revisit in v0.2. */
    if (opts.reg_file_size != 0) {
        dr_fprintf(STDERR, "[libdft_dr] init: reg_file_size=%zu requested "
                           "but is compile-time in v0.1; ignored\n",
                   opts.reg_file_size);
    }

    /* Internal-global plumbing: the syscall source path reads mmap_type, the
     * CMPS (m2m) propagator reads limit_offset. Must be set before
     * libdft_setup() so the first read syscall sees the right values. */
    mmap_type    = (opts.mmap_paint_method != 0);
    limit_offset = opts.max_offset_per_byte;

    libdft_setup();
    g_initialized = true;
    return true;
}

void shutdown() {
    /* libdft_setup() registers dr_register_exit_event(event_exit), which
     * calls finish() + tears down drmgr/drreg. Calling libdft_die() here
     * would force-kill the process; instead we mark the flag and let the
     * DR exit event do the work. Idempotent. */
    g_initialized = false;
}

}  // namespace libdft_dr
