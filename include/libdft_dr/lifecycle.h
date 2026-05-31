/* libdft_dr/lifecycle.h -- Layer 1 of the public API.
 *
 * Stand up / tear down the taint engine. See docs/api-design.md §3.
 */
#ifndef LIBDFT_DR_LIFECYCLE_H_
#define LIBDFT_DR_LIFECYCLE_H_

#include <cstddef>
#include <string>
#include <vector>

namespace libdft_dr {

struct init_options_t {
    /* v0.1 supports single-threaded targets only; multi-thread is v0.2. */
    bool single_threaded = true;

    /* Module basenames to treat as opaque (taint flows over them via syscall
     * hooks, not per-insn propagation). Optional perf optimization. Maps to
     * the existing VUZZER_MNT_POLICY/.modskip mechanism. */
    std::vector<std::string> opaque_modules = {};

    /* Override per-thread shadow register count. 0 = library default. */
    std::size_t reg_file_size = 0;

    /* mmap source-painting strategy: 1 (default) paints all bytes in the
     * mapped range with their absolute file offset, matching libdft64's
     * "full" behavior; 0 disables mmap-time painting (read syscalls still
     * paint, but mmap regions are not eagerly tagged). */
    int mmap_paint_method = 1;

    /* Per-byte tag-width cap consumed by the CMPS (m2m) propagator: a byte
     * whose tag contains more than this many offsets is treated as untagged
     * for emission purposes. Matches libdft64's "-maxoff" knob (default 4). */
    int max_offset_per_byte = 4;
};

/* Register drmgr/drreg + all our events. Returns false on hard failure
 * (logged to stderr). Must be called from dr_client_main, before the app
 * starts running. */
bool init(const init_options_t &opts);

/* Idempotent. Called automatically at DR exit if the client doesn't call it. */
void shutdown();

}  // namespace libdft_dr

#endif  /* LIBDFT_DR_LIFECYCLE_H_ */
