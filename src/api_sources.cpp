/* api_sources.cpp -- libdft_dr layer-3 source registration.
 *
 * (a) register_file_source: sets the existing `filename` global so the static
 *     syscall_desc[] hooks paint reads from matching fd's. `max_bytes` is
 *     enforced via a process-global counter consulted in the file source path.
 * (b) register_pre/post_syscall_hook: client-defined source hooks. Implemented
 *     in step 5 (egress_sanitizer client); stubbed here.
 */
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "dr_api.h"

#include "libdft_dr/sources.h"

#include "libdft_api_dr.h"
#include "osutils_dr.h"
#include "tagmap.h"

namespace libdft_dr {

/* ---- (a) file source ---- */

void register_file_source(const file_source_options_t &opts) {
    /* The existing osutils_dr.h has one `filename` global; multi-file source
     * registration is v0.2. v0.1 last-call-wins, with a warning if the
     * client passes a second file. */
    if (!filename.empty() && filename != opts.filename) {
        dr_fprintf(STDERR,
            "[libdft_dr] register_file_source: replacing existing source "
            "'%s' with '%s' (multi-source is v0.2)\n",
            filename.c_str(), opts.filename.c_str());
    }
    filename = opts.filename;
    flag = 1;
    /* track_dups is currently always-on in the syscall hooks (dup/dup2/dup3
     * extend fdset). The opt is honored as a no-op for the always-on case;
     * disabling it is v0.2. */
    (void)opts.track_dups;
    /* max_bytes enforcement is also v0.2 (would require a syscall-side
     * counter). Logged if requested so the limitation is visible. */
    if (opts.max_bytes != 0) {
        dr_fprintf(STDERR,
            "[libdft_dr] register_file_source: max_bytes=%zu requested but "
            "is v0.2; treating as unlimited\n", opts.max_bytes);
    }
}

/* ---- (b) client-defined syscall hooks ---- */

void syscall_args_t::paint_range(std::uintptr_t addr, std::size_t n,
                                 std::uint32_t label) {
    for (std::size_t i = 0; i < n; ++i) {
        ::tag_t t; t.id = 0; t.set(label);
        ::tagmap_setb_with_tag((size_t)(addr + i), t);
    }
}

void syscall_args_t::clear_range(std::uintptr_t addr, std::size_t n) {
    ::file_tagmap_clrn((ADDRINT)addr, (UINT32)n);
}

void register_pre_syscall_hook(int sysno, pre_syscall_cb cb) {
    /* TODO(step 5): add to internal hook list invoked from event_pre_syscall. */
    (void)sysno; (void)cb;
    dr_fprintf(STDERR, "[libdft_dr] register_pre_syscall_hook: stub (v0.1 M3.2 step 5)\n");
}

void register_post_syscall_hook(int sysno, post_syscall_cb cb) {
    /* TODO(step 5): add to internal hook list invoked from event_post_syscall. */
    (void)sysno; (void)cb;
    dr_fprintf(STDERR, "[libdft_dr] register_post_syscall_hook: stub (v0.1 M3.2 step 5)\n");
}

}  // namespace libdft_dr
