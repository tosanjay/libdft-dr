/* libdft_dr/sources.h -- Layer 3 source-painting extension points.
 *
 * Two patterns: (a) built-in file-source for "paint these file bytes by
 * offset", and (b) raw syscall hooks for client-defined sources.
 * See docs/api-design.md §5.1.
 */
#ifndef LIBDFT_DR_SOURCES_H_
#define LIBDFT_DR_SOURCES_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "dr_api.h"

namespace libdft_dr {

/* ---- (a) Built-in file source ---- */

struct file_source_options_t {
    /* Substring match on the resolved path passed to open/openat. Empty =
     * treat every input read as tainted (matches the libdft64 default when
     * -filename was empty). */
    std::string filename;

    /* If true, also paint reads on fd's dup()'d from a matching fd. */
    bool track_dups = true;

    /* Cap total bytes painted across the entire run. 0 = unlimited. */
    std::size_t max_bytes = 0;
};

/* Register the built-in file source. May be called more than once to paint
 * multiple files simultaneously. */
void register_file_source(const file_source_options_t &opts);

/* ---- (b) Client-defined syscall hooks ---- */

struct syscall_args_t {
    int sysno;
    std::uintptr_t arg[6];

    /* Helper: paint `n` bytes at `addr` with singleton tag make_tag(label). */
    void paint_range(std::uintptr_t addr, std::size_t n, std::uint32_t label);

    /* Helper: clear taint on `n` bytes at `addr`. */
    void clear_range(std::uintptr_t addr, std::size_t n);
};

using pre_syscall_cb  = std::function<void(syscall_args_t &args)>;
using post_syscall_cb = std::function<void(syscall_args_t &args, long result)>;

/* Hooks are additive: multiple hooks on the same sysno are all invoked,
 * registration order. */
void register_pre_syscall_hook(int sysno, pre_syscall_cb cb);
void register_post_syscall_hook(int sysno, post_syscall_cb cb);

}  // namespace libdft_dr

#endif  /* LIBDFT_DR_SOURCES_H_ */
