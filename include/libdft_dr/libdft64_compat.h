/* libdft_dr/libdft64_compat.h -- best-effort source-compat shim for clients
 * coming from libdft64 (Pin).
 *
 * Drop-in usage: change `#include "libdft_api.h"` (and friends) to
 *   #include <libdft_dr/libdft64_compat.h>
 * and the AngoraFuzzer/VUzzer reference client surface compiles unchanged.
 *
 * Covers the 12 names listed in docs/api-design.md Q-API.3. Not exhaustive;
 * unsupported corners (tag_dir_setb on raw page-table internals, the
 * Pin-only REG_INDX/THREADID macros, the ins_desc/XED scheduling table)
 * are not shimmed -- those were always implementation-private in libdft64
 * even though they leaked through the headers.
 *
 * The shim is HEADER-ONLY: every entry is an inline wrapper around the
 * libdft_dr:: namespaced API. Zero runtime cost.
 */
#ifndef LIBDFT_DR_LIBDFT64_COMPAT_H_
#define LIBDFT_DR_LIBDFT64_COMPAT_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "libdft_dr/tag.h"

/* ---- types ---- */

/* Pin's libdft64 had a `tag_t` typedef; reuse the libdft_dr handle. Clients
 * that compared tag.id directly will need a small port (use raw()), but
 * everything that went through tag_combine/tag_sprint/etc. just works. */
using tag_t = libdft_dr::tag_t;

/* libdft64 used a tag_traits trait to expose the empty value. */
template <typename T>
struct tag_traits {};

template <>
struct tag_traits<libdft_dr::tag_t> {
    typedef libdft_dr::tag_t type;
    static inline libdft_dr::tag_t cleared_val() { return libdft_dr::tag_t{}; }
};

/* ---- tag ops ---- */

inline libdft_dr::tag_t tag_combine(libdft_dr::tag_t &lhs, libdft_dr::tag_t &rhs) {
    return libdft_dr::combine(lhs, rhs);
}

inline bool tag_count(const libdft_dr::tag_t &t) {
    return !t.empty();
}

inline std::string tag_sprint(const libdft_dr::tag_t &t) {
    return libdft_dr::to_string(t);
}

/* ---- file-byte tagmap shorthand ---- */

inline void tagmap_setb_with_tag(std::size_t addr, const libdft_dr::tag_t &t) {
    libdft_dr::set_mem_tag(addr, t);
}

inline void file_tagmap_setb(std::size_t addr, std::uint32_t offset) {
    libdft_dr::set_mem_tag(addr, libdft_dr::make_tag(offset));
}

inline void file_tagmap_clrb(std::size_t addr) {
    libdft_dr::clear_mem(addr, 1);
}

inline void file_tagmap_clrn(std::size_t addr, std::size_t n) {
    libdft_dr::clear_mem(addr, n);
}

inline libdft_dr::tag_t file_tagmap_getb(std::size_t addr) {
    return libdft_dr::get_mem_tag(addr);
}

inline bool file_tag_testb(std::size_t addr) {
    return !libdft_dr::get_mem_tag(addr).empty();
}

/* ---- register-shadow shorthand ---- */

inline libdft_dr::tag_t R64TAG(reg_id_t r) { return libdft_dr::get_reg_tag(r); }
inline libdft_dr::tag_t R32TAG(reg_id_t r) { return libdft_dr::get_reg_tag(r); }
inline libdft_dr::tag_t R16TAG(reg_id_t r) { return libdft_dr::get_reg_tag(r); }
inline libdft_dr::tag_t R8TAG(reg_id_t r)  { return libdft_dr::get_reg_tag(r); }

#endif  /* LIBDFT_DR_LIBDFT64_COMPAT_H_ */
