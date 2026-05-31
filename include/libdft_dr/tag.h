/* libdft_dr/tag.h -- Layer 2 of the public API.
 *
 * The tag model: opaque 32-bit handle, plus shadow I/O for memory and the
 * current thread's VCPU registers. See docs/api-design.md §4.
 *
 * Implementation: `tag_t` wraps an interned-set id (see src/tagmap.h). Two
 * tag_t's compare equal iff they represent the same label set. id 0 = empty.
 */
#ifndef LIBDFT_DR_TAG_H_
#define LIBDFT_DR_TAG_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <type_traits>

#include "dr_api.h"  /* for reg_id_t */

namespace libdft_dr {

class tag_t {
public:
    constexpr tag_t() noexcept : id_(0) {}
    constexpr bool empty() const noexcept { return id_ == 0; }
    constexpr bool operator==(tag_t o) const noexcept { return id_ == o.id_; }
    constexpr bool operator!=(tag_t o) const noexcept { return id_ != o.id_; }

    /* Escape hatch for the internal implementation; clients should not depend
     * on this representation (it will change in v0.2 if custom tag types
     * land). */
    constexpr std::uint32_t raw() const noexcept { return id_; }
    static constexpr tag_t from_raw(std::uint32_t r) noexcept { return tag_t{r}; }

private:
    constexpr explicit tag_t(std::uint32_t id) noexcept : id_(id) {}
    std::uint32_t id_;
};
static_assert(sizeof(tag_t) == 4, "tag_t must be 4 bytes");
static_assert(std::is_trivially_copyable<tag_t>::value, "tag_t must be trivially copyable");

/* Construct a singleton tag from a single label id (e.g. a file byte offset).
 * Caller-defined label semantics; the library treats `label` as opaque. */
tag_t make_tag(std::uint32_t label);

/* Union of two tags. O(1) amortized via the memoized intern table. */
tag_t combine(tag_t a, tag_t b);

/* Enumerate the labels in `t`. The visitor may return false to stop early.
 * Order is unspecified but deterministic. */
using label_visitor = std::function<bool(std::uint32_t label)>;
void enumerate(tag_t t, const label_visitor &fn);

/* Serialize as "{1,4,7}" / "{}". */
std::string to_string(tag_t t);

/* ---- Memory shadow I/O ---- */

tag_t get_mem_tag(std::uintptr_t addr);
void  set_mem_tag(std::uintptr_t addr, tag_t t);
void  clear_mem(std::uintptr_t addr, std::size_t n);

/* Union of the tags of n consecutive bytes starting at addr. */
tag_t get_mem_tag_range(std::uintptr_t addr, std::size_t n);

/* ---- Register shadow I/O ----
 *
 * Must be called from within an instrumentation callback (e.g. a sink). Reads
 * the current thread's VCPU shadow register file.
 *
 * `reg` is a DR register id (DR_REG_RAX etc.); the library maps it to the
 * internal DFT_REG_* index. */
tag_t get_reg_tag(reg_id_t reg);                              /* first byte */
tag_t get_reg_tag_byte(reg_id_t reg, std::size_t byte_idx);
void  set_reg_tag(reg_id_t reg, tag_t t);                     /* all bytes */
void  set_reg_tag_byte(reg_id_t reg, std::size_t byte_idx, tag_t t);
tag_t get_reg_tag_range(reg_id_t reg);                        /* union all */

}  // namespace libdft_dr

#endif  /* LIBDFT_DR_TAG_H_ */
