/* tagmap.h -- shadow memory for the DR taint engine.
 *
 * Phase 5.2 (interned-label tag representation, arch-doc D32): the per-byte
 * shadow cell is a 4-byte interned label (`dft_label.id`) into a global
 * set table that lives in tagmap.cpp. id 0 == the empty set. The EWAH set
 * machinery is confined to tagmap.cpp; on the hot path (MOV/store/combine of
 * register and memory shadow) a cell is just a 4-byte value, so copies are a
 * single move and combine is a memoized 2-label lookup. The actual offset set
 * is materialized only at the rare cmp.out/lea.out sinks (tag_sprint).
 *
 * The public API (tag_t, tag_combine/sprint/count, .set/.numberOfOnes,
 * tag_traits::cleared_val, tag_dir_setb/getb, file_tagmap_*) is unchanged from
 * the EWAH version so the syscall source-painting and the Phase-5 opcode
 * handlers compile untouched and produce byte-identical sink output.
 *
 * NOTE: the global set table is process-global and lock-free; valid because
 * the taint targets are single-threaded CLI parsers. A multi-threaded SUT
 * would need a lock around intern/combine (see tagmap.cpp).
 */
#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include <cstdint>
#include <string>

#include "dr_compat.h"
#include "libdft_log.h"

#define FLAG_TYPE uint8_t
#define VALUE_ID 0

/* the bitmap geometry (unchanged) */
#define PAGE_SIZE	4096
#define PAGE_BITS	12
#define TOP_DIR_SZ 		0x800000
#define PAGETABLE_SZ		0X1000
#define PAGETABLE_BITS 24

#define OFFSET_MASK	0x00000FFFU
#define PAGETABLE_OFFSET_MASK 0x00FFFFFFU

#define VIRT2PAGETABLE(addr) ((addr) >> PAGETABLE_BITS)
#define VIRT2PAGETABLE_OFFSET(addr) (((addr) & PAGETABLE_OFFSET_MASK)>>PAGE_BITS)
#define VIRT2PAGE(addr) VIRT2PAGETABLE_OFFSET(addr)
#define VIRT2OFFSET(addr) ((addr) & OFFSET_MASK)

/* Interned-label shadow cell. Trivially copyable (4 bytes). id 0 = empty. */
struct dft_label {
	uint32_t id;
	void set(uint32_t offset);        /* intern singleton {offset} into this */
	uint32_t numberOfOnes() const;    /* size of the interned set */
};

typedef dft_label tag_t;

template<typename T> struct tag_traits {};
template<>
struct tag_traits<dft_label> {
	typedef dft_label type;
	static const dft_label cleared_val;
};

/* union of two labels' sets, memoized -> result label */
tag_t tag_combine(tag_t & lhs, tag_t & rhs);
/* materialize the label's offset set as "{a,b,...}" / "{}" (sink-only) */
std::string tag_sprint(tag_t const & tag);
/* nonempty test (id != 0) */
bool tag_count(tag_t const & tag);

/* Walk the labels in `tag` in ascending order. The visitor may return false
 * to stop early. Used by the public libdft_dr::enumerate(). */
#include <cstdint>
bool tag_walk(tag_t const & tag,
              bool (*visit)(uint32_t label, void *user),
              void *user);

extern void libdft_die();

/* three-level page table of labels */
typedef struct {
	tag_t tag [PAGE_SIZE];
} tag_page_t;
typedef struct {
	tag_page_t* page[PAGETABLE_SZ];
} tag_table_t;
typedef struct {
	tag_table_t* table[TOP_DIR_SZ];
} tag_dir_t;

/* tagmap API */
int tagmap_alloc(void);
void tagmap_free(void);

inline void tag_dir_setb(tag_dir_t & dir, ADDRINT addr, tag_t const & tag)
{
    if(addr > 0x7fffffffffff){
	return;
    }
    if(dir.table[VIRT2PAGETABLE(addr)] == NULL)
    {
        tag_table_t * new_table = new (std::nothrow) tag_table_t();
        if (new_table == NULL) {
            LOG("Failed to allocate tag table!\n");
            libdft_die();
        }
        dir.table[VIRT2PAGETABLE(addr)] = new_table;
    }
    tag_table_t * table = dir.table[VIRT2PAGETABLE(addr)];
    if ((*table).page[VIRT2PAGE(addr)] == NULL)
    {
        tag_page_t * new_page = new (std::nothrow) tag_page_t();
        if (new_page == NULL) {
            LOG("Failed to allocate tag page!\n");
            libdft_die();
        }
        (*table).page[VIRT2PAGE(addr)] = new_page;  /* value-init -> id 0 */
    }
    tag_page_t * page = (*table).page[VIRT2PAGE(addr)];
    (*page).tag[VIRT2OFFSET(addr)] = tag;
}

inline tag_t const * tag_dir_getb_as_ptr(tag_dir_t const & dir, ADDRINT addr) {
    if(addr > 0x7fffffffffff){
	return NULL;
    }
    if(dir.table[VIRT2PAGETABLE(addr)]) {
        tag_table_t * table = dir.table[VIRT2PAGETABLE(addr)];
        if ((*table).page[VIRT2PAGE(addr)]) {
            tag_page_t * page = (*table).page[VIRT2PAGE(addr)];
            if (page != NULL)
                return &(*page).tag[VIRT2OFFSET(addr)];
        }
    }
    return &tag_traits<tag_t>::cleared_val;
}

inline tag_t tag_dir_getb(tag_dir_t const & dir, ADDRINT addr) {
    return *tag_dir_getb_as_ptr(dir, addr);
}

void tagmap_setb_with_tag(size_t addr, tag_t const &tag);
void file_tagmap_clrb(ADDRINT);
void file_tagmap_clrn(ADDRINT, UINT32);
tag_t file_tagmap_getb(ADDRINT);
bool file_tag_testb(ADDRINT addr);

#endif /* __TAGMAP_H__ */
