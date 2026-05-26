/* tagmap.h -- shadow memory for the DR taint engine (C.4 Phase 2).
 *
 * Ported from libdft64/tagmap.h. The data structure (3-level page table of
 * EWAHBoolArray tags) and the public API are UNCHANGED so that:
 *   - source-painting produces byte-identical tags to the Pin baseline
 *     (load-bearing for the later cmp.out/lea.out parity gates), and
 *   - the Phase 5 opcode handlers can target the same tag_dir_setb/getb API.
 *
 * Only the Pin dependency is swapped: pin.H -> dr_compat.h (type bridge) and
 * Pin's LOG() -> the no-op shim. We use the system EWAHBoolArray header
 * (<ewah.h>, EWAHBoolArray 0.4.0) deliberately rather than vendoring a fresh
 * copy: the Pin tree links the same system header, so the tag bit layout is
 * guaranteed identical across both arms.
 */
#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include <utility>
#include <ewah.h>
#include <map>
#include <new>
#include <algorithm>
#include <sstream>
#include <string>

#include "dr_compat.h"
#include "libdft_log.h"

typedef EWAHBoolArray<uint32_t> libdft_tag_ewah;

#define FLAG_TYPE uint8_t

typedef libdft_tag_ewah tag_t;

#define VALUE_ID 0

/*
 * the bitmap size in bytes
 */
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

#define TEST_MASK(src,mask) ((src&(mask)) == (mask))
#define SET_MASK(src,mask) (src|mask)
#define CLR_MASK(src,mask) (src&(~(mask)))

typedef struct {
	tag_t tag [PAGE_SIZE];
} tag_page_t;
typedef struct {
	tag_page_t* page[PAGETABLE_SZ];
} tag_table_t;
typedef struct {
	tag_table_t* table[TOP_DIR_SZ];
} tag_dir_t;

template<typename T> struct tag_traits {};
template<typename T> T tag_combine(T & lhs, T & rhs);
template<typename T> std::string tag_sprint(T const & tag);
template<typename T> bool tag_count(T const & tag);

template<>
struct tag_traits<EWAHBoolArray<uint32_t>>
{
        typedef EWAHBoolArray<uint32_t> type;
        typedef uint8_t inner_type;
        static const bool is_container = true;
        static const EWAHBoolArray<uint32_t> cleared_val;
        static const EWAHBoolArray<uint32_t> set_val;
};
template<>
EWAHBoolArray<uint32_t> tag_combine(EWAHBoolArray<uint32_t> & lhs, EWAHBoolArray<uint32_t> & rhs);
template<>
std::string tag_sprint(EWAHBoolArray<uint32_t> const & tag);
template<>
bool tag_count(EWAHBoolArray<uint32_t> const & tag);

extern void libdft_die();

/* tagmap API */
int tagmap_alloc(void);
void tagmap_free(void);

/* File Taint */
inline void tag_dir_setb(tag_dir_t & dir, ADDRINT addr, tag_t const & tag)
{
    if(addr > 0x7fffffffffff){
	return;
    }
    if(dir.table[VIRT2PAGETABLE(addr)] == NULL)
    {
        tag_table_t * new_table = new (std::nothrow) tag_table_t();
        if (new_table == NULL)
        {
            LOG("Failed to allocate tag table!\n");
            libdft_die();
        }
        dir.table[VIRT2PAGETABLE(addr)] = new_table;
    }

    tag_table_t * table = dir.table[VIRT2PAGETABLE(addr)];
    if ((*table).page[VIRT2PAGE(addr)] == NULL)
    {
        tag_page_t * new_page = new (std::nothrow) tag_page_t();
        if (new_page == NULL)
        {
            LOG("Failed to allocate tag page!\n");
            libdft_die();
        }
        std::fill(new_page->tag, new_page->tag + PAGE_SIZE, tag_traits<tag_t>::cleared_val);
        (*table).page[VIRT2PAGE(addr)] = new_page;
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
