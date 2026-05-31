/* tagmap.cpp -- shadow memory + interned-label set table (Phase 5.2, D32).
 *
 * The per-byte shadow cell is a 4-byte label (dft_label.id). This file owns the
 * id <-> set mapping: g_sets[id] is the EWAH offset set, g_intern dedups sets so
 * equal sets share an id, and g_combine memoizes label-pair unions. id 0 is the
 * empty set. EWAH work happens only here (intern on a fresh singleton, union on
 * a combine miss, serialization at a sink) -- never on the MOV/store hot path.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <ewah.h>

#include "tagmap.h"
#include "branch_pred.h"

typedef EWAHBoolArray<uint32_t> ewah_t;

/* For File taint: the shadow page table of labels. */
tag_dir_t tag_dir;

const dft_label tag_traits<dft_label>::cleared_val = { 0 };

/* ---------- interned-label set table ---------- */

static std::vector<ewah_t> g_sets;                       /* id -> offset set */
static std::unordered_map<std::string, uint32_t> g_intern; /* sprint(set) -> id */
static std::unordered_map<uint64_t, uint32_t> g_combine;   /* (a<<32|b) -> id */

/* canonical serialization (also the cmp.out/lea.out wire form). */
static std::string
ewah_sprint(const ewah_t &s)
{
    if (s.numberOfOnes()) {
        std::stringstream ss;
        ss << s;
        return ss.str();
    }
    return "{}";
}

static uint32_t
intern_set(const ewah_t &s)
{
    std::string k = ewah_sprint(s);
    auto it = g_intern.find(k);
    if (it != g_intern.end())
        return it->second;
    uint32_t id = (uint32_t)g_sets.size();
    g_sets.push_back(s);
    g_intern.emplace(std::move(k), id);
    return id;
}

/* ---------- dft_label members ---------- */

void
dft_label::set(uint32_t offset)
{
    ewah_t s;
    s.set(offset);
    id = intern_set(s);
}

uint32_t
dft_label::numberOfOnes() const
{
    if (id == 0 || id >= g_sets.size())
        return 0;
    return (uint32_t)g_sets[id].numberOfOnes();
}

/* ---------- tag operations ---------- */

tag_t
tag_combine(tag_t &lhs, tag_t &rhs)
{
    if (lhs.id == rhs.id) return lhs;
    if (lhs.id == 0)      return rhs;
    if (rhs.id == 0)      return lhs;

    uint64_t key = ((uint64_t)lhs.id << 32) | (uint64_t)rhs.id;
    auto it = g_combine.find(key);
    if (it != g_combine.end())
        return tag_t{ it->second };

    ewah_t r;
    g_sets[lhs.id].logicalor(g_sets[rhs.id], r);
    uint32_t id = intern_set(r);
    g_combine[key] = id;
    /* union is commutative -- memoize the mirror too. */
    g_combine[((uint64_t)rhs.id << 32) | (uint64_t)lhs.id] = id;
    return tag_t{ id };
}

std::string
tag_sprint(tag_t const &tag)
{
    if (tag.id == 0 || tag.id >= g_sets.size())
        return "{}";
    return ewah_sprint(g_sets[tag.id]);
}

bool
tag_count(tag_t const &tag)
{
    return tag.id != 0;
}

bool
tag_walk(tag_t const &tag, bool (*visit)(uint32_t, void *), void *user)
{
    if (tag.id == 0 || tag.id >= g_sets.size())
        return true;
    /* EWAH iteration: yields set offsets in ascending order. */
    const ewah_t &s = g_sets[tag.id];
    for (ewah_t::const_iterator it = s.begin(); it != s.end(); ++it) {
        if (!visit((uint32_t)*it, user))
            return false;
    }
    return true;
}

/* ---------- tagmap API ---------- */

int
tagmap_alloc(void)
{
    /* id 0 must be the empty set so cleared_val{0} == empty. */
    g_sets.clear();
    g_intern.clear();
    g_combine.clear();
    ewah_t empty;
    g_sets.push_back(empty);
    g_intern[ewah_sprint(empty)] = 0;
    return 0;
}

void
tagmap_free(void)
{
}

/* Set taint at addr */
void PIN_FAST_ANALYSIS_CALL
tagmap_setb_with_tag(size_t addr, tag_t const &tag)
{
    tag_dir_setb(tag_dir, addr, tag);
}

/* Clear taint at addr */
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrb(ADDRINT addr)
{
    tagmap_setb_with_tag(addr, tag_traits<tag_t>::cleared_val);
}

/* Clear n taint bytes starting from addr */
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrn(ADDRINT addr, UINT32 n)
{
    for (ADDRINT i = addr; i < addr + n; i++)
        file_tagmap_clrb(i);
}

/* Get taint at addr */
tag_t
file_tagmap_getb(ADDRINT addr)
{
    return tag_dir_getb(tag_dir, addr);
}

bool
file_tag_testb(ADDRINT addr)
{
    if (addr > 0x7fffffffffff)
        return 0;
    return 1;
}
