/* tagmap.cpp -- shadow memory for the DR taint engine (C.4 Phase 2).
 * Ported from libdft64/tagmap.cpp. Pin's PIN_FAST_ANALYSIS_CALL expands to
 * nothing via dr_compat.h; the EWAH tag_combine/sprint/count specializations
 * and the global tag_dir are otherwise verbatim.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tagmap.h"
#include "branch_pred.h"

/* For File taint */
tag_dir_t tag_dir;
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::cleared_val = EWAHBoolArray<uint32_t>{};
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::set_val = EWAHBoolArray<uint32_t>{};

template<>
EWAHBoolArray<uint32_t> tag_combine(EWAHBoolArray<uint32_t> & lhs, EWAHBoolArray<uint32_t> & rhs) {
	EWAHBoolArray<uint32_t> result;
	lhs.logicalor(rhs, result);
	return result;
}

template<>
std::string tag_sprint(EWAHBoolArray<uint32_t> const & tag) {
    std::stringstream ss;
    if(tag.numberOfOnes())
    	ss << tag;
    else
	return "{}";
    return ss.str();
}

template<>
bool tag_count(EWAHBoolArray<uint32_t> const & tag) {
	if(tag.numberOfOnes()){
		return 1;
	}else{
		return 0;
	}
}

int
tagmap_alloc(void)
{
	return 0;
}

void
tagmap_free(void)
{
}

/* Set taint at addr */
void PIN_FAST_ANALYSIS_CALL
tagmap_setb_with_tag(size_t addr, tag_t const & tag)
{
    tag_dir_setb(tag_dir, addr, tag);
}

/* Clear taint at addr */
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrb(ADDRINT addr){
	tagmap_setb_with_tag(addr, tag_traits<tag_t>::cleared_val);
}

/* Clear n taint bytes starting from addr */
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrn(ADDRINT addr, UINT32 n){
	ADDRINT i;
	for(i=addr;i<addr+n;i++){
		file_tagmap_clrb(i);
	}
}

/* Get taint at addr */
tag_t file_tagmap_getb(ADDRINT addr){
	return tag_dir_getb(tag_dir, addr);
}

bool file_tag_testb(ADDRINT addr){
        if (addr > 0x7fffffffffff)
                return 0;
        return 1;
}
