/*
 * sdft_summaries_dr.h -- DR port of libdft64/sdft_summaries.h (C.4 Phase 4).
 *
 * Function-summary table loader (C.3). Parses libc_summaries.conf into an
 * in-memory table the sdft_hook uses to apply one of six shape handlers at
 * function entry instead of per-instruction libdft propagation through libc.
 *
 * Pure std::string/vector/map -- the only change from the Pin header is
 * dropping pin.H. The matched names are MANGLED (the conf carries mangled C++
 * symbols), so the DR symbol enumeration must leave names mangled.
 */
#ifndef SDFT_SUMMARIES_DR_H
#define SDFT_SUMMARIES_DR_H

#include <string>
#include <vector>
#include <map>

namespace sdft {

enum Shape {
    SHAPE_INVALID         = 0,
    SHAPE_SOURCE          = 1,  // buf=<idx>, len=<idx|literal>
    SHAPE_SOURCE_RET_PTR  = 2,  // [len=<idx>]
    SHAPE_PROP_PTR2PTR    = 3,  // dst, src, len
    SHAPE_PROP_PTR2VAL    = 4,  // src=<csv>, [len]
    SHAPE_PROP_SCALAR     = 5,  // args=<csv>
    SHAPE_CLOBBER_ONLY    = 6,
};

enum Policy {
    POLICY_OPTIMISTIC   = 0,    // under-taint default (VUzzer)
    POLICY_CONSERVATIVE = 1,    // over-taint default
};

enum RefKind {
    REF_NONE     = 0,
    REF_ARG      = 1,    // .value = arg index 0..5
    REF_LITERAL  = 2,    // .value = constant
    REF_RET      = 3,    // value field unused
    REF_STRLEN   = 4,    // length-of-string-at-*src
    REF_WCSLEN   = 5,
};

struct Ref {
    int kind;     // RefKind
    int value;    // arg index or literal
    Ref() : kind(REF_NONE), value(0) {}
};

struct Summary {
    Shape shape;
    Ref dst;                  // PROP_PTR2PTR
    std::vector<int> src;     // PROP_PTR2PTR / PROP_PTR2VAL
    Ref len;                  // SOURCE / SOURCE_RET_PTR / PROP_PTR2PTR / PROP_PTR2VAL
    std::vector<int> args;    // PROP_SCALAR / SOURCE
    int buf;                  // SOURCE: arg index of buffer pointer
    Summary() : shape(SHAPE_INVALID), buf(-1) {}
};

struct AliasRule {
    std::string pattern;     // glob (supports trailing '*')
    std::string canonical;
};

bool load(const std::string &conf_path);
const Summary *find(const std::string &rtn_name);
Policy policy(void);
size_t func_count(void);
size_t alias_count(void);
void log_summary(void);

}  // namespace sdft

#endif  // SDFT_SUMMARIES_DR_H
