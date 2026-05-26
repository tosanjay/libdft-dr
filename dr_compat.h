/* dr_compat.h -- Pin->DR source-portability bridge (C.4 Phase 2).
 *
 * libdft64 was written against Pin's type vocabulary (ADDRINT, UINT32, ...)
 * and the PIN_FAST_ANALYSIS_CALL calling-convention tag. To port the
 * shadow-memory + syscall layer with minimal edits to the hot bodies, we keep
 * those spellings and map them onto plain C++ / DR equivalents here. DR never
 * defines these names itself, so there is no collision with dr_api.h.
 *
 * This is the "single typedef-bridge header" the c4_dr_port_plan.md Phase 5
 * mapping table anticipates; introduced in Phase 2 so the tagmap/syscall code
 * reads like its Pin origin.
 */
#ifndef __DR_COMPAT_H__
#define __DR_COMPAT_H__

#include <cstdint>
#include <cstddef>

typedef uintptr_t ADDRINT;
typedef uint64_t  UINT64;
typedef uint32_t  UINT32;
typedef uint16_t  UINT16;
typedef uint8_t   UINT8;
typedef int64_t   INT64;
typedef int32_t   INT32;
typedef bool      BOOL;

#ifndef TRUE
#define TRUE  true
#endif
#ifndef FALSE
#define FALSE false
#endif

/* Pin's fast-analysis-call tag has no DR equivalent (DR inlines or clean-calls
 * explicitly). Expand to nothing. */
#define PIN_FAST_ANALYSIS_CALL

#endif /* __DR_COMPAT_H__ */
