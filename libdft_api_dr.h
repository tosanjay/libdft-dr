/* libdft_api_dr.h -- DR port of libdft64's core glue (C.4 Phase 2).
 *
 * Owns the per-thread context (VCPU shadow + syscall context), the libdft
 * lifecycle (setup/die/finish), and the syscall dispatch surface. The VCPU
 * register-file shadow (gpr_file) is carried forward unused in Phase 2 so the
 * struct is ready for the Phase 5 opcode handlers; only syscall_ctx is
 * exercised now.
 *
 * Differences from the Pin libdft_api.h:
 *   - Thread identity is the DR drcontext, not a small THREADID; per-thread
 *     state lives in a drmgr TLS slot rather than a realloc'd array.
 *   - Syscall callbacks take (syscall_ctx_t*) only -- the Pin THREADID arg is
 *     dropped (no hook ever used it).
 *   - Pin/XED-only surface (opnd_t, ins_desc_t, REG*_INDX) is deferred to
 *     Phase 5.
 */
#ifndef __LIBDFT_API_DR_H__
#define __LIBDFT_API_DR_H__

#include <sys/syscall.h>
#include <unistd.h>

#include "dr_api.h"
#include "dr_compat.h"
#include "tagmap.h"

#define SYSCALL_MAX	(__NR_sched_getattr + 1)	/* max syscall number */
#define SYSCALL_ARG_NUM	6				/* syscall arguments */
#define SYSCALL_ARG0	0
#define SYSCALL_ARG1	1
#define SYSCALL_ARG2	2
#define SYSCALL_ARG3	3
#define SYSCALL_ARG4	4
#define SYSCALL_ARG5	5

/* DFT register-file indices (carried forward for the Phase 5 opcode handlers;
 * only the array dimensions GRP_NUM/TAGS_PER_GPR matter to Phase 2). */
#define DFT_REG_RDI     3
#define DFT_REG_RSI     4
#define DFT_REG_RBP     5
#define DFT_REG_RSP     6
#define DFT_REG_RBX     7
#define DFT_REG_RDX     8
#define DFT_REG_RCX     9
#define DFT_REG_RAX     10
#define DFT_REG_R8      11
#define DFT_REG_R9      12
#define DFT_REG_R10     13
#define DFT_REG_R11     14
#define DFT_REG_R12     15
#define DFT_REG_R13     16
#define DFT_REG_R14     17
#define DFT_REG_R15     18
#define GRP_NUM         43		/* general purpose registers */
#define TAGS_PER_GPR    16

/* cmp.out / lea.out outputs (opened empty in Phase 2; written by the Phase 5
 * opcode handlers via dr_fprintf). DR's file API is used rather than
 * std::ofstream: C++ iostream globals are not safe to construct under DR's
 * private loader (they pull in glibc stdio/locale init and crash). */
extern file_t out;
extern file_t out_lea;

extern int limit_offset;
extern bool mmap_type;
extern int flag;			/* set once a taint source is opened */

/* virtual-CPU shadow context */
typedef struct {
	tag_t gpr_file[GRP_NUM + 1][TAGS_PER_GPR];
} vcpu_ctx_t;

/* system call context: up to SYSCALL_ARG_NUM args saved in pre-, ret in post- */
typedef struct {
	int	nr;			/* syscall number */
	ADDRINT	arg[SYSCALL_ARG_NUM];	/* arguments */
	ADDRINT	ret;			/* return value */
	void	*aux;			/* auxiliary data (unused under DR) */
} syscall_ctx_t;

/* per-thread context */
typedef struct {
	vcpu_ctx_t	vcpu;
	syscall_ctx_t	syscall_ctx;
	UINT32		syscall_nr;
	/* M7 prep (v0.2 DFPG): over-approximate register-taint bitmask.
	 * Bit row N set iff gpr_file[N][*] might contain a non-empty tag.
	 * In v0.1 this is recomputed on demand (libdft_compute_gpr_mask);
	 * v0.2's DFPG will add incremental updates from the per-insn handlers
	 * once the access patterns are pinned down by drbbdup integration. */
	UINT32		gpr_mask_cached;	/* v0.1: unused, zero. v0.2: cached. */
} thread_ctx_t;

/* libdft API */
void libdft_setup(void);	/* register drmgr/drreg + all events */
void libdft_die(void);
void finish(void);		/* flush + close output, dump telemetry */

/* Per-thread context for the calling thread (drwrap/clean-call callbacks).
 * Returns NULL before the thread-init event has run. */
thread_ctx_t *libdft_get_thread_ctx(void *drcontext);

/* M7 prep (v0.2 DFPG groundwork): compute the over-approximate GPR taint
 * bitmask from current shadow state. Bit N set iff gpr_file[N][0..7] has
 * any non-empty tag. Cost: 16 * 8 = 128 cell reads; called at most once
 * per BB-entry dispatch (rare relative to per-insn work). The cached
 * thread_ctx_t::gpr_mask_cached field is reserved for the v0.2
 * incremental-update path. */
static inline UINT32
libdft_compute_gpr_mask(const thread_ctx_t *tc)
{
	UINT32 m = 0;
	for (unsigned row = DFT_REG_RDI; row <= DFT_REG_R15; ++row) {
		for (unsigned b = 0; b < 8; ++b) {
			if (tc->vcpu.gpr_file[row][b].id != 0) {
				m |= (1u << row);
				break;
			}
		}
	}
	return m;
}

#endif /* __LIBDFT_API_DR_H__ */
