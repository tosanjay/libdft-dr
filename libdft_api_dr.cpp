/* libdft_api_dr.cpp -- DR port of libdft64's core glue (C.4 Phase 2).
 *
 * Stands up the taint engine's lifecycle on DR: per-thread context in a drmgr
 * TLS slot, and the syscall enter/exit dispatch that drives the source hooks.
 * NO opcode instrumentation is registered here -- that is Phase 5. The result
 * is a client that paints shadow memory at input-read syscalls exactly as the
 * Pin engine does, while leaving cmp.out/lea.out empty.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"

#include "libdft_api_dr.h"
#include "syscall_desc_dr.h"
#include "tagmap.h"
#include "branch_pred.h"
#include "libdft_log.h"
#include "mnt_consumer_dr.h"

/* cmp.out / lea.out outputs (empty in Phase 2; DR file handles). */
file_t out = INVALID_FILE;
file_t out_lea = INVALID_FILE;

int flag = 0;
int limit_offset;
bool mmap_type;

/* syscall descriptors (defined in syscall_desc_dr.cpp) */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* per-thread context TLS slot */
static int tls_idx = -1;

static inline thread_ctx_t *
cur_thread_ctx(void *drcontext)
{
	return (thread_ctx_t *)drmgr_get_tls_field(drcontext, tls_idx);
}

/*
 * thread start: allocate the per-thread context (VCPU shadow + syscall ctx).
 */
static void
event_thread_init(void *drcontext)
{
	thread_ctx_t *tctx = new thread_ctx_t();
	if (unlikely(tctx == NULL)) {
		dr_fprintf(STDERR, "[libdft-dr] thread_ctx alloc failed\n");
		libdft_die();
	}
	drmgr_set_tls_field(drcontext, tls_idx, tctx);
}

static void
event_thread_exit(void *drcontext)
{
	thread_ctx_t *tctx = cur_thread_ctx(drcontext);
	delete tctx;
	drmgr_set_tls_field(drcontext, tls_idx, NULL);
}

/*
 * syscall filter: pre/post events fire only for syscalls we actually save
 * arguments for (a hook is registered, or the syscall writes its arguments).
 * Mirrors the save_args|retval_args gate in the Pin sysenter/sysexit path.
 */
static bool
event_filter_syscall(void *drcontext, int sysnum)
{
	if (sysnum < 0 || sysnum >= SYSCALL_MAX)
		return false;
	return (syscall_desc[sysnum].save_args | syscall_desc[sysnum].retval_args) != 0;
}

/*
 * syscall enter: save the arguments and invoke the pre-syscall hook (if any).
 */
static bool
event_pre_syscall(void *drcontext, int sysnum)
{
	thread_ctx_t *tctx = cur_thread_ctx(drcontext);

	if (unlikely(sysnum < 0 || sysnum >= SYSCALL_MAX)) {
		tctx->syscall_ctx.nr = -1;
		return true;
	}

	tctx->syscall_ctx.nr = sysnum;

	if (syscall_desc[sysnum].save_args | syscall_desc[sysnum].retval_args) {
		for (size_t i = 0; i < syscall_desc[sysnum].nargs; i++)
			tctx->syscall_ctx.arg[i] =
				(ADDRINT)dr_syscall_get_param(drcontext, (int)i);

		if (unlikely(syscall_desc[sysnum].pre != NULL))
			syscall_desc[sysnum].pre(&tctx->syscall_ctx);
	}
	return true; /* always execute the syscall */
}

/*
 * syscall exit: capture the return value and invoke the post-syscall hook, or
 * apply the default cleanup (clear taint on syscall-written argument buffers).
 */
static void
event_post_syscall(void *drcontext, int sysnum)
{
	thread_ctx_t *tctx = cur_thread_ctx(drcontext);
	int nr = tctx->syscall_ctx.nr;

	if (unlikely(nr < 0 || nr >= SYSCALL_MAX))
		return;

	if (syscall_desc[nr].save_args | syscall_desc[nr].retval_args) {
		tctx->syscall_ctx.ret = (ADDRINT)dr_syscall_get_result(drcontext);

		if (syscall_desc[nr].post != NULL) {
			syscall_desc[nr].post(&tctx->syscall_ctx);
		} else {
			/* default: clear taint on buffers the syscall wrote */
			if ((ssize_t)tctx->syscall_ctx.ret < 0)
				return;
			for (size_t i = 0; i < syscall_desc[nr].nargs; i++)
				if (unlikely(syscall_desc[nr].map_args[i] > 0))
					if (likely((void *)tctx->syscall_ctx.arg[i] != NULL))
						file_tagmap_clrn(tctx->syscall_ctx.arg[i],
								 syscall_desc[nr].map_args[i]);
		}
	}
}

/* G2 parity counters (defined in syscall_desc_dr.cpp) */
extern unsigned long long g_src_events;
extern unsigned long long g_src_bytes;

void
finish(void)
{
	if (out != INVALID_FILE)
		dr_close_file(out);
	if (out_lea != INVALID_FILE)
		dr_close_file(out_lea);
	dr_fprintf(STDERR, "[libdft-dr] taint sources: %llu events, %llu bytes painted\n",
		   g_src_events, g_src_bytes);
	/* C.2 telemetry */
	mnt::log_summary();
}

static void
event_exit(void)
{
	finish();
	drmgr_unregister_tls_field(tls_idx);
	drmgr_unregister_thread_init_event(event_thread_init);
	drmgr_unregister_thread_exit_event(event_thread_exit);
	drmgr_unregister_pre_syscall_event(event_pre_syscall);
	drmgr_unregister_post_syscall_event(event_post_syscall);
	drreg_exit();
	drmgr_exit();
}

void
libdft_setup(void)
{
	drmgr_init();
	drreg_options_t ops = { sizeof(ops), 3 /*max scratch slots*/, false };
	drreg_init(&ops);

	tls_idx = drmgr_register_tls_field();
	if (tls_idx == -1) {
		dr_fprintf(STDERR, "[libdft-dr] failed to reserve TLS field\n");
		libdft_die();
	}

	tagmap_alloc();

	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);

	dr_register_filter_syscall_event(event_filter_syscall);
	drmgr_register_pre_syscall_event(event_pre_syscall);
	drmgr_register_post_syscall_event(event_post_syscall);

	/* C.2 static MNT subsystem (registers its own module load/unload events;
	 * no-op if VUZZER_MNT_POLICY=off). */
	(void)mnt::init();

	dr_register_exit_event(event_exit);
}

void
libdft_die(void)
{
	tagmap_free();
	LOG("died\n");
	dr_exit_process(1);
}
