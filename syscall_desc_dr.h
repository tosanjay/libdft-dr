/* syscall_desc_dr.h -- syscall descriptor table interface for the DR port.
 *
 * Ported from libdft64/syscall_desc.h. The auxiliary OS struct/type
 * definitions are reproduced verbatim so the descriptor table's sizeof(...)
 * map_args entries resolve identically to the Pin build. The only behavioral
 * change is the callback signature: the Pin THREADID first argument is dropped
 * (no hook ever read it); DR identifies the thread via drcontext upstream.
 */
#ifndef __SYSCALL_DESC_DR_H__
#define __SYSCALL_DESC_DR_H__

#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <asm/ldt.h>
#include <asm/posix_types.h>
#include <sys/stat.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/mqueue.h>
#include <linux/perf_event.h>
#include <linux/utsname.h>

#include <signal.h>

#include "libdft_api_dr.h"
#include "branch_pred.h"
#include "tagmap.h"

#ifndef STDIN
	#define STDIN 0
#endif
#ifndef STDOUT
	#define STDOUT 1
#endif
#ifndef STDERR
	#define STDERR 2
#endif

typedef unsigned long old_sigset_t;

struct old_linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_offset;
	unsigned short	d_namlen;
	char		d_name[1];
};

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

typedef	__kernel_old_uid_t	old_uid_t;
typedef	__kernel_old_gid_t	old_gid_t;

struct getcpu_cache {
	unsigned long blob[128 / sizeof(long)];
};

typedef struct __user_cap_header_struct {
	__u32 version;
	int pid;
} *cap_user_header_t;

typedef struct __user_cap_data_struct {
	__u32 effective;
	__u32 permitted;
	__u32 inheritable;
} *cap_user_data_t;

#define Q_GETFMT	0x800004
#define Q_GETINFO	0x800005
#define Q_GETQUOTA	0x800007
#define Q_SETQUOTA	0x800008
#define XQM_CMD(x)	(('X'<<8)+(x))
#define Q_XGETQUOTA     XQM_CMD(3)
#define Q_XGETQSTAT     XQM_CMD(5)

struct if_dqinfo {
	__u64 dqi_bgrace;
	__u64 dqi_igrace;
	__u32 dqi_flags;
	__u32 dqi_valid;
};

struct if_dqblk {
	__u64 dqb_bhardlimit;
	__u64 dqb_bsoftlimit;
	__u64 dqb_curspace;
	__u64 dqb_ihardlimit;
	__u64 dqb_isoftlimit;
	__u64 dqb_curinodes;
	__u64 dqb_btime;
	__u64 dqb_itime;
	__u32 dqb_valid;
};

typedef struct fs_qfilestat {
	__u64 qfs_ino;
	__u64 qfs_nblks;
	__u32 qfs_nextents;
} fs_qfilestat_t;

struct fs_quota_stat {
	__s8		qs_version;
	__u16		qs_flag;
	__s8		qs_pad;
	fs_qfilestat_t	qs_uquota;
	fs_qfilestat_t	qs_gquota;
	__u32		qs_incoredqs;
	__s32		qs_btimelimit;
	__s32		qs_itimelimit;
	__s32		qs_rtbtimelimit;
	__u16		qs_bwarnlimit;
	__u16		qs_iwarnlimit;
};

struct fs_disk_quota {
	__s8	d_version;
	__s8	d_flags;
	__u16	d_fieldmask;
	__u32	d_id;
	__u64	d_blk_hardlimit;
	__u64	d_blk_softlimit;
	__u64	d_ino_hardlimit;
	__u64	d_ino_softlimit;
	__u64	d_bcount;
	__u64	d_icount;
	__s32	d_itimer;
	__s32	d_btimer;
	__u16	d_iwarns;
	__u16	d_bwarns;
	__s32	d_padding2;
	__u64	d_rtb_hardlimit;
	__u64	d_rtb_softlimit;
	__u64	d_rtbcount;
	__s32	d_rtbtimer;
	__u16	d_rtbwarns;
	__s16	d_padding3;
	char	d_padding4[8];
};

#define SEMCTL	3
#define MSGRCV	12
#define MSGCTL	14
#define SHMCTL	24

#define IPC_FIX	256

struct sched_attr {
	__u32 size;
	__u32 sched_policy;
	__u64 sched_flags;
	__s32 sched_nice;
	__u32 sched_priority;
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
};

struct file_handle {
	unsigned int  handle_bytes;
	int           handle_type;
	unsigned char f_handle[0];
};

typedef __u32 u32;
typedef __u64 git_t;

/* <ustat.h> was dropped from modern glibc; the Pin build used Pin's bundled
 * headers. ustat(2) is obsolete and never invoked by our targets -- this is
 * here only so the descriptor table's sizeof(struct ustat) cleanup width
 * matches the Pin baseline. Layout per glibc's historical bits/ustat.h. */
struct ustat {
	__daddr_t f_tfree;
	__ino_t   f_tinode;
	char      f_fname[6];
	char      f_fpack[6];
};

#define SYS_ACCEPT	5
#define SYS_GETSOCKNAME	6
#define SYS_GETPEERNAME	7
#define SYS_SOCKETPAIR	8
#define SYS_RECV	10
#define SYS_RECVFROM	12
#define SYS_GETSOCKOPT	15
#define SYS_RECVMSG	17
#define SYS_ACCEPT4	18
#define SYS_RECVMMSG	19

/* page size in bytes */
#define PAGE_SZ		4096

/* system call descriptor */
typedef struct {
	size_t nargs;				/* number of arguments */
	size_t save_args;			/* flag; save arguments */
	size_t retval_args;			/* flag; returns value in arguments */
	size_t map_args[SYSCALL_ARG_NUM];	/* arguments map */
	void (* pre)(syscall_ctx_t*);		/* pre-syscall callback */
	void (* post)(syscall_ctx_t*);		/* post-syscall callback */
} syscall_desc_t;

/* syscall API */
int syscall_set_pre(syscall_desc_t*, void (*)(syscall_ctx_t*));
int syscall_clr_pre(syscall_desc_t*);
int syscall_set_post(syscall_desc_t*, void (*)(syscall_ctx_t*));
int syscall_clr_post(syscall_desc_t*);

#endif /* __SYSCALL_DESC_DR_H__ */
