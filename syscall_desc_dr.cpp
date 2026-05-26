/* syscall_desc_dr.cpp -- syscall descriptor table + source hooks (DR port).
 *
 * Ported from libdft64/syscall_desc.cpp. The 316-entry descriptor table is
 * verbatim. The source hooks (read, open, openat, dup, close, pread64, mmap,
 * munmap)
 * are byte-for-byte the Pin logic with two mechanical changes:
 *   - signature (THREADID, syscall_ctx_t*) -> (syscall_ctx_t*); and
 *   - the Pin pread64/stat shims are dropped -- under DR's private libc the
 *     real glibc pread64/stat are available, so we call them directly.
 *
 * This is the layer that PAINTS taint at input-read sources; opcode-level
 * propagation arrives in Phase 5.
 */
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <sys/stat.h>

#include <asm/fcntl.h>
#include <linux/sysctl.h>
#include <linux/kexec.h>

#include <err.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <linux/mempolicy.h>
#include <termios.h>
#include <stdio.h>
#include <stdint.h>

#include "syscall_desc_dr.h"
#include "osutils_dr.h"
#include "tagmap.h"
#include "libdft_api_dr.h"
#include "libdft_log.h"

/* engine globals (defined in libdft_api_dr.cpp) */
extern int flag;
extern bool mmap_type;
extern int limit_offset;

/* scratch for the mmap magic-byte recheck */
static char buf2[4];

/* G2 parity instrumentation: count source-painting events + bytes so the DR
 * arm can be compared against the Pin engine's pintool.log "Setting taint"
 * tally. Cheap; printed once at exit by finish(). */
unsigned long long g_src_events = 0;
unsigned long long g_src_bytes = 0;

/* callbacks declaration */
static void post_read_hook(syscall_ctx_t*);
static void post_mmap_hook(syscall_ctx_t*);
static void post_munmap_hook(syscall_ctx_t*);
static void post_open_hook(syscall_ctx_t*);
static void post_openat_hook(syscall_ctx_t*);
static void post_dup3_hook(syscall_ctx_t*);
static void post_dup2_hook(syscall_ctx_t*);
static void post_dup_hook(syscall_ctx_t*);
static void post_close_hook(syscall_ctx_t*);
static void post_pread64_hook(syscall_ctx_t*);

/* syscall descriptors */
syscall_desc_t syscall_desc[SYSCALL_MAX] = {
	/* __NR_read = 0 */
	{ 3, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_read_hook},
	/* __NR_write = 1 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_open = 2 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_open_hook},
	/* __NR_close = 3 */
	{ 1, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_close_hook},
	/* __NR_stat = 4 */
	{ 2, 0, 1, {0 ,sizeof(struct stat) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fstat = 5 */
	{ 2, 1, 1, {0 ,sizeof(struct stat) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lstat = 6 */
	{ 2, 0, 1, {0 ,sizeof(struct stat) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_poll = 7 */
	{ 3, 1, 1, {sizeof(struct pollfd) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lseek = 8 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mmap = 9 */
	{ 6, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_mmap_hook},
	/* __NR_mprotect = 10 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_munmap = 11 */
	{ 2, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_munmap_hook},
	/* __NR_brk = 12 */
	{ 1, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigaction = 13 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct sigaction) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigprocmask = 14 */
	{ 4, 0, 1, {0 ,sizeof(sigset_t) ,sizeof(sigset_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigreturn = 15 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ioctl = 16 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_pread64 = 17 */
	{ 4, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_pread64_hook},
	/* __NR_pwrite64 = 18 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_readv = 19 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_writev = 20 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_access = 21 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_pipe = 22 */
	{ 1, 0, 1, {sizeof(int) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_select = 23 */
	{ 5, 0, 1, {0 ,sizeof(fd_set) ,sizeof(fd_set) ,sizeof(fd_set) ,sizeof(struct timeval) ,0}, NULL, NULL},
	/* __NR_sched_yield = 24 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mremap = 25 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_msync = 26 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mincore = 27 */
	{ 3, 1, 1, {0 ,0 ,sizeof(unsigned char) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_madvise = 28 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_shmget = 29 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_shmat = 30 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_shmctl = 31 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct shmid_ds) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_dup = 32 */
	{ 1, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_dup_hook},
	/* __NR_dup2 = 33 */
	{ 2, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_dup2_hook},
	/* __NR_pause = 34 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_nanosleep = 35 */
	{ 2, 0, 1, {sizeof(struct timespec) ,sizeof(struct timespec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getitimer = 36 */
	{ 2, 0, 1, {0 ,sizeof(struct itimerval) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_alarm = 37 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setitimer = 38 */
	{ 3, 0, 1, {0 ,sizeof(struct itimerval) ,sizeof(struct itimerval) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpid = 39 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sendfile = 40 */
	{ 4, 0, 1, {0 ,0 ,sizeof(off_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_socket = 41 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_connect = 42 */
	{ 3, 0, 1, {0 ,sizeof(struct sockaddr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_accept = 43 */
	{ 3, 0, 1, {0 ,sizeof(struct sockaddr) ,sizeof(int) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sendto = 44 */
	{ 6, 0, 1, {0 ,0 ,0 ,0 ,sizeof(struct sockaddr) ,0}, NULL, NULL},
	/* __NR_recvfrom = 45 */
	{ 6, 0, 1, {0 ,0 ,0 ,0 ,sizeof(struct sockaddr) ,sizeof(int)}, NULL, NULL},
	/* __NR_sendmsg = 46 */
	{ 3, 0, 1, {0 ,sizeof(struct msghdr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_recvmsg = 47 */
	{ 3, 0, 1, {0 ,sizeof(struct msghdr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_shutdown = 48 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_bind = 49 */
	{ 3, 0, 1, {0 ,sizeof(struct sockaddr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_listen = 50 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getsockname = 51 */
	{ 3, 0, 1, {0 ,sizeof(struct sockaddr) ,sizeof(int) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpeername = 52 */
	{ 3, 0, 1, {0 ,sizeof(struct sockaddr) ,sizeof(int) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_socketpair = 53 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(int) ,0 ,0}, NULL, NULL},
	/* __NR_setsockopt = 54 */
	{ 5, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getsockopt = 55 */
	{ 5, 0, 1, {0 ,0 ,0 ,0 ,sizeof(int) ,0}, NULL, NULL},
	/* __NR_clone = 56 */
	{ 4, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fork = 57 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_vfork = 58 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_execve = 59 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_exit = 60 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_wait4 = 61 */
	{ 4, 0, 1, {0 ,sizeof(int) ,0 ,sizeof(struct rusage) ,0 ,0}, NULL, NULL},
	/* __NR_kill = 62 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_uname = 63 */
	{ 1, 0, 1, {sizeof(struct utsname) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_semget = 64 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_semop = 65 */
	{ 3, 0, 1, {0 ,sizeof(struct sembuf) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_semctl = 66 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_shmdt = 67 */
	{ 1, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_msgget = 68 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_msgsnd = 69 */
	{ 4, 0, 1, {0 ,sizeof(struct msgbuf) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_msgrcv = 70 */
	{ 5, 0, 1, {0 ,sizeof(struct msgbuf) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_msgctl = 71 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct msqid_ds) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fcntl = 72 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_flock = 73 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fsync = 74 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fdatasync = 75 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_truncate = 76 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ftruncate = 77 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getdents = 78 */
	{ 3, 0, 1, {0 ,sizeof(struct linux_dirent) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getcwd = 79 */
	{ 2, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_chdir = 80 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fchdir = 81 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rename = 82 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mkdir = 83 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rmdir = 84 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_creat = 85 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_link = 86 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_unlink = 87 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_symlink = 88 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_readlink = 89 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_chmod = 90 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fchmod = 91 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_chown = 92 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fchown = 93 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lchown = 94 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_umask = 95 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_gettimeofday = 96 */
	{ 2, 0, 1, {sizeof(struct timeval) ,sizeof(struct timezone) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getrlimit = 97 */
	{ 2, 0, 1, {0 ,sizeof(struct rlimit) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getrusage = 98 */
	{ 2, 0, 1, {0 ,sizeof(struct rusage) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sysinfo = 99 */
	{ 1, 0, 1, {sizeof(struct sysinfo) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_times = 100 */
	{ 1, 0, 1, {sizeof(struct sysinfo) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ptrace = 101 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getuid = 102 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_syslog = 103 */
	{ 3, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getgid = 104 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setuid = 105 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setgid = 106 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_geteuid = 107 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getegid = 108 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setpgid = 109 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getppid = 110 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpgrp = 111 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setsid = 112 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setreuid = 113 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setregid = 114 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getgroups = 115 */
	{ 2, 1, 1, {0 ,sizeof(gid_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setgroups = 116 */
	{ 2, 0, 1, {0 ,sizeof(gid_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setresuid = 117 */
	{ 3, 0, 1, {sizeof(uid_t) ,sizeof(uid_t) ,sizeof(uid_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getresuid = 118 */
	{ 3, 0, 1, {sizeof(uid_t) ,sizeof(uid_t) ,sizeof(uid_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setresgid = 119 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getresgid = 120 */
	{ 3, 0, 1, {sizeof(git_t) ,sizeof(git_t) ,sizeof(git_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpgid = 121 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setfsuid = 122 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setfsgid = 123 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getsid = 124 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_capget = 125 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_capset = 126 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigpending = 127 */
	{ 2, 1, 1, {sizeof(sigset_t) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigtimedwait = 128 */
	{ 4, 0, 1, {0 ,sizeof(siginfo_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigqueueinfo = 129 */
	{ 3, 0, 1, {0 ,0 ,sizeof(siginfo_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_sigsuspend = 130 */
	{ 2, 0, 1, {sizeof(sigset_t) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sigaltstack = 131 */
	{ 2, 0, 1, {0 ,sizeof(stack_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_utime = 132 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mknod = 133 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_uselib = 134 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_personality = 135 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ustat = 136 */
	{ 2, 0, 1, {0 ,sizeof(struct ustat) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_statfs = 137 */
	{ 2, 0, 1, {0 ,sizeof(struct statfs) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fstatfs = 138 */
	{ 2, 0, 1, {0 ,sizeof(struct statfs) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sysfs = 139 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpriority = 140 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setpriority = 141 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_setparam = 142 */
	{ 2, 0, 1, {0 ,sizeof(struct sched_param) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_getparam = 143 */
	{ 2, 0, 1, {0 ,sizeof(struct sched_param) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_setscheduler = 144 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct sched_param) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_getscheduler = 145 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_get_priority_max = 146 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_get_priority_min = 147 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_rr_get_interval = 148 */
	{ 2, 0, 1, {0 ,sizeof(struct timespec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mlock = 149 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_munlock = 150 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mlockall = 151 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_munlockall = 152 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_vhangup = 153 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_modify_ldt = 154 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_pivot_root = 155 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR__sysctl = 156 */
	{ 1, 1, 1, {sizeof(struct __sysctl_args) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_prctl = 157 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_arch_prctl = 158 */
	{ 2, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_adjtimex = 159 */
	{ 1, 0, 1, {sizeof(struct timex) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setrlimit = 160 */
	{ 2, 0, 1, {0 ,sizeof(struct rlimit) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_chroot = 161 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sync = 162 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_acct = 163 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_settimeofday = 164 */
	{ 2, 0, 1, {sizeof(struct timeval) ,sizeof(struct timezone) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mount = 165 */
	{ 5, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_umount2 = 166 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_swapon = 167 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_swapoff = 168 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_reboot = 169 */
	{ 4, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sethostname = 170 */
	{ 2, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setdomainname = 171 */
	{ 2, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_iopl = 172 */
	{ 1, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ioperm = 173 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_create_module = 174 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_init_module = 175 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_delete_module = 176 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_get_kernel_syms = 177 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_query_module = 178 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_quotactl = 179 */
	{ 4, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_nfsservctl = 180 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getpmsg = 181 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_putpmsg = 182 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_afs_syscall = 183 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_tuxcall = 184 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_security = 185 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_gettid = 186 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_readahead = 187 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setxattr = 188 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lsetxattr = 189 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fsetxattr = 190 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getxattr = 191 */
	{ 4, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lgetxattr = 192 */
	{ 4, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fgetxattr = 193 */
	{ 4, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_listxattr = 194 */
	{ 3, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_llistxattr = 195 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_flistxattr = 196 */
	{ 3, 0, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_removexattr = 197 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lremovexattr = 198 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fremovexattr = 199 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_tkill = 200 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_time = 201 */
	{ 1, 0, 1, {sizeof(time_t) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_futex = 202 */
	{ 6, 0, 1, {sizeof(u32) ,0 ,0 ,sizeof(struct timespec) ,sizeof(u32) ,0}, NULL, NULL},
	/* __NR_sched_setaffinity = 203 */
	{ 3, 0, 1, {0 ,0 ,sizeof(unsigned long) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_getaffinity = 204 */
	{ 3, 0, 1, {0 ,0 ,sizeof(unsigned long) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_set_thread_area = 205 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_io_setup = 206 */
	{ 2, 0, 1, {0 ,sizeof(aio_context_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_io_destroy = 207 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_io_getevents = 208 */
	{ 4, 1, 1, {0 ,0 ,0 ,sizeof(struct io_event) ,0 ,0}, NULL, NULL},
	/* __NR_io_submit = 209 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct iocb) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_io_cancel = 210 */
	{ 3, 0, 1, {0 ,sizeof(struct iocb) ,sizeof(struct io_event) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_get_thread_area = 211 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_lookup_dcookie = 212 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_create = 213 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_ctl_old = 214 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_wait_old = 215 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_remap_file_pages = 216 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getdents64 = 217 */
	{ 3, 1, 1, {0 ,sizeof(struct linux_dirent) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_set_tid_address = 218 */
	{ 1, 0, 1, {sizeof(int) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_restart_syscall = 219 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_semtimedop = 220 */
	{ 4, 0, 1, {0 ,sizeof(struct sembuf) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fadvise64 = 221 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timer_create = 222 */
	{ 3, 0, 1, {0 ,sizeof(struct sigevent) ,sizeof(timer_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timer_settime = 223 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct itimerspec) ,0 ,0}, NULL, NULL},
	/* __NR_timer_gettime = 224 */
	{ 2, 0, 1, {0 ,sizeof(struct itimerspec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timer_getoverrun = 225 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timer_delete = 226 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_clock_settime = 227 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_clock_gettime = 228 */
	{ 2, 0, 1, {0 ,sizeof(struct timespec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_clock_getres = 229 */
	{ 2, 0, 1, {0 ,sizeof(struct timespec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_clock_nanosleep = 230 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct timespec) ,0 ,0}, NULL, NULL},
	/* __NR_exit_group = 231 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_wait = 232 */
	{ 4, 1, 1, {0 ,sizeof(struct epoll_event) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_ctl = 233 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct epoll_event) ,0 ,0}, NULL, NULL},
	/* __NR_tgkill = 234 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_utimes = 235 */
	{ 2, 0, 1, {0 ,sizeof(struct timeval) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_vserver = 236 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mbind = 237 */
	{ 6, 0, 1, {0 ,0 ,0 ,sizeof(unsigned long) ,0 ,0}, NULL, NULL},
	/* __NR_set_mempolicy = 238 */
	{ 3, 0, 1, {0 ,sizeof(unsigned long) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_get_mempolicy = 239 */
	{ 5, 1, 1, {sizeof(int) ,sizeof(unsigned long) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mq_open = 240 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct mq_attr) ,0 ,0}, NULL, NULL},
	/* __NR_mq_unlink = 241 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mq_timedsend = 242 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mq_timedreceive = 243 */
	{ 5, 1, 1, {0 ,0 ,0 ,sizeof(unsigned int) ,0 ,0}, NULL, NULL},
	/* __NR_mq_notify = 244 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mq_getsetattr = 245 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct mq_attr) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_kexec_load = 246 */
	{ 4, 0, 1, {0 ,0 ,sizeof(struct kexec_segment) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_waitid = 247 */
	{ 5, 0, 1, {0 ,0 ,sizeof(siginfo_t) ,0 ,sizeof(struct rusage) ,0}, NULL, NULL},
	/* __NR_add_key = 248 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_request_key = 249 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_keyctl = 250 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ioprio_set = 251 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_ioprio_get = 252 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_inotify_init = 253 */
	{ 0, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_inotify_add_watch = 254 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_inotify_rm_watch = 255 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_migrate_pages = 256 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_openat = 257 */
	{ 4, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_openat_hook},
	/* __NR_mkdirat = 258 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_mknodat = 259 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fchownat = 260 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_futimesat = 261 */
	{ 3, 0, 1, {0 ,0 ,sizeof(struct timeval) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_newfstatat = 262 */
	{ 4, 0, 1, {0 ,0 ,sizeof(struct stat) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_unlinkat = 263 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_renameat = 264 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_linkat = 265 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_symlinkat = 266 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_readlinkat = 267 */
	{ 4, 1, 1, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fchmodat = 268 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_faccessat = 269 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_pselect6 = 270 */
	{ 6, 0, 1, {0 ,sizeof(fd_set) ,sizeof(fd_set) ,sizeof(fd_set) ,sizeof(struct timespec) ,0}, NULL, NULL},
	/* __NR_ppoll = 271 */
	{ 5, 0, 1, {sizeof(struct pollfd) ,0 ,sizeof(struct timespec) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_unshare = 272 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_set_robust_list = 273 */
	{ 2, 0, 1, {sizeof(struct robust_list_head) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_get_robust_list = 274 */
	{ 3, 0, 1, {0 ,sizeof(struct robust_list_head) ,sizeof(size_t) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_splice = 275 */
	{ 6, 0, 1, {0 ,sizeof(loff_t) ,0 ,sizeof(loff_t) ,0 ,0}, NULL, NULL},
	/* __NR_tee = 276 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sync_file_range = 277 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_vmsplice = 278 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_move_pages = 279 */
	{ 6, 0, 1, {0 ,0 ,0 ,0 ,sizeof(int) ,0}, NULL, NULL},
	/* __NR_utimensat = 280 */
	{ 4, 0, 1, {0 ,0 ,sizeof(struct timespec) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_pwait = 281 */
	{ 6, 0, 1, {0 ,sizeof(struct epoll_event) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_signalfd = 282 */
	{ 3, 0, 1, {0 ,sizeof(sigset_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timerfd_create = 283 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_eventfd = 284 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fallocate = 285 */
	{ 4, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_timerfd_settime = 286 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct itimerspec) ,0 ,0}, NULL, NULL},
	/* __NR_timerfd_gettime = 287 */
	{ 2, 0, 1, {0 ,sizeof(struct itimerspec) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_accept4 = 288 */
	{ 4, 0, 1, {0 ,sizeof(struct sockaddr) ,sizeof(int) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_signalfd4 = 289 */
	{ 4, 0, 1, {0 ,sizeof(sigset_t) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_eventfd2 = 290 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_epoll_create1 = 291 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_dup3 = 292 */
	{ 3, 1, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, post_dup3_hook},
	/* __NR_pipe2 = 293 */
	{ 2, 0, 1, {sizeof(int) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_inotify_init1 = 294 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_preadv = 295 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_pwritev = 296 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_rt_tgsigqueueinfo = 297 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(siginfo_t) ,0 ,0}, NULL, NULL},
	/* __NR_perf_event_open = 298 */
	{ 5, 0, 1, {sizeof(struct perf_event_attr) ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_recvmmsg = 299 */
	{ 5, 0, 1, {0 ,sizeof(struct msghdr) ,0 ,0 ,sizeof(struct timespec) ,0}, NULL, NULL},
	/* __NR_fanotify_init = 300 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_fanotify_mark = 301 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_prlimit64 = 302 */
	{ 4, 0, 1, {0 ,0 ,0 ,sizeof(struct rlimit) ,0 ,0}, NULL, NULL},
	/* __NR_name_to_handle_at = 303 */
	{ 5, 0, 1, {0 ,0 ,sizeof(struct file_handle) ,sizeof(int) ,0 ,0}, NULL, NULL},
	/* __NR_open_by_handle_at = 304 */
	{ 5, 0, 1, {0 ,0 ,sizeof(struct file_handle) ,sizeof(int) ,0 ,0}, NULL, NULL},
	/* __NR_clock_adjtime = 305 */
	{ 2, 0, 1, {0 ,sizeof(struct timex) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_syncfs = 306 */
	{ 1, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sendmmsg = 307 */
	{ 4, 0, 1, {0 ,sizeof(struct mmsghdr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_setns = 308 */
	{ 2, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_getcpu = 309 */
	{ 3, 0, 1, {sizeof(unsigned) ,sizeof(unsigned) ,sizeof(struct getcpu_cache) ,0 ,0 ,0}, NULL, NULL},
	/* __NR_process_vm_readv = 310 */
	{ 6, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_process_vm_writev = 311 */
	{ 6, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_kcmp = 312 */
	{ 5, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_finit_module = 313 */
	{ 3, 0, 0, {0 ,0 ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_setattr = 314 */
	{ 3, 0, 1, {0 ,sizeof(struct sched_attr) ,0 ,0 ,0 ,0}, NULL, NULL},
	/* __NR_sched_getattr = 315 */
	{ 4, 0, 1, {0 ,sizeof(struct sched_attr) ,0 ,0 ,0 ,0}, NULL, NULL},
};

/*
 * add a new pre-syscall callback into a syscall descriptor
 */
int
syscall_set_pre(syscall_desc_t *desc, void (* pre)(syscall_ctx_t*))
{
	if (unlikely((desc == NULL) | (pre == NULL)))
		return 1;
	desc->pre = pre;
	desc->save_args = 1;
	return 0;
}

/*
 * add a new post-syscall callback into a syscall descriptor
 */
int
syscall_set_post(syscall_desc_t *desc, void (* post)(syscall_ctx_t*))
{
	if (unlikely((desc == NULL) | (post == NULL)))
		return 1;
	desc->post = post;
	desc->save_args = 1;
	return 0;
}

/*
 * remove the pre-syscall callback from a syscall descriptor
 */
int
syscall_clr_pre(syscall_desc_t *desc)
{
	if (unlikely(desc == NULL))
		return 1;
	desc->pre = NULL;
	if (desc->post == NULL)
		desc->save_args = 0;
	return 0;
}

/*
 * remove the post-syscall callback from a syscall descriptor
 */
int
syscall_clr_post(syscall_desc_t *desc)
{
	if (unlikely(desc == NULL))
		return 1;
	desc->post = NULL;
	if (desc->pre == NULL)
		desc->save_args = 0;
	return 0;
}

/* __NR_(p)read(64) and __NR_readlink post syscall hook */
static void
post_read_hook(syscall_ctx_t *ctx)
{
	ADDRINT buf = ctx->arg[SYSCALL_ARG1];
	uint32_t nbytes;

	if (unlikely((ssize_t)ctx->ret <= 0))
		return;

	nbytes = (uint32_t)ctx->ret;

	int fd = ctx->arg[SYSCALL_ARG0];

	if (fdset.find(fd) != fdset.end()) {
		off_t read_offset_start = 0;
		size_t i = 0;
		g_src_events++; g_src_bytes += nbytes;
		LOG("Setting taint " + decstr(fd) + " " + decstr(nbytes) + "bytes\n");
		read_offset_start = lseek(fd, 0, SEEK_CUR);
		if (unlikely(read_offset_start < 0)) {
			LOG("Error on lseeking " + decstr(fd) + "\n");
		}
		read_offset_start -= nbytes;
		while (i < nbytes) {
			tag_t ts_prev = file_tagmap_getb(buf+i);
			tag_t t;
			t.set(read_offset_start+i);
			tagmap_setb_with_tag(buf+i, t);
			i++;
		}
	} else {
		size_t i = 0;
		while (i < nbytes) {
			file_tagmap_clrb(buf+i);
			i++;
		}
	}
}

/* __NR_open post syscall hook */
static void
post_open_hook(syscall_ctx_t *ctx)
{
	int fd = (int) ctx->ret;
	LOG("In open\n");
	const std::string fdn = fdname(fd);

	if (!in_dtracker_whitelist(fdn) && !path_isdir(fdn)) {
		fdset.insert(fd);
		flag = 1;
		LOG("Inserted " + fdn + " " + decstr(fd) + ".\n");
	} else {
		LOG("Info ignoring fd " + decstr(fd) + "\n");
	}
}

/* __NR_openat post syscall hook */
static void
post_openat_hook(syscall_ctx_t *ctx)
{
	post_open_hook(ctx);
}

/* __NR_dup3 post syscall hook */
static void
post_dup3_hook(syscall_ctx_t *ctx)
{
	int oldfd = (int) ctx->arg[SYSCALL_ARG0];
	int newfd = (int) ctx->arg[SYSCALL_ARG1];
	LOG("In dup3\n");
	if (fdset.find(oldfd) != fdset.end()) {
		fdset.insert(newfd);
	}
}

static void
post_dup2_hook(syscall_ctx_t *ctx)
{
	int oldfd = (int) ctx->arg[SYSCALL_ARG0];
	int newfd = (int) ctx->arg[SYSCALL_ARG1];
	LOG("In dup2\n");
	if (fdset.find(oldfd) != fdset.end()) {
		fdset.insert(newfd);
	}
}

static void
post_dup_hook(syscall_ctx_t *ctx)
{
	int oldfd = (int) ctx->arg[SYSCALL_ARG0];
	int newfd = (int) ctx->ret;
	LOG("In dup\n");
	if (fdset.find(oldfd) != fdset.end() && newfd != -1) {
		fdset.insert(newfd);
	}
}

/* __NR_close post syscall hook */
static void
post_close_hook(syscall_ctx_t *ctx)
{
	int ret_val = (int) ctx->ret;
	if (unlikely(ret_val) < 0) {
		LOG("Error in Close \n");
		return;
	}
	int fd = (int)ctx->arg[SYSCALL_ARG0];
	LOG("close " + decstr(fd) + "\n");
	std::set<int>::iterator it = fdset.find(fd);
	if (it == fdset.end())	return;
	fdset.erase(it);
}

/* __NR_pread64 post syscall hook */
static void
post_pread64_hook(syscall_ctx_t *ctx)
{
	if (unlikely((ssize_t) ctx->ret < 0)) {
		return;
	}
	uint32_t nr = (uint32_t) ctx->ret;
	int fd = (int) ctx->arg[SYSCALL_ARG0];
	const ADDRINT buf = (ADDRINT) ctx->arg[SYSCALL_ARG1];
	const off_t read_offset_start = (off_t) ctx->arg[SYSCALL_ARG3];
	LOG("pread64 " + decstr(nr) + "\n");
	if (fdset.find(fd) != fdset.end()) {
		size_t i = 0;
		g_src_events++; g_src_bytes += nr;
		while (i < nr) {
			tag_t ts_prev = file_tagmap_getb(buf+i);
			tag_t t;
			t.set(read_offset_start+i);
			tagmap_setb_with_tag(buf+i, t);
			i++;
		}
	} else {
		size_t i = 0;
		while (i < nr) {
			file_tagmap_clrb(buf+i);
			i++;
		}
	}
}

/* __NR_mmap post syscall hook */
static void
post_mmap_hook(syscall_ctx_t *ctx)
{
	/* the map offset */
	size_t offset = (size_t)ctx->arg[SYSCALL_ARG1];

	/* mmap() was not successful; optimized branch */
	if (unlikely((void *)ctx->ret == MAP_FAILED))
		return;

	/* estimate offset; optimized branch */
	if (unlikely(offset < PAGE_SZ))
		offset = PAGE_SZ;
	else
		offset = offset + PAGE_SZ - (offset % PAGE_SZ);

	/* grow downwards; optimized branch */
	if (unlikely((int)ctx->arg[SYSCALL_ARG3] & MAP_GROWSDOWN))
		ctx->ret = ctx->ret + offset - 1;

	ADDRINT buf = (ADDRINT) ctx->ret;
	int fd = (int) ctx->arg[SYSCALL_ARG4];
	size_t nr = (size_t) ctx->arg[SYSCALL_ARG1];
	intmax_t _fd_offset = ctx->arg[SYSCALL_ARG5];
	LOG("In mmap " + decstr(fd) + " " + decstr(_fd_offset) +"\n");
	if (fd >= 0 && fdset.find(fd) != fdset.end()) {
		size_t i = 0;
		off_t offset_start;

		if (mmap_type == 0) {
			LOG("Lseek \n");
			offset_start = lseek(fd, 0, SEEK_CUR);
		} else if (mmap_type == 1) {
			off_t fsize = lseek(fd, 0, SEEK_END);
			struct stat st;
			std::string fname = fdname(fd);
			if (stat(fname.c_str(), &st) == 0) {
				LOG("inside fstart " + decstr(st.st_size) + "\n");
				fsize = st.st_size;
			}
			UINT32 j = 0;
			offset_start = j + _fd_offset;
			LOG(fname + " " + decstr(fsize) +  " " + decstr(offset_start) + " " + decstr(nr)+  "\n");
			if ((UINT32)offset_start > (UINT32)fsize) {
				int nread = pread64(fd, buf2, (ssize_t) 4, 0);
				LOG(decstr(fd) + " " +  decstr(nread) + "\n");
				char *a = (char *)buf;
				if (nread == 4) {
					if (strcmp(buf2, a) == 0) {
						offset_start = 0;
					} else {
						LOG("libdft_die\n");
						libdft_die();
					}
				} else {
					LOG("libdft_die\n");
					libdft_die();
				}
			}
		}
		g_src_events++; g_src_bytes += nr;
		while (i < nr) {
			tag_t ts = file_tagmap_getb(buf+i);
			tag_t t;
			t.set(offset_start+i);
			tagmap_setb_with_tag(buf+i, t);
			i++;
		}
	} else {
		size_t i = 0;
		while (i < nr) {
			file_tagmap_clrb(buf+i);
			i++;
		}
	}
}

static void
post_munmap_hook(syscall_ctx_t *ctx)
{
	if ((ssize_t)ctx->ret < 0) {
		LOG("munmap failed\n");
		return;
	}
	size_t len = (size_t)ctx->arg[SYSCALL_ARG1];
	ADDRINT buf = (ADDRINT) ctx->arg[SYSCALL_ARG0];
	for (size_t i = 0; i < len; i++) {
		file_tagmap_clrb(buf+i);
	}
}
