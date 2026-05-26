/* osutils_dr.cpp -- fd/path helpers for the DR taint engine (C.4 Phase 2).
 * Ported from libdft64/osutils.cpp (Linux path only). */
#include "osutils_dr.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <stdio.h>

#define __PROC_SELF_FD "/proc/self/fd"

/* Filename for which we track taint, and the live fds resolving to it. */
std::string filename;
std::set<int> fdset;

std::string fdname(int fd) {
	char ppath[PATH_MAX];
	char fpath[PATH_MAX];
	int w;

	/* build /proc/self/fd/<fd> */
	w = snprintf(ppath, PATH_MAX * sizeof(char), "%s/%d", __PROC_SELF_FD, fd);
	assert(w < (int)(PATH_MAX * sizeof(char)));

	w = readlink(ppath, fpath, PATH_MAX * sizeof(char));
	if (w < 0) {
		return std::string(strerror(errno));
	} else if (w >= PATH_MAX) {
		fpath[PATH_MAX - 1] = '\0';
		return std::string(fpath) + std::string("...");
	} else {
		fpath[w] = '\0';
		return std::string(fpath);
	}
}
