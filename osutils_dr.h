/* osutils_dr.h -- fd/path helpers for the DR taint engine (C.4 Phase 2).
 * Ported from libdft64/osutils.H. Pure libc (no Pin); only the LOG macro and
 * pin.H include are dropped. `filename` holds the taint-source path and
 * `fdset` the set of fds currently resolving to it.
 */
#ifndef __OSUTILS_DR_H__
#define __OSUTILS_DR_H__

#include <string>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libdft_log.h"

extern std::string filename;
extern std::set<int> fdset;

/* Is `fname` NOT the taint-source file? (1 = ignore, 0 = track) */
inline int in_dtracker_whitelist(const std::string & fname) {
	LOG("in_dtracker_whitelist " + fname + "\n");
	if (fname.find(filename) != std::string::npos) {
		return 0;
	} else {
		return 1;
	}
}

inline int path_isdir(const std::string & path) {
	struct stat stats;
	return (stat(path.c_str(), &stats) == 0 && S_ISDIR(stats.st_mode));
}

inline int path_exists(const std::string & path) {
	return (access(path.c_str(), F_OK) == 0);
}

/* Resolve an open fd to its path via /proc/self/fd. */
std::string fdname(int fd);

#endif /* __OSUTILS_DR_H__ */
