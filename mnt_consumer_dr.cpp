/*
 * mnt_consumer_dr.cpp -- DR port of libdft64/mnt_consumer.cpp (C.4 Phase 3).
 * See mnt_consumer_dr.h. Algorithm verbatim from the Pin consumer; I/O and
 * logging retargeted to DR's file API + dr_fprintf (DR's private loader makes
 * FILE* stdio / std::cerr unsafe -- same hazard that bit the Phase 2 ofstream).
 */
#include "mnt_consumer_dr.h"

#include "drmgr.h"

#include <cstdint>
#include <cstdlib>   // getenv, realpath
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <utility>

namespace mnt {

/* ---------- internal state ---------- */

enum Policy {
    POLICY_OFF      = -1,
    POLICY_LEAN     = 0,
    POLICY_SOUND    = 1,
    POLICY_V2_PERPC = 2,
};

struct ImageMnt {
    std::string name;          // basename, e.g., "libtiff.so.5.7.0"
    ADDRINT low;               // module start (runtime)
    ADDRINT high;              // module end (runtime, inclusive)
    UINT64  file_image_base;   // analyzer's image_base (typically 0x100000)
    std::vector<UINT64> mnt_sorted;  // sorted image-rel offsets that are MNT
};

static Policy s_policy = POLICY_LEAN;
static bool s_inited = false;
static std::vector<ImageMnt> s_images;

/* One-entry cache for the is_mnt fast path (hot loops stay in one image). */
static const ImageMnt *s_last_img = NULL;

/* Runtime MNT ranges registered by sdft_hook (Phase 4). Sorted by low PC. */
typedef std::pair<ADDRINT, ADDRINT> RtnRange;
static std::vector<RtnRange> s_ranges;
static bool s_ranges_dirty = false;

/* Diagnostics. */
static UINT64 s_total_lookups = 0;
static UINT64 s_total_hits = 0;
static UINT64 s_total_misses_no_img = 0;
static UINT64 s_total_rtn_hits = 0;

/* ---------- helpers ---------- */

static const char *POLICY_NAMES[] = { "lean", "sound", "v2_perpc" };

static Policy parse_policy_env(void) {
    const char *p = std::getenv("VUZZER_MNT_POLICY");
    if (p == NULL || std::strlen(p) == 0) return POLICY_LEAN;
    if (std::strcmp(p, "lean")     == 0) return POLICY_LEAN;
    if (std::strcmp(p, "sound")    == 0) return POLICY_SOUND;
    if (std::strcmp(p, "v2_perpc") == 0) return POLICY_V2_PERPC;
    if (std::strcmp(p, "off")      == 0) return POLICY_OFF;
    dr_fprintf(STDERR, "[mnt] WARNING: unknown VUZZER_MNT_POLICY='%s', "
                       "defaulting to 'lean'\n", p);
    return POLICY_LEAN;
}

/* basename (last path component). */
static std::string basename_of(const std::string &path) {
    size_t pos = path.find_last_of('/');
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

/* Candidate paths for <basename>.mnt.bin (search order per the header).
 * Tries both the SONAME-style basename and the realpath-resolved versioned
 * name (handles libtiff.so.5 -> libtiff.so.5.7.0). */
static std::vector<std::string>
build_search_paths(const std::string &img_path) {
    std::vector<std::string> out;
    std::vector<std::string> bases;
    bases.push_back(basename_of(img_path));
    char resolved[4096];
    if (realpath(img_path.c_str(), resolved) != NULL) {
        std::string r = std::string(resolved);
        std::string b = basename_of(r);
        if (b != bases[0]) bases.push_back(b);
    }
    const char *env_dir = std::getenv("VUZZER_MNT_DIR");
    std::string dir_aside;
    size_t pos = img_path.find_last_of('/');
    if (pos != std::string::npos) {
        dir_aside = img_path.substr(0, pos);
    }
    for (size_t bi = 0; bi < bases.size(); ++bi) {
        const std::string &b = bases[bi];
        if (env_dir != NULL && std::strlen(env_dir) > 0) {
            out.push_back(std::string(env_dir) + "/" + b + ".mnt.bin");
        }
        if (!dir_aside.empty()) {
            out.push_back(dir_aside + "/" + b + ".mnt.bin");
        }
        out.push_back("bin/_test/" + b + ".mnt.bin");
    }
    return out;
}

/* dr_read_file wrapper: true iff exactly `n` bytes were read. */
static inline bool read_exact(file_t f, void *buf, size_t n) {
    return dr_read_file(f, buf, n) == (ssize_t)n;
}

/* Read a .mnt.bin file. Header format documented in
 * fuzzer-code/mnt/ghidra_mnt_step12_proto.py::_write_mnt_bin. */
static bool load_mnt_bin(const std::string &path, ImageMnt &im,
                         Policy policy) {
    file_t f = dr_open_file(path.c_str(), DR_FILE_READ);
    if (f == INVALID_FILE) return false;

    char magic[4];
    if (!read_exact(f, magic, 4) ||
        magic[0] != 'M' || magic[1] != 'N' ||
        magic[2] != 'T' || magic[3] != 'B') {
        dr_fprintf(STDERR, "[mnt] %s: bad magic\n", path.c_str());
        dr_close_file(f);
        return false;
    }
    UINT32 version, default_policy;
    UINT64 image_base;
    UINT32 n_sound, n_lean_extra, n_v2_extra, reserved;
    if (!read_exact(f, &version, 4) ||
        !read_exact(f, &default_policy, 4) ||
        !read_exact(f, &image_base, 8) ||
        !read_exact(f, &n_sound, 4) ||
        !read_exact(f, &n_lean_extra, 4) ||
        !read_exact(f, &n_v2_extra, 4) ||
        !read_exact(f, &reserved, 4)) {
        dr_fprintf(STDERR, "[mnt] %s: short header\n", path.c_str());
        dr_close_file(f);
        return false;
    }
    if (version != 2) {
        dr_fprintf(STDERR, "[mnt] %s: unsupported version %u\n",
                   path.c_str(), version);
        dr_close_file(f);
        return false;
    }
    im.file_image_base = image_base;

    // sound always; lean adds lean_extra; v2_perpc adds v2_extra.
    UINT32 cap = n_sound;
    if (policy == POLICY_LEAN)     cap += n_lean_extra;
    if (policy == POLICY_V2_PERPC) cap += n_v2_extra;
    im.mnt_sorted.reserve(cap);

    UINT64 buf;
    for (UINT32 i = 0; i < n_sound; ++i) {
        if (!read_exact(f, &buf, 8)) goto fail;
        im.mnt_sorted.push_back(buf);
    }
    for (UINT32 i = 0; i < n_lean_extra; ++i) {
        if (!read_exact(f, &buf, 8)) goto fail;
        if (policy == POLICY_LEAN) im.mnt_sorted.push_back(buf);
    }
    for (UINT32 i = 0; i < n_v2_extra; ++i) {
        if (!read_exact(f, &buf, 8)) goto fail;
        if (policy == POLICY_V2_PERPC) im.mnt_sorted.push_back(buf);
    }
    dr_close_file(f);
    // Per-tier sorted, but the merge may be globally unsorted; sort for
    // binary_search.
    std::sort(im.mnt_sorted.begin(), im.mnt_sorted.end());
    return true;

fail:
    dr_fprintf(STDERR, "[mnt] %s: truncated body\n", path.c_str());
    dr_close_file(f);
    return false;
}

/* ---------- public API ---------- */

int init(void) {
    if (s_inited) return 0;
    s_policy = parse_policy_env();
    if (s_policy == POLICY_OFF) {
        dr_fprintf(STDERR, "[mnt] disabled (VUZZER_MNT_POLICY=off)\n");
        s_inited = true;
        return 0;
    }
    drmgr_register_module_load_event(on_module_load);
    drmgr_register_module_unload_event(on_module_unload);
    dr_fprintf(STDERR, "[mnt] init: policy=%s\n", POLICY_NAMES[s_policy]);
    s_inited = true;
    return 0;
}

void on_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    (void)drcontext;
    (void)loaded;
    if (s_policy == POLICY_OFF) return;
    std::string path = (info->full_path != NULL) ? info->full_path : "";
    std::vector<std::string> candidates = build_search_paths(path);

    ImageMnt im;
    im.name = basename_of(path);
    im.low  = (ADDRINT)info->start;
    im.high = (ADDRINT)info->end - 1;  // Pin IMG_HighAddress is inclusive

    bool found = false;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (load_mnt_bin(candidates[i], im, s_policy)) {
            dr_fprintf(STDERR, "[mnt] loaded %s for %s low=0x%llx high=0x%llx "
                               "n_mnt=%zu\n",
                       candidates[i].c_str(), im.name.c_str(),
                       (unsigned long long)im.low,
                       (unsigned long long)im.high, im.mnt_sorted.size());
            found = true;
            break;
        }
    }
    if (!found) {
        dr_fprintf(STDERR, "[mnt] no .mnt.bin for %s (image not "
                           "MNT-skippable)\n", im.name.c_str());
    }
    s_images.push_back(std::move(im));
    s_last_img = NULL;  // invalidate cache (vector may have realloc'd)
}

void on_module_unload(void *drcontext, const module_data_t *info) {
    (void)drcontext;
    ADDRINT low = (ADDRINT)info->start;
    for (std::vector<ImageMnt>::iterator it = s_images.begin();
         it != s_images.end(); ++it) {
        if (it->low == low) {
            s_images.erase(it);
            s_last_img = NULL;
            return;
        }
    }
}

static bool rtn_range_contains(ADDRINT pc) {
    if (s_ranges.empty()) return false;
    if (s_ranges_dirty) {
        std::sort(s_ranges.begin(), s_ranges.end());
        s_ranges_dirty = false;
    }
    RtnRange probe(pc + 1, 0);
    std::vector<RtnRange>::const_iterator it =
        std::lower_bound(s_ranges.begin(), s_ranges.end(), probe);
    if (it == s_ranges.begin()) return false;
    --it;
    return (pc >= it->first && pc < it->second);
}

void add_rtn_range(ADDRINT low, ADDRINT high) {
    if (high <= low) return;
    s_ranges.push_back(std::make_pair(low, high));
    s_ranges_dirty = true;
}

int is_mnt(ADDRINT pc) {
    if (s_policy == POLICY_OFF) {
        if (rtn_range_contains(pc)) {
            s_total_rtn_hits++;
            return 1;
        }
        return 0;
    }
    s_total_lookups++;

    const ImageMnt *im = s_last_img;
    if (im != NULL && pc >= im->low && pc <= im->high) {
        UINT64 rel = (UINT64)(pc - im->low);
        if (std::binary_search(im->mnt_sorted.begin(),
                               im->mnt_sorted.end(), rel)) {
            s_total_hits++;
            return 1;
        }
        if (rtn_range_contains(pc)) {
            s_total_rtn_hits++;
            return 1;
        }
        return 0;
    }

    for (size_t i = 0; i < s_images.size(); ++i) {
        const ImageMnt &cand = s_images[i];
        if (pc >= cand.low && pc <= cand.high) {
            s_last_img = &cand;
            UINT64 rel = (UINT64)(pc - cand.low);
            if (std::binary_search(cand.mnt_sorted.begin(),
                                   cand.mnt_sorted.end(), rel)) {
                s_total_hits++;
                return 1;
            }
            if (rtn_range_contains(pc)) {
                s_total_rtn_hits++;
                return 1;
            }
            return 0;
        }
    }
    s_total_misses_no_img++;
    if (rtn_range_contains(pc)) {
        s_total_rtn_hits++;
        return 1;
    }
    return 0;
}

void log_summary(void) {
    dr_fprintf(STDERR, "[mnt] summary: lookups=%llu hits=%llu rtn_hits=%llu "
                       "misses_no_img=%llu images_tracked=%zu rtn_ranges=%zu "
                       "policy=%s\n",
               (unsigned long long)s_total_lookups,
               (unsigned long long)s_total_hits,
               (unsigned long long)s_total_rtn_hits,
               (unsigned long long)s_total_misses_no_img,
               s_images.size(), s_ranges.size(),
               ((s_policy >= 0 && s_policy <= 2) ? POLICY_NAMES[s_policy]
                                                 : "off"));
    for (size_t i = 0; i < s_images.size(); ++i) {
        const ImageMnt &im = s_images[i];
        dr_fprintf(STDERR, "[mnt]   %s low=0x%llx high=0x%llx n_mnt=%zu\n",
                   im.name.c_str(), (unsigned long long)im.low,
                   (unsigned long long)im.high, im.mnt_sorted.size());
    }
}

}  // namespace mnt
