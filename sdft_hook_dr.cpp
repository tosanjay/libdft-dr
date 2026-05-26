/*
 * sdft_hook_dr.cpp -- DR port of libdft64/sdft_hook.cpp (C.4 Phase 4).
 *
 * The 6 shape handlers are the Pin logic verbatim, except they take the
 * per-thread context pointer (from drmgr TLS) rather than a Pin THREADID.
 *
 * Pin instrumented functions via RTN_AddInstrumentFunction + RTN_InsertCall
 * (IPOINT_BEFORE, IARG_FUNCARG_ENTRYPOINT_VALUE 0..5). DR has no RTN concept,
 * so at each module load we drsym_enumerate_symbols_ex over the module's
 * symbols (MANGLED -- the conf carries mangled names) and, for every symbol
 * sdft::find() recognizes, drwrap_wrap_ex() its entry. The wrap pre-callback
 * reads args via drwrap_get_arg and runs the same dispatch. The function body
 * [start,end) is registered with mnt::add_rtn_range so the Phase 5 trace
 * dispatch skips per-instruction propagation inside it.
 */
#include "sdft_hook_dr.h"
#include "sdft_summaries_dr.h"
#include "libdft_api_dr.h"
#include "tagmap.h"
#include "mnt_consumer_dr.h"

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "drsyms.h"

#include <cstring>
#include <cstdlib>
#include <string>
#include <set>

namespace sdft_hook {

static bool s_active = false;

/* Addresses already wrapped -- drsym yields multiple symbols (aliases) at one
 * PC, and several exported names can resolve to the same implementation, so we
 * dedupe by resolved address. */
static std::set<app_pc> s_wrapped;

/* ---------- internal helpers (verbatim from Pin, tid -> thread_ctx_t*) ---- */

static int arg_to_reg(int arg_idx) {
    switch (arg_idx) {
        case 0: return DFT_REG_RDI;
        case 1: return DFT_REG_RSI;
        case 2: return DFT_REG_RDX;
        case 3: return DFT_REG_RCX;
        case 4: return DFT_REG_R8;
        case 5: return DFT_REG_R9;
        default: return -1;
    }
}

struct ArgVals {
    ADDRINT a[6];
};

static const UINT64 MAX_PROP_BYTES = 256 * 1024;

/* Fault-free strlen/wcslen over app memory. The Pin engine called raw
 * strlen() on the arg pointer, relying on it always being a valid string;
 * under DR a misclassified summary (or an IFUNC/alias wrapped at a PC whose
 * args differ) can hand us a non-pointer, so we bound-scan via dr_safe_read
 * and stop at the first unreadable byte. Bounded by MAX_PROP_BYTES. */
static UINT64 safe_strlen(ADDRINT p) {
    if (p == 0) return 0;
    size_t n = 0; char c; size_t got;
    while (n < MAX_PROP_BYTES) {
        if (!dr_safe_read((const void *)(p + n), 1, &c, &got) || got != 1)
            break;
        if (c == '\0') break;
        ++n;
    }
    return (UINT64)n;
}

static UINT64 safe_wcslen_bytes(ADDRINT p) {
    if (p == 0) return 0;
    size_t n = 0; wchar_t w; size_t got;
    while (n < MAX_PROP_BYTES / sizeof(wchar_t)) {
        if (!dr_safe_read((const void *)(p + n * sizeof(wchar_t)),
                          sizeof(wchar_t), &w, &got) || got != sizeof(wchar_t))
            break;
        if (w == L'\0') break;
        ++n;
    }
    return (UINT64)(n * sizeof(wchar_t));
}

static UINT64 resolve_len(const sdft::Ref &lenref,
                          const ArgVals &av,
                          ADDRINT src_ptr_for_strlen) {
    switch (lenref.kind) {
        case sdft::REF_ARG:
            if (lenref.value >= 0 && lenref.value <= 5)
                return (UINT64)av.a[lenref.value];
            return 0;
        case sdft::REF_LITERAL:
            return (UINT64)lenref.value;
        case sdft::REF_STRLEN:
            return safe_strlen(src_ptr_for_strlen);
        case sdft::REF_WCSLEN:
            return safe_wcslen_bytes(src_ptr_for_strlen);
        case sdft::REF_RET:
        case sdft::REF_NONE:
        default:
            return 0;
    }
}

static ADDRINT resolve_ptr(const sdft::Ref &r, const ArgVals &av) {
    if (r.kind == sdft::REF_ARG && r.value >= 0 && r.value <= 5)
        return av.a[r.value];
    return 0;
}

static void clobber_caller_saved(thread_ctx_t *tc) {
    static const int regs[] = {
        DFT_REG_RAX, DFT_REG_RCX, DFT_REG_RDX, DFT_REG_RSI, DFT_REG_RDI,
        DFT_REG_R8,  DFT_REG_R9,  DFT_REG_R10, DFT_REG_R11
    };
    static const tag_t cleared = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < sizeof(regs)/sizeof(regs[0]); ++i) {
        for (int b = 0; b < TAGS_PER_GPR; ++b) {
            tc->vcpu.gpr_file[regs[i]][b] = cleared;
        }
    }
}

static void rax_set_all(thread_ctx_t *tc, const tag_t &t) {
    for (int b = 0; b < 8; ++b) {
        tc->vcpu.gpr_file[DFT_REG_RAX][b] = t;
    }
}

/* ---------- per-shape analysis routines ---------- */

static void handle_clobber(thread_ctx_t *tc) {
    clobber_caller_saved(tc);
}

static void handle_prop_ptr2ptr(thread_ctx_t *tc,
                                ADDRINT a0, ADDRINT a1, ADDRINT a2,
                                ADDRINT a3, ADDRINT a4, ADDRINT a5,
                                const sdft::Summary *sum) {
    ArgVals av; av.a[0]=a0; av.a[1]=a1; av.a[2]=a2;
    av.a[3]=a3; av.a[4]=a4; av.a[5]=a5;

    if (sum->src.empty()) { clobber_caller_saved(tc); return; }
    ADDRINT src = av.a[sum->src[0]];
    ADDRINT dst = (sum->dst.kind == sdft::REF_RET)
                    ? 0
                    : resolve_ptr(sum->dst, av);
    UINT64 n = resolve_len(sum->len, av, src);
    if (n > MAX_PROP_BYTES) n = MAX_PROP_BYTES;

    if (dst != 0 && src != 0) {
        for (UINT64 i = 0; i < n; ++i) {
            tag_t t = file_tagmap_getb(src + i);
            tagmap_setb_with_tag(dst + i, t);
        }
        if (n > 0) {
            tag_t t = file_tagmap_getb(dst);
            rax_set_all(tc, t);
        }
    }
    clobber_caller_saved(tc);
    if (dst != 0 && n > 0) {
        tag_t t = file_tagmap_getb(dst);
        rax_set_all(tc, t);
    }
}

static void handle_prop_ptr2val(thread_ctx_t *tc,
                                ADDRINT a0, ADDRINT a1, ADDRINT a2,
                                ADDRINT a3, ADDRINT a4, ADDRINT a5,
                                const sdft::Summary *sum) {
    ArgVals av; av.a[0]=a0; av.a[1]=a1; av.a[2]=a2;
    av.a[3]=a3; av.a[4]=a4; av.a[5]=a5;

    tag_t accum = tag_traits<tag_t>::cleared_val;
    for (size_t s = 0; s < sum->src.size(); ++s) {
        int idx = sum->src[s];
        if (idx < 0 || idx > 5) continue;
        ADDRINT p = av.a[idx];
        if (p == 0) continue;
        UINT64 n = resolve_len(sum->len, av, p);
        if (n > MAX_PROP_BYTES) n = MAX_PROP_BYTES;
        for (UINT64 i = 0; i < n; ++i) {
            tag_t t = file_tagmap_getb(p + i);
            accum = tag_combine(accum, t);
        }
    }
    clobber_caller_saved(tc);
    rax_set_all(tc, accum);
}

static void handle_prop_scalar(thread_ctx_t *tc,
                               const sdft::Summary *sum) {
    tag_t accum = tag_traits<tag_t>::cleared_val;
    for (size_t s = 0; s < sum->args.size(); ++s) {
        int reg = arg_to_reg(sum->args[s]);
        if (reg < 0) continue;
        for (int b = 0; b < 8; ++b) {
            tag_t t = tc->vcpu.gpr_file[reg][b];
            accum = tag_combine(accum, t);
        }
    }
    clobber_caller_saved(tc);
    rax_set_all(tc, accum);
}

/* ---------- counters ---------- */

static UINT64 s_intercepted_rtns = 0;
static UINT64 s_calls_per_shape[7] = {0,0,0,0,0,0,0};

static void count_call(const sdft::Summary *sum) {
    int sh = (int)sum->shape;
    if (sh >= 0 && sh < 7) s_calls_per_shape[sh]++;
}

/* ---------- dispatch (drwrap pre-callback) ---------- */

static void dispatch(thread_ctx_t *tc,
                     ADDRINT a0, ADDRINT a1, ADDRINT a2,
                     ADDRINT a3, ADDRINT a4, ADDRINT a5,
                     const sdft::Summary *sum) {
    switch (sum->shape) {
        case sdft::SHAPE_SOURCE:
        case sdft::SHAPE_SOURCE_RET_PTR:
        case sdft::SHAPE_CLOBBER_ONLY:
            handle_clobber(tc);
            break;
        case sdft::SHAPE_PROP_PTR2PTR:
            handle_prop_ptr2ptr(tc, a0,a1,a2,a3,a4,a5, sum);
            break;
        case sdft::SHAPE_PROP_PTR2VAL:
            handle_prop_ptr2val(tc, a0,a1,a2,a3,a4,a5, sum);
            break;
        case sdft::SHAPE_PROP_SCALAR:
            handle_prop_scalar(tc, sum);
            break;
        default:
            break;
    }
}

static void sdft_pre(void *wrapcxt, void **user_data) {
    const sdft::Summary *sum = (const sdft::Summary *)*user_data;
    if (sum == NULL) return;
    void *drcontext = drwrap_get_drcontext(wrapcxt);
    thread_ctx_t *tc = libdft_get_thread_ctx(drcontext);
    if (tc == NULL) return;

    ADDRINT a0 = (ADDRINT)drwrap_get_arg(wrapcxt, 0);
    ADDRINT a1 = (ADDRINT)drwrap_get_arg(wrapcxt, 1);
    ADDRINT a2 = (ADDRINT)drwrap_get_arg(wrapcxt, 2);
    ADDRINT a3 = (ADDRINT)drwrap_get_arg(wrapcxt, 3);
    ADDRINT a4 = (ADDRINT)drwrap_get_arg(wrapcxt, 4);
    ADDRINT a5 = (ADDRINT)drwrap_get_arg(wrapcxt, 5);

    count_call(sum);
    dispatch(tc, a0, a1, a2, a3, a4, a5, sum);
}

/* ---------- module-load symbol enumeration ---------- */

struct EnumCtx {
    app_pc base;             /* module load base */
    module_handle_t handle;  /* for dr_get_proc_address (IFUNC resolution) */
};

static UINT64 s_ifunc_resolved = 0;  /* wraps redirected past an IFUNC/PLT */

static bool
enum_sym_cb(drsym_info_t *info, drsym_error_t status, void *data) {
    if (status != DRSYM_SUCCESS && status != DRSYM_ERROR_LINE_NOT_AVAILABLE)
        return true;  // keep enumerating
    if (info->name == NULL || info->name[0] == '\0')
        return true;

    const sdft::Summary *sum = sdft::find(std::string(info->name));
    if (sum == NULL)
        return true;

    EnumCtx *ctx = (EnumCtx *)data;
    app_pc symtab_pc = ctx->base + info->start_offs;

    /* D22: resolve the wrap target by name through the loader. For a glibc
     * IFUNC (memcpy/strcpy/...), the exported "memcpy" symbol's symtab offset
     * is the resolver/PLT path, NOT where calls land; dr_get_proc_address
     * returns the resolved implementation -- the address execution actually
     * reaches. Non-exported/local symbols return NULL -> fall back to the
     * symtab offset (correct for non-IFUNC locals). */
    app_pc resolved = (app_pc)dr_get_proc_address(ctx->handle, info->name);
    app_pc func_pc = (resolved != NULL) ? resolved : symtab_pc;

    // Dedupe by resolved address (aliases + names sharing one implementation).
    if (s_wrapped.count(func_pc) != 0)
        return true;
    s_wrapped.insert(func_pc);
    s_intercepted_rtns++;

    if (func_pc == symtab_pc) {
        // Non-IFUNC: the symtab [start,end) is the real body -> MNT-skippable.
        if (info->end_offs > info->start_offs)
            mnt::add_rtn_range((ADDRINT)func_pc,
                               (ADDRINT)(ctx->base + info->end_offs));
    } else {
        // IFUNC-resolved: symtab range is the resolver's, not the executed
        // body's. Deriving the resolved body's range is deferred to Phase 5
        // (where the MNT range first has an effect, via drsym_lookup_address);
        // a missing range only costs the body-skip optimization, never
        // correctness, and is inert until the Phase 5 trace dispatch exists.
        s_ifunc_resolved++;
    }

    drwrap_wrap_ex(func_pc, sdft_pre, NULL, (void *)sum, DRWRAP_CALLCONV_AMD64);
    return true;
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded) {
    (void)drcontext;
    (void)loaded;
    if (info->full_path == NULL || info->full_path[0] == '\0')
        return;
    /* Never wrap the instrumentation runtime itself: DR's core + extension
     * libs + this client use libc internally, and Pin likewise does not
     * instrument its own runtime. */
    if (dr_memory_is_dr_internal(info->start) ||
        dr_memory_is_in_client(info->start))
        return;
    EnumCtx ctx;
    ctx.base = info->start;
    ctx.handle = info->handle;
    /* MANGLED names: the conf carries mangled C++ symbols. */
    drsym_enumerate_symbols_ex(info->full_path, enum_sym_cb,
                               sizeof(drsym_info_t), &ctx,
                               DRSYM_LEAVE_MANGLED);
}

/* ---------- public API ---------- */

int init(const std::string &conf_path) {
    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_fprintf(STDERR, "[sdft_hook] init failed: drsym_init\n");
        return 1;
    }
    drwrap_init();
    if (!sdft::load(conf_path)) {
        dr_fprintf(STDERR, "[sdft_hook] init failed: cannot load conf\n");
        drwrap_exit();
        drsym_exit();
        return 1;
    }
    drmgr_register_module_load_event(event_module_load);
    s_active = true;
    dr_fprintf(STDERR, "[sdft_hook] init ok: %s\n", conf_path.c_str());
    return 0;
}

void log_summary(void) {
    static const char *names[] = {
        "INVALID", "SOURCE", "SOURCE_RET_PTR",
        "PROP_PTR2PTR", "PROP_PTR2VAL", "PROP_SCALAR", "CLOBBER_ONLY"
    };
    dr_fprintf(STDERR, "[sdft_hook] intercepted_rtns=%llu (ifunc_resolved=%llu)\n",
               (unsigned long long)s_intercepted_rtns,
               (unsigned long long)s_ifunc_resolved);
    for (int i = 1; i < 7; ++i) {
        dr_fprintf(STDERR, "[sdft_hook]   shape %s: %llu calls\n",
                   names[i], (unsigned long long)s_calls_per_shape[i]);
    }
    sdft::log_summary();
}

void shutdown(void) {
    if (!s_active) return;
    drmgr_unregister_module_load_event(event_module_load);
    drwrap_exit();
    drsym_exit();
    s_active = false;
}

}  // namespace sdft_hook
