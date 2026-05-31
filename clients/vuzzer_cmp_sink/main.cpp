/* clients/vuzzer_cmp_sink/main.cpp -- DR client emitting libdft64-style
 * cmp.out + lea.out for vuzzer64-v2.
 *
 * Built ENTIRELY on the libdft_dr public API:
 *   libdft_dr::init({})              -- lifecycle (layer 1)
 *   libdft_dr::register_file_source  -- file source painting (layer 3a)
 *   libdft_dr::register_sink(CMP/LEA, cb)  -- sink registration (layer 3b)
 *
 * Output format: byte-equivalent to libdft64's cmp.out / lea.out (the contract
 * with vuzzer64-v2's Python parsers read_taint() / read_lea()).
 */
#include <string>
#include <vector>

#include "dr_api.h"
#include "droption.h"

#include "libdft_dr/lifecycle.h"
#include "libdft_dr/sinks.h"
#include "libdft_dr/sources.h"
#include "libdft_dr/tag.h"

using namespace dynamorio::droption;

static droption_t<std::string> op_cmpfile(
    DROPTION_SCOPE_CLIENT, "o", "cmp.out", "CMP taint output file",
    "Path for per-CMP taint records (libdft64 cmp.out equivalent).");
static droption_t<std::string> op_leafile(
    DROPTION_SCOPE_CLIENT, "leao", "lea.out", "LEA taint output file",
    "Path for per-LEA taint records.");
static droption_t<std::string> op_filename(
    DROPTION_SCOPE_CLIENT, "filename", "", "Tainted input filename",
    "Substring match on the input file path; matching bytes are taint sources.");
static droption_t<int> op_timeout(
    DROPTION_SCOPE_CLIENT, "x", 0, "Watchdog timeout (seconds)",
    "Kill the app after this many seconds; 0 disables. The Python run() "
    "wrapper is the primary timeout enforcer.");
static droption_t<int> op_maxoff(
    DROPTION_SCOPE_CLIENT, "maxoff", 4, "Tracked taint width per byte",
    "Drop CMP/LEA records where any byte carries more than this many offsets "
    "(libdft default 4).");
static droption_t<int> op_mmap(
    DROPTION_SCOPE_CLIENT, "mmap", 1, "mmap source-painting method",
    "Pass through to libdft_dr::init_options_t.mmap_paint_method (default 1).");

/* Client-owned output handles (no longer the libdft_api_dr.h globals). */
static file_t g_out     = INVALID_FILE;
static file_t g_out_lea = INVALID_FILE;
static int    g_maxoff  = 4;

/* libdft "loop-noise" filter: split each field on ',' and drop the line if
 * any byte's tag carries more than maxoff offsets. */
static int
comma_tokens(const std::string &s) {
    int n = 1;
    for (char c : s) if (c == ',') n++;
    return n;
}

static void
write_record(file_t fh, const std::vector<std::string> &fields,
             int filter_lo, int filter_hi)
{
    if (fh == INVALID_FILE) return;
    for (int i = filter_lo; i < filter_hi; i++)
        if (comma_tokens(fields[i]) > g_maxoff)
            return;
    std::string line;
    line.reserve(64 * fields.size());
    for (const auto &f : fields) { line += f; line += ' '; }
    line += '\n';
    dr_write_file(fh, line.data(), line.size());
}

static void
on_cmp_sink(const libdft_dr::sink_context_t &ctx) {
    /* CMP record is 21 fields; libdft filters [3..18]. */
    write_record(g_out, ctx.legacy_record(), 3, 19);
}

static void
on_lea_sink(const libdft_dr::sink_context_t &ctx) {
    /* LEA record is 10 fields; libdft filters [2..9]. */
    write_record(g_out_lea, ctx.legacy_record(), 2, 10);
}

static void
watchdog_thread(void *)
{
    dr_client_thread_set_suspendable(false);
    dr_sleep((uint64)op_timeout.get_value() * 1000);
    dr_exit_process(0);
}

static void
event_exit(void)
{
    if (g_out     != INVALID_FILE) dr_close_file(g_out);
    if (g_out_lea != INVALID_FILE) dr_close_file(g_out_lea);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("libdft-dta-dr (vuzzer cmp/lea sink)",
                       "https://github.com/tosanjay/libdft-dr");

    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv,
                                       &parse_err, NULL)) {
        dr_fprintf(STDERR, "[vuzzer_cmp_sink] option parse error: %s\n",
                   parse_err.c_str());
    }

    g_out     = dr_open_file(op_cmpfile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);
    g_out_lea = dr_open_file(op_leafile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);
    g_maxoff  = op_maxoff.get_value();
    dr_register_exit_event(event_exit);

    /* Layer-1 init. */
    libdft_dr::init_options_t opts;
    opts.mmap_paint_method    = op_mmap.get_value();
    opts.max_offset_per_byte  = op_maxoff.get_value();
    if (!libdft_dr::init(opts)) {
        dr_fprintf(STDERR, "[vuzzer_cmp_sink] libdft_dr::init failed\n");
        dr_exit_process(1);
    }

    /* Layer-3 file source. */
    libdft_dr::file_source_options_t fopts;
    fopts.filename = op_filename.get_value();
    libdft_dr::register_file_source(fopts);

    /* Layer-3 sinks. */
    libdft_dr::register_sink(libdft_dr::opcode_class::CMP, on_cmp_sink);
    libdft_dr::register_sink(libdft_dr::opcode_class::LEA, on_lea_sink);

    if (op_timeout.get_value() > 0)
        dr_create_client_thread(watchdog_thread, NULL);
}
