/* clients/egress_sanitizer/main.cpp -- "did secrets just leave the box?".
 *
 * Reference client for the api-design.md §1B pattern. Paints a file via the
 * built-in source, then alerts when the buffer passed to write() contains
 * any tainted byte.
 *
 * Invocation:
 *   drrun -c libdft-egress-dr.so \
 *     -filename /etc/passwd -- /path/to/program
 *
 * Output: one line per offending write() to stderr (and -o file if given):
 *   ALERT: write(fd=N, buf=0x..., n=M) -- tainted bytes {1,2,5,...}
 *
 * v0.1 LIMITATION: glibc's `write` is an IFUNC (indirect function); a naive
 * drsym_lookup_symbol may resolve to the resolver stub rather than the
 * concrete entry, in which case drwrap_get_arg returns garbage and the
 * callback faults. Workarounds for v0.2:
 *   (a) wrap a non-IFUNC symbol like `__GI___libc_write`, or
 *   (b) wrap by name via the existing sdft_hook IFUNC-resolution logic.
 * The source here demonstrates the API; the live demo is a v0.2 polish item.
 */
#include <cstdint>
#include <string>

#include "dr_api.h"
#include "droption.h"

#include "libdft_dr/lifecycle.h"
#include "libdft_dr/sinks.h"
#include "libdft_dr/sources.h"
#include "libdft_dr/tag.h"

using namespace dynamorio::droption;

static droption_t<std::string> op_filename(
    DROPTION_SCOPE_CLIENT, "filename", "",
    "Tainted input filename (substring match)", "");
static droption_t<std::string> op_outfile(
    DROPTION_SCOPE_CLIENT, "o", "", "Alert log file (default stderr)", "");

static file_t g_out = INVALID_FILE;
static unsigned long g_alerts = 0;

static void
on_write(const libdft_dr::func_sink_context_t &ctx) {
    std::uintptr_t buf = ctx.arg(1);
    std::size_t    n   = (std::size_t)ctx.arg(2);
    if (n == 0 || buf == 0) return;
    if (!ctx.arg_pointed_is_tainted(1, n)) return;

    libdft_dr::tag_t t = ctx.arg_pointed_tag(1, n);
    std::string labels = libdft_dr::to_string(t);
    char line[512];
    int len = snprintf(line, sizeof(line),
        "ALERT: write(fd=%ld, buf=0x%lx, n=%zu) -- tainted bytes %s\n",
        (long)ctx.arg(0), (unsigned long)buf, n, labels.c_str());
    if (len > 0) {
        if (g_out != INVALID_FILE) dr_write_file(g_out, line, len);
        dr_fprintf(STDERR, "%s", line);
    }
    g_alerts++;
}

static void event_exit(void) {
    dr_fprintf(STDERR, "[egress_sanitizer] %lu alert(s) fired\n", g_alerts);
    if (g_out != INVALID_FILE) dr_close_file(g_out);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("libdft-egress-dr",
                       "https://github.com/tosanjay/libdft-dr");
    std::string err;
    droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &err, NULL);

    if (!op_outfile.get_value().empty())
        g_out = dr_open_file(op_outfile.get_value().c_str(),
                             DR_FILE_WRITE_OVERWRITE);
    dr_register_exit_event(event_exit);

    libdft_dr::init_options_t opts;
    if (!libdft_dr::init(opts)) dr_exit_process(1);

    if (!op_filename.get_value().empty()) {
        libdft_dr::file_source_options_t f;
        f.filename = op_filename.get_value();
        libdft_dr::register_file_source(f);
    }

    /* Wrap write() in libc. */
    libdft_dr::register_func_sink("write", "libc.so.6", on_write);
}
