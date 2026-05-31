/* libdft-dta-dr -- DynamoRIO port of libdft64's taint tracker (C.4).
 *
 * PHASE 2: source-painting foundation. Hooks the input-read syscalls
 * (read, pread64, open, openat, dup, close, mmap, munmap), paints shadow at
 * taint sources exactly as the Pin engine does, and tears down cleanly. There
 * are NO opcode handlers yet, so cmp.out / lea.out are created but stay empty.
 * Opcode-level taint propagation arrives in Phases 3-5.
 *
 * The canonical engine remains libdft64/ (Pin); that tree is the A/B baseline.
 *
 * Options (kept byte-compatible with the Pin tool's KNOBs and runfuzzer's
 * DRTNTCMD): -o <cmp.out> -leao <lea.out> -filename <path> -x <timeout-secs>.
 * The maxoff/mmap knobs default to the Pin values (4, 1).
 */
#include <string>
#include "dr_api.h"
#include "droption.h"

#include "libdft_api_dr.h"
#include "osutils_dr.h"

using namespace dynamorio::droption;

static droption_t<std::string> op_cmpfile(
    DROPTION_SCOPE_CLIENT, "o", "cmp.out", "CMP taint output file",
    "Path for per-CMP taint records (libdft64 cmp.out equivalent).");
static droption_t<std::string> op_leafile(
    DROPTION_SCOPE_CLIENT, "leao", "lea.out", "LEA taint output file",
    "Path for per-LEA taint records (libdft64 lea.out equivalent).");
static droption_t<std::string> op_filename(
    DROPTION_SCOPE_CLIENT, "filename", "", "Tainted input filename",
    "Input file whose bytes are taint sources.");
static droption_t<int> op_timeout(
    DROPTION_SCOPE_CLIENT, "x", 0, "Watchdog timeout (seconds)",
    "Kill the app after this many seconds; 0 disables. The Python run() "
    "wrapper is the primary timeout enforcer.");
static droption_t<int> op_maxoff(
    DROPTION_SCOPE_CLIENT, "maxoff", 4, "Tracked taint width per byte",
    "How many bytes of taint to track per byte (Pin default 4).");
static droption_t<int> op_mmap(
    DROPTION_SCOPE_CLIENT, "mmap", 1, "mmap taint-spread method",
    "Method used to spread taint through mmap (Pin default 1).");

static void
watchdog_thread(void *arg)
{
    dr_client_thread_set_suspendable(false);
    dr_sleep((uint64)op_timeout.get_value() * 1000); /* seconds -> ms */
    dr_exit_process(0);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("libdft-dta-dr (Phase 2: source painting)",
                       "https://github.com/tosanjay/libdft-dr");
    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv,
                                       &parse_err, NULL)) {
        dr_fprintf(STDERR, "[libdft-dta-dr] option parse error: %s\n",
                   parse_err.c_str());
    }

    /* cmp.out / lea.out: truncate to empty (Phase 2 emits no records, but the
     * Python read_taint() expects the files to exist). DR file API -- see the
     * note in libdft_api_dr.h on why not std::ofstream. */
    out = dr_open_file(op_cmpfile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);
    out_lea = dr_open_file(op_leafile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);

    filename = op_filename.get_value();
    limit_offset = op_maxoff.get_value();
    mmap_type = (op_mmap.get_value() != 0);

    libdft_setup();

    if (op_timeout.get_value() > 0)
        dr_create_client_thread(watchdog_thread, NULL);
}
