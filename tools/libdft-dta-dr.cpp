/* libdft-dta-dr -- DynamoRIO port of libdft64's taint tracker (C.4).
 *
 * PHASE 0 STUB. No taint propagation, no syscall hooks, no opcode handlers.
 * It only stands up the DR client lifecycle (drmgr + drreg) and the two
 * output-file knobs (-o cmp.out, -leao lea.out) so the runfuzzer --mode dr
 * taint path round-trips and produces empty-but-present output files.
 *
 * The canonical engine remains libdft64/ (Pin). This tree is filled in
 * across Phases 2-5 of c4_dr_port_plan.md; until then it is a no-op.
 */
#include <string>
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "droption.h"

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
    DROPTION_SCOPE_CLIENT, "x", 0, "Per-input timeout (seconds)",
    "Watchdog timeout; 0 disables. Parsed for parity with the Pin tool.");

static void
truncate_output(const std::string &path)
{
    if (path.empty())
        return;
    file_t f = dr_open_file(path.c_str(), DR_FILE_WRITE_OVERWRITE);
    if (f != INVALID_FILE)
        dr_close_file(f);
}

static void
event_exit(void)
{
    /* Phase 0: emit empty output files so the Python parser sees a
     * present-but-empty cmp.out/lea.out (read_taint treats that as
     * "no taint", which is the correct no-op semantics). */
    truncate_output(op_cmpfile.get_value());
    truncate_output(op_leafile.get_value());
    drreg_exit();
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("libdft-dta-dr (Phase 0 stub)",
                       "https://github.com/tosanjay/vuzzer64-v2");
    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv,
                                       &parse_err, NULL)) {
        dr_fprintf(STDERR, "[libdft-dta-dr] option parse error: %s\n",
                   parse_err.c_str());
    }
    drmgr_init();
    drreg_options_t ops = { sizeof(ops), 3 /*max slots*/, false };
    drreg_init(&ops);
    dr_register_exit_event(event_exit);
}
