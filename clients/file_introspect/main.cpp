/* clients/file_introspect/main.cpp -- "what input bytes fed this PC?".
 *
 * Reference client for the api-design.md §1A pattern. Paints a file via the
 * built-in source, then dumps the per-byte tag of one or two memory regions
 * each time control hits a specified PC range.
 *
 * Invocation:
 *   drrun -c libdft-introspect-dr.so \
 *     -filename /path/to/input -lo 0x401000 -hi 0x401100 \
 *     -addr1 0x7fff... -size1 16 -- /path/to/target
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
    DROPTION_SCOPE_CLIENT, "filename", "", "Tainted input filename", "");
static droption_t<uint64> op_lo(
    DROPTION_SCOPE_CLIENT, "lo", 0, "Sink PC range low", "");
static droption_t<uint64> op_hi(
    DROPTION_SCOPE_CLIENT, "hi", 0, "Sink PC range high (exclusive)", "");
static droption_t<uint64> op_addr1(
    DROPTION_SCOPE_CLIENT, "addr1", 0, "Memory region 1 base", "");
static droption_t<uint64> op_size1(
    DROPTION_SCOPE_CLIENT, "size1", 0, "Memory region 1 size", "");
static droption_t<uint64> op_addr2(
    DROPTION_SCOPE_CLIENT, "addr2", 0, "Memory region 2 base", "");
static droption_t<uint64> op_size2(
    DROPTION_SCOPE_CLIENT, "size2", 0, "Memory region 2 size", "");
static droption_t<std::string> op_outfile(
    DROPTION_SCOPE_CLIENT, "o", "introspect.out",
    "Output file (per-hit dump)", "");

static file_t g_out = INVALID_FILE;

static void
on_pc_hit(const libdft_dr::sink_context_t &ctx) {
    if (g_out == INVALID_FILE) return;
    auto dump = [](file_t f, const char *label,
                   std::uintptr_t addr, std::size_t n) {
        if (n == 0 || addr == 0) return;
        libdft_dr::tag_t t = libdft_dr::get_mem_tag_range(addr, n);
        std::string s = libdft_dr::to_string(t);
        char hdr[128];
        snprintf(hdr, sizeof(hdr), "%s [0x%lx..+%zu] -> ",
                 label, (unsigned long)addr, n);
        dr_write_file(f, hdr, strlen(hdr));
        dr_write_file(f, s.data(), s.size());
        dr_write_file(f, "\n", 1);
    };
    char hdr[64];
    snprintf(hdr, sizeof(hdr), "hit pc=0x%lx\n", (unsigned long)ctx.pc);
    dr_write_file(g_out, hdr, strlen(hdr));
    dump(g_out, "  region1", (std::uintptr_t)op_addr1.get_value(),
         (std::size_t)op_size1.get_value());
    dump(g_out, "  region2", (std::uintptr_t)op_addr2.get_value(),
         (std::size_t)op_size2.get_value());
}

static void event_exit(void) {
    if (g_out != INVALID_FILE) dr_close_file(g_out);
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("libdft-introspect-dr",
                       "https://github.com/tosanjay/libdft-dr");
    std::string err;
    droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &err, NULL);

    g_out = dr_open_file(op_outfile.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);
    dr_register_exit_event(event_exit);

    libdft_dr::init_options_t opts;
    if (!libdft_dr::init(opts)) dr_exit_process(1);

    if (!op_filename.get_value().empty()) {
        libdft_dr::file_source_options_t f;
        f.filename = op_filename.get_value();
        libdft_dr::register_file_source(f);
    }

    if (op_hi.get_value() > op_lo.get_value()) {
        libdft_dr::register_pc_range_sink(
            (app_pc)op_lo.get_value(),
            (app_pc)op_hi.get_value(),
            on_pc_hit);
    } else {
        dr_fprintf(STDERR, "[file_introspect] no PC range given; nothing to do\n");
    }
}
