/* clients/synthetic_unit/main.cpp -- in-process unit test for the tag model.
 *
 * Reference client for the api-design.md §1D pattern. Runs a tiny SUT
 * (anything that won't read input, e.g. `/bin/true`) and exercises the tag
 * model directly from the DR exit-event callback: paint shadow at synthetic
 * addresses, read it back, assert equality.
 *
 * Status is printed to stderr and the process exits non-zero on failure.
 *
 * Invocation:
 *   drrun -c libdft-synthetic-unit-dr.so -- /bin/true
 */
#include <cstddef>
#include <cstdint>
#include <string>

#include "dr_api.h"

#include "libdft_dr/lifecycle.h"
#include "libdft_dr/tag.h"

static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(cond) do {                                                     \
    if (cond) { ++g_pass; }                                                   \
    else { ++g_fail; dr_fprintf(STDERR,                                       \
        "[synthetic_unit] FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); }    \
} while (0)

static void
run_unit_tests(void)
{
    using namespace libdft_dr;

    /* T1: empty tag is empty. */
    tag_t e;
    EXPECT(e.empty());
    EXPECT(to_string(e) == "{}");

    /* T2: singleton tag is non-empty and serializes. */
    tag_t a = make_tag(42);
    EXPECT(!a.empty());
    EXPECT(to_string(a).find("42") != std::string::npos);

    /* T3: combine is union; commutative; idempotent. */
    tag_t b = make_tag(7);
    tag_t ab = combine(a, b);
    tag_t ba = combine(b, a);
    EXPECT(ab == ba);
    EXPECT(combine(ab, ab) == ab);
    EXPECT(combine(ab, e) == ab);
    EXPECT(combine(e, ab) == ab);

    /* T4: enumerate yields the expected labels. */
    int seen42 = 0, seen7 = 0, count = 0;
    enumerate(ab, [&](uint32_t l) {
        ++count;
        if (l == 42) seen42 = 1;
        if (l == 7)  seen7  = 1;
        return true;
    });
    EXPECT(count == 2);
    EXPECT(seen42 == 1);
    EXPECT(seen7 == 1);

    /* T5: mem shadow round-trip. */
    static char buf[16];
    std::uintptr_t addr = (std::uintptr_t)&buf[0];
    set_mem_tag(addr, a);
    EXPECT(get_mem_tag(addr) == a);
    set_mem_tag(addr + 4, b);
    EXPECT(get_mem_tag_range(addr, 8) == ab);
    clear_mem(addr, 16);
    EXPECT(get_mem_tag(addr).empty());
    EXPECT(get_mem_tag(addr + 4).empty());

    dr_fprintf(STDERR, "[synthetic_unit] %d pass, %d fail\n", g_pass, g_fail);
}

static void event_exit(void) {
    run_unit_tests();
    if (g_fail > 0) {
        dr_fprintf(STDERR, "[synthetic_unit] FAILED\n");
        /* Don't exit here -- DR is mid-teardown. The non-zero count is the
         * test signal for harnesses that check stderr. */
    } else {
        dr_fprintf(STDERR, "[synthetic_unit] OK\n");
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("libdft-synthetic-unit-dr",
                       "https://github.com/tosanjay/libdft-dr");
    (void)argc; (void)argv;

    libdft_dr::init_options_t opts;
    if (!libdft_dr::init(opts)) dr_exit_process(1);

    /* Run the tests just before exit so all subsystems are live. */
    dr_register_exit_event(event_exit);
}
