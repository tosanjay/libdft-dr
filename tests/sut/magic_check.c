/* tests/sut/magic_check.c -- tiny CI SUT for libdft-dr regression tests.
 *
 * Reads the input file, CMPs the first 4 bytes against constants, prints
 * the match count. Deterministic, no external deps. Used by the CI parity
 * check: vuzzer_cmp_sink emits cmp.out records tainted at offsets {0,1,2,3}.
 *
 * Build: cc -O0 -o magic_check magic_check.c
 * Run:   magic_check tests/seeds/tiny.bin
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t buf[8];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 4) { fprintf(stderr, "file too short\n"); return 1; }

    /* CMP each of the first 4 input bytes against a distinct constant.
     * Each CMP becomes a cmp.out record tainted at offset {i}. */
    int matches = 0;
    if (buf[0] == 0xAA) matches++;
    if (buf[1] == 0xBB) matches++;
    if (buf[2] == 0xCC) matches++;
    if (buf[3] == 0xDD) matches++;

    printf("%d\n", matches);
    return 0;
}
