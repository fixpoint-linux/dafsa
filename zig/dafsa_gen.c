/* dafsa_gen.c — Deterministic op-script generator for the differential harness.
 *
 * Emits a U3-style interleaved add/lookup/del script with stats snapshots,
 * using rand_r(seed) for full reproducibility.  Keys are drawn from a
 * 3-symbol alphabet (0x61/0x62/0x63 = 'a'/'b'/'c') to force heavy confluence
 * (shared sub-automata, clone-on-write, register merges).  Built with gcc;
 * the SAME generated script is fed to both the C and Zig drivers, so only
 * the generator's own determinism matters (rand_r is deterministic per-seed).
 *
 * Usage: ./dafsa_gen <seed> <nops>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int seed = (argc > 1) ? (unsigned int)strtoul(argv[1], NULL, 10) : 1u;
    long nops = (argc > 2) ? strtol(argv[2], NULL, 10) : 5000;
    unsigned int state = seed;
    const unsigned char alpha[3] = { 0x61, 0x62, 0x63 };

    printf("create\n");
    long since_stats = 0;
    for (long i = 0; i < nops; i++) {
        int r = rand_r(&state) % 100;
        /* key length 1..8 bytes (2..16 hex chars) — short enough to fit the
         * C driver's 4095-char fgets window, so no truncation divergence. */
        int klen = 1 + (rand_r(&state) % 8);
        char hex[40];
        for (int k = 0; k < klen; k++) {
            unsigned char b = alpha[rand_r(&state) % 3];
            sprintf(hex + k * 2, "%02x", b);
        }
        hex[klen * 2] = '\0';
        const char *op;
        if (r < 60) op = "add";        /* 60% add — grows the DAFSA */
        else if (r < 80) op = "lookup"; /* 20% lookup */
        else op = "del";               /* 20% del — exercises re-add/ghost paths */
        printf("%s %s\n", op, hex);
        since_stats++;
        if (since_stats >= 500) { printf("stats\n"); since_stats = 0; }
    }
    printf("stats\nfree\n");
    return 0;
}
