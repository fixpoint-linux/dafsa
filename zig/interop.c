/* interop.c — U9 cross-engine file interop check.
 *
 * One source, TWO builds:
 *   (a) C engine   (static link against the carrasco .c files)
 *   (b) Zig engine (dynamic link against zig/lib/libdafsa.so)
 *
 * Usage:
 *   interop w <prefix>   — build a 300-key DAFSA (290 plain + 10 embedded-NUL
 *                          keys), save <prefix>.pdwg, write <prefix>.wal with
 *                          12 overlay-form ops (4 DEL + 8 ADD).
 *   interop r <prefix>   — load <prefix>.pdwg three ways (dafsa_load,
 *                          dafsa_load_readonly, dafsa_view_open), verify every
 *                          key, replay <prefix>.wal (12 records), open the
 *                          layered view and verify overlay semantics
 *                          (4 DEL misses, 8 ADD hits).
 *
 * Matrix: w(C)→r(Zig), w(Zig)→r(C); the two .pdwg/.wal pairs must also be
 * byte-identical to each other.
 */
#include "dafsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int fails;

static void chk(int cond, const char *msg) {
    if (!cond) {
        printf("FAIL: %s\n", msg);
        fails++;
    }
}

static int replay_cb(uint8_t op, const unsigned char *key, uint32_t len, void *user) {
    (void)op; (void)key; (void)len;
    (*(int *)user)++;
    return 0;
}

/* Overlay-form key: word "ov-" + NUL + 8-byte payload (12 bytes total).
 * Payload differs per i so bucket slots stay distinct. */
static void ovkey(unsigned char *rec, int i) {
    rec[0] = 'o'; rec[1] = 'v'; rec[2] = '-'; rec[3] = 0;
    rec[4] = 'P'; rec[5] = (unsigned char)i; rec[6] = 0xAA;
    rec[7] = 0; rec[8] = 0; rec[9] = 0; rec[10] = 0;
    rec[11] = (unsigned char)(i + 1);
}

int main(int argc, char **argv) {
    char pdwg[512], walp[512];
    dafsa *d;

    if (argc != 3) { fprintf(stderr, "usage: interop w|r <prefix>\n"); return 2; }
    snprintf(pdwg, sizeof pdwg, "%s.pdwg", argv[2]);
    snprintf(walp, sizeof walp, "%s.wal", argv[2]);

    if (argv[1][0] == 'w') {
        dafsa_wal *w;
        char k[64];
        unsigned char rec[12];
        uint32_t nkeys = 0;
        int i;

        d = dafsa_create();
        chk(d != NULL, "create");
        /* 290 distinct plain keys (7i mod 1000 keeps the numeric field
         * distinct for i < 143 and the letter fields break the rest) */
        for (i = 0; i < 290; i++) {
            snprintf(k, sizeof k, "word-%04d-%c%c", i * 7 % 1000,
                     (char)('a' + i % 26), (char)('a' + (i * 3) % 26));
            if (dafsa_add(d, (const unsigned char *)k) == 1) nkeys++;
        }
        /* 10 embedded-NUL keys: "nu\0<digit>z<EE>" */
        for (i = 0; i < 10; i++) {
            unsigned char nk[6];
            nk[0] = 'n'; nk[1] = 'u'; nk[2] = 0;
            nk[3] = (unsigned char)('0' + i); nk[4] = 'z'; nk[5] = 0xEE;
            if (dafsa_add_n(d, nk, 6) == 1) nkeys++;
        }
        chk(nkeys == 300, "300 keys added");
        chk(dafsa_save(d, pdwg) == 0, "save pdwg");

        w = dafsa_wal_open_rw(walp);
        chk(w != NULL, "wal open");
        for (i = 0; i < 12; i++) {
            ovkey(rec, i);
            if (i < 4)
                chk(dafsa_wal_append_del(w, rec, 12) == 0, "wal del");
            else
                chk(dafsa_wal_append_add(w, rec, 12) == 0, "wal add");
        }
        chk(dafsa_wal_sync(w) == 0, "wal sync");
        dafsa_wal_close(w);
        dafsa_free(d);
        printf("WROTE %s + %s (300 keys, 12 wal ops) fails=%d\n", pdwg, walp, fails);
        return fails ? 1 : 0;
    }

    /* ── read/verify mode ─────────────────────────────────────────────── */
    {
        char k[64];
        dafsa_view *v, *lv;
        dafsa_wal *w;
        int count = 0, i;
        dafsa_stats_out st;

        d = dafsa_load(pdwg);
        chk(d != NULL, "load");
        dafsa_stats(d, &st);
        chk(st.n_final >= 1, "stats sane");
        for (i = 0; i < 290; i++) {
            snprintf(k, sizeof k, "word-%04d-%c%c", i * 7 % 1000,
                     (char)('a' + i % 26), (char)('a' + (i * 3) % 26));
            if (dafsa_lookup(d, (const unsigned char *)k) != 1) {
                printf("FAIL: plain key %s\n", k);
                fails++;
                break;
            }
        }
        chk(fails == 0, "all 290 plain keys lookup");
        for (i = 0; i < 10; i++) {
            unsigned char nk[6];
            nk[0] = 'n'; nk[1] = 'u'; nk[2] = 0;
            nk[3] = (unsigned char)('0' + i); nk[4] = 'z'; nk[5] = 0xEE;
            chk(dafsa_lookup_n(d, nk, 6) == 1, "embedded-NUL key lookup");
        }
        dafsa_free(d);

        d = dafsa_load_readonly(pdwg);
        chk(d != NULL, "load_readonly");
        chk(dafsa_lookup(d, (const unsigned char *)"word-0000-aa") == 1, "ro lookup");
        dafsa_free(d);

        v = dafsa_view_open(pdwg);
        chk(v != NULL, "view_open");
        chk(dafsa_view_lookup_n(v, (const unsigned char *)"word-0000-aa", 12) == 1,
            "view lookup hit");
        chk(dafsa_view_lookup_n(v, (const unsigned char *)"word-9999-zz", 12) == 0,
            "view lookup miss");
        dafsa_view_close(v);

        w = dafsa_wal_open_ro(walp);
        chk(w != NULL, "wal ro open");
        chk(dafsa_wal_replay(w, replay_cb, &count) == 0, "replay");
        chk(count == 12, "12 wal records");
        dafsa_wal_close(w);

        lv = dafsa_view_open_layered(pdwg, walp);
        chk(lv != NULL, "layered open");
        {
            unsigned char rec[12];
            int hits = 0, misses = 0;
            for (i = 0; i < 12; i++) {
                ovkey(rec, i);
                if (dafsa_view_lookup_n(lv, rec, 12) == 1) hits++; else misses++;
            }
            chk(hits == 8 && misses == 4, "layered 8 ADD hits / 4 DEL misses");
        }
        dafsa_view_close(lv);

        if (fails) { printf("INTEROP READ FAILED (%d)\n", fails); return 1; }
        printf("INTEROP READ OK (%s)\n", pdwg);
    }
    return 0;
}
