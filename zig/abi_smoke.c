/* abi_smoke.c — U9 C-ABI smoke test.
 *
 * ONE source, TWO links:
 *   (a) C engine:   gcc -I.. abi_smoke.c ../dafsa*.c -o ref_smoke
 *   (b) Zig engine: gcc -I.. abi_smoke.c -L lib -ldafsa -Wl,-rpath,.../lib
 * Run each in its own workdir; stdout and every file written must be
 * byte-identical between the two builds (differential ABI gate).
 *
 * Language under test (7 keys): {"a\0c", "abc", "abd", "p\0x", "p\0y", "p\0z",
 * "q\0x"} plus empty and "xy" added-then-deleted along the way.
 * Sorted order: a\0c < abc < abd < p\0x < p\0y < p\0z < q\0x.
 *
 * Exercises EVERY exported symbol: create/free/abi, add/lookup/delete (+_n,
 * NUL-terminated twins, NULL guards), build_sorted, prefix_enum (full + early
 * stop + NULL cb), save/load/load_readonly, stats, dot (FILE*), view_open/
 * close/lookup_n/prefix_enum/open_layered, wal_open/_rw/_ro/append_add/
 * append_del/sync/size/replay/close, rank_n/rank_from/select_n/select_from/
 * range_count_n/range_count_from, ensure_subtree, view_subtree_counts
 * (free()d with the consumer's libc free — proves heap interop),
 * view_rank_n/view_select_n/view_range_count_n.
 */
#include "dafsa.h"
#include "dafsa_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void chk(int cond, const char *msg) {
    printf("%s: %s\n", cond ? "ok" : "FAIL", msg);
    if (!cond) fails++;
}

static long g_enum_count;
static int enum_cb(const unsigned char *p, size_t n, void *user) {
    (void)user;
    g_enum_count++;
    printf("  enum[%ld] len=%zu %02x%02x%02x\n", g_enum_count, n,
           n > 0 ? p[0] : 0, n > 1 ? p[1] : 0, n > 2 ? p[2] : 0);
    return 0;
}
static int enum_stop_cb(const unsigned char *p, size_t n, void *user) {
    (void)p; (void)n; (void)user;
    return 1; /* early stop */
}

static int g_replay_count;
static int replay_cb(uint8_t op, const unsigned char *key, uint32_t len, void *user) {
    (void)user;
    g_replay_count++;
    printf("  replay op=%u len=%u %02x%02x\n", op, len,
           len > 0 ? key[0] : 0, len > 1 ? key[1] : 0);
    return 0;
}

int main(int argc, char **argv) {
    const char *wd = argc > 1 ? argv[1] : ".";
    char path[512];
    dafsa_stats_out st, bst;
    dafsa *d, *e;
    dafsa_view *v;
    dafsa_wal *w;
    unsigned char ko[64];
    FILE *f;
    int rn;

    chk(dafsa_abi_version() == DAFSA_ABI_VERSION, "abi version");

    /* ── lifecycle + key ops (embedded NUL, empty, NULL guards) ─────────── */
    d = dafsa_create();
    chk(d != NULL, "create");
    chk(dafsa_add_n(d, (const unsigned char *)"abc", 3) == 1, "add_n abc");
    chk(dafsa_add_n(d, (const unsigned char *)"abd", 3) == 1, "add_n abd");
    chk(dafsa_add_n(d, (const unsigned char *)"abc", 3) == 0, "add_n abc dup");
    chk(dafsa_add_n(d, (const unsigned char *)"a\0c", 3) == 1, "add_n a-NUL-c");
    chk(dafsa_add_n(d, NULL, 4) == -1, "add_n NULL+len -> -1");
    chk(dafsa_lookup_n(d, (const unsigned char *)"abc", 3) == 1, "lookup_n abc");
    chk(dafsa_lookup_n(d, (const unsigned char *)"a\0c", 3) == 1, "lookup_n a-NUL-c");
    chk(dafsa_lookup_n(d, (const unsigned char *)"ab", 2) == 0, "lookup_n prefix-only");
    chk(dafsa_lookup_n(d, NULL, 5) == 0, "lookup_n NULL+len -> 0");
    chk(dafsa_add_n(d, (const unsigned char *)"", 0) == 1, "add_n empty");
    chk(dafsa_lookup_n(d, (const unsigned char *)"", 0) == 1, "lookup_n empty");
    chk(dafsa_delete_n(d, (const unsigned char *)"", 0) == 1, "delete_n empty");
    chk(dafsa_lookup_n(d, (const unsigned char *)"", 0) == 0, "lookup_n empty gone");
    chk(dafsa_delete_n(d, (const unsigned char *)"zzz", 3) == 0, "delete_n absent");
    chk(dafsa_delete_n(d, NULL, 2) == -1, "delete_n NULL+len -> -1");

    /* NUL-terminated twins */
    chk(dafsa_add(d, (const unsigned char *)"xy") == 1, "add xy");
    chk(dafsa_lookup(d, (const unsigned char *)"xy") == 1, "lookup xy");
    chk(dafsa_lookup(d, (const unsigned char *)"xyz") == 0, "lookup xyz");
    chk(dafsa_delete(d, (const unsigned char *)"xy") == 1, "delete xy");
    chk(dafsa_delete(d, (const unsigned char *)"xy") == 0, "delete xy again");

    /* W\0 payload families for prefix_enum */
    chk(dafsa_add_n(d, (const unsigned char *)"p\0x", 3) == 1, "add_n p-NUL-x");
    chk(dafsa_add_n(d, (const unsigned char *)"p\0y", 3) == 1, "add_n p-NUL-y");
    chk(dafsa_add_n(d, (const unsigned char *)"p\0z", 3) == 1, "add_n p-NUL-z");
    chk(dafsa_add_n(d, (const unsigned char *)"q\0x", 3) == 1, "add_n q-NUL-x");

    /* ── stats ──────────────────────────────────────────────────────────── */
    dafsa_stats(d, &st);
    printf("stats: %u %u %u %u %llu\n", st.n_states_total, st.n_states_reachable,
           st.n_final, st.n_trans, (unsigned long long)st.register_probes);
    /* minimal DAFSA: all 7 key-end leaves merge into ONE shared final sink
     * (n_final == 1); the key COUNT (7) is proven via rank/select and
     * view_subtree_counts below */
    chk(st.n_final == 1, "stats n_final == 1 (shared final sink)");
    dafsa_stats(NULL, &st);
    dafsa_stats(d, NULL);

    /* ── prefix_enum (W\0 semantics + user data + early stop) ───────────── */
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"a", 1, enum_cb, &fails);
    chk(rn == 1, "prefix_enum a -> 1 (a-NUL-c)");
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"p", 1, enum_cb, &fails);
    chk(rn == 3, "prefix_enum p -> 3");
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"q", 1, enum_cb, &fails);
    chk(rn == 1, "prefix_enum q -> 1");
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"r", 1, enum_cb, &fails);
    chk(rn == 0, "prefix_enum r -> 0");
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"ab", 2, enum_cb, &fails);
    chk(rn == 0, "prefix_enum ab -> 0 (no 0x00 edge)");
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"p", 1, NULL, &fails);
    chk(rn == -1, "prefix_enum NULL cb -> -1");
    g_enum_count = 0;
    rn = (int)dafsa_prefix_enum(d, (const unsigned char *)"p", 1, enum_stop_cb, &fails);
    chk(rn == 1, "prefix_enum early-stop -> 1");

    /* ── save / load / load_readonly ────────────────────────────────────── */
    snprintf(path, sizeof path, "%s/a.pdwg", wd);
    chk(dafsa_save(d, path) == 0, "save a.pdwg");
    chk(dafsa_save(NULL, path) == -1, "save NULL dafsa");
    chk(dafsa_save(d, NULL) == -1, "save NULL path");
    e = dafsa_load(path);
    chk(e != NULL, "load a.pdwg");
    chk(dafsa_lookup_n(e, (const unsigned char *)"abc", 3) == 1, "load lookup abc");
    chk(dafsa_lookup_n(e, (const unsigned char *)"a\0c", 3) == 1, "load lookup a-NUL-c");
    chk(dafsa_lookup_n(e, (const unsigned char *)"p\0y", 3) == 1, "load lookup p-NUL-y");
    dafsa_free(e);
    e = dafsa_load_readonly(path);
    chk(e != NULL, "load_readonly a.pdwg");
    chk(dafsa_lookup_n(e, (const unsigned char *)"abd", 3) == 1, "loadro lookup abd");
    dafsa_free(e);
    chk(dafsa_load("/nonexistent/x.pdwg") == NULL, "load missing -> NULL");

    /* ── dot (FILE* + format) ───────────────────────────────────────────── */
    snprintf(path, sizeof path, "%s/a.dot", wd);
    f = fopen(path, "w");
    chk(f != NULL, "fopen a.dot");
    dafsa_dot(d, f);
    fclose(f);
    dafsa_dot(d, NULL);
    dafsa_dot(NULL, stdout);

    /* ── build_sorted (same language) ───────────────────────────────────── */
    {
        const unsigned char *keys[] = {
            (const unsigned char *)"a\0c",
            (const unsigned char *)"abc",
            (const unsigned char *)"abd",
            (const unsigned char *)"p\0x",
            (const unsigned char *)"p\0y",
            (const unsigned char *)"p\0z",
            (const unsigned char *)"q\0x",
        };
        size_t lens[7] = { 3, 3, 3, 3, 3, 3, 3 };
        e = dafsa_build_sorted(keys, lens, 7);
        chk(e != NULL, "build_sorted 7 keys");
        dafsa_stats(e, &bst);
        printf("build stats: %u %u %u %u %llu\n", bst.n_states_total,
               bst.n_states_reachable, bst.n_final, bst.n_trans,
               (unsigned long long)bst.register_probes);
        /* C engine: build_sorted is MORE compact than the incremental
         * register path (9 vs 11 reachable states here) — the language
         * itself must match exactly */
        chk(bst.n_final == st.n_final, "build n_final == incremental");
        chk(dafsa_rank_n(e, (const unsigned char *)"zz", 2) == 7,
            "build language == 7 keys");
        chk(dafsa_select_n(e, 6, ko, sizeof ko) == 3 &&
            memcmp(ko, "q\0x", 3) == 0, "build select 6 == q-NUL-x");
        chk(dafsa_lookup_n(e, (const unsigned char *)"a\0c", 3) == 1, "build lookup a-NUL-c");
        snprintf(path, sizeof path, "%s/b.pdwg", wd);
        chk(dafsa_save(e, path) == 0, "build save b.pdwg");
        dafsa_free(e);
        e = dafsa_build_sorted(NULL, NULL, 0);
        chk(e != NULL, "build_sorted nkeys=0");
        dafsa_stats(e, &bst);
        chk(bst.n_final == 0 && bst.n_states_reachable == 1, "empty build stats");
        dafsa_free(e);
        chk(dafsa_build_sorted(NULL, lens, 7) == NULL, "build_sorted NULL keys -> NULL");
    }

    /* ── rank / select / range_count (+ _from, ensure_subtree) ──────────── */
    chk(dafsa_rank_n(d, (const unsigned char *)"abc", 3) == 1, "rank abc == 1");
    chk(dafsa_rank_n(d, (const unsigned char *)"p\0y", 3) == 4, "rank p-NUL-y == 4");
    chk(dafsa_rank_n(d, (const unsigned char *)"zz", 2) == 7, "rank zz == 7");
    chk(dafsa_rank_n(d, (const unsigned char *)"", 0) == 0, "rank empty == 0");
    rn = dafsa_select_n(d, 0, ko, sizeof ko);
    chk(rn == 3 && memcmp(ko, "a\0c", 3) == 0, "select 0 == a-NUL-c");
    rn = dafsa_select_n(d, 1, ko, sizeof ko);
    chk(rn == 3 && memcmp(ko, "abc", 3) == 0, "select 1 == abc");
    rn = dafsa_select_n(d, 6, ko, sizeof ko);
    chk(rn == 3 && memcmp(ko, "q\0x", 3) == 0, "select 6 == q-NUL-x");
    chk(dafsa_select_n(d, 6, ko, 2) == -1, "select cap too small -> -1");
    chk(dafsa_select_n(d, 7, ko, sizeof ko) == -1, "select k==total -> -1");
    chk(dafsa_range_count_n(d, (const unsigned char *)"a", 1,
                               (const unsigned char *)"b", 1) == 3, "rancount [a,b) == 3");
    chk(dafsa_range_count_n(d, (const unsigned char *)"b", 1,
                               (const unsigned char *)"z", 1) == 4, "rancount [b,z) == 4");
    chk(dafsa_range_count_n(d, (const unsigned char *)"p", 1,
                               (const unsigned char *)"q", 1) == 3, "rancount [p,q) == 3");
    chk(dafsa_ensure_subtree(d) == 7, "ensure_subtree == 7 keys");
    chk(dafsa_rank_from(d, 1, (const unsigned char *)"p\0y", 3) == 4,
        "rank_from(initial,p-NUL-y) == 4");
    rn = dafsa_select_from(d, 1, 0, ko, sizeof ko);
    chk(rn == 3 && memcmp(ko, "a\0c", 3) == 0, "select_from(initial,0) == a-NUL-c");
    chk(dafsa_range_count_from(d, 1, (const unsigned char *)"a", 1,
                                  (const unsigned char *)"b", 1) == 3,
        "range_count_from(initial,[a,b)) == 3");
    chk(dafsa_select_from(d, 99, 0, ko, sizeof ko) == -1, "select_from bad s -> -1");
    chk(dafsa_rank_from(d, 0, (const unsigned char *)"a", 1) == 0, "rank_from s=0 -> 0");

    /* ── view (zero-copy) ───────────────────────────────────────────────── */
    snprintf(path, sizeof path, "%s/a.pdwg", wd);
    v = dafsa_view_open(path);
    chk(v != NULL, "view_open a.pdwg");
    chk(dafsa_view_lookup_n(v, (const unsigned char *)"abc", 3) == 1, "view lookup abc");
    chk(dafsa_view_lookup_n(v, (const unsigned char *)"a\0c", 3) == 1, "view lookup a-NUL-c");
    chk(dafsa_view_lookup_n(v, (const unsigned char *)"ab", 2) == 0, "view lookup prefix");
    chk(dafsa_view_lookup_n(v, NULL, 3) == 0, "view lookup NULL -> 0");
    g_enum_count = 0;
    rn = (int)dafsa_view_prefix_enum(v, (const unsigned char *)"p", 1, enum_cb, &fails);
    chk(rn == 3, "view prefix_enum p -> 3");
    rn = (int)dafsa_view_prefix_enum(v, (const unsigned char *)"p", 1, NULL, &fails);
    chk(rn == -1, "view prefix_enum NULL cb -> -1");

    /* view rank/select/range + subtree_counts (consumer free()) */
    chk(dafsa_view_rank_n(v, (const unsigned char *)"abc", 3) == 1, "view rank abc == 1");
    rn = dafsa_view_select_n(v, 0, ko, sizeof ko);
    chk(rn == 3 && memcmp(ko, "a\0c", 3) == 0, "view select 0 == a-NUL-c");
    chk(dafsa_view_select_n(v, 9, ko, sizeof ko) == -1, "view select oob -> -1");
    chk(dafsa_view_range_count_n(v, (const unsigned char *)"a", 1,
                                    (const unsigned char *)"b", 1) == 3,
        "view rancount [a,b) == 3");
    {
        uint64_t *counts = NULL;
        uint64_t total = dafsa_view_subtree_counts(v, &counts);
        chk(counts != NULL && total == 7, "view_subtree_counts total == 7");
        free(counts); /* c_allocator-owned: consumer free() must work */
    }
    dafsa_view_close(v);
    dafsa_view_close(NULL);
    chk(dafsa_view_open("/nonexistent/q.pdwg") == NULL, "view_open missing -> NULL");

    /* ── WAL: rw + append + sync + size + replay + ro ───────────────────── */
    snprintf(path, sizeof path, "%s/w.wal", wd);
    w = dafsa_wal_open_rw(path);
    chk(w != NULL, "wal_open_rw w.wal");
    chk(dafsa_wal_append_add(w, (const unsigned char *)"k\0y", 3) == 0, "wal append_add NUL key");
    chk(dafsa_wal_append_del(w, (const unsigned char *)"abc", 3) == 0, "wal append_del");
    chk(dafsa_wal_append_add(w, (const unsigned char *)"xy", 2) == 0, "wal append_add xy");
    chk(dafsa_wal_append_add(w, NULL, 2) == -1, "wal append NULL key -> -1");
    chk(dafsa_wal_sync(w) == 0, "wal sync");
    printf("wal size: %llu\n", (unsigned long long)dafsa_wal_size(w));
    g_replay_count = 0;
    chk(dafsa_wal_replay(w, replay_cb, &fails) == 0, "wal replay ok");
    chk(g_replay_count == 3, "wal replay visited 3 records");
    chk(dafsa_wal_replay(w, NULL, &fails) == -1, "wal replay NULL cb -> -1");
    dafsa_wal_close(w);
    dafsa_wal_close(NULL);
    w = dafsa_wal_open_ro(path);
    chk(w != NULL, "wal_open_ro");
    g_replay_count = 0;
    chk(dafsa_wal_replay(w, replay_cb, &fails) == 0 && g_replay_count == 3,
        "wal ro replay 3");
    dafsa_wal_close(w);
    w = dafsa_wal_open(path); /* back-compat writer alias */
    chk(w != NULL, "wal_open back-compat");
    chk(dafsa_wal_size(w) > 0, "wal_open size > 0");
    dafsa_wal_close(w);
    chk(dafsa_wal_open_rw("/nonexistent/dir/x.wal") == NULL, "wal_open_rw bad dir -> NULL");

    /* ── layered view (base + WAL overlay) ──────────────────────────────── */
    snprintf(path, sizeof path, "%s/a.pdwg", wd);
    {
        char walp[512];
        snprintf(walp, sizeof walp, "%s/w.wal", wd);
        v = dafsa_view_open_layered(path, walp);
        chk(v != NULL, "view_open_layered a.pdwg+w.wal");
        /* w.wal holds NON-overlay-form records (k-NUL-y, abc, xy): the
         * overlay only ingests word+NUL+payload8 records, so lookups fall
         * through to the base (C-engine semantics; values printed for the
         * cross-engine diff and asserted in the S11-mirror block below) */
        printf("layered abc=%d abd=%d xy=%d\n",
               dafsa_view_lookup_n(v, (const unsigned char *)"abc", 3),
               dafsa_view_lookup_n(v, (const unsigned char *)"abd", 3),
               dafsa_view_lookup_n(v, (const unsigned char *)"xy", 2));
        g_enum_count = 0;
        rn = (int)dafsa_view_prefix_enum(v, (const unsigned char *)"p", 1, enum_cb, &fails);
        printf("layered pfx p -> %d\n", rn);
        dafsa_view_close(v);
        /* layered with missing WAL file must still open (plain view) */
        v = dafsa_view_open_layered(path, "/nonexistent/x.wal");
        chk(v != NULL, "view_open_layered missing wal -> open");
        chk(dafsa_view_lookup_n(v, (const unsigned char *)"abc", 3) == 1,
            "layered-missing-wal lookup abc");
        dafsa_view_close(v);
        /* NULL wal path */
        v = dafsa_view_open_layered(path, NULL);
        chk(v != NULL, "view_open_layered NULL wal");
        dafsa_view_close(v);
    }

    /* ── layered view, overlay form (word+NUL+payload8) — mirrors S11 ──── */
    {
        const unsigned char k1[10] = {'a',0, 1,0,0,0,0,0,0,1};
        const unsigned char k2[10] = {'a',0, 1,0,0,0,0,0,0,2};
        const unsigned char k3[10] = {'a',0, 1,0,0,0,0,0,0,3};
        const unsigned char k4[10] = {'a',0, 1,0,0,0,0,0,0,4};
        const unsigned char k5[10] = {'b',0, 2,0,0,0,0,0,0,1};
        const unsigned char k6[10] = {'b',0, 2,0,0,0,0,0,0,2};
        char base2[512], wal2[512];
        dafsa *d2;
        dafsa_wal *w2;

        snprintf(base2, sizeof base2, "%s/c.pdwg", wd);
        snprintf(wal2, sizeof wal2, "%s/w2.wal", wd);
        d2 = dafsa_create();
        chk(dafsa_add_n(d2, k1, 10) == 1 && dafsa_add_n(d2, k2, 10) == 1 &&
            dafsa_add_n(d2, k5, 10) == 1, "ov base 3 keys");
        chk(dafsa_save(d2, base2) == 0, "ov save c.pdwg");
        dafsa_free(d2);
        w2 = dafsa_wal_open_rw(wal2);
        chk(w2 != NULL, "ov wal_open_rw w2.wal");
        chk(dafsa_wal_append_add(w2, k3, 10) == 0, "ov w2 add a-P3");
        chk(dafsa_wal_append_add(w2, k1, 10) == 0, "ov w2 re-add a-P1");
        chk(dafsa_wal_append_del(w2, k5, 10) == 0, "ov w2 del b-P1");
        chk(dafsa_wal_sync(w2) == 0, "ov w2 sync");
        dafsa_wal_close(w2);

        v = dafsa_view_open_layered(base2, wal2);
        chk(v != NULL, "ov layered open c.pdwg+w2.wal");
        chk(dafsa_view_lookup_n(v, k1, 10) == 1, "ov layered a-P1 (ADD)");
        chk(dafsa_view_lookup_n(v, k2, 10) == 1, "ov layered a-P2 (base)");
        chk(dafsa_view_lookup_n(v, k3, 10) == 1, "ov layered a-P3 (ADD)");
        chk(dafsa_view_lookup_n(v, k4, 10) == 0, "ov layered a-P4 miss");
        chk(dafsa_view_lookup_n(v, k5, 10) == 0, "ov layered b-P1 (DEL)");
        chk(dafsa_view_lookup_n(v, k6, 10) == 0, "ov layered b-P2 miss");
        g_enum_count = 0;
        rn = (int)dafsa_view_prefix_enum(v, (const unsigned char *)"a", 1,
                                         enum_cb, &fails);
        chk(rn == 3, "ov layered pfx a -> 3 (merge+dedup)");
        g_enum_count = 0;
        rn = (int)dafsa_view_prefix_enum(v, (const unsigned char *)"b", 1,
                                         enum_cb, &fails);
        chk(rn == 0, "ov layered pfx b -> 0 (tombstone)");
        dafsa_view_close(v);
    }

    dafsa_free(d);
    dafsa_free(NULL);

    printf("== %s (fails=%d) ==\n", fails ? "SMOKE FAILED" : "SMOKE PASSED", fails);
    return fails ? 1 : 0;
}
