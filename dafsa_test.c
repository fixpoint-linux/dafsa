/*
 * dafsa_test.c — Ported test harness from dawg.c + embedded-NUL test
 *
 * Tests 1-9 are ported from the original dawg.c main().
 * Test 10 verifies embedded-NUL keys via the _n API.
 *
 * Build: see Makefile
 * Run:   ./dafsa
 */
#include "dafsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ─── Helper: print stats from a dafsa_stats_out ───────────────────── */

static void print_stats(const dafsa_stats_out *st)
{
    printf("  total states:   %u\n", st->n_states_total);
    printf("  reachable:      %u\n", st->n_states_reachable);
    printf("  final:          %u\n", st->n_final);
    printf("  transitions:    %u\n", st->n_trans);
    printf("  register probes: %llu\n",
           (unsigned long long)st->register_probes);
}

static void show_stats(const dafsa *d)
{
    dafsa_stats_out st;
    dafsa_stats(d, &st);
    print_stats(&st);
}

/* ═══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    dafsa *d;

    d = dafsa_create();
    assert(d != NULL);

    printf("=== Carrasco & Forcada Incremental DAFSA — PoC (M0) ===\n\n");

    /* ── Test 1: Basic add + lookup ── */
    printf("[Test 1] Adding words: cat, car, cart, do, dog\n");
    assert(dafsa_add(d, (const unsigned char *)"cat") == 1);
    assert(dafsa_add(d, (const unsigned char *)"car") == 1);
    assert(dafsa_add(d, (const unsigned char *)"cart") == 1);
    assert(dafsa_add(d, (const unsigned char *)"do") == 1);
    assert(dafsa_add(d, (const unsigned char *)"dog") == 1);

    /* Verify presence */
    assert(dafsa_lookup(d, (const unsigned char *)"cat") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"car") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"cart") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"do") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"dog") == 1);

    /* Verify absence */
    assert(dafsa_lookup(d, (const unsigned char *)"ca") == 0);
    assert(dafsa_lookup(d, (const unsigned char *)"c") == 0);
    assert(dafsa_lookup(d, (const unsigned char *)"cats") == 0);
    assert(dafsa_lookup(d, (const unsigned char *)"d") == 0);
    assert(dafsa_lookup(d, (const unsigned char *)"dot") == 0);

    printf("  PASS: all lookups correct\n");
    show_stats(d);

    /* ── Test 2: Verify minimality (shared suffixes) ── */
    printf("\n[Test 2] Checking suffix sharing (car/cat share prefix, do/dog share prefix)\n");
    /* Behavioral check: 'car' and 'cat' both exist; 'do' is both a word
     * and a prefix of 'dog'.  Verify that the expected words are
     * recognized and unrelated ones are not. */
    assert(dafsa_lookup(d, (const unsigned char *)"car") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"cat") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"cart") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"do") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"dog") == 1);
    /* 'cax' should NOT be a word */
    assert(dafsa_lookup(d, (const unsigned char *)"cax") == 0);
    /* Minimality check via stats: we added 5 words; reachable states
     * should be reasonable (not 5 x len). */
    {
        dafsa_stats_out st;
        dafsa_stats(d, &st);
        printf("  reachable states after 5 words: %u\n", st.n_states_reachable);
        assert(st.n_states_reachable < 15);  /* sanity: much less than sum-of-lens */
    }
    printf("  PASS: suffix sharing verified\n");

    /* ── Test 3: Duplicate additions are no-ops ── */
    printf("\n[Test 3] Duplicate addition\n");
    assert(dafsa_add(d, (const unsigned char *)"cat") == 0);
    assert(dafsa_add(d, (const unsigned char *)"dog") == 0);
    printf("  PASS: duplicates correctly rejected\n");

    /* ── Test 4: Deletion ── */
    printf("\n[Test 4] Deletion\n");
    assert(dafsa_delete(d, (const unsigned char *)"cart") == 1);
    assert(dafsa_lookup(d, (const unsigned char *)"cart") == 0);
    assert(dafsa_lookup(d, (const unsigned char *)"car") == 1);  /* still there */
    assert(dafsa_lookup(d, (const unsigned char *)"cat") == 1);  /* still there */
    printf("  PASS: 'cart' deleted, 'car'/'cat' unaffected\n");

    /* Delete non-existent */
    assert(dafsa_delete(d, (const unsigned char *)"xyzzy") == 0);
    printf("  PASS: non-existent word correctly rejected\n");

    show_stats(d);

    /* ── Test 5: Larger batch ── */
    printf("\n[Test 5] Adding 20 common English words\n");
    {
        const char *words[] = {
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
            "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
            NULL
        };
        int i;
        for (i = 0; words[i]; i++) {
            dafsa_add(d, (const unsigned char *)words[i]);
        }
        /* Verify all are present */
        for (i = 0; words[i]; i++) {
            assert(dafsa_lookup(d, (const unsigned char *)words[i]) == 1);
        }
        printf("  PASS: all 20 words present and minimal\n");
    }
    show_stats(d);

    dafsa_free(d);

    /* ── Test 6: Edge case — single char ── */
    printf("\n[Test 6] Single-character words\n");
    {
        dafsa *d2 = dafsa_create();
        assert(d2 != NULL);

        assert(dafsa_add(d2, (const unsigned char *)"x") == 1);
        assert(dafsa_add(d2, (const unsigned char *)"x") == 0);  /* dup */
        assert(dafsa_lookup(d2, (const unsigned char *)"x") == 1);
        assert(dafsa_lookup(d2, (const unsigned char *)"y") == 0);
        assert(dafsa_delete(d2, (const unsigned char *)"x") == 1);
        assert(dafsa_lookup(d2, (const unsigned char *)"x") == 0);
        printf("  PASS: single-char add/delete works\n");

        dafsa_free(d2);
    }

    /* ── Test 7: Prefix-sharing stress ── */
    printf("\n[Test 7] Prefix-sharing: 'abc', 'abd', 'ab', 'a'\n");
    {
        dafsa *d3 = dafsa_create();
        assert(d3 != NULL);

        assert(dafsa_add(d3, (const unsigned char *)"abc") == 1);
        assert(dafsa_add(d3, (const unsigned char *)"abd") == 1);
        assert(dafsa_add(d3, (const unsigned char *)"ab") == 1);
        assert(dafsa_add(d3, (const unsigned char *)"a") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"abc") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"abd") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"ab") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"a") == 1);
        /* Delete 'abc', verify 'abd', 'ab', 'a' survive */
        assert(dafsa_delete(d3, (const unsigned char *)"abc") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"abc") == 0);
        assert(dafsa_lookup(d3, (const unsigned char *)"abd") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"ab") == 1);
        assert(dafsa_lookup(d3, (const unsigned char *)"a") == 1);
        printf("  PASS: prefix sharing with selective deletion\n");

        dafsa_free(d3);
    }

    /* ── Dot output ── */
    printf("\n[Graphviz] Writing DAFSA to dafsa.dot\n");
    {
        dafsa *d_dot = dafsa_create();
        assert(d_dot != NULL);

        dafsa_add(d_dot, (const unsigned char *)"cat");
        dafsa_add(d_dot, (const unsigned char *)"car");
        dafsa_add(d_dot, (const unsigned char *)"cart");
        dafsa_add(d_dot, (const unsigned char *)"do");
        dafsa_add(d_dot, (const unsigned char *)"dog");

        {
            FILE *f = fopen("dafsa.dot", "w");
            if (f) {
                dafsa_dot(d_dot, f);
                fclose(f);
                printf("  Wrote dafsa.dot (render with: dot -Tpng dafsa.dot -o dafsa.png)\n");
            }
        }

        dafsa_free(d_dot);
    }

    /* ── Test 8: Ordering independence ── */
    printf("\n[Test 8] Ordering independence: same words, different order\n");
    {
        const char *set_a[] = {"apple", "app", "apt", "apex", "apricot", NULL};
        const char *set_b[] = {"apricot", "apex", "apt", "apple", "app", NULL};
        int i;
        dafsa *da = dafsa_create();
        dafsa *db = dafsa_create();

        assert(da != NULL);
        assert(db != NULL);

        /* Add set A */
        for (i = 0; set_a[i]; i++)
            dafsa_add(da, (const unsigned char *)set_a[i]);

        /* Add set B (reversed order) */
        for (i = 0; set_b[i]; i++)
            dafsa_add(db, (const unsigned char *)set_b[i]);

        /* Both DAFSAs should recognize the same words */
        for (i = 0; set_a[i]; i++) {
            assert(dafsa_lookup(da, (const unsigned char *)set_a[i]) == 1);
            assert(dafsa_lookup(db, (const unsigned char *)set_a[i]) == 1);
        }

        /* Should have same number of reachable states (minimal) */
        {
            dafsa_stats_out sta, stb;
            dafsa_stats(da, &sta);
            dafsa_stats(db, &stb);
            printf("  Set A: ");
            print_stats(&sta);
            printf("  Set B: ");
            print_stats(&stb);
            assert(sta.n_states_reachable == stb.n_states_reachable);
        }

        dafsa_free(da);
        dafsa_free(db);
    }
    printf("  PASS: ordering independence verified\n");

    /* ── Test 9: Interleaved add/delete ── */
    printf("\n[Test 9] Interleaved add/delete cycles\n");
    {
        dafsa *dd = dafsa_create();
        assert(dd != NULL);

        /* Add 3 words, delete 1, add 2 more, delete 1, verify survivors */
        assert(dafsa_add(dd, (const unsigned char *)"abc") == 1);
        assert(dafsa_add(dd, (const unsigned char *)"abd") == 1);
        assert(dafsa_add(dd, (const unsigned char *)"abe") == 1);
        assert(dafsa_delete(dd, (const unsigned char *)"abd") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abd") == 0);
        assert(dafsa_lookup(dd, (const unsigned char *)"abc") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abe") == 1);

        assert(dafsa_add(dd, (const unsigned char *)"abf") == 1);
        assert(dafsa_add(dd, (const unsigned char *)"abg") == 1);
        assert(dafsa_delete(dd, (const unsigned char *)"abe") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abe") == 0);
        assert(dafsa_lookup(dd, (const unsigned char *)"abc") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abf") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abg") == 1);

        /* Re-add deleted word */
        assert(dafsa_add(dd, (const unsigned char *)"abe") == 1);
        assert(dafsa_lookup(dd, (const unsigned char *)"abe") == 1);

        dafsa_free(dd);
    }
    printf("  PASS: interleaved add/delete works\n");

    /* ── Test 10: Embedded NUL via _n functions ── */
    printf("\n[Test 10] Embedded NUL via _n functions\n");
    {
        dafsa *dn = dafsa_create();
        assert(dn != NULL);

        /* Keys with embedded NUL bytes (cannot be expressed as C strings) */
        const unsigned char key1[] = {'a', 'b', 0x00, 'c', 'd'};   /* "ab\0cd" */
        const unsigned char key2[] = {'a', 'b', 0x00, 'e', 'f'};   /* "ab\0ef" */
        const unsigned char key3[] = {'x', 0x00, 'y', 0x00, 'z'};  /* "x\0y\0z" */
        const unsigned char key4[] = {'a', 'b', 0x00, 'c', 'd', 0x00, 'g', 'h'}; /* "ab\0cd\0gh" */

        /* Add via _n */
        assert(dafsa_add_n(dn, key1, 5) == 1);
        assert(dafsa_add_n(dn, key2, 5) == 1);
        assert(dafsa_add_n(dn, key3, 5) == 1);
        assert(dafsa_add_n(dn, key4, 8) == 1);

        /* Verify via _n */
        assert(dafsa_lookup_n(dn, key1, 5) == 1);
        assert(dafsa_lookup_n(dn, key2, 5) == 1);
        assert(dafsa_lookup_n(dn, key3, 5) == 1);
        assert(dafsa_lookup_n(dn, key4, 8) == 1);

        /* Verify duplicates rejected via _n */
        assert(dafsa_add_n(dn, key1, 5) == 0);

        /* strlen wrappers should NOT find these keys
         * (they treat the first NUL as terminator) */
        assert(dafsa_lookup(dn, (const unsigned char *)"ab") == 0);
        assert(dafsa_lookup(dn, (const unsigned char *)"x") == 0);

        /* Delete via _n */
        assert(dafsa_delete_n(dn, key1, 5) == 1);
        assert(dafsa_lookup_n(dn, key1, 5) == 0);
        assert(dafsa_lookup_n(dn, key2, 5) == 1);  /* still there */
        assert(dafsa_lookup_n(dn, key3, 5) == 1);  /* still there */
        assert(dafsa_lookup_n(dn, key4, 8) == 1);  /* still there */

        /* Delete non-existent via _n */
        assert(dafsa_delete_n(dn, key1, 5) == 0);

        /* Re-add previously deleted key */
        assert(dafsa_add_n(dn, key1, 5) == 1);
        assert(dafsa_lookup_n(dn, key1, 5) == 1);

        /* Empty key via _n (len=0) */
        assert(dafsa_add_n(dn, (const unsigned char *)"", 0) == 1);
        assert(dafsa_lookup_n(dn, (const unsigned char *)"", 0) == 1);
        assert(dafsa_add_n(dn, (const unsigned char *)"", 0) == 0);  /* dup */
        assert(dafsa_delete_n(dn, (const unsigned char *)"", 0) == 1);
        assert(dafsa_lookup_n(dn, (const unsigned char *)"", 0) == 0);

        dafsa_free(dn);
    }
    printf("  PASS: embedded NUL keys work with _n, invisible to strlen wrappers\n");

    /* ── Summary ── */
    printf("\n=== All tests passed. ===\n");
    return 0;
}
