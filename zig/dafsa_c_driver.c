// dafsa_c_driver.c — Protocol driver for the op protocol (C engine is the oracle)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include "../dafsa.h"
#include "../dafsa_internal.h"   /* rank/select/range_count + trans_find (U8 oracle) */

static int parse_hex_key(const char *s, unsigned char **out, size_t *out_len) {
    size_t in_len = strlen(s);
    if (in_len == 0) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    if (in_len % 2 != 0) return -1; // odd length invalid
    size_t len = in_len / 2;
    unsigned char *buf = (unsigned char*)malloc(len);
    if (!buf) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = s[2*i];
        int lo = s[2*i+1];
        if (!isxdigit(hi) || !isxdigit(lo)) { free(buf); return -1; }
        buf[i] = (unsigned char)((isdigit(hi)?hi-'0':tolower(hi)-'a'+10)<<4 | (isdigit(lo)?lo-'0':tolower(lo)-'a'+10));
    }
    *out = buf;
    *out_len = len;
    return 0;
}

static int handle_add(struct dafsa *d, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= add -1\n");
        return 0;
    }
    int rc = dafsa_add_n(d, key, len);
    printf("= add %d\n", rc);
    free(key);
    return 0;
}

static int handle_lookup(struct dafsa *d, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= lookup 0\n");
        return 0;
    }
    int rc = dafsa_lookup_n(d, key, len);
    printf("= lookup %d\n", rc);
    free(key);
    return 0;
}

static int handle_del(struct dafsa *d, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= del -1\n");
        return 0;
    }
    int rc = dafsa_delete_n(d, key, len);
    printf("= del %d\n", rc);
    free(key);
    return 0;
}

static int handle_stats(struct dafsa *d) {
    dafsa_stats_out st;
    dafsa_stats(d, &st);
    printf("= stats %u %u %u %u %llu\n", st.n_states_total, st.n_states_reachable, st.n_final, st.n_trans, (unsigned long long)st.register_probes);
    return 0;
}

// ─── persistence ops (U5) ──────────────────────────────────────────────────
// Grammar (op_protocol.md): 'save NAME' → '= save 0|-1'; 'load NAME' →
// '= load 1|0'; 'loadro NAME' → '= loadro 1|0'.  Paths resolve under the
// workdir (argv[1], exposed via WORKDIR).  save persists the current handle;
// load/loadro parse the file and REPLACE the current handle on success.
static const char *workdir_path(const char *name, char *out, size_t outsz) {
    const char *wd = getenv("WORKDIR");
    if (!wd) wd = ".";
    if (snprintf(out, outsz, "%s/%s", wd, name) >= (int)outsz) return NULL;
    return out;
}

static int handle_save(struct dafsa *d, const char *name) {
    char path[4096];
    if (!workdir_path(name, path, sizeof(path))) {
        printf("= save -1\n");
        return 0;
    }
    int rc = dafsa_save(d, path);
    printf("= save %d\n", rc);
    return 0;
}

static int handle_load(struct dafsa **d, const char *name, int readonly) {
    char path[4096];
    if (!workdir_path(name, path, sizeof(path))) {
        printf("= %s 0\n", readonly ? "loadro" : "load");
        return 0;
    }
    struct dafsa *nd = readonly ? dafsa_load_readonly(path) : dafsa_load(path);
    if (!nd) {
        printf("= %s 0\n", readonly ? "loadro" : "load");
        return 0;
    }
    if (*d) dafsa_free(*d);
    *d = nd;
    printf("= %s 1\n", readonly ? "loadro" : "load");
    return 0;
}

// ─── build op state (Daciuk bulk construction) ──────────────────────────────
// Grammar (op_protocol.md): 'buildbegin' / 'bkey HEX'* / 'buildend' → '= build 1|0'.
// Collected keys are fed to dafsa_build_sorted (which requires a SORTED,
// DEDUPLICATED list).  On success the resulting handle REPLACES the current one.
static unsigned char **build_keys = NULL;
static size_t *build_lens = NULL;
static size_t build_count = 0;
static size_t build_cap = 0;
static int build_active = 0;   /* inside a buildbegin..buildend block */
static int build_valid = 1;    /* any bkey had invalid hex => 0 */

static void build_reset(void) {
    for (size_t i = 0; i < build_count; i++) free(build_keys[i]);
    build_count = 0;
    build_valid = 1;
    build_active = 0;
}

static int handle_create(struct dafsa **d) {
    struct dafsa *tmp = dafsa_create();
    if (!tmp) { printf("= create 0\n"); return 0; }
    *d = tmp;
    printf("= create 1\n");
    return 0;
}

static int handle_free(struct dafsa *d) {
    dafsa_free(d);
    printf("= free 1\n");
    return 0;
}

static int handle_abi(struct dafsa *d) {
    uint32_t abi = dafsa_abi_version();
    printf("= abi %u\n", abi);
    (void)d;
    return 0;
}

// ─── view ops (U6) ──────────────────────────────────────────────────────────
// Grammar: 'vopen NAME' → '= vopen 1|0'; 'vlookup HEX' → '= vlookup 1|0';
// 'vprefix HEX' → '= vprefix <count>' + count '<hex>' payload lines;
// 'vclose' → '= vclose'.  Ops operate on the current view handle (a
// dafsa_view opened over a .pdwg file saved into the workdir).
static struct dafsa_view *g_view = NULL;

// Enum callback: appends each payload as lowercase hex to a dynamic list,
// so we can print the count line first, then the payload lines.
static char **vpfx_lines = NULL;
static size_t vpfx_count = 0;
static size_t vpfx_cap = 0;

static int vpfx_cb(const unsigned char *payload, size_t payload_len, void *user) {
    (void)user;
    if (vpfx_count >= vpfx_cap) {
        size_t nc = vpfx_cap ? vpfx_cap * 2 : 16;
        char **nl = realloc(vpfx_lines, nc * sizeof(*nl));
        if (!nl) return 1; /* OOM: stop early */
        vpfx_lines = nl;
        vpfx_cap = nc;
    }
    size_t hexlen = payload_len * 2;
    char *line = malloc(hexlen + 1);
    if (!line) return 1;
    for (size_t i = 0; i < payload_len; i++)
        sprintf(line + 2 * i, "%02x", payload[i]);
    line[hexlen] = '\0';
    vpfx_lines[vpfx_count++] = line;
    return 0;
}

static void vpfx_free_lines(void) {
    for (size_t i = 0; i < vpfx_count; i++) free(vpfx_lines[i]);
    vpfx_count = 0;
}

static int handle_vopen(const char *name) {
    char path[4096];
    if (!workdir_path(name, path, sizeof(path))) {
        printf("= vopen 0\n");
        return 0;
    }
    struct dafsa_view *nv = dafsa_view_open(path);
    if (!nv) {
        printf("= vopen 0\n");
        return 0;
    }
    if (g_view) dafsa_view_close(g_view);
    g_view = nv;
    printf("= vopen 1\n");
    return 0;
}

static int handle_vlookup(const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= vlookup 0\n");
        return 0;
    }
    int rc = g_view ? dafsa_view_lookup_n(g_view, key, len) : 0;
    printf("= vlookup %d\n", rc);
    free(key);
    return 0;
}

static int handle_vprefix(const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= vprefix 0\n");
        return 0;
    }
    vpfx_free_lines();
    long count = g_view ? dafsa_view_prefix_enum(g_view, key, len, vpfx_cb, NULL) : 0;
    printf("= vprefix %ld\n", count);
    for (size_t i = 0; i < vpfx_count; i++) printf("%s\n", vpfx_lines[i]);
    vpfx_free_lines();
    free(key);
    return 0;
}

static int handle_vclose(void) {
    if (g_view) { dafsa_view_close(g_view); g_view = NULL; }
    printf("= vclose\n");
    return 0;
}

// ─── WAL ops (U7) ──────────────────────────────────────────────────────────
// Grammar (op_protocol.md): 'wopen NAME' → '= wopen 1|0' (rw);
// 'wopenro NAME' → '= wopenro 1|0'; 'wadd/wdel HEX' → '= wadd 0|-1';
// 'wsize' → '= wsize <n>'; 'wreplay' → '= wreplay <n>' + per-record
// '<op> <hex>' lines; 'wclose' → '= wclose'; 'lopen FST WAL' → '= lopen 1|0'
// (layered view; subsequent vlookup/vprefix exercise the overlay).
static struct dafsa_wal *g_wal = NULL;

static char **wrep_lines = NULL;
static size_t wrep_count = 0;
static size_t wrep_cap = 0;

static int wreplay_cb(uint8_t op, const unsigned char *key, uint32_t key_len, void *user) {
    (void)user;
    if (wrep_count >= wrep_cap) {
        size_t nc = wrep_cap ? wrep_cap * 2 : 16;
        char **nl = realloc(wrep_lines, nc * sizeof(*nl));
        if (!nl) return 1;
        wrep_lines = nl;
        wrep_cap = nc;
    }
    size_t hexlen = key_len * 2;
    char *line = malloc(hexlen + 3); /* op + space + hex + NUL */
    if (!line) return 1;
    size_t o = 0;
    line[o++] = (char)('0' + op);
    line[o++] = ' ';
    for (size_t i = 0; i < key_len; i++)
        sprintf(line + o + 2 * i, "%02x", key[i]);
    line[o + hexlen] = '\0';
    wrep_lines[wrep_count++] = line;
    return 0;
}

static void wrep_free_lines(void) {
    for (size_t i = 0; i < wrep_count; i++) free(wrep_lines[i]);
    wrep_count = 0;
}

static int handle_wopen(const char *name) {
    char path[4096];
    if (!workdir_path(name, path, sizeof(path))) { printf("= wopen 0\n"); return 0; }
    struct dafsa_wal *nw = dafsa_wal_open_rw(path);
    if (!nw) { printf("= wopen 0\n"); return 0; }
    if (g_wal) dafsa_wal_close(g_wal);
    g_wal = nw;
    printf("= wopen 1\n");
    return 0;
}

static int handle_wopenro(const char *name) {
    char path[4096];
    if (!workdir_path(name, path, sizeof(path))) { printf("= wopenro 0\n"); return 0; }
    struct dafsa_wal *nw = dafsa_wal_open_ro(path);
    if (!nw) { printf("= wopenro 0\n"); return 0; }
    if (g_wal) dafsa_wal_close(g_wal);
    g_wal = nw;
    printf("= wopenro 1\n");
    return 0;
}

static int handle_wadd(struct dafsa_wal *w, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) { printf("= wadd -1\n"); return 0; }
    int rc = w ? dafsa_wal_append_add(w, key, (uint32_t)len) : -1;
    printf("= wadd %d\n", rc);
    free(key);
    return 0;
}

static int handle_wdel(struct dafsa_wal *w, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) { printf("= wdel -1\n"); return 0; }
    int rc = w ? dafsa_wal_append_del(w, key, (uint32_t)len) : -1;
    printf("= wdel %d\n", rc);
    free(key);
    return 0;
}

static int handle_wsize(struct dafsa_wal *w) {
    printf("= wsize %llu\n", (unsigned long long)(w ? dafsa_wal_size(w) : 0));
    return 0;
}

static int handle_wreplay(struct dafsa_wal *w) {
    wrep_free_lines();
    if (!w) { printf("= wreplay 0\n"); return 0; }
    dafsa_wal_replay(w, wreplay_cb, NULL);
    printf("= wreplay %zu\n", wrep_count);
    for (size_t i = 0; i < wrep_count; i++) printf("%s\n", wrep_lines[i]);
    wrep_free_lines();
    return 0;
}

static int handle_wclose(void) {
    if (g_wal) { dafsa_wal_close(g_wal); g_wal = NULL; }
    printf("= wclose\n");
    return 0;
}

static int handle_lopen(const char *fst, const char *wal_name) {
    char pf[4096], pw[4096];
    if (!workdir_path(fst, pf, sizeof(pf)) || !workdir_path(wal_name, pw, sizeof(pw))) {
        printf("= lopen 0\n");
        return 0;
    }
    struct dafsa_view *nv = dafsa_view_open_layered(pf, pw);
    if (!nv) { printf("= lopen 0\n"); return 0; }
    if (g_view) dafsa_view_close(g_view);
    g_view = nv;
    printf("= lopen 1\n");
    return 0;
}

// ─── rank/select/rancount ops (U8) ──────────────────────────────────────────
// Grammar: 'rank HEX' → '= rank <u64>'; 'select K' → '= select <len> <hex>' |
// '= select -1'; 'rancount A B' → '= rc <u64>'; 'fromstate HEX' → '= fromstate 1|0'
// (walks the prefix from initial via trans_find and sets the start state used
// by subsequent rank/select/rancount; 0 => the *_n forms from initial).
// 'vrank/vselect/vrancount' exercise the view rank over the current view.
static unsigned int g_from_state = 0;

static int handle_fromstate(struct dafsa *d, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= fromstate 0\n");
        return 0;
    }
    unsigned int s = d->initial;
    int ok = 1;
    for (size_t i = 0; i < len; i++) {
        int tr = trans_find(&d->states[s], key[i]);
        if (tr < 0) { ok = 0; break; }
        s = trans_arr(&d->states[s])[tr].target;
    }
    if (ok && s != 0) { g_from_state = s; printf("= fromstate 1\n"); }
    else { g_from_state = 0; printf("= fromstate 0\n"); }
    free(key);
    return 0;
}

static int handle_rank(struct dafsa *d, const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) {
        printf("= rank 0\n");
        return 0;
    }
    uint64_t r = g_from_state ? dafsa_rank_from(d, g_from_state, key, len)
                              : dafsa_rank_n(d, key, len);
    printf("= rank %llu\n", (unsigned long long)r);
    free(key);
    return 0;
}

static int handle_select(struct dafsa *d, const char *arg) {
    uint64_t k = strtoull(arg, NULL, 10);
    unsigned char key_out[4096];
    int r = g_from_state ? dafsa_select_from(d, g_from_state, k, key_out, sizeof(key_out))
                         : dafsa_select_n(d, k, key_out, sizeof(key_out));
    if (r < 0) { printf("= select -1\n"); return 0; }
    printf("= select %d ", r);
    for (int i = 0; i < r; i++) printf("%02x", key_out[i]);
    printf("\n");
    return 0;
}

static int handle_rancount(struct dafsa *d, const char *loa, const char *hia) {
    unsigned char *lo = NULL, *hi = NULL; size_t lo_len = 0, hi_len = 0;
    if (parse_hex_key(loa, &lo, &lo_len) != 0 || parse_hex_key(hia, &hi, &hi_len) != 0) {
        if (lo) free(lo);
        if (hi) free(hi);
        printf("= rc 0\n");
        return 0;
    }
    uint64_t r = g_from_state ? dafsa_range_count_from(d, g_from_state, lo, lo_len, hi, hi_len)
                              : dafsa_range_count_n(d, lo, lo_len, hi, hi_len);
    printf("= rc %llu\n", (unsigned long long)r);
    free(lo); free(hi);
    return 0;
}

static int handle_vrank(const char *arg) {
    unsigned char *key = NULL; size_t len = 0;
    if (parse_hex_key(arg, &key, &len) != 0) { printf("= vrank 0\n"); return 0; }
    uint64_t r = g_view ? dafsa_view_rank_n(g_view, key, len) : 0;
    printf("= vrank %llu\n", (unsigned long long)r);
    free(key);
    return 0;
}

static int handle_vselect(const char *arg) {
    uint64_t k = strtoull(arg, NULL, 10);
    unsigned char key_out[4096];
    int r = g_view ? dafsa_view_select_n(g_view, k, key_out, sizeof(key_out)) : -1;
    if (r < 0) { printf("= vselect -1\n"); return 0; }
    printf("= vselect %d ", r);
    for (int i = 0; i < r; i++) printf("%02x", key_out[i]);
    printf("\n");
    return 0;
}

static int handle_vrancount(const char *loa, const char *hia) {
    unsigned char *lo = NULL, *hi = NULL; size_t lo_len = 0, hi_len = 0;
    if (parse_hex_key(loa, &lo, &lo_len) != 0 || parse_hex_key(hia, &hi, &hi_len) != 0) {
        if (lo) free(lo);
        if (hi) free(hi);
        printf("= vrc 0\n");
        return 0;
    }
    uint64_t r = g_view ? dafsa_view_range_count_n(g_view, lo, lo_len, hi, hi_len) : 0;
    printf("= vrc %llu\n", (unsigned long long)r);
    free(lo); free(hi);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <workdir>\n", argv[0]);
        return 2;
    }
    setenv("WORKDIR", argv[1], 1);

    struct dafsa *d = NULL;

    char line[4096];
    while (fgets(line, sizeof(line), stdin)) {
        char *p = line; while (*p && isspace((unsigned char)*p)) p++;
        char *nl = strchr(p, '\n'); if (nl) *nl = '\0';
        if (*p == '\0') continue;

        if (strcmp(p, "buildbegin") == 0) {
            build_reset();
            build_active = 1;
        } else if (build_active && strncmp(p, "bkey ", 5) == 0) {
            unsigned char *key = NULL; size_t len = 0;
            if (parse_hex_key(p + 5, &key, &len) != 0) {
                build_valid = 0;
            } else {
                if (build_count >= build_cap) {
                    size_t nc = build_cap ? build_cap * 2 : 16;
                    unsigned char **nk = realloc(build_keys, nc * sizeof(*nk));
                    size_t *nl = NULL;
                    if (nk) nl = realloc(build_lens, nc * sizeof(*nl));
                    if (!nk || !nl) { if (nk) build_keys = nk; build_valid = 0; }
                    else { build_keys = nk; build_lens = nl; build_cap = nc; }
                }
                if (build_valid && build_count < build_cap) {
                    build_keys[build_count] = key;
                    build_lens[build_count] = len;
                    build_count++;
                } else {
                    free(key);
                    build_valid = 0;
                }
            }
        } else if (strcmp(p, "buildend") == 0) {
            int ok = build_valid;
            build_active = 0;
            struct dafsa *nd = NULL;
            if (ok) {
                nd = dafsa_build_sorted((const unsigned char *const *)build_keys,
                                        build_lens, build_count);
            }
            build_reset();
            if (!nd) {
                printf("= build 0\n");
            } else {
                if (d) dafsa_free(d);
                d = nd;
                printf("= build 1\n");
            }
        } else if (strcmp(p, "create") == 0) {
            handle_create(&d);
        } else if (strcmp(p, "free") == 0) {
            handle_free(d); d = NULL;
        } else if (strncmp(p, "vopen ", 6) == 0) {
            handle_vopen(p + 6);
        } else if (strncmp(p, "vlookup ", 8) == 0) {
            handle_vlookup(p + 8);
        } else if (strncmp(p, "vprefix ", 8) == 0) {
            handle_vprefix(p + 8);
        } else if (strncmp(p, "vrank ", 6) == 0) {
            handle_vrank(p + 6);
        } else if (strncmp(p, "vselect ", 8) == 0) {
            handle_vselect(p + 8);
        } else if (strncmp(p, "vrancount ", 10) == 0) {
            char *rest = p + 10;
            char *sp = strchr(rest, ' ');
            if (!sp) { printf("= vrc 0\n"); }
            else { *sp = '\0'; handle_vrancount(rest, sp + 1); }
        } else if (strcmp(p, "vclose") == 0) {
            handle_vclose();
        } else if (strcmp(p, "wclose") == 0) {
            handle_wclose();
        } else if (strncmp(p, "wopen ", 6) == 0) {
            handle_wopen(p + 6);
        } else if (strncmp(p, "wopenro ", 8) == 0) {
            handle_wopenro(p + 8);
        } else if (strncmp(p, "wadd ", 5) == 0) {
            handle_wadd(g_wal, p + 5);
        } else if (strncmp(p, "wdel ", 5) == 0) {
            handle_wdel(g_wal, p + 5);
        } else if (strcmp(p, "wsize") == 0) {
            handle_wsize(g_wal);
        } else if (strcmp(p, "wreplay") == 0) {
            handle_wreplay(g_wal);
        } else if (strncmp(p, "lopen ", 6) == 0) {
            char *rest = p + 6;
            char *sp = strchr(rest, ' ');
            if (!sp) { printf("= lopen 0\n"); }
            else { *sp = '\0'; handle_lopen(rest, sp + 1); }
        } else if (d) {
            if (strcmp(p, "abi") == 0) handle_abi(d);
            else if (strncmp(p, "add ", 4) == 0) handle_add(d, p+4);
            else if (strncmp(p, "lookup ", 7) == 0) handle_lookup(d, p+7);
            else if (strncmp(p, "del ", 4) == 0) handle_del(d, p+4);
            else if (strcmp(p, "stats") == 0) handle_stats(d);
            else if (strncmp(p, "loadro ", 7) == 0) handle_load(&d, p+7, 1);
            else if (strncmp(p, "load ", 5) == 0) handle_load(&d, p+5, 0);
            else if (strncmp(p, "save ", 5) == 0) handle_save(d, p+5);
            else if (strncmp(p, "fromstate ", 10) == 0) handle_fromstate(d, p+10);
            else if (strncmp(p, "rancount ", 9) == 0) {
                char *rest = p + 9;
                char *sp = strchr(rest, ' ');
                if (!sp) { printf("= rc 0\n"); }
                else { *sp = '\0'; handle_rancount(d, rest, sp + 1); }
            }
            else if (strncmp(p, "rank ", 5) == 0) handle_rank(d, p+5);
            else if (strncmp(p, "select ", 7) == 0) handle_select(d, p+7);
            else printf("= error NOTIMPL\n");
        } else {
            printf("= error NOTIMPL\n");
        }
    }

    if (g_view) { dafsa_view_close(g_view); g_view = NULL; }
    if (g_wal) { dafsa_wal_close(g_wal); g_wal = NULL; }
    if (d) { dafsa_free(d); }
    return 0;
}
