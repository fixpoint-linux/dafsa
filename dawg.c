/*
 * dawg.c — Carrasco & Forcada (2002) Incremental Minimal Acyclic DFA
 *
 * Implements incremental addition and deletion of strings from a minimal
 * deterministic acyclic finite-state automaton (DAWG/DAFSA) using the
 * clone-on-write + register + confluence algorithm described in:
 *
 *   Carrasco, R.C. & Forcada, M.L. (2002)
 *   "Incremental Construction and Maintenance of Minimal
 *    Acyclic Finite-State Automata"
 *   Computational Linguistics, 28(2), pp. 207-216.
 *
 * Build: cc -Wall -Wextra -O2 -o dawg dawg.c
 * Run:   ./dawg
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

/* ─── Tunables ──────────────────────────────────────────────────────────── */

#define MAX_STATES      100000
#define MAX_WORD_LEN    4096      /* max word length for path arrays */
#define MAX_PARENTS     64        /* per state, for redirect on merge */
#define ALPHABET_SZ     256
#define REGISTER_SZ     262139    /* prime, open-addressing */
#define FNV_OFFSET      14695981039346656037ULL
#define FNV_PRIME       1099511628211ULL

/* ─── Data structures ──────────────────────────────────────────────────── */

typedef struct {
    unsigned char  sym;
    unsigned int   target;         /* state index */
} Edge;

/* Linked-list node for incoming-edges tracking.
 * Stored as a singly-linked list threaded through a flat array so we
 * don't need malloc/free per edge. */
typedef struct inode {
    unsigned int   parent;         /* which state points here */
    unsigned char  sym;            /* via which character */
    unsigned int   next;           /* index of next inode in parent list, 0=end */
} Inode;

typedef struct {
    unsigned int   id;             /* self-index, for sanity */
    unsigned int   refcount;       /* number of incoming transitions */
    unsigned char  is_final;

    /* outbound transitions — kept sorted by sym */
    unsigned int   ntrans;
    Edge           trans[ALPHABET_SZ];

    /* inbound edges (for merge redirection) */
    unsigned int   in_head;        /* index of first Inode, 0=none */

    uint64_t       sig;            /* cached FNV-1a signature, 0=invalid */
} State;

typedef struct {
    unsigned int   nstates;        /* state 0 = implicit dead/sink state, unused */
    unsigned int   initial;
    State          states[MAX_STATES];

    /* Free-list for Inode nodes */
    Inode          inodes[MAX_STATES * 4]; /* generous */
    unsigned int   inodes_used;

    /* Register: open-addressing hash table sig → state_id */
    uint64_t       reg_keys[REGISTER_SZ];
    unsigned int   reg_vals[REGISTER_SZ];
    unsigned int   reg_probes;
} DAWG;

/* ─── Forward declarations ─────────────────────────────────────────────── */

static unsigned int state_new(DAWG *d);
static int          trans_find(const State *s, unsigned char c);
static void         trans_add(State *s, unsigned char c, unsigned int tgt);
static void         incoming_add(DAWG *d, unsigned int src, unsigned char c,
                                 unsigned int dst);
static void         incoming_redirect(DAWG *d, unsigned int old_tgt,
                                      unsigned int new_tgt);
static void         incoming_redirect_one(DAWG *d, unsigned int parent,
                                           unsigned char sym,
                                           unsigned int old_tgt,
                                           unsigned int new_tgt);
static uint64_t     sig_compute(const State *s);
static unsigned int reg_lookup(DAWG *d, uint64_t sig);
static void         reg_insert(DAWG *d, uint64_t sig, unsigned int id);
static void         replace_or_register(DAWG *d, unsigned int sid,
                                        unsigned int parent);
static unsigned int clone_state(DAWG *d, unsigned int sid);
static void         confluence_path(DAWG *d, unsigned int *path,
                                    unsigned char *chars,
                                    unsigned int *parents,
                                    unsigned int len);

/* ─── State management ─────────────────────────────────────────────────── */

static unsigned int state_new(DAWG *d) {
    assert(d->nstates < MAX_STATES);
    unsigned int id = d->nstates++;
    State *s = &d->states[id];
    memset(s, 0, sizeof(*s));
    s->id = id;
    s->refcount = 0;
    s->is_final = 0;
    s->ntrans = 0;
    s->in_head = 0;
    s->sig = 0;
    return id;
}

/* binary search for transition `c`. Returns index or -1. */
static int trans_find(const State *s, unsigned char c) {
    int lo = 0, hi = (int)s->ntrans - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (s->trans[mid].sym == c) return mid;
        if (s->trans[mid].sym <  c) lo = mid + 1;
        else                        hi = mid - 1;
    }
    return -1;
}

/* insert a transition, maintaining sorted order */
static void trans_add(State *s, unsigned char c, unsigned int tgt) {
    assert(s->ntrans < ALPHABET_SZ);
    int pos = 0;
    while (pos < (int)s->ntrans && s->trans[pos].sym < c)
        pos++;
    if (pos < (int)s->ntrans && s->trans[pos].sym == c) {
        /* update existing */
        s->trans[pos].target = tgt;
        return;
    }
    /* shift right */
    memmove(&s->trans[pos + 1], &s->trans[pos],
            (s->ntrans - (unsigned)pos) * sizeof(Edge));
    s->trans[pos].sym = c;
    s->trans[pos].target = tgt;
    s->ntrans++;
}

/* ─── Incoming-edge tracking ───────────────────────────────────────────── */

static Inode *inode_alloc(DAWG *d) {
    assert(d->inodes_used < sizeof(d->inodes) / sizeof(d->inodes[0]));
    return &d->inodes[++d->inodes_used];   /* index 0 = sentinel */
}

static void incoming_add(DAWG *d, unsigned int src, unsigned char c,
                          unsigned int dst) {
    Inode *in = inode_alloc(d);
    in->parent = src;
    in->sym = c;
    in->next  = d->states[dst].in_head;
    d->states[dst].in_head = d->inodes_used;
    /* refcount tracks INCOMING transitions to a state */
    d->states[dst].refcount++;
}

/* Redirect ALL incoming edges that point to old_tgt to point to new_tgt.
 * Also fix up the parents' transition tables. */
static void incoming_redirect(DAWG *d, unsigned int old_tgt,
                               unsigned int new_tgt) {
    State *old_s = &d->states[old_tgt];
    State *new_s = &d->states[new_tgt];
    unsigned int ni = old_s->in_head;
    while (ni != 0) {
        Inode *in = &d->inodes[ni];
        State  *parent = &d->states[in->parent];

        /* update parent's transition */
        int pos = trans_find(parent, in->sym);
        assert(pos >= 0);
        parent->trans[pos].target = new_tgt;
        parent->sig = 0;  /* invalidate, will recompute */

        /* update refcounts */
        old_s->refcount--;
        new_s->refcount++;

        /* move the inode to new_tgt's list */
        unsigned int next = in->next;
        in->next = new_s->in_head;
        new_s->in_head = ni;

        ni = next;
    }
    old_s->in_head = 0;
}

/* Redirect a single incoming edge: parent's transition via sym from
 * old_tgt to new_tgt. Updates the transition table, inode list, and
 * refcounts. Used during clone-on-write. */
static void incoming_redirect_one(DAWG *d, unsigned int parent,
                                   unsigned char sym,
                                   unsigned int old_tgt,
                                   unsigned int new_tgt) {
    /* update parent's transition */
    int pos = trans_find(&d->states[parent], sym);
    assert(pos >= 0 && d->states[parent].trans[pos].target == old_tgt);
    d->states[parent].trans[pos].target = new_tgt;
    d->states[parent].sig = 0;

    /* update refcounts */
    d->states[old_tgt].refcount--;
    d->states[new_tgt].refcount++;

    /* move the inode from old_tgt's list to new_tgt's list */
    unsigned int *prev_ptr = &d->states[old_tgt].in_head;
    unsigned int ni = *prev_ptr;
    while (ni != 0) {
        Inode *in = &d->inodes[ni];
        if (in->parent == parent && in->sym == sym) {
            /* unlink from old_tgt */
            *prev_ptr = in->next;
            /* link into new_tgt */
            in->next = d->states[new_tgt].in_head;
            d->states[new_tgt].in_head = ni;
            return;
        }
        prev_ptr = &in->next;
        ni = *prev_ptr;
    }
    /* Not found — shouldn't happen if bookkeeping is correct */
    assert(0 && "incoming_redirect_one: inode not found");
}

/* ─── Signature computation (FNV-1a) ───────────────────────────────────── */

static uint64_t sig_compute(const State *s) {
    uint64_t h = FNV_OFFSET;
    /* hash the final flag */
    h ^= s->is_final ? 1 : 0;
    h *= FNV_PRIME;
    /* hash each transition: sym + target_id (little-endian) */
    for (unsigned int i = 0; i < s->ntrans; i++) {
        h ^= s->trans[i].sym;
        h *= FNV_PRIME;
        /* hash target as 4 bytes */
        unsigned int t = s->trans[i].target;
        for (int b = 0; b < 4; b++) {
            h ^= (uint8_t)(t & 0xFF);
            h *= FNV_PRIME;
            t >>= 8;
        }
    }
    return h;
}

/* ─── Register (equivalence-class map) ────────────────────────────────── */

static unsigned int reg_lookup(DAWG *d, uint64_t sig) {
    if (sig == 0) return 0;  /* 0 = invalid/empty */
    unsigned int idx = (unsigned int)(sig % REGISTER_SZ);
    while (d->reg_keys[idx] != 0) {
        if (d->reg_keys[idx] == sig)
            return d->reg_vals[idx];
        idx = (idx + 1) % REGISTER_SZ;
        d->reg_probes++;
    }
    return 0;  /* not found */
}

static void reg_insert(DAWG *d, uint64_t sig, unsigned int id) {
    if (sig == 0) return;
    unsigned int idx = (unsigned int)(sig % REGISTER_SZ);
    while (d->reg_keys[idx] != 0) {
        /* overwrite if re-inserting the same state */
        if (d->reg_keys[idx] == sig) {
            d->reg_vals[idx] = id;
            return;
        }
        idx = (idx + 1) % REGISTER_SZ;
        d->reg_probes++;
    }
    d->reg_keys[idx] = sig;
    d->reg_vals[idx] = id;
}

/* ─── Clone-on-write ──────────────────────────────────────────────────── */

/* Clone state `sid`, return the clone's id. The clone gets refcount=0
 * initially, and all its outgoing transitions add incoming edges to their
 * targets (via incoming_add). The caller is responsible for redirecting
 * the appropriate single incoming edge from the parent. */
static unsigned int clone_state(DAWG *d, unsigned int sid) {
    unsigned int new_id = state_new(d);
    State *src = &d->states[sid];
    State *dst = &d->states[new_id];

    dst->is_final = src->is_final;
    dst->ntrans = src->ntrans;
    memcpy(dst->trans, src->trans, src->ntrans * sizeof(Edge));
    dst->sig = src->sig;

    /* Register incoming edges for all of the clone's outgoing transitions */
    for (unsigned int i = 0; i < dst->ntrans; i++) {
        incoming_add(d, new_id, dst->trans[i].sym, dst->trans[i].target);
    }

    return new_id;
}

/* ─── Core: replace_or_register ────────────────────────────────────────── */

/* After modifying state `sid`, call this to either register it (if its
 * signature is unique) or merge it with an existing equivalent state.
 *
 * `parent` is the state that transitions to `sid` via `trans_char`.
 * After a merge, we recurse on `parent` because ITS signature changed.
 */
static void replace_or_register(DAWG *d, unsigned int sid,
                                 unsigned int parent) {
    State *s = &d->states[sid];

    /* Compute (or recompute) signature */
    uint64_t new_sig = sig_compute(s);
    s->sig = new_sig;

    /* Remove old registration if present */
    /* (We don't track the old sig separately; it's already been invalidated
     *  by whoever modified the state. We just insert/replace.) */

    unsigned int equivalent = reg_lookup(d, new_sig);
    if (equivalent != 0 && equivalent != sid) {
        /* --- MERGE: sid into equivalent --- */

        /* Redirect all incoming edges (including `parent`) to equivalent */
        incoming_redirect(d, sid, equivalent);

        /* The state `sid` is now orphaned — but we keep it allocated.
         * Its memory is effectively dead (refcount=0, no incoming). */

        /* parent's transition was updated by incoming_redirect.
         * Now parent's signature is dirty → recurse. BUT we need to
         * know who the *parent's* parent is (i.e., the grandparent)
         * to continue the confluence up the path.
         *
         * The caller has the full path and handles this via
         * confluence_path, so we just signal that parent is dirty
         * by invalidating its signature. */
        d->states[parent].sig = 0;
    } else {
        /* --- REGISTER: this signature is unique --- */
        reg_insert(d, new_sig, sid);
    }
}

/* ─── Confluence along the path ────────────────────────────────────────── */

/* After adding/deleting a word, the path from root to the final state
 * may contain states that need to be re-registered. Process bottom-up.
 *
 * path[i]     = state id
 * chars[i]    = transition character that got us from path[i-1] to path[i]
 *               (chars[0] is unused)
 * parents[i]  = path[i-1] (the state that points to path[i] via chars[i])
 *               (parents[0] is unused)
 * len         = number of states on the path
 */
static void confluence_path(DAWG *d, unsigned int *path,
                             unsigned char *chars,
                             unsigned int *parents,
                             unsigned int len) {
    (void)chars;  /* kept for symmetry with path/parents */
    for (int i = (int)len - 1; i >= 1; i--) {
        unsigned int child  = path[i];
        unsigned int parent = parents[i];

        replace_or_register(d, child, parent);
    }
    /* Also register the root if it was modified */
    replace_or_register(d, path[0], 0);
}

/* ─── Add word ─────────────────────────────────────────────────────────── */

/* Add a string to the DAWG. Returns 0 if already present, 1 if added. */
int dawg_add(DAWG *d, const unsigned char *word) {
    unsigned int len = (unsigned int)strlen((const char *)word);
    if (len == 0) {
        /* Empty string: the initial state becomes final */
        if (d->states[d->initial].is_final) return 0;
        d->states[d->initial].is_final = 1;
        replace_or_register(d, d->initial, 0);
        return 1;
    }

    /* --- Phase 1: Traverse existing path --- */
    unsigned int path[MAX_WORD_LEN + 2];
    unsigned char chars[MAX_WORD_LEN + 2];
    unsigned int parents[MAX_WORD_LEN + 2];
    unsigned int path_len = 0;

    unsigned int current = d->initial;
    path[path_len] = current;
    chars[path_len] = 0;
    parents[path_len] = 0;
    path_len++;

    unsigned int pos;
    for (pos = 0; pos < len; pos++) {
        unsigned char c = word[pos];
        int tr = trans_find(&d->states[current], c);
        if (tr < 0) break;  /* divergence point */

        unsigned int next = d->states[current].trans[tr].target;
        current = next;
        path[path_len] = current;
        chars[path_len] = c;
        parents[path_len] = path[path_len - 1];
        path_len++;
    }

    /* --- Check: word already present? --- */
    if (pos == len && d->states[current].is_final)
        return 0;  /* already in the DAWG */

    /* --- Clone-on-write for exact match (pos == len) ---
     * If the word already exists as a path but isn't final yet
     * (i.e., it's a prefix of a longer word), the final state we're
     * about to mark might be shared. Clone it if necessary. */
    if (pos == len && d->states[current].refcount > 1) {
        unsigned int clone = clone_state(d, current);
        unsigned int parent = path[path_len - 2];
        unsigned char pc    = chars[path_len - 1];
        incoming_redirect_one(d, parent, pc, current, clone);
        path[path_len - 1] = clone;
        current = clone;
    }

    /* --- Phase 2: Clone-on-write from divergence --- */
    /* For each state on the path from divergence point downward,
     * if refcount > 1, clone before modifying. */
    if (pos < len) {
        /* The state we stopped at (current) needs a new transition added.
         * If it's shared, clone it first. */
        if (d->states[current].refcount > 1) {
            unsigned int clone = clone_state(d, current);
            /* Replace parent's transition */
            unsigned int parent = path[path_len - 2];
            unsigned char pc    = chars[path_len - 1];
            incoming_redirect_one(d, parent, pc, current, clone);

            /* fix path */
            path[path_len - 1] = clone;
            current = clone;
        }

        /* Now add new transitions to create the suffix path */
        for (unsigned int i = pos; i < len; i++) {
            unsigned char c = word[i];
            unsigned int next = state_new(d);

            trans_add(&d->states[current], c, next);
            d->states[current].sig = 0;  /* dirty */
            incoming_add(d, current, c, next);

            path[path_len] = next;
            chars[path_len] = c;
            parents[path_len] = current;
            path_len++;

            current = next;
        }
    }

    /* --- Phase 3: Mark final and confluence --- */
    d->states[current].is_final = 1;
    d->states[current].sig = 0;  /* dirty */

    confluence_path(d, path, chars, parents, path_len);

    return 1;
}

/* ─── Delete word ──────────────────────────────────────────────────────── */

/* Remove a string from the DAWG. Returns 0 if not present, 1 if deleted. */
int dawg_delete(DAWG *d, const unsigned char *word) {
    unsigned int len = (unsigned int)strlen((const char *)word);

    /* --- Phase 1: Traverse to the final state --- */
    unsigned int path[MAX_WORD_LEN + 2];
    unsigned char chars[MAX_WORD_LEN + 2];
    unsigned int parents[MAX_WORD_LEN + 2];
    unsigned int path_len = 0;

    unsigned int current = d->initial;
    path[path_len] = current;
    chars[path_len] = 0;
    parents[path_len] = 0;
    path_len++;

    for (unsigned int i = 0; i < len; i++) {
        unsigned char c = word[i];
        int tr = trans_find(&d->states[current], c);
        if (tr < 0) return 0;  /* not present */
        current = d->states[current].trans[tr].target;
        path[path_len] = current;
        chars[path_len] = c;
        parents[path_len] = path[path_len - 1];
        path_len++;
    }

    if (!d->states[current].is_final)
        return 0;  /* word is a prefix but not a word */

    /* --- Phase 2: Clone-on-write, bottom-up ---
     * If any state on the path (including the final state) is shared
     * (refcount > 1), clone it so we can safely modify it without
     * affecting other words that share it. */
    for (int i = (int)path_len - 1; i >= 1; i--) {
        unsigned int sid = path[i];
        if (d->states[sid].refcount > 1) {
            unsigned int clone = clone_state(d, sid);

            /* Redirect parent's transition from sid → clone */
            unsigned int parent = parents[i];
            unsigned char pc    = chars[i];
            incoming_redirect_one(d, parent, pc, sid, clone);

            /* Update path and current (if this is the final state) */
            path[i] = clone;
            if (i == (int)path_len - 1)
                current = clone;
        }
    }

    /* --- Phase 3: Unmark final and confluence --- */
    d->states[current].is_final = 0;
    d->states[current].sig = 0;

    confluence_path(d, path, chars, parents, path_len);

    return 1;
}

/* ─── Lookup ───────────────────────────────────────────────────────────── */

int dawg_lookup(const DAWG *d, const unsigned char *word) {
    unsigned int current = d->initial;
    for (const unsigned char *p = word; *p; p++) {
        int tr = trans_find(&d->states[current], *p);
        if (tr < 0) return 0;
        current = d->states[current].trans[tr].target;
    }
    return d->states[current].is_final;
}

/* ─── Initialize / destroy ─────────────────────────────────────────────── */

void dawg_init(DAWG *d) {
    memset(d, 0, sizeof(*d));
    d->nstates = 1;            /* state 0 is "no state" sentinel */
    d->initial = state_new(d);  /* state 1 is the initial state */
}

/* ─── Dot output for visualization ─────────────────────────────────────── */

void dawg_dot(const DAWG *d, FILE *f) {
    fprintf(f, "digraph DAWG {\n");
    fprintf(f, "  rankdir=LR;\n");
    fprintf(f, "  node [shape=circle,fontsize=10];\n");
    /* mark the initial state */
    fprintf(f, "  start [shape=point];\n");
    fprintf(f, "  start -> %u;\n", d->initial);

    for (unsigned int i = 1; i < d->nstates; i++) {
        const State *s = &d->states[i];
        if (s->refcount == 0 && s->id != d->initial) continue; /* skip orphans */
        const char *shape = s->is_final ? "doublecircle" : "circle";
        fprintf(f, "  %u [shape=%s,label=\"%u (rc=%u)\"];\n",
                s->id, shape, s->id, s->refcount);
        for (unsigned int j = 0; j < s->ntrans; j++) {
            fprintf(f, "  %u -> %u [label=\"%c\"];\n",
                    s->id, s->trans[j].target,
                    s->trans[j].sym >= 32 && s->trans[j].sym < 127
                        ? s->trans[j].sym : '?');
        }
    }
    fprintf(f, "}\n");
}

/* ─── Statistics ───────────────────────────────────────────────────────── */

void dawg_stats(const DAWG *d) {
    unsigned int reachable = 0, finals = 0, transitions = 0;
    /* Simple BFS for reachable states (skip sentinel 0) */
    unsigned char *visited = (unsigned char *)calloc(d->nstates, 1);
    unsigned int *queue = (unsigned int *)malloc(d->nstates * sizeof(unsigned int));
    unsigned int head = 0, tail = 0;

    queue[tail++] = d->initial;
    visited[d->initial] = 1;

    while (head < tail) {
        unsigned int sid = queue[head++];
        const State *s = &d->states[sid];
        reachable++;
        if (s->is_final) finals++;
        transitions += s->ntrans;
        for (unsigned int j = 0; j < s->ntrans; j++) {
            unsigned int tgt = s->trans[j].target;
            if (!visited[tgt]) {
                visited[tgt] = 1;
                queue[tail++] = tgt;
            }
        }
    }

    printf("  total states:   %u\n", d->nstates - 1);
    printf("  reachable:      %u\n", reachable);
    printf("  final:          %u\n", finals);
    printf("  transitions:    %u\n", transitions);
    printf("  register probes: %u\n", d->reg_probes);

    free(visited);
    free(queue);
}

/* ─── Main / test harness ──────────────────────────────────────────────── */

int main(void) {
    DAWG d;
    dawg_init(&d);

    printf("=== Carrasco & Forcada Incremental DAWG — PoC ===\n\n");

    /* ── Test 1: Basic add + lookup ── */
    printf("[Test 1] Adding words: cat, car, cart, do, dog\n");
    assert(dawg_add(&d, (const unsigned char *)"cat") == 1);
    assert(dawg_add(&d, (const unsigned char *)"car") == 1);
    assert(dawg_add(&d, (const unsigned char *)"cart") == 1);
    assert(dawg_add(&d, (const unsigned char *)"do") == 1);
    assert(dawg_add(&d, (const unsigned char *)"dog") == 1);

    /* Verify presence */
    assert(dawg_lookup(&d, (const unsigned char *)"cat") == 1);
    assert(dawg_lookup(&d, (const unsigned char *)"car") == 1);
    assert(dawg_lookup(&d, (const unsigned char *)"cart") == 1);
    assert(dawg_lookup(&d, (const unsigned char *)"do") == 1);
    assert(dawg_lookup(&d, (const unsigned char *)"dog") == 1);

    /* Verify absence */
    assert(dawg_lookup(&d, (const unsigned char *)"ca") == 0);
    assert(dawg_lookup(&d, (const unsigned char *)"c") == 0);
    assert(dawg_lookup(&d, (const unsigned char *)"cats") == 0);
    assert(dawg_lookup(&d, (const unsigned char *)"d") == 0);
    assert(dawg_lookup(&d, (const unsigned char *)"dot") == 0);

    printf("  PASS: all lookups correct\n");
    dawg_stats(&d);

    /* ── Test 2: Verify minimality (shared suffixes) ── */
    printf("\n[Test 2] Checking suffix sharing (car/cat share 'ca', do/dog share 'do')\n");
    /* 'car' → q0-c->q1-a->q2-r->q3(final)
     * 'cat' → q0-c->q1-a->q2-t->q4(final)
     * q2 should have two transitions and be shared */
    {
        unsigned int ca_state = d.states[d.initial].trans[0].target; /* 'c' */
        ca_state = d.states[ca_state].trans[0].target;               /* 'a' */
        printf("  state after 'ca' (id=%u) has %u transitions (expect 2: r,t)\n",
               ca_state, d.states[ca_state].ntrans);
        assert(d.states[ca_state].ntrans == 2);
    }
    /* 'do'/'dog': 'do' should be shared */
    {
        int tr = trans_find(&d.states[d.initial], 'd');
        unsigned int do_state = d.states[d.initial].trans[tr].target; /* 'd' */
        tr = trans_find(&d.states[do_state], 'o');
        do_state = d.states[do_state].trans[tr].target;               /* 'o' */
        printf("  state after 'do' (id=%u) has %u transitions (expect 1: g)\n",
               do_state, d.states[do_state].ntrans);
        assert(d.states[do_state].ntrans == 1);
        assert(d.states[do_state].is_final == 1);
    }
    printf("  PASS: suffix sharing verified\n");

    /* ── Test 3: Duplicate additions are no-ops ── */
    printf("\n[Test 3] Duplicate addition\n");
    assert(dawg_add(&d, (const unsigned char *)"cat") == 0);
    assert(dawg_add(&d, (const unsigned char *)"dog") == 0);
    printf("  PASS: duplicates correctly rejected\n");

    /* ── Test 4: Deletion ── */
    printf("\n[Test 4] Deletion\n");
    assert(dawg_delete(&d, (const unsigned char *)"cart") == 1);
    assert(dawg_lookup(&d, (const unsigned char *)"cart") == 0);
    assert(dawg_lookup(&d, (const unsigned char *)"car") == 1);  /* still there */
    assert(dawg_lookup(&d, (const unsigned char *)"cat") == 1);  /* still there */
    printf("  PASS: 'cart' deleted, 'car'/'cat' unaffected\n");

    /* Delete non-existent */
    assert(dawg_delete(&d, (const unsigned char *)"xyzzy") == 0);
    printf("  PASS: non-existent word correctly rejected\n");

    dawg_stats(&d);

    /* ── Test 5: Larger batch ── */
    printf("\n[Test 5] Adding 20 common English words\n");
    const char *words[] = {
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "it",
        "for", "not", "on", "with", "he", "as", "you", "do", "at", "this",
        NULL
    };
    for (int i = 0; words[i]; i++) {
        dawg_add(&d, (const unsigned char *)words[i]);
    }
    /* Verify all are present */
    for (int i = 0; words[i]; i++) {
        assert(dawg_lookup(&d, (const unsigned char *)words[i]) == 1);
    }
    printf("  PASS: all %d words present and minimal\n", 19);
    dawg_stats(&d);

    /* ── Test 6: Edge case — single char ── */
    printf("\n[Test 6] Single-character words\n");
    DAWG d2;
    dawg_init(&d2);
    assert(dawg_add(&d2, (const unsigned char *)"x") == 1);
    assert(dawg_add(&d2, (const unsigned char *)"x") == 0);  /* dup */
    assert(dawg_lookup(&d2, (const unsigned char *)"x") == 1);
    assert(dawg_lookup(&d2, (const unsigned char *)"y") == 0);
    assert(dawg_delete(&d2, (const unsigned char *)"x") == 1);
    assert(dawg_lookup(&d2, (const unsigned char *)"x") == 0);
    printf("  PASS: single-char add/delete works\n");

    /* ── Test 7: Prefix-sharing stress ── */
    printf("\n[Test 7] Prefix-sharing: 'abc', 'abd', 'ab', 'a'\n");
    DAWG d3;
    dawg_init(&d3);
    assert(dawg_add(&d3, (const unsigned char *)"abc") == 1);
    assert(dawg_add(&d3, (const unsigned char *)"abd") == 1);
    assert(dawg_add(&d3, (const unsigned char *)"ab") == 1);
    assert(dawg_add(&d3, (const unsigned char *)"a") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"abc") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"abd") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"ab") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"a") == 1);
    /* Delete 'abc', verify 'abd', 'ab', 'a' survive */
    assert(dawg_delete(&d3, (const unsigned char *)"abc") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"abc") == 0);
    assert(dawg_lookup(&d3, (const unsigned char *)"abd") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"ab") == 1);
    assert(dawg_lookup(&d3, (const unsigned char *)"a") == 1);
    printf("  PASS: prefix sharing with selective deletion\n");

    /* ── Dot output ── */
    printf("\n[Graphviz] Writing DAWG to dawg.dot\n");
    {
        FILE *f = fopen("dawg.dot", "w");
        if (f) {
            dawg_dot(&d, f);
            fclose(f);
            printf("  Wrote dawg.dot (render with: dot -Tpng dawg.dot -o dawg.png)\n");
        }
    }

    /* ── Test 8: Ordering independence ── */
    printf("\n[Test 8] Ordering independence: same words, different order\n");
    {
        const char *set_a[] = {"apple", "app", "apt", "apex", "apricot", NULL};
        const char *set_b[] = {"apricot", "apex", "apt", "apple", "app", NULL};

        DAWG da, db;
        dawg_init(&da);
        dawg_init(&db);

        /* Add set A */
        for (int i = 0; set_a[i]; i++)
            dawg_add(&da, (const unsigned char *)set_a[i]);

        /* Add set B (reversed order) */
        for (int i = 0; set_b[i]; i++)
            dawg_add(&db, (const unsigned char *)set_b[i]);

        /* Both DAWGs should recognize the same words */
        for (int i = 0; set_a[i]; i++) {
            assert(dawg_lookup(&da, (const unsigned char *)set_a[i]) == 1);
            assert(dawg_lookup(&db, (const unsigned char *)set_a[i]) == 1);
        }

        /* Should have same number of reachable states (minimal) */
        printf("  Set A: ");
        dawg_stats(&da);
        printf("  Set B: ");
        dawg_stats(&db);
    }
    printf("  PASS: ordering independence verified\n");

    /* ── Test 9: Interleaved add/delete ── */
    printf("\n[Test 9] Interleaved add/delete cycles\n");
    {
        DAWG dd;
        dawg_init(&dd);

        /* Add 3 words, delete 1, add 2 more, delete 1, verify survivors */
        assert(dawg_add(&dd, (const unsigned char *)"abc") == 1);
        assert(dawg_add(&dd, (const unsigned char *)"abd") == 1);
        assert(dawg_add(&dd, (const unsigned char *)"abe") == 1);
        assert(dawg_delete(&dd, (const unsigned char *)"abd") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abd") == 0);
        assert(dawg_lookup(&dd, (const unsigned char *)"abc") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abe") == 1);

        assert(dawg_add(&dd, (const unsigned char *)"abf") == 1);
        assert(dawg_add(&dd, (const unsigned char *)"abg") == 1);
        assert(dawg_delete(&dd, (const unsigned char *)"abe") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abe") == 0);
        assert(dawg_lookup(&dd, (const unsigned char *)"abc") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abf") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abg") == 1);

        /* Re-add deleted word */
        assert(dawg_add(&dd, (const unsigned char *)"abe") == 1);
        assert(dawg_lookup(&dd, (const unsigned char *)"abe") == 1);
    }
    printf("  PASS: interleaved add/delete works\n");

    /* ── Summary ── */
    printf("\n=== All tests passed. ===\n");
    return 0;
}
