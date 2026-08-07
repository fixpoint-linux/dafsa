/*
 * dafsa.c -- Carrasco & Forcada (2002) Incremental Minimal Acyclic DFA
 *
 * Implements incremental addition and deletion of strings from a minimal
 * deterministic acyclic finite-state automaton (DAFSA) using the
 * clone-on-write + register + confluence algorithm described in:
 *
 *   Carrasco, R.C. & Forcada, M.L. (2002)
 *   "Incremental Construction and Maintenance of Minimal
 *    Acyclic Finite-State Automata"
 *   Computational Linguistics, 28(2), pp. 207-216.
 *
 * Refactored from dawg.c: heap-allocated/growable arrays, opaque handle,
 * length-delimited key API.
 */
#include "dafsa.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

/* ─── Tunables ──────────────────────────────────────────────────────────── */

#define DAFSA_MAX_STATES_HARD  100000000
#define MAX_WORD_LEN           4096
#define ALPHABET_SZ            256
#define FNV_OFFSET             14695981039346656037ULL
#define FNV_PRIME              1099511628211ULL

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

    /* outbound transitions -- kept sorted by sym */
    unsigned int   ntrans;
    Edge           trans[ALPHABET_SZ];

    /* inbound edges (for merge redirection) */
    unsigned int   in_head;        /* index of first Inode, 0=none */

    uint64_t       sig;            /* cached FNV-1a signature, 0=invalid */
} State;

struct dafsa {
    unsigned int   nstates;        /* state 0 = implicit dead/sink state, unused */
    unsigned int   initial;        /* initial state id */

    /* Heap arrays with doubling growth */
    State         *states;
    size_t         states_cap;     /* capacity (allocated count) */

    Inode         *inodes;
    size_t         inodes_cap;
    unsigned int   inodes_used;    /* index 0 = sentinel */

    /* Register: open-addressing hash table sig -> state_id */
    uint64_t      *reg_keys;
    uint32_t      *reg_vals;
    size_t         reg_cap;        /* capacity (prime) */
    size_t         reg_used;       /* count of occupied slots */
    uint64_t       reg_probes;
};

/* ─── Forward declarations ─────────────────────────────────────────────── */

static unsigned int state_new(dafsa *d);
static int          trans_find(const State *s, unsigned char c);
static void         trans_add(State *s, unsigned char c, unsigned int tgt);
static void         incoming_add(dafsa *d, unsigned int src, unsigned char c,
                                 unsigned int dst);
static void         incoming_redirect(dafsa *d, unsigned int old_tgt,
                                      unsigned int new_tgt);
static void         incoming_redirect_one(dafsa *d, unsigned int parent,
                                           unsigned char sym,
                                           unsigned int old_tgt,
                                           unsigned int new_tgt);
static uint64_t     sig_compute(const State *s);
static unsigned int reg_lookup(dafsa *d, uint64_t sig);
static void         reg_insert(dafsa *d, uint64_t sig, unsigned int id);
static void         reg_grow(dafsa *d);
static void         replace_or_register(dafsa *d, unsigned int sid,
                                        unsigned int parent);
static unsigned int clone_state(dafsa *d, unsigned int sid);
static void         confluence_path(dafsa *d, unsigned int *path,
                                    unsigned char *chars,
                                    unsigned int *parents,
                                    unsigned int len);
static int          trans_find(const State *s, unsigned char c);

/* ─── Prime helpers (for register growth) ──────────────────────────────── */

static int is_prime(size_t n)
{
    size_t d;
    if (n < 2) return 0;
    if (n % 2 == 0) return n == 2;
    for (d = 3; d * d <= n; d += 2) {
        if (n % d == 0) return 0;
    }
    return 1;
}

static size_t next_prime(size_t n)
{
    if (n < 2) return 2;
    if (n % 2 == 0) n++;
    while (!is_prime(n))
        n += 2;
    return n;
}

/* ─── Lifecycle ────────────────────────────────────────────────────────── */

dafsa *dafsa_create(void)
{
    dafsa *d;

    d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    d->states_cap = 4096;
    d->states = calloc(d->states_cap, sizeof(State));
    if (!d->states) goto fail;

    d->inodes_cap = 4096;
    d->inodes = calloc(d->inodes_cap, sizeof(Inode));
    if (!d->inodes) goto fail;

    d->reg_cap = 4093;   /* prime */
    d->reg_keys = calloc(d->reg_cap, sizeof(uint64_t));
    if (!d->reg_keys) goto fail;
    d->reg_vals = calloc(d->reg_cap, sizeof(uint32_t));
    if (!d->reg_vals) goto fail;

    d->nstates = 1;            /* state 0 is "no state" sentinel */
    d->initial = state_new(d);  /* state 1 is the initial state */
    d->inodes_used = 0;
    d->reg_used = 0;
    d->reg_probes = 0;

    return d;

fail:
    dafsa_free(d);
    return NULL;
}

void dafsa_free(dafsa *d)
{
    if (!d) return;
    free(d->states);
    free(d->inodes);
    free(d->reg_keys);
    free(d->reg_vals);
    free(d);
}

/* ─── State management ─────────────────────────────────────────────────── */

static unsigned int state_new(dafsa *d)
{
    if (d->nstates >= DAFSA_MAX_STATES_HARD) {
        fprintf(stderr, "dafsa: max states exceeded (%u)\n",
                (unsigned)DAFSA_MAX_STATES_HARD);
        abort();
    }

    if (d->nstates >= d->states_cap) {
        size_t new_cap = d->states_cap * 2;
        State *new_states;

        if (new_cap > (size_t)DAFSA_MAX_STATES_HARD + 1)
            new_cap = (size_t)DAFSA_MAX_STATES_HARD + 1;

        new_states = realloc(d->states, new_cap * sizeof(State));
        if (!new_states) {
            fprintf(stderr, "dafsa: OOM growing states\n");
            abort();
        }
        /* Zero-initialize the newly allocated tail */
        memset(new_states + d->states_cap, 0,
               (new_cap - d->states_cap) * sizeof(State));
        d->states = new_states;
        d->states_cap = new_cap;
    }

    {
        unsigned int id = d->nstates++;
        State *s = &d->states[id];
        memset(s, 0, sizeof(*s));
        s->id = id;
        return id;
    }
}

/* ─── Inode allocation ─────────────────────────────────────────────────── */

static Inode *inode_alloc(dafsa *d)
{
    if (d->inodes_used + 1 >= d->inodes_cap) {
        size_t new_cap = d->inodes_cap * 2;
        Inode *new_inodes = realloc(d->inodes, new_cap * sizeof(Inode));
        if (!new_inodes) {
            fprintf(stderr, "dafsa: OOM growing inodes\n");
            abort();
        }
        memset(new_inodes + d->inodes_cap, 0,
               (new_cap - d->inodes_cap) * sizeof(Inode));
        d->inodes = new_inodes;
        d->inodes_cap = new_cap;
    }
    return &d->inodes[++d->inodes_used];   /* index 0 = sentinel */
}

/* ─── Transition helpers ───────────────────────────────────────────────── */

/* binary search for transition `c`. Returns index or -1. */
static int trans_find(const State *s, unsigned char c)
{
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
static void trans_add(State *s, unsigned char c, unsigned int tgt)
{
    assert(s->ntrans < ALPHABET_SZ);
    {
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
}

/* ─── Incoming-edge tracking ───────────────────────────────────────────── */

static void incoming_add(dafsa *d, unsigned int src, unsigned char c,
                          unsigned int dst)
{
    Inode *in = inode_alloc(d);   /* may realloc d->inodes */
    in->parent = src;
    in->sym = c;
    in->next  = d->states[dst].in_head;   /* re-fetched by index, safe */
    d->states[dst].in_head = d->inodes_used;
    d->states[dst].refcount++;
}

/* Redirect ALL incoming edges that point to old_tgt to point to new_tgt.
 * Also fix up the parents' transition tables.
 *
 * IMPORTANT: This function holds State* and Inode* across its loop body
 * but no realloc-triggering call is made inside the loop, so they remain
 * valid. Callers must re-fetch any State* / Inode* they hold across the
 * call to this function (which they do -- callers use indices). */
static void incoming_redirect(dafsa *d, unsigned int old_tgt,
                               unsigned int new_tgt)
{
    State *old_s = &d->states[old_tgt];  /* fetched once; no realloc in body */
    State *new_s = &d->states[new_tgt];
    unsigned int ni = old_s->in_head;

    while (ni != 0) {
        Inode *in = &d->inodes[ni];
        State  *parent = &d->states[in->parent];
        int pos;

        /* update parent's transition */
        pos = trans_find(parent, in->sym);
        assert(pos >= 0);
        parent->trans[pos].target = new_tgt;
        parent->sig = 0;  /* invalidate, will recompute */

        /* update refcounts */
        old_s->refcount--;
        new_s->refcount++;

        /* move the inode to new_tgt's list */
        {
            unsigned int next = in->next;
            in->next = new_s->in_head;
            new_s->in_head = ni;
            ni = next;
        }
    }
    old_s->in_head = 0;
}

/* Redirect a single incoming edge: parent's transition via sym from
 * old_tgt to new_tgt. Updates the transition table, inode list, and
 * refcounts. Used during clone-on-write.
 *
 * Pointer safety: accesses d->states[] and d->inodes[] by index/re-fetch
 * each iteration. No realloc-triggering call in the loop body. */
static void incoming_redirect_one(dafsa *d, unsigned int parent,
                                   unsigned char sym,
                                   unsigned int old_tgt,
                                   unsigned int new_tgt)
{
    int pos;

    /* update parent's transition */
    pos = trans_find(&d->states[parent], sym);
    assert(pos >= 0 && d->states[parent].trans[pos].target == old_tgt);
    d->states[parent].trans[pos].target = new_tgt;
    d->states[parent].sig = 0;

    /* update refcounts */
    d->states[old_tgt].refcount--;
    d->states[new_tgt].refcount++;

    /* move the inode from old_tgt's list to new_tgt's list */
    {
        unsigned int *prev_ptr = &d->states[old_tgt].in_head;
        unsigned int ni = *prev_ptr;

        while (ni != 0) {
            /* Re-fetch inode each iteration (safe -- no realloc in loop) */
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
    }
    /* Not found -- shouldn't happen if bookkeeping is correct */
    assert(0 && "incoming_redirect_one: inode not found");
}

/* ─── Signature computation (FNV-1a) ───────────────────────────────────── */

static uint64_t sig_compute(const State *s)
{
    uint64_t h = FNV_OFFSET;

    /* hash the final flag */
    h ^= s->is_final ? 1 : 0;
    h *= FNV_PRIME;

    /* hash each transition: sym + target_id (little-endian) */
    {
        unsigned int i;
        for (i = 0; i < s->ntrans; i++) {
            unsigned int t;
            int b;

            h ^= s->trans[i].sym;
            h *= FNV_PRIME;
            /* hash target as 4 bytes */
            t = s->trans[i].target;
            for (b = 0; b < 4; b++) {
                h ^= (uint8_t)(t & 0xFF);
                h *= FNV_PRIME;
                t >>= 8;
            }
        }
    }
    return h;
}

/* ─── Register (equivalence-class map) ────────────────────────────────── */

static unsigned int reg_lookup(dafsa *d, uint64_t sig)
{
    size_t idx;

    if (sig == 0) return 0;  /* 0 = invalid/empty */

    idx = (size_t)(sig % d->reg_cap);
    while (d->reg_keys[idx] != 0) {
        if (d->reg_keys[idx] == sig)
            return d->reg_vals[idx];
        idx = (idx + 1) % d->reg_cap;
        d->reg_probes++;
    }
    return 0;  /* not found */
}

/* Grow the register: double capacity -> next prime, rehash all entries. */
static void reg_grow(dafsa *d)
{
    size_t new_cap = next_prime(d->reg_cap * 2);
    uint64_t *new_keys;
    uint32_t *new_vals;
    size_t i;

    new_keys = calloc(new_cap, sizeof(uint64_t));
    new_vals = calloc(new_cap, sizeof(uint32_t));
    if (!new_keys || !new_vals) {
        free(new_keys);
        free(new_vals);
        fprintf(stderr, "dafsa: OOM growing register\n");
        abort();
    }

    /* Rehash all existing entries */
    for (i = 0; i < d->reg_cap; i++) {
        uint64_t sig = d->reg_keys[i];
        if (sig == 0) continue;
        {
            size_t idx = (size_t)(sig % new_cap);
            while (new_keys[idx] != 0)
                idx = (idx + 1) % new_cap;
            new_keys[idx] = sig;
            new_vals[idx] = d->reg_vals[i];
        }
    }

    free(d->reg_keys);
    free(d->reg_vals);
    d->reg_keys = new_keys;
    d->reg_vals = new_vals;
    d->reg_cap   = new_cap;
    /* reg_used is unchanged (same number of entries) */
}

static void reg_insert(dafsa *d, uint64_t sig, unsigned int id)
{
    size_t idx;

    if (sig == 0) return;

    /* Grow if load factor would exceed 0.7 after insert */
    if ((d->reg_used + 1) * 10 > d->reg_cap * 7)
        reg_grow(d);

    idx = (size_t)(sig % d->reg_cap);
    while (d->reg_keys[idx] != 0) {
        /* overwrite if re-inserting the same state */
        if (d->reg_keys[idx] == sig) {
            d->reg_vals[idx] = id;
            return;
        }
        idx = (idx + 1) % d->reg_cap;
        d->reg_probes++;
    }
    d->reg_keys[idx] = sig;
    d->reg_vals[idx] = id;
    d->reg_used++;
}

/* Rebuild the register from scratch over all live states.  Merge operations
 * leave stale sig->id entries pointing at dead/orphan states; a later state
 * with the same signature would then merge into the wrong target.  Called
 * after a delete (which merges) to guarantee a clean equivalence map. */
static void reg_rebuild(dafsa *d)
{
    unsigned int i;

    memset(d->reg_keys, 0, d->reg_cap * sizeof(uint64_t));
    memset(d->reg_vals, 0, d->reg_cap * sizeof(uint32_t));
    d->reg_used = 0;

    for (i = 1; i < d->nstates; i++) {
        if (d->states[i].refcount != 0 || i == d->initial) {
            uint64_t sig = sig_compute(&d->states[i]);
            d->states[i].sig = sig;
            reg_insert(d, sig, i);
        }
    }
}

/* ─── Clone-on-write ──────────────────────────────────────────────────── */

/* Clone state `sid`, return the clone's id. The clone gets refcount=0
 * initially, and all its outgoing transitions add incoming edges to their
 * targets (via incoming_add). The caller is responsible for redirecting
 * the appropriate single incoming edge from the parent.
 *
 * Pointer safety: state_new() may realloc d->states, so we fetch src/dst
 * AFTER state_new. incoming_add() may realloc d->inodes, but dst/src point
 * into d->states (separate allocation), so they remain valid. */
static unsigned int clone_state(dafsa *d, unsigned int sid)
{
    unsigned int new_id = state_new(d);   /* MAY REALLOC d->states */

    /* Re-fetch AFTER state_new: the old &d->states[sid] would be stale */
    State *src = &d->states[sid];
    State *dst = &d->states[new_id];

    dst->is_final = src->is_final;
    dst->ntrans = src->ntrans;
    memcpy(dst->trans, src->trans, src->ntrans * sizeof(Edge));
    dst->sig = src->sig;

    /* Register incoming edges for all of the clone's outgoing transitions.
     * incoming_add may realloc d->inodes, but dst is in d->states (safe). */
    {
        unsigned int i;
        for (i = 0; i < dst->ntrans; i++) {
            incoming_add(d, new_id, dst->trans[i].sym, dst->trans[i].target);
        }
    }

    return new_id;
}

/* ─── Core: replace_or_register ────────────────────────────────────────── */

/* After modifying state `sid`, call this to either register it (if its
 * signature is unique) or merge it with an existing equivalent state.
 *
 * `parent` is the state that transitions to `sid`.
 * After a merge, parent's signature is invalidated; confluence_path
 * will re-register it.
 *
 * Pointer safety: s = &d->states[sid] is fetched once. reg_lookup and
 * reg_insert may realloc reg_keys/reg_vals (separate allocation), so s
 * remains valid. incoming_redirect also does not realloc states/inodes. */
static void replace_or_register(dafsa *d, unsigned int sid,
                                 unsigned int parent)
{
    State *s = &d->states[sid];  /* fetched once; states not realloc'd here */
    uint64_t new_sig;
    unsigned int equivalent;

    /* Compute (or recompute) signature */
    new_sig = sig_compute(s);
    s->sig = new_sig;

    equivalent = reg_lookup(d, new_sig);
    if (equivalent != 0 && equivalent != sid) {
        /* --- MERGE: sid into equivalent --- */
        incoming_redirect(d, sid, equivalent);

        /* Repoint the register entry: this signature now belongs to the
         * surviving state `equivalent`, not the merged-away `sid`.  Leaving
         * the stale sid entry would make a later state with the same signature
         * merge into a dead id. */
        reg_insert(d, new_sig, equivalent);

        /* parent's transition was updated by incoming_redirect.
         * Now parent's signature is dirty. */
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
 * chars[i]    = transition character from path[i-1] to path[i]
 *               (chars[0] is unused)
 * parents[i]  = path[i-1]
 * len         = number of states on the path
 *
 * Pointer safety: operates entirely on indices in the path[]/parents[]
 * stack arrays. replace_or_register re-fetches State * internally. */
static void confluence_path(dafsa *d, unsigned int *path,
                             unsigned char *chars,
                             unsigned int *parents,
                             unsigned int len)
{
    int i;
    (void)chars;  /* kept for symmetry */
    for (i = (int)len - 1; i >= 1; i--) {
        unsigned int child  = path[i];
        unsigned int parent = parents[i];
        replace_or_register(d, child, parent);
    }
    /* Also register the root if it was modified */
    replace_or_register(d, path[0], 0);
}

/* ─── Add word (length-delimited) ──────────────────────────────────────── */

int dafsa_add_n(dafsa *d, const unsigned char *key, size_t len)
{
    unsigned int path[MAX_WORD_LEN + 2];
    unsigned char chars[MAX_WORD_LEN + 2];
    unsigned int parents[MAX_WORD_LEN + 2];
    unsigned int path_len;
    unsigned int current;
    unsigned int pos;

    if (len == 0) {
        /* Empty string: the initial state becomes final */
        if (d->states[d->initial].is_final) return 0;
        d->states[d->initial].is_final = 1;
        replace_or_register(d, d->initial, 0);
        return 1;
    }
    if (key == NULL) return -1;   /* defensive: non-empty key must be non-NULL */
    assert(len <= MAX_WORD_LEN);

    /* --- Phase 1: Traverse existing path --- */
    current  = d->initial;
    path_len = 0;

    path[path_len]    = current;
    chars[path_len]   = 0;
    parents[path_len] = 0;
    path_len++;

    for (pos = 0; pos < len; pos++) {
        unsigned char c = key[pos];
        int tr = trans_find(&d->states[current], c);
        if (tr < 0) break;  /* divergence point */

        {
            unsigned int next = d->states[current].trans[tr].target;
            current = next;
            path[path_len]    = current;
            chars[path_len]   = c;
            parents[path_len] = path[path_len - 1];
            path_len++;
        }
    }

    /* --- Check: word already present? --- */
    if (pos == len && d->states[current].is_final)
        return 0;  /* already in the DAFSA */

    /* --- Clone-on-write: make the prefix path private (ascending) ---
     * Clone every shared state along the path from root toward the leaf.
     * Each redirect targets the already-private parent path[di-1], so it
     * never affects other words that share a sub-automaton.  This is required
     * when re-adding a word whose (deleted) ghost branch is still shared with
     * another word, as well as when adding a fresh suffix at a divergence. */
    {
        unsigned int di;
        for (di = 1; di < path_len; di++) {
            unsigned int sid = path[di];
            if (d->states[sid].refcount > 1) {
                unsigned int clone = clone_state(d, sid);
                unsigned int parent = path[di - 1];
                unsigned char pc    = chars[di];

                /* clone_state may realloc states; re-fetch via indices */
                incoming_redirect_one(d, parent, pc, sid, clone);

                /* Update path (and the parent pointer of the next element) */
                path[di] = clone;
                if (di + 1 < path_len)
                    parents[di + 1] = clone;
            }
        }
        current = path[path_len - 1];
    }

    /* --- Phase 2: Add suffix from the divergence point --- */
    if (pos < len) {
        unsigned int i;
        for (i = pos; i < len; i++) {
            unsigned char c = key[i];
            unsigned int next;

            next = state_new(d);   /* MAY REALLOC states */
            /* re-fetch state via index -- current is an index, safe */
            trans_add(&d->states[current], c, next);
            d->states[current].sig = 0;  /* dirty */

            incoming_add(d, current, c, next);  /* MAY REALLOC inodes */

            path[path_len]    = next;
            chars[path_len]   = c;
            parents[path_len] = current;
            path_len++;

            current = next;
        }
    }

    /* --- Phase 3: Mark final and confluence --- */
    d->states[current].is_final = 1;
    d->states[current].sig = 0;  /* dirty */

    confluence_path(d, path, chars, parents, path_len);

    /* The confluence may have merged states, leaving stale register entries.
     * Rebuild so the next operation starts from a clean equivalence map. */
    reg_rebuild(d);

    return 1;
}

/* ─── Delete word (length-delimited) ───────────────────────────────────── */

int dafsa_delete_n(dafsa *d, const unsigned char *key, size_t len)
{
    unsigned int path[MAX_WORD_LEN + 2];
    unsigned char chars[MAX_WORD_LEN + 2];
    unsigned int parents[MAX_WORD_LEN + 2];
    unsigned int path_len;
    unsigned int current;
    unsigned int i;
    int di;

    if (len == 0) {
        if (!d->states[d->initial].is_final) return 0;
        d->states[d->initial].is_final = 0;
        d->states[d->initial].sig = 0;
        replace_or_register(d, d->initial, 0);
        return 1;
    }
    if (key == NULL) return -1;   /* defensive: non-empty key must be non-NULL */
    assert(len <= MAX_WORD_LEN);

    /* --- Phase 1: Traverse to the final state --- */
    current  = d->initial;
    path_len = 0;

    path[path_len]    = current;
    chars[path_len]   = 0;
    parents[path_len] = 0;
    path_len++;

    for (i = 0; i < len; i++) {
        unsigned char c = key[i];
        int tr = trans_find(&d->states[current], c);
        if (tr < 0) return 0;  /* not present */
        current = d->states[current].trans[tr].target;
        path[path_len]    = current;
        chars[path_len]   = c;
        parents[path_len] = path[path_len - 1];
        path_len++;
    }

    if (!d->states[current].is_final)
        return 0;  /* word is a prefix but not a word */

    /* --- Phase 2: Clone-on-write, bottom-up ---
     * Walk the path from the root toward the leaf (ascending).  At each step
     * the parent (path[di-1]) is already private -- either it was cloned in
     * the previous iteration (refcount == 1) or it had refcount == 1 to begin
     * with -- so redirecting its single edge on the path cannot affect any
     * other word.  (A descending walk would redirect the edge of a still-shared
     * parent and corrupt words that share the sub-automaton.) */
    {
        for (di = 1; di < (int)path_len; di++) {
            unsigned int sid = path[di];
            if (d->states[sid].refcount > 1) {
                unsigned int clone = clone_state(d, sid);
                /* parent is the (possibly just-cloned) previous path state;
                 * must re-read path[di-1], NOT the stale parents[] snapshot */
                unsigned int parent = path[di - 1];
                unsigned char pc    = chars[di];

                /* clone_state may realloc states; re-fetch via indices */
                incoming_redirect_one(d, parent, pc, sid, clone);

                /* Update path -- and current if this is the final state */
                path[di] = clone;
                if (di < (int)path_len - 1)
                    parents[di + 1] = clone;
                if (di == (int)path_len - 1)
                    current = clone;
            }
        }
    }

    /* --- Phase 3: Unmark final and confluence --- */
    d->states[current].is_final = 0;
    d->states[current].sig = 0;

    confluence_path(d, path, chars, parents, path_len);

    /* Delete merges states (via confluence), which leaves stale register
     * entries pointing at merged-away/dead states.  Rebuild the register so
     * a subsequent add of a re-used signature merges into a live state. */
    reg_rebuild(d);

    return 1;
}

/* ─── Lookup (length-delimited) ────────────────────────────────────────── */

int dafsa_lookup_n(const dafsa *d, const unsigned char *key, size_t len)
{
    unsigned int current = d->initial;
    size_t i;

    if (key == NULL && len > 0) return 0;  /* defensive */

    for (i = 0; i < len; i++) {
        int tr = trans_find(&d->states[current], key[i]);
        if (tr < 0) return 0;
        current = d->states[current].trans[tr].target;
    }
    return d->states[current].is_final;
}

/* ─── NUL-terminated convenience wrappers ──────────────────────────────── */

int dafsa_add(dafsa *d, const unsigned char *word)
{
    return dafsa_add_n(d, word, strlen((const char *)word));
}

int dafsa_lookup(const dafsa *d, const unsigned char *word)
{
    return dafsa_lookup_n(d, word, strlen((const char *)word));
}

int dafsa_delete(dafsa *d, const unsigned char *word)
{
    return dafsa_delete_n(d, word, strlen((const char *)word));
}

/* ─── Persistence ─────────────────────────────────────────────────────── */

/* On-disk format (ROADMAP 1.3): all integers little-endian, explicit byte
 * writes (State/Edge have padding; never fwrite raw structs).
 *
 *   HEADER:  magic[4]="PDWG"; u32 version=1; u32 n_states; u32 n_trans;
 *            u32 initial_id=1; u32 n_final; u32 reserved=0
 *   STATE TABLE: (n_states+1) x 8B, entry 0 = (0,0): per id: u32 trans_offset; u32 ntrans
 *   FINAL BITMAP: ceil((n_states+1)/8) bytes; bit i set iff reachable state i is final
 *   CSR TRANSITIONS: n_trans x 5B (u8 sym; u32 target_id), grouped by state in
 *            state-table order, sorted by sym asc.  Sink 0 -> 0, else new id.
 */

static int put_u8(FILE *f, uint8_t v)
{
    return fputc(v, f) == EOF ? -1 : 0;
}

static int put_u32_le(FILE *f, uint32_t v)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (put_u8(f, (uint8_t)(v & 0xFF)) != 0) return -1;
        v >>= 8;
    }
    return 0;
}

static int get_u8(FILE *f, uint8_t *out)
{
    int c = fgetc(f);
    if (c == EOF) return -1;
    *out = (uint8_t)c;
    return 0;
}

static int get_u32_le(FILE *f, uint32_t *out)
{
    uint32_t v = 0;
    int i;
    for (i = 0; i < 4; i++) {
        int c = fgetc(f);
        if (c == EOF) return -1;
        v |= ((uint32_t)(uint8_t)c) << (8 * i);
    }
    *out = v;
    return 0;
}

/* Save a compact, minimal form: BFS-renumber reachable states 1..N (initial
 * -> 1), drop orphans (refcount 0 / unreachable).  Atomic: write path.tmp,
 * fflush, fsync, fclose, rename.  Returns 0 on success, -1 on any error.
 * `d` is const and is never mutated. */
int dafsa_save(const dafsa *d, const char *path)
{
    FILE *f = NULL;
    char *tmp_path = NULL;
    uint32_t *old_to_new = NULL;
    uint32_t *queue = NULL;
    uint32_t *offsets = NULL;
    unsigned char *visited = NULL;
    uint32_t n_reach = 0, n_trans = 0, n_final = 0;
    uint32_t head, tail, i, j;
    size_t path_len;
    int ok = -1;

    if (!d || !path) return -1;

    old_to_new = (uint32_t *)calloc(d->nstates, sizeof(uint32_t));
    queue      = (uint32_t *)malloc(d->nstates * sizeof(uint32_t));
    visited    = (unsigned char *)calloc(d->nstates, 1);
    if (!old_to_new || !queue || !visited) goto out;

    /* BFS from initial, renumber reachable states in BFS order 1..N */
    head = 0; tail = 0;
    queue[tail++] = d->initial;
    visited[d->initial] = 1;
    while (head < tail) {
        uint32_t old = queue[head++];
        const State *s = &d->states[old];
        old_to_new[old] = ++n_reach;
        if (s->is_final) n_final++;
        n_trans += s->ntrans;
        for (j = 0; j < s->ntrans; j++) {
            uint32_t tgt = s->trans[j].target;
            if (!visited[tgt]) {
                visited[tgt] = 1;
                queue[tail++] = tgt;
            }
        }
    }

    /* cumulative per-state transition offsets (BFS order = new id order):
     * trans_offset[i] = start index into the CSR of state i's transitions */
    offsets = (uint32_t *)calloc(n_reach + 1, sizeof(uint32_t));
    if (!offsets) goto out;
    {
        uint32_t run = 0;
        offsets[0] = 0;
        for (i = 1; i <= n_reach; i++) {
            offsets[i] = run;
            run += d->states[queue[i - 1]].ntrans;
        }
    }

    /* atomic: write to path.tmp then rename onto path */
    path_len = strlen(path);
    tmp_path = (char *)malloc(path_len + 5);
    if (!tmp_path) goto out;
    snprintf(tmp_path, path_len + 5, "%s.tmp", path);

    f = fopen(tmp_path, "wb");
    if (!f) goto out;

    /* header */
    if (put_u8(f, 'P') || put_u8(f, 'D') || put_u8(f, 'W') || put_u8(f, 'G'))
        goto fail;
    if (put_u32_le(f, 1)) goto fail;            /* version */
    if (put_u32_le(f, n_reach)) goto fail;      /* n_states */
    if (put_u32_le(f, n_trans)) goto fail;      /* n_trans */
    if (put_u32_le(f, 1)) goto fail;            /* initial_id */
    if (put_u32_le(f, n_final)) goto fail;      /* n_final */
    if (put_u32_le(f, 0)) goto fail;            /* reserved */

    /* state table: (n_states+1) x 8B, entry 0 = (0,0) */
    if (put_u32_le(f, 0) || put_u32_le(f, 0)) goto fail;
    for (i = 1; i <= n_reach; i++) {
        const State *s = &d->states[queue[i - 1]];
        if (put_u32_le(f, offsets[i])) goto fail;
        if (put_u32_le(f, s->ntrans)) goto fail;
    }

    /* final bitmap: ceil((n_states+1)/8) bytes; bit 0 always 0 */
    {
        uint32_t nb = (n_reach + 8) / 8;
        for (i = 0; i < nb; i++) {
            uint8_t byte = 0;
            for (j = 0; j < 8; j++) {
                uint32_t idx = i * 8 + j;
                if (idx >= 1 && idx <= n_reach &&
                    d->states[queue[idx - 1]].is_final)
                    byte |= (uint8_t)(1u << j);
            }
            if (put_u8(f, byte)) goto fail;
        }
    }

    /* CSR: transitions grouped by state in state-table order (sym asc) */
    for (i = 1; i <= n_reach; i++) {
        const State *s = &d->states[queue[i - 1]];
        for (j = 0; j < s->ntrans; j++) {
            if (put_u8(f, s->trans[j].sym)) goto fail;
            if (put_u32_le(f, old_to_new[s->trans[j].target])) goto fail;
        }
    }

    if (ferror(f)) goto fail;

    /* atomic commit */
    if (fflush(f) != 0) goto fail;
    if (fsync(fileno(f)) != 0) goto fail;
    if (fclose(f) != 0) { f = NULL; goto fail; }
    f = NULL;
    if (rename(tmp_path, path) != 0) goto fail;

    ok = 0;
    goto out;

fail:
    if (f) fclose(f);
    if (tmp_path) remove(tmp_path);
    ok = -1;

out:
    free(tmp_path);
    free(old_to_new);
    free(queue);
    free(offsets);
    free(visited);
    return ok;
}

/* Materialize the on-disk compact form back into a fully mutable DAFSA:
 * rebuilds the incoming-edge lists (refcount + in_head) and the register.
 * Returns the handle, or NULL on any error (partial handle freed). */
dafsa *dafsa_load(const char *path)
{
    FILE *f = NULL;
    dafsa *d = NULL;
    uint32_t *trans_offsets = NULL;
    uint8_t *final_bits = NULL;
    uint32_t version, n_states, n_trans, initial_id, n_final, reserved;
    uint32_t running;
    size_t bitmap_bytes;
    uint32_t i, j;

    if (!path) return NULL;

    f = fopen(path, "rb");
    if (!f) return NULL;

    /* header */
    {
        uint8_t magic[4];
        if (get_u8(f, &magic[0]) || get_u8(f, &magic[1]) ||
            get_u8(f, &magic[2]) || get_u8(f, &magic[3]))
            goto fail;
        if (magic[0] != 'P' || magic[1] != 'D' ||
            magic[2] != 'W' || magic[3] != 'G')
            goto fail;
    }
    if (get_u32_le(f, &version) || get_u32_le(f, &n_states) ||
        get_u32_le(f, &n_trans) || get_u32_le(f, &initial_id) ||
        get_u32_le(f, &n_final) || get_u32_le(f, &reserved))
        goto fail;
    (void)reserved;
    if (version != 1) goto fail;
    if (initial_id != 1) goto fail;
    if (n_states == 0) goto fail;                       /* initial must exist */
    if ((size_t)n_states + 1 > SIZE_MAX / sizeof(State)) goto fail;

    d = dafsa_create();
    if (!d) goto fail;

    /* grow states array to hold n_states+1 entries */
    if ((size_t)n_states + 1 > d->states_cap) {
        size_t new_cap = (size_t)n_states + 1;
        State *new_states = (State *)realloc(d->states, new_cap * sizeof(State));
        if (!new_states) goto fail;
        memset(new_states + d->states_cap, 0,
               (new_cap - d->states_cap) * sizeof(State));
        d->states = new_states;
        d->states_cap = new_cap;
    }
    d->nstates = n_states + 1;
    d->initial = 1;

    /* zero sink + live states; restore self indices */
    memset(d->states, 0, (size_t)(n_states + 1) * sizeof(State));
    for (i = 0; i <= n_states; i++)
        d->states[i].id = i;

    trans_offsets = (uint32_t *)malloc((n_states + 1) * sizeof(uint32_t));
    if (!trans_offsets) goto fail;

    /* state table: entry 0 = sink (0,0) */
    {
        uint32_t off, nt;
        if (get_u32_le(f, &off) || get_u32_le(f, &nt)) goto fail;
        if (off != 0 || nt != 0) goto fail;
    }
    for (i = 1; i <= n_states; i++) {
        uint32_t off, nt;
        if (get_u32_le(f, &off) || get_u32_le(f, &nt)) goto fail;
        if (nt > ALPHABET_SZ) goto fail;                /* >256 impossible */
        trans_offsets[i] = off;
        d->states[i].ntrans = nt;
    }

    /* validate offsets are cumulative and consistent with n_trans */
    running = 0;
    for (i = 1; i <= n_states; i++) {
        if (trans_offsets[i] != running) goto fail;
        running += d->states[i].ntrans;
    }
    if (running != n_trans) goto fail;

    /* final bitmap */
    bitmap_bytes = (size_t)((n_states + 8) / 8);
    final_bits = (uint8_t *)malloc(bitmap_bytes);
    if (!final_bits) goto fail;
    if (fread(final_bits, 1, bitmap_bytes, f) != bitmap_bytes) goto fail;
    {
        uint32_t finals = 0;
        for (i = 1; i <= n_states; i++) {
            if (final_bits[i / 8] & (uint8_t)(1u << (i % 8))) {
                d->states[i].is_final = 1;
                finals++;
            }
        }
        if (finals != n_final) goto fail;
    }

    /* CSR: direct copy into trans[] (already sorted, no trans_add) */
    for (i = 1; i <= n_states; i++) {
        State *s = &d->states[i];
        for (j = 0; j < s->ntrans; j++) {
            uint8_t sym;
            uint32_t target;
            if (get_u8(f, &sym) || get_u32_le(f, &target)) goto fail;
            if (target > n_states) goto fail;           /* 0 = sink, else 1..N */
            s->trans[j].sym = sym;
            s->trans[j].target = target;
        }
    }

    /* rebuild incoming edges: restores refcount + in_head */
    for (i = 1; i <= n_states; i++) {
        State *s = &d->states[i];
        for (j = 0; j < s->ntrans; j++)
            incoming_add(d, i, s->trans[j].sym, s->trans[j].target);
    }

    /* rebuild register: sig_compute + reg_insert per live state */
    for (i = 1; i <= n_states; i++) {
        State *s = &d->states[i];
        uint64_t sig = sig_compute(s);
        s->sig = sig;
        reg_insert(d, sig, i);
    }

    fclose(f);
    free(trans_offsets);
    free(final_bits);
    return d;

fail:
    if (f) fclose(f);
    dafsa_free(d);
    free(trans_offsets);
    free(final_bits);
    return NULL;
}

/* ─── Prefix enumeration ──────────────────────────────────────────────── */

/* Recursive DFS from `state`, appending transition bytes into buf.  Calls
 * cb at each final state with the accumulated payload (bytes collected after
 * the 0x00 edge).  Returns non-zero to stop early. */
static int enum_dfs(const dafsa *d, unsigned int state, unsigned char *buf,
                    size_t depth, dafsa_enum_cb cb, void *user, long *count)
{
    const State *s = &d->states[state];
    uint32_t j;

    if (s->is_final) {
        (*count)++;
        if (cb(buf, depth, user) != 0) return 1;
    }
    if (depth >= MAX_WORD_LEN) return 0;
    for (j = 0; j < s->ntrans; j++) {
        buf[depth] = (unsigned char)s->trans[j].sym;
        if (enum_dfs(d, s->trans[j].target, buf, depth + 1,
                     cb, user, count) != 0)
            return 1;
    }
    return 0;
}

/* Enumerate keys of form prefix || 0x00 || payload.  Walks the prefix from
 * the initial state, requires a 0x00 edge next (W\0 semantics), then DFS the
 * payload states calling cb(payload, len).  Returns the number of keys
 * enumerated; 0 if the prefix is absent or not a key boundary. */
long dafsa_prefix_enum(const dafsa *d, const unsigned char *prefix,
                       size_t prefix_len, dafsa_enum_cb cb, void *user)
{
    unsigned int current;
    unsigned char buf[MAX_WORD_LEN];
    size_t i;
    int tr;
    long count = 0;

    if (!d || !cb) return -1;
    if (prefix == NULL && prefix_len > 0) return 0;
    if (prefix_len > MAX_WORD_LEN) return 0;

    current = d->initial;

    /* walk the prefix */
    for (i = 0; i < prefix_len; i++) {
        tr = trans_find(&d->states[current], prefix[i]);
        if (tr < 0) return 0;
        current = d->states[current].trans[tr].target;
    }

    /* W\0 semantics: a 0x00 edge must exist from the final prefix state */
    tr = trans_find(&d->states[current], 0x00);
    if (tr < 0) return 0;
    current = d->states[current].trans[tr].target;

    enum_dfs(d, current, buf, 0, cb, user, &count);
    return count;
}

/* ─── Statistics ───────────────────────────────────────────────────────── */

void dafsa_stats(const dafsa *d, dafsa_stats_out *out)
{
    unsigned char *visited;
    unsigned int *queue;
    unsigned int head, tail;
    unsigned int reachable, finals, transitions;

    if (!d || !out) return;

    visited = (unsigned char *)calloc(d->nstates, 1);
    queue   = (unsigned int *)malloc(d->nstates * sizeof(unsigned int));
    if (!visited || !queue) {
        free(visited);
        free(queue);
        /* Degrade gracefully: return zeros */
        memset(out, 0, sizeof(*out));
        return;
    }

    head     = 0;
    tail     = 0;
    reachable = 0;
    finals    = 0;
    transitions = 0;

    queue[tail++] = d->initial;
    visited[d->initial] = 1;

    while (head < tail) {
        unsigned int sid = queue[head++];
        const State *s = &d->states[sid];

        reachable++;
        if (s->is_final) finals++;
        transitions += s->ntrans;

        {
            unsigned int j;
            for (j = 0; j < s->ntrans; j++) {
                unsigned int tgt = s->trans[j].target;
                if (!visited[tgt]) {
                    visited[tgt] = 1;
                    queue[tail++] = tgt;
                }
            }
        }
    }

    out->n_states_total     = d->nstates - 1;  /* exclude sink 0 */
    out->n_states_reachable = reachable;
    out->n_final            = finals;
    out->n_trans            = transitions;
    out->register_probes    = d->reg_probes;

    free(visited);
    free(queue);
}

/* ─── Dot output for visualization ─────────────────────────────────────── */

void dafsa_dot(const dafsa *d, FILE *f)
{
    unsigned int i;

    if (!d || !f) return;

    fprintf(f, "digraph DAFSA {\n");
    fprintf(f, "  rankdir=LR;\n");
    fprintf(f, "  node [shape=circle,fontsize=10];\n");
    /* mark the initial state */
    fprintf(f, "  start [shape=point];\n");
    fprintf(f, "  start -> %u;\n", d->initial);

    for (i = 1; i < d->nstates; i++) {
        const State *s = &d->states[i];
        const char *shape;
        unsigned int j;

        if (s->refcount == 0 && s->id != d->initial) continue; /* skip orphans */

        shape = s->is_final ? "doublecircle" : "circle";
        fprintf(f, "  %u [shape=%s,label=\"%u (rc=%u)\"];\n",
                s->id, shape, s->id, s->refcount);

        for (j = 0; j < s->ntrans; j++) {
            fprintf(f, "  %u -> %u [label=\"%c\"];\n",
                    s->id, s->trans[j].target,
                    s->trans[j].sym >= 32 && s->trans[j].sym < 127
                        ? s->trans[j].sym : '?');
        }
    }
    fprintf(f, "}\n");
}
