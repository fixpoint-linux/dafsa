// dafsa_build.zig — Bulk minimal DAFSA construction (Daciuk et al. 2000)
//
// Port of dafsa_build.c — builds a MINIMAL DAFSA from a SORTED, DEDUPLICATED
// key list in ~linear time via the construction algorithm of:
//
//   Daciuk, J., Mihov, S., Watson, B.W., & Watson, R.E. (2000)
//   "Incremental Construction of Minimal Acyclic Finite-State Automata"
//   Computational Linguistics, 26(1), pp. 3-16.
//
// Uses the engine's existing primitives (stateNew, transAdd, incomingAdd,
// replaceOrRegister) without modifying any core module or adding new internal
// helpers.  State-ID faithfulness for the build path is NOT required (see the
// IMPLEMENTATION NOTE below) — the differential gate is language-level stats +
// byte-equal save, both of which canonicalize on the language.
//
// IMPLEMENTATION NOTE: Because we freeze states bottom-up via the register
// as soon as they can no longer change (suffix of a prefix that won't be
// seen again), and dafsa_save BFS-renumbers reachable states and serializes
// only sym-ascending transitions + final bits, ANY minimal DAFSA with the
// same language will serialize byte-identical.  We do NOT need to reproduce
// the incremental path's internal numbering/refcounts/inodes/register/free-list.
//
// NOTE ON THE FILENAME: never name this file build.zig — reserved by the Zig
// build system.  dafsa_build.zig is the canonical name.

const std = @import("std");
const internal = @import("internal.zig");
const state = @import("state.zig");
const core = @import("core.zig");
const dafsa_mod = @import("dafsa.zig");
const Dafsa = internal.Dafsa;

const MAX_WORD_LEN = internal.MAX_WORD_LEN;

// Length of longest common prefix between two length-delimited keys.
// Returns the byte position of the first difference (0..min(alen,blen)).
fn lcp(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) break;
    }
    return i;
}

// keys[i] is the i-th key (length-delimited; empty slice == empty key).
// PRE: keys are in unsigned-byte lexicographic order, no duplicates.
// Returns a new handle (free with dafsaFree) or null on OOM/bad args.
// nkeys == 0 => empty dafsa.
pub fn dafsaBuildSorted(keys: []const []const u8) ?*Dafsa {
    const nkeys = keys.len;

    if (nkeys == 0) return dafsa_mod.dafsaCreate();

    const d = dafsa_mod.dafsaCreate() orelse return null;

    // Find max key length and ensure scratch.
    {
        var max_len: usize = 0;
        for (keys) |k| {
            if (k.len > max_len) max_len = k.len;
        }
        if (max_len > MAX_WORD_LEN) {
            dafsa_mod.dafsaFree(d);
            return null;
        }
        // Always ensure scratch is allocated — even for empty keys,
        // we need the spath array for the root entry.
        if (state.dafsaEnsureScratch(d, if (max_len > 0) max_len else 1) != 0) {
            dafsa_mod.dafsaFree(d);
            return null;
        }
    }

    // Active path stack: spath = state ids, sparents = parent state ids,
    // schars = transition symbols.  Indexing: path[0] = root (initial),
    // path[1..sp-1] = suffix states.  sp is the depth (number of states).
    var sp: usize = 0;
    d.spath[sp] = d.initial;
    d.sparents[sp] = 0;
    d.schars[sp] = 0;
    sp = 1;

    var prev: []const u8 = &.{};
    var prev_len: usize = 0;

    var i: usize = 0;
    while (i < nkeys) : (i += 1) {
        const w = keys[i];
        const wlen = w.len;
        const j = lcp(prev[0..prev_len], w[0..wlen]); // common-prefix length

        // --- Freeze suffix below depth j: register bottom-up ---
        // States below the divergence point can never change again
        // (sorted input guarantees no later key shares this suffix).
        // Each state on the suffix path has refcount==1 (guaranteed by the
        // Daciuk construction: the only parent is the state above it on the
        // active path).
        while (sp > j + 1) {
            sp -= 1;
            _ = core.replaceOrRegister(d, d.spath[sp], d.sparents[sp]);
        }

        // --- Extend suffix w[j..wlen-1] from path[sp-1] ---
        {
            var cur = d.spath[sp - 1];
            var k = j;
            while (k < wlen) : (k += 1) {
                const nxt = state.stateNew(d); // may realloc states

                // Re-fetch via index — state_new may have realloc'd
                state.transAdd(&d.states[cur], w[k], nxt);
                d.states[cur].sig = 0;

                core.incomingAdd(d, cur, w[k], nxt); // may realloc inodes

                d.spath[sp] = nxt;
                d.sparents[sp] = cur;
                d.schars[sp] = w[k];
                sp += 1;
                cur = nxt;
            }

            // Mark final and dirty signature.
            d.states[cur].is_final = 1;
            d.states[cur].sig = 0;
        }

        // Special case: wlen==0 — mark initial as final (must be first key).
        if (wlen == 0) {
            d.states[d.initial].is_final = 1;
            d.states[d.initial].sig = 0;
        }

        prev = w;
        prev_len = wlen;
    }

    // --- Final flush: register remaining path bottom-up ---
    while (sp > 1) {
        sp -= 1;
        _ = core.replaceOrRegister(d, d.spath[sp], d.sparents[sp]);
    }

    // Register root.
    _ = core.replaceOrRegister(d, d.initial, 0);

    return d;
}
