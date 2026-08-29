// rank.zig — Tier-2 order-statistics (rank / select / range_count).
// Faithful Zig port of dafsa_rank.c.
//
// Implements the per-state DISTINCT-complete-keys-reachable subtree counts
// for a minimized DAFSA, plus order-statistics primitives built on them:
//
//   dafsaEnsureSubtree — lazily (re)builds d.subtree once, memoizing each
//                        state's count; O(n_states + n_trans).
//   dafsaRankN         — number of complete keys strictly < key.
//   dafsaSelectN       — k-th complete key (0-indexed, lex order).
//   dafsaRangeCountN   — half-open [lo, hi) key count.
//
// Each order-statistic has a PREFIX-BOUND (start-state) twin used by the
// relation layer's *_bound API: dafsaRankFrom / dafsaSelectFrom /
// dafsaRangeCountFrom take a start state `s` (the state reached by walking a
// bound prefix) and rank/select/count within that state's subtree.  The plain
// *_n variants are thin wrappers over the same core with s = d.initial.
//
// Correctness of the recurrence (count(s) = is_final(s) + sum over s's
// OUTGOING transitions of count(target)): within a state every transition has
// a DISTINCT symbol, so the per-transition key sets are disjoint; a state
// shared by N parents is counted once per parent edge, which is CORRECT
// because each parent edge carries a distinct symbol => disjoint full-key
// sets.  The DFA's determinism guarantees #walks == #keys, so summing counts
// never double-counts.  All counts are u64: a cross-product relation with
// N x M distinct keys has only ~N+M+2 states, so counts can exceed 2^32 long
// before the DAFSA is huge (a u32 would silently mis-evaluate range_count
// above 4B keys).
//
// The counts are a pure cached diagnostic in the same spirit as dafsa_stats:
// NOT persisted, rebuilt lazily on first use.  The array is freed in
// dafsaFree and realloc'd in dafsaEnsureSubtree when nstates grows (stateNew
// can push nstates up between builds), so there is no stale-size bug.
//
// OOM-DEGRADES-TO-0 SEMANTICS (matches C exactly): subtree_valid stays 0 when
// a build fails (alloc failure), so the next call retries the build.  On a
// failed build the rank/select/range_count ops degrade to 0 / -1 (never
// abort).

const std = @import("std");
const internal = @import("internal.zig");
const Dafsa = internal.Dafsa;

// ─── subtree path-count: number of DISTINCT complete keys reachable from s ──
// For a MINIMIZED DAG this is memoized bottom-up; a state shared by N parents
// contributes its count to each parent edge, which is CORRECT (each parent edge
// is a distinct symbol => disjoint key sets). count(s) = is_final(s) + sum over
// outgoing transitions of count(target). Recursion is over the DAG state graph
// (one frame per state), so depth is bounded by n_states, not by key length.
fn countRecurse(d: *const Dafsa, s: u32, memo: []u64, visiting: []u8) u64 {
    const st = &d.states[s];
    if (visiting[s] != 0) return memo[s]; // DAG revisit: already computed
    var c: u64 = if (st.is_final != 0) 1 else 0;
    const arr = internal.transArrC(st);
    var j: u32 = 0;
    while (j < st.ntrans) : (j += 1) {
        c +%= countRecurse(d, arr[j].target, memo, visiting);
    }
    memo[s] = c;
    visiting[s] = 1;
    return c;
}

// Lazily (re)build the per-state subtree-count array into d.subtree.
// Returns the root count (== number of distinct keys == n_final semantics).
// On OOM degrades to 0 (d.subtree_valid stays 0 so the next call retries);
// never aborts.
pub fn dafsaEnsureSubtree(d: *Dafsa) u64 {
    if (d.subtree_valid != 0) return d.subtree[d.initial];
    if (d.subtree_cap < d.nstates) {
        if (d.subtree.len != 0) d.allocator.free(d.subtree);
        d.subtree = d.allocator.alloc(u64, d.nstates) catch {
            d.subtree = internal.emptySlice(u64);
            d.subtree_cap = 0;
            return 0; // OOM: degrade
        };
        @memset(d.subtree, 0);
        d.subtree_cap = d.nstates;
    } else {
        @memset(d.subtree[0..d.nstates], 0);
    }
    const vis = d.allocator.alloc(u8, d.nstates) catch return 0;
    defer d.allocator.free(vis);
    @memset(vis, 0);
    _ = countRecurse(d, d.initial, d.subtree, vis);
    d.subtree_valid = 1;
    return d.subtree[d.initial];
}

// rank within the subtree rooted at state `s` = number of complete keys
// reachable from `s` strictly lexicographically < key.  O(len * ntrans).
// Correct for absent keys (returns insertion position).  OOM during the lazy
// build degrades to 0 (never abort).
fn rankCore(d: *Dafsa, s: u32, key: []const u8) u64 {
    var r: u64 = 0;
    var cur_s = s;

    if (cur_s == 0 or cur_s >= d.nstates) return 0;
    _ = dafsaEnsureSubtree(d);
    if (d.subtree_valid == 0) return 0; // OOM during build: degrade to 0

    for (key, 0..) |c, i| {
        const st = &d.states[cur_s];

        // If `cur_s` is final, the key key[0..i-1] is itself a complete key that
        // is a strict prefix of `key`, hence strictly < it: count it.
        if (st.is_final != 0) r +%= 1;

        // Transitions are sym-ascending; accumulate every subtree whose first
        // byte is < c (those keys diverge earlier and are < key), stop at the
        // == c edge.
        var matched: i32 = -1;
        const arr = internal.transArrC(st);
        var j: u32 = 0;
        while (j < st.ntrans) : (j += 1) {
            const e = arr[j];
            if (e.sym < c) {
                r +%= d.subtree[e.target];
            } else if (e.sym == c) {
                matched = @intCast(j);
                break;
            } else {
                break; // sorted: no later entry can equal c
            }
        }
        if (matched < 0) return r; // key diverges here: insertion position
        cur_s = internal.transArrC(st)[@intCast(matched)].target;
        _ = i;
    }
    // Consumed all `len` bytes.  If cur_s is final the key is present and must
    // NOT count itself (strictly <); if not final the key is an absent prefix,
    // and all strictly-smaller keys were already accumulated above.
    return r;
}

// rank(key) = number of complete keys strictly lexicographically < key
// (start state = d.initial).  See rankCore.
pub fn dafsaRankN(d: *Dafsa, key: []const u8) u64 {
    return rankCore(d, d.initial, key);
}

// Prefix-bound form: rank within the subtree rooted at `s` (the state reached
// by walking the bound prefix).  See rankCore.
pub fn dafsaRankFrom(d: *Dafsa, s: u32, key: []const u8) u64 {
    return rankCore(d, s, key);
}

// select within the subtree rooted at state `s`: the k-th complete key in lex
// order (0-indexed), written to key_out.  Returns the key length on success, or
// -1 if k >= total count of the subtree or on OOM (never aborts).
fn selectCore(d: *Dafsa, s: u32, k: u64, key_out: []u8) i32 {
    var pos: usize = 0;
    var kk = k;
    var cur_s = s;

    if (cur_s == 0 or cur_s >= d.nstates) return -1;
    _ = dafsaEnsureSubtree(d);
    if (d.subtree_valid == 0) return -1; // OOM during build: degrade to -1

    const total = d.subtree[cur_s];
    if (kk >= total) return -1; // out of range

    while (true) {
        const st = &d.states[cur_s];

        if (st.is_final != 0) {
            if (kk == 0) return @intCast(pos); // key_out[0..pos-1] is the k-th key
            kk -%= 1; // skip the "ends here" key
        }
        // Descend into the smallest-sym transition whose subtree contains the
        // k-th key.
        const arr = internal.transArrC(st);
        var descended = false;
        var j: u32 = 0;
        while (j < st.ntrans) : (j += 1) {
            const e = arr[j];
            const cnt = d.subtree[e.target];
            if (kk < cnt) {
                if (pos >= key_out.len) return -1; // key too long for buffer
                key_out[pos] = e.sym;
                pos += 1;
                cur_s = e.target;
                descended = true;
                break;
            }
            kk -%= cnt;
        }
        if (!descended) return -1; // unreachable if k < total; defensive
    }
}

// select(k) = the k-th complete key in lex order (0-indexed), written to
// key_out.  Returns the key length on success, or -1 if k >= total count or on
// OOM (never aborts).
pub fn dafsaSelectN(d: *Dafsa, k: u64, key_out: []u8) i32 {
    return selectCore(d, d.initial, k, key_out);
}

// Prefix-bound form: select within the subtree rooted at `s`.  See selectCore.
pub fn dafsaSelectFrom(d: *Dafsa, s: u32, k: u64, key_out: []u8) i32 {
    return selectCore(d, s, k, key_out);
}

// range_count within the subtree rooted at `s` = number of complete keys in the
// half-open interval [lo, hi), i.e. rank(hi) - rank(lo).  Returns 0 on
// error/OOM (never abort).
fn rangeCountCore(d: *Dafsa, s: u32, lo: []const u8, hi: []const u8) u64 {
    const rhi = rankCore(d, s, hi);
    const rlo = rankCore(d, s, lo);
    return if (rhi > rlo) rhi - rlo else 0;
}

// range_count = number of complete keys in the half-open interval [lo, hi),
// i.e. rank(hi) - rank(lo).  Returns 0 on error/OOM (never abort).
pub fn dafsaRangeCountN(d: *Dafsa, lo: []const u8, hi: []const u8) u64 {
    return rangeCountCore(d, d.initial, lo, hi);
}

// Prefix-bound form: range_count within the subtree rooted at `s`.
pub fn dafsaRangeCountFrom(d: *Dafsa, s: u32, lo: []const u8, hi: []const u8) u64 {
    return rangeCountCore(d, s, lo, hi);
}
