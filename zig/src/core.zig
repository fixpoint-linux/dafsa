// core.zig — Core DAFSA algorithms (mirrors dafsa_core.c)
//
// The correctness-critical heart: incoming-edge tracking, FNV-1a signatures,
// open-addressing register, clone-on-write, replace_or_register (stale-entry
// validation), confluence_path, and the add/delete/lookup entry points.
// Every allocation order and the clone-on-write ASCENDING (root→leaf) walk
// are replicated 1:1 with the C engine.

const std = @import("std");
const internal = @import("internal.zig");
const state = @import("state.zig");
const Dafsa = internal.Dafsa;
const State = internal.State;
const Inode = internal.Inode;
const Edge = internal.Edge;
const TransHeap = internal.TransHeap;

const FNV_OFFSET = internal.FNV_OFFSET;
const FNV_PRIME = internal.FNV_PRIME;
const MAX_WORD_LEN = internal.MAX_WORD_LEN;
const DAFSA_INLINE_N = internal.DAFSA_INLINE_N;

// ─── Incoming-edge tracking (dafsa_core.c:5-14) ─────────────────────────────

pub fn incomingAdd(d: *Dafsa, src: u32, c: u8, dst: u32) void {
    const in = state.inodeAlloc(d); // may realloc d.inodes
    in.parent = src;
    in.sym = c;
    in.next = d.states[dst].in_head; // re-fetched by index, safe
    d.states[dst].in_head = d.inodes_used;
    d.states[dst].refcount += 1;
}

// Redirect ALL incoming edges that point to old_tgt to point to new_tgt, and
// fix up parents' transition tables (dafsa_core.c:23-58).  No realloc-triggering
// call inside the loop — State* fetched once stay valid; callers re-fetch by
// index.  If old_tgt becomes an orphan, free it for reuse.
pub fn incomingRedirect(d: *Dafsa, old_tgt: u32, new_tgt: u32) void {
    var ni = d.states[old_tgt].in_head;
    while (ni != 0) {
        const in = &d.inodes[ni];
        const parent = in.parent;

        // update parent's transition
        const pos = state.transFind(&d.states[parent], in.sym);
        std.debug.assert(pos >= 0);
        internal.transArr(&d.states[parent])[@intCast(pos)].target = new_tgt;
        d.states[parent].sig = 0; // invalidate, will recompute

        // update refcounts
        d.states[old_tgt].refcount -= 1;
        d.states[new_tgt].refcount += 1;

        // move the inode to new_tgt's list
        const next = in.next;
        in.next = d.states[new_tgt].in_head;
        d.states[new_tgt].in_head = ni;
        ni = next;
    }
    d.states[old_tgt].in_head = 0;

    // If old_tgt is now an orphan, free it for reuse.
    if (d.states[old_tgt].refcount == 0 and old_tgt != d.initial)
        state.stateFree(d, old_tgt);
}

// Redirect a single incoming edge: parent's transition via sym from old_tgt
// to new_tgt (dafsa_core.c:66-110).  Used during clone-on-write.  No realloc
// in the loop body — re-fetch inode each iteration.
pub fn incomingRedirectOne(
    d: *Dafsa,
    parent: u32,
    sym: u8,
    old_tgt: u32,
    new_tgt: u32,
) void {
    // update parent's transition
    const pos = state.transFind(&d.states[parent], sym);
    std.debug.assert(pos >= 0);
    std.debug.assert(internal.transArr(&d.states[parent])[@intCast(pos)].target == old_tgt);
    internal.transArr(&d.states[parent])[@intCast(pos)].target = new_tgt;
    d.states[parent].sig = 0;

    // update refcounts
    d.states[old_tgt].refcount -= 1;
    d.states[new_tgt].refcount += 1;

    // move the inode from old_tgt's list to new_tgt's list
    var prev_ptr: *u32 = &d.states[old_tgt].in_head;
    var ni = prev_ptr.*;
    while (ni != 0) {
        const in = &d.inodes[ni];
        if (in.parent == parent and in.sym == sym) {
            // unlink from old_tgt
            prev_ptr.* = in.next;
            // link into new_tgt
            in.next = d.states[new_tgt].in_head;
            d.states[new_tgt].in_head = ni;

            // If old_tgt is now an orphan, free it for reuse.
            if (d.states[old_tgt].refcount == 0 and old_tgt != d.initial)
                state.stateFree(d, old_tgt);

            return;
        }
        prev_ptr = &in.next;
        ni = prev_ptr.*;
    }
    // Not found — shouldn't happen if bookkeeping is correct.
    @panic("incoming_redirect_one: inode not found");
}

// ─── Signature computation: FNV-1a (dafsa_core.c:119-138) ────────────────────
//
// h ^= is_final ? 1 : 0; h *%= FNV_PRIME;  then for each transition:
// h ^= sym; h *%= FNV_PRIME; h ^= full 32-bit target; h *%= FNV_PRIME.
// All multiplies are WRAPPING (*%=) — plain * panics in ReleaseSafe.

pub fn sigCompute(s: *const State) u64 {
    var h: u64 = FNV_OFFSET;
    h ^= @as(u64, if (s.is_final != 0) 1 else 0);
    h *%= FNV_PRIME;

    const arr = internal.transArrC(s);
    var i: u32 = 0;
    while (i < s.ntrans) : (i += 1) {
        h ^= @as(u64, arr[i].sym);
        h *%= FNV_PRIME;
        h ^= @as(u64, arr[i].target); // xor the full 32-bit target once
        h *%= FNV_PRIME;
    }
    return h;
}

// ─── Register: open-addressing sig → state_id (dafsa_core.c:142-239) ────────

pub fn regLookup(d: *Dafsa, sig: u64) u32 {
    if (sig == 0) return 0; // 0 = invalid/empty

    var idx: usize = @intCast(sig % d.reg_cap);
    while (d.reg_keys[idx] != 0) {
        if (d.reg_keys[idx] == sig) return d.reg_vals[idx];
        idx = (idx + 1) % d.reg_cap;
        d.reg_probes += 1; // PER COLLISION STEP only
    }
    return 0; // not found
}

// Grow the register: double capacity → next_prime, rehash all entries
// (dafsa_core.c:179-214).  New arrays MUST be zero-initialized — the
// open-addressing empty sentinel is reg_keys[idx]==0.
pub fn regGrow(d: *Dafsa) void {
    const a = d.allocator;
    const new_cap = nextPrime(d.reg_cap * 2);
    const new_keys = a.alloc(u64, new_cap) catch @panic("dafsa: OOM growing register");
    const new_vals = a.alloc(u32, new_cap) catch @panic("dafsa: OOM growing register");
    @memset(new_keys, 0);
    @memset(new_vals, 0);

    // Rehash all existing entries.
    var i: usize = 0;
    while (i < d.reg_cap) : (i += 1) {
        const sig = d.reg_keys[i];
        if (sig == 0) continue;
        var idx: usize = @intCast(sig % new_cap);
        while (new_keys[idx] != 0) idx = (idx + 1) % new_cap;
        new_keys[idx] = sig;
        new_vals[idx] = d.reg_vals[i];
    }

    if (d.reg_keys.len != 0) a.free(d.reg_keys);
    if (d.reg_vals.len != 0) a.free(d.reg_vals);
    d.reg_keys = new_keys;
    d.reg_vals = new_vals;
    d.reg_cap = new_cap;
    // reg_used unchanged (same number of entries).
}

pub fn regInsert(d: *Dafsa, sig: u64, id: u32) void {
    if (sig == 0) return;

    // Grow if load factor would exceed 0.7 after insert.
    if ((d.reg_used + 1) * 10 > d.reg_cap * 7) regGrow(d);

    var idx: usize = @intCast(sig % d.reg_cap);
    while (d.reg_keys[idx] != 0) {
        // overwrite if re-inserting the same state
        if (d.reg_keys[idx] == sig) {
            d.reg_vals[idx] = id;
            return;
        }
        idx = (idx + 1) % d.reg_cap;
        d.reg_probes += 1;
    }
    d.reg_keys[idx] = sig;
    d.reg_vals[idx] = id;
    d.reg_used += 1;
}

// ─── Prime helpers (dafsa.c:20-38) — replicated exactly; the prime sequence
// determines reg_cap growth and thus probe counts (observable via stats).

pub fn isPrime(n: usize) bool {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    var d: usize = 3;
    while (d * d <= n) : (d += 2) {
        if (n % d == 0) return false;
    }
    return true;
}

pub fn nextPrime(n: usize) usize {
    if (n < 2) return 2;
    var v = n;
    if (v % 2 == 0) v += 1;
    while (!isPrime(v)) v += 2;
    return v;
}

// ─── Clone-on-write (dafsa_core.c:251-282) ───────────────────────────────────
//
// Clone state `sid`.  Clone gets refcount=0; all its outgoing transitions add
// incoming edges to their targets.  Caller redirects the single parent edge.
// state_new may realloc d.states → re-fetch src/dst AFTER state_new.

pub fn cloneState(d: *Dafsa, sid: u32) u32 {
    const new_id = state.stateNew(d); // MAY REALLOC d.states

    // Re-fetch AFTER state_new: the old &d.states[sid] would be stale.
    const src = &d.states[sid];
    const dst = &d.states[new_id];

    dst.is_final = src.is_final;
    dst.ntrans = src.ntrans;
    if (src.ntrans > 0) {
        if (state.transReserve(dst, src.ntrans) != 0) {
            std.debug.print("dafsa: OOM cloning transitions\n", .{});
            @panic("dafsa: OOM cloning transitions");
        }
        // trans_reserve may have promoted inline→heap; re-fetch arrays now.
        const src_arr = internal.transArrC(src);
        const dst_arr = internal.transArr(dst);
        @memcpy(dst_arr[0..src.ntrans], src_arr[0..src.ntrans]);
    }
    dst.sig = src.sig;

    // Register incoming edges for all of the clone's outgoing transitions.
    // incoming_add may realloc d.inodes, but dst is in d.states (separate).
    var i: u32 = 0;
    const dst_arr2 = internal.transArrC(dst);
    while (i < dst.ntrans) : (i += 1) {
        incomingAdd(d, new_id, dst_arr2[i].sym, dst_arr2[i].target);
    }

    return new_id;
}

// ─── replace_or_register (dafsa_core.c:299-342) ─────────────────────────────
//
// THE FIRST CORRECTNESS CRUX: a register entry is only a valid merge target
// iff the state it names is still live (refcount>0 or it's the initial state)
// AND still carries that exact signature.  Otherwise the entry is stale and
// must be ignored — this is what makes incremental register maintenance
// correct without a full reg_rebuild on every op.  After a merge, reg_insert
// REPOINTS the entry to the surviving state (dafsa_core.c:327).
// Returns 1 if a merge occurred, 0 otherwise.

pub fn replaceOrRegister(d: *Dafsa, sid: u32, parent: u32) i32 {
    const s = &d.states[sid]; // fetched once; states not realloc'd here

    const new_sig = sigCompute(s);
    s.sig = new_sig;

    const equivalent = regLookup(d, new_sig);
    if (equivalent != 0 and equivalent != sid and
        (d.states[equivalent].refcount != 0 or equivalent == d.initial) and
        d.states[equivalent].sig == new_sig)
    {
        // --- MERGE: sid into equivalent ---
        incomingRedirect(d, sid, equivalent);

        // Repoint the register entry: this signature now belongs to the
        // surviving state `equivalent`, not the merged-away `sid`.
        regInsert(d, new_sig, equivalent);

        // parent's transition was updated by incoming_redirect; now parent's
        // signature is dirty.  parent may be 0 when called for the root —
        // writes to sentinel state 0 are harmless (unused slot).
        d.states[parent].sig = 0;

        return 1; // sid was freed by incoming_redirect
    } else {
        // --- REGISTER: this signature is unique (or its entry was stale) ---
        regInsert(d, new_sig, sid);
        return 0;
    }
}

// ─── Confluence along the path (dafsa_core.c:358-372) ──────────────────────
//
// After adding/deleting, the path from root to the final state may contain
// states that need re-registration.  Process bottom-up (i = len-1 down to 1),
// then also register the root.  Returns 1 if any state merged.

pub fn confluencePath(d: *Dafsa, path: []u32, parents: []u32, len: u32) i32 {
    var merged: i32 = 0;
    var i: i32 = @as(i32, @intCast(len)) - 1;
    while (i >= 1) : (i -= 1) {
        const ui: u32 = @intCast(i);
        const child = path[ui];
        const parent = parents[ui];
        if (replaceOrRegister(d, child, parent) != 0) merged = 1;
    }
    if (replaceOrRegister(d, path[0], 0) != 0) merged = 1;
    return merged;
}

// ─── Add word (dafsa_core.c:376-508) ────────────────────────────────────────

pub fn dafsaAddN(d: *Dafsa, key: []const u8) i32 {
    d.subtree_valid = 0; // coarse invalidation: DAG restructured below

    const len = key.len;
    if (len == 0) {
        // Empty string: the initial state becomes final.
        if (d.states[d.initial].is_final != 0) return 0;
        d.states[d.initial].is_final = 1;
        _ = replaceOrRegister(d, d.initial, 0);
        return 1;
    }
    // C: if (key == NULL) return -1;  — unreachable here (slices aren't NULL).
    if (len > MAX_WORD_LEN) return -1; // hard guard: path arrays bounded

    if (state.dafsaEnsureScratch(d, len) != 0) return -1;

    // --- Phase 1: Traverse existing path ---
    var current = d.initial;
    var path_len: u32 = 0;

    d.spath[path_len] = current;
    d.schars[path_len] = 0;
    d.sparents[path_len] = 0;
    path_len += 1;

    var pos: usize = 0;
    while (pos < len) : (pos += 1) {
        const c = key[pos];
        const tr = state.transFind(&d.states[current], c);
        if (tr < 0) break; // divergence point

        const next = internal.transArrC(&d.states[current])[@intCast(tr)].target;
        current = next;
        d.spath[path_len] = current;
        d.schars[path_len] = c;
        d.sparents[path_len] = d.spath[path_len - 1];
        path_len += 1;
    }

    // --- Check: word already present? ---
    if (pos == len and d.states[current].is_final != 0) {
        return 0; // already in the DAFSA
    }

    // --- Phase 2: Clone-on-write, make the prefix path private (ASCENDING root→leaf).
    // Each clone redirects the single already-private parent edge via
    // incoming_redirect_one; never affects other words sharing the sub-automaton.
    // Required when re-adding a word whose (deleted) ghost branch is still shared.
    {
        var di: u32 = 1;
        while (di < path_len) : (di += 1) {
            const sid = d.spath[di];
            if (d.states[sid].refcount > 1) {
                const clone = cloneState(d, sid);
                const parent = d.spath[di - 1];
                const pc = d.schars[di];

                // clone_state may realloc states; re-fetch via indices.
                incomingRedirectOne(d, parent, pc, sid, clone);

                d.spath[di] = clone;
                if (di + 1 < path_len) d.sparents[di + 1] = clone;
            }
        }
        current = d.spath[path_len - 1];
    }

    // --- Phase 3: Add suffix from the divergence point ---
    if (pos < len) {
        var i = pos;
        while (i < len) : (i += 1) {
            const c = key[i];

            const next = state.stateNew(d); // MAY REALLOC states
            state.transAdd(&d.states[current], c, next);
            d.states[current].sig = 0; // dirty

            incomingAdd(d, current, c, next); // MAY REALLOC inodes

            d.spath[path_len] = next;
            d.schars[path_len] = c;
            d.sparents[path_len] = current;
            path_len += 1;

            current = next;
        }
    }

    // --- Phase 4: Mark final and confluence ---
    d.states[current].is_final = 1;
    d.states[current].sig = 0; // dirty

    _ = confluencePath(d, d.spath, d.sparents, path_len);
    return 1;
}

// ─── Delete word (dafsa_core.c:512-624) ─────────────────────────────────────

pub fn dafsaDeleteN(d: *Dafsa, key: []const u8) i32 {
    d.subtree_valid = 0;

    const len = key.len;
    if (len == 0) {
        if (d.states[d.initial].is_final == 0) return 0;
        d.states[d.initial].is_final = 0;
        d.states[d.initial].sig = 0;
        _ = replaceOrRegister(d, d.initial, 0);
        return 1;
    }
    if (len > MAX_WORD_LEN) return -1;

    if (state.dafsaEnsureScratch(d, len) != 0) return -1;

    // --- Phase 1: Traverse to the final state ---
    var current = d.initial;
    var path_len: u32 = 0;

    d.spath[path_len] = current;
    d.schars[path_len] = 0;
    d.sparents[path_len] = 0;
    path_len += 1;

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const c = key[i];
        const tr = state.transFind(&d.states[current], c);
        if (tr < 0) return 0; // not present

        const next = internal.transArrC(&d.states[current])[@intCast(tr)].target;
        current = next;

        d.spath[path_len] = current;
        d.schars[path_len] = c;
        d.sparents[path_len] = d.spath[path_len - 1];
        path_len += 1;
    }

    if (d.states[current].is_final == 0) return 0; // word is a prefix but not a word

    // --- Phase 2: Clone-on-write, ASCENDING (root→leaf).
    // At each step the parent (path[di-1]) is already private (cloned in the
    // previous iteration, or had refcount==1 to begin with), so redirecting
    // its single edge on the path cannot affect any other word.
    // THE SECOND CRUX: parent must be re-read from spath[di-1], NOT the stale
    // parents[] snapshot (dafsa_core.c:596); also update current when
    // di == path_len-1 (dafsa_core.c:606-607).
    {
        var di: i32 = 1;
        while (di < @as(i32, @intCast(path_len))) : (di += 1) {
            const udi: u32 = @intCast(di);
            const sid = d.spath[udi];
            if (d.states[sid].refcount > 1) {
                const clone = cloneState(d, sid);
                const parent = d.spath[udi - 1]; // re-read, NOT stale parents[]
                const pc = d.schars[udi];

                incomingRedirectOne(d, parent, pc, sid, clone);

                d.spath[udi] = clone;
                if (di < @as(i32, @intCast(path_len)) - 1)
                    d.sparents[udi + 1] = clone;
                if (di == @as(i32, @intCast(path_len)) - 1)
                    current = clone;
            }
        }
    }

    // --- Phase 3: Unmark final and confluence ---
    d.states[current].is_final = 0;
    d.states[current].sig = 0;

    _ = confluencePath(d, d.spath, d.sparents, path_len);
    return 1;
}

// ─── Lookup (dafsa_core.c:628-650) ──────────────────────────────────────────

pub fn dafsaLookupN(d: *Dafsa, key: []const u8) i32 {
    var current = d.initial;

    for (key, 0..) |c, idx| {
        const tr = state.transFind(&d.states[current], c);
        if (tr < 0) return 0;
        current = internal.transArrC(&d.states[current])[@intCast(tr)].target;
        _ = idx;
    }
    return @intCast(d.states[current].is_final);
}
