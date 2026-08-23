// state.zig — State management and transition helpers (mirrors dafsa_state.c)
//
// All TransHeap allocation pointer math is encapsulated here.

const std = @import("std");
const internal = @import("internal.zig");
const Dafsa = internal.Dafsa;
const State = internal.State;
const Inode = internal.Inode;
const Edge = internal.Edge;
const TransHeap = internal.TransHeap;

const INLINE_N = internal.DAFSA_INLINE_N;
const ALPHABET_SZ = internal.ALPHABET_SZ;
const DAFSA_MAX_STATES_HARD = internal.DAFSA_MAX_STATES_HARD;

// ─── TransHeap allocation helpers (encapsulates ALL pointer math) ──────────
//
// Layout: [TransHeap header (8B)] [cap × Edge (8B each)] in one allocation.
// We allocate as a raw []u8 (c_allocator → malloc, ≥16-byte aligned) and cast.

fn transHeapBytes(th: *TransHeap) []u8 {
    const sz = @sizeOf(TransHeap) + @as(usize, th.cap) * @sizeOf(Edge);
    const base: [*]u8 = @ptrCast(th);
    return base[0..sz];
}

fn transHeapAlloc(allocator: std.mem.Allocator, cap: u32) *TransHeap {
    const sz = @sizeOf(TransHeap) + @as(usize, cap) * @sizeOf(Edge);
    const buf = allocator.alloc(u8, sz) catch @panic("dafsa: OOM growing transitions");
    const th: *TransHeap = @ptrCast(@alignCast(buf.ptr));
    th.cap = cap;
    return th;
}

fn transHeapRealloc(allocator: std.mem.Allocator, th: *TransHeap, new_cap: u32) *TransHeap {
    const old_sz = @sizeOf(TransHeap) + @as(usize, th.cap) * @sizeOf(Edge);
    const new_sz = @sizeOf(TransHeap) + @as(usize, new_cap) * @sizeOf(Edge);
    const old_buf: []u8 = @as([*]u8, @ptrCast(th))[0..old_sz];
    // c_allocator.realloc → libc realloc: preserves contents, ≥16-aligned.
    const new_buf = allocator.realloc(old_buf, new_sz) catch @panic("dafsa: OOM growing transitions");
    const new_th: *TransHeap = @ptrCast(@alignCast(new_buf.ptr));
    new_th.cap = new_cap;
    return new_th;
}

fn transHeapFree(allocator: std.mem.Allocator, th: *TransHeap) void {
    allocator.free(transHeapBytes(th));
}

// Public wrapper for dafsa_free's per-state trans_heap sweep.
pub fn freeStateTransHeap(d: *Dafsa, s: *State) void {
    if (s.trans_heap) |th| {
        transHeapFree(d.allocator, th);
        s.trans_heap = null;
    }
}

// ─── State management (dafsa_state.c:5-50) ──────────────────────────────────

fn zeroState(s: *State) void {
    s.* = std.mem.zeroes(State);
}

// Pop the free-list first (LIFO, recycled slots don't count against the cap),
// else allocate a fresh slot via the nstates++ high-water mark (never
// decremented — orphans live in the free-list).  Mirrors dafsa_state.c:5-50.
pub fn stateNew(d: *Dafsa) u32 {
    if (d.free_head != 0) {
        const id = d.free_head;
        // sig reused as next ptr; narrowing u64→u32 is safe (state ids bounded
        // by 100M, matches the C documented bounded-ids assumption).
        d.free_head = @intCast(d.states[id].sig);
        zeroState(&d.states[id]);
        return id;
    }

    if (d.nstates >= DAFSA_MAX_STATES_HARD) {
        std.debug.print("dafsa: max states exceeded ({d})\n", .{DAFSA_MAX_STATES_HARD});
        @panic("dafsa: max states exceeded");
    }

    if (d.nstates >= d.states_cap) {
        var new_cap = d.states_cap * 2;
        if (new_cap == 0) new_cap = 4096; // defensive; create() pre-allocates
        if (new_cap > @as(usize, DAFSA_MAX_STATES_HARD) + 1)
            new_cap = @as(usize, DAFSA_MAX_STATES_HARD) + 1;
        const new_states = d.allocator.realloc(d.states, new_cap) catch @panic("dafsa: OOM growing states");
        // Zero-initialize the newly allocated tail (C: memset(new + old_cap, 0, ...)).
        for (new_states[d.states_cap..new_cap]) |*s| zeroState(s);
        d.states = new_states;
        d.states_cap = new_cap;
    }

    {
        const id = d.nstates;
        d.nstates += 1;
        zeroState(&d.states[id]);
        return id;
    }
}

// Remove phantom inode entries from children's in_head chains.  Called by
// stateFree BEFORE it frees the trans[] array (dafsa_state.c:61-89).  At most
// one match per (child, sym), breaks after the first.
pub fn stateDetachFromChildren(d: *Dafsa, sid: u32) void {
    const s = &d.states[sid];
    var j: u32 = 0;
    while (j < s.ntrans) : (j += 1) {
        const sym = internal.transArr(s)[j].sym;
        const child = internal.transArr(s)[j].target;

        // Walk child's in_head chain, unlink the (sid, sym) inode.
        var prev_ptr: *u32 = &d.states[child].in_head;
        var ni = prev_ptr.*;
        while (ni != 0) {
            const in = &d.inodes[ni];
            if (in.parent == sid and in.sym == sym) {
                prev_ptr.* = in.next;
                d.states[child].refcount -= 1;
                break;
            }
            prev_ptr = &in.next;
            ni = prev_ptr.*;
        }
    }
}

// Release an orphan state slot to the LIFO free-list (dafsa_state.c:95-117).
// Detaches phantom inodes from children BEFORE freeing trans[] (walks trans).
pub fn stateFree(d: *Dafsa, id: u32) void {
    const s = &d.states[id];
    stateDetachFromChildren(d, id);

    if (s.trans_heap) |th| {
        transHeapFree(d.allocator, th);
        s.trans_heap = null;
    }
    s.ntrans = 0;
    s.refcount = 0;
    s.is_final = 0;
    s.in_head = 0;
    // Chain into free-list via the sig field (next ptr, narrowed u64→u32).
    s.sig = d.free_head;
    d.free_head = id;
}

// ─── Inode allocation (dafsa_state.c:121-136) ───────────────────────────────
// index 0 = sentinel; first real inode is at inodes_used=1.

pub fn inodeAlloc(d: *Dafsa) *Inode {
    if (@as(usize, d.inodes_used) + 1 >= d.inodes_cap) {
        var new_cap = d.inodes_cap * 2;
        if (new_cap == 0) new_cap = 4096;
        const new_inodes = d.allocator.realloc(d.inodes, new_cap) catch @panic("dafsa: OOM growing inodes");
        for (new_inodes[d.inodes_cap..new_cap]) |*ino| ino.* = std.mem.zeroes(Inode);
        d.inodes = new_inodes;
        d.inodes_cap = new_cap;
    }
    d.inodes_used += 1;
    return &d.inodes[d.inodes_used];
}

// ─── Scratch arena for add/delete path traversal (dafsa_state.c:142-180) ───
//
// Ensures spath/schars/sparents can hold `len+2` entries.  Returns 0 on
// success, -1 on OOM.  Not reentrant on the same handle.

pub fn dafsaEnsureScratch(d: *Dafsa, len: usize) i32 {
    const need = len + 2;
    if (d.scratch_cap >= need) return 0;

    // Use malloc-not-realloc semantics (old pointers stay valid until all
    // three succeed, then swap) to mirror the C exactly.  On any failure we
    // free the already-allocated new buffers and return -1, leaving the old
    // scratch intact.  (errdefer is useless here: this function returns i32,
    // not an error union, so it never fires.)
    const a = d.allocator;
    const new_path = a.alloc(u32, need) catch return -1;
    const new_chars = a.alloc(u8, need) catch {
        a.free(new_path);
        return -1;
    };
    const new_parents = a.alloc(u32, need) catch {
        a.free(new_chars);
        a.free(new_path);
        return -1;
    };

    // Copy old contents (if any).
    if (d.spath.len != 0) {
        const old_n = d.scratch_cap;
        @memcpy(new_path[0..old_n], d.spath[0..old_n]);
        @memcpy(new_chars[0..old_n], d.schars[0..old_n]);
        @memcpy(new_parents[0..old_n], d.sparents[0..old_n]);
    }
    if (d.spath.len != 0) a.free(d.spath);
    if (d.schars.len != 0) a.free(d.schars);
    if (d.sparents.len != 0) a.free(d.sparents);

    d.spath = new_path;
    d.schars = new_chars;
    d.sparents = new_parents;
    d.scratch_cap = need;
    return 0;
}

// ─── Transition helpers (dafsa_state.c:185-282) ────────────────────────────

// Find transition `c`. Returns index or -1.  Linear scan with early exit on
// the sorted-array invariant for n<=8, binary search otherwise
// (dafsa_state.c:185-209).
pub fn transFind(s: *const State, c: u8) i32 {
    const n = s.ntrans;
    const arr = internal.transArrC(s);
    if (n <= 8) {
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const sy = arr[i].sym;
            if (sy == c) return @intCast(i);
            if (sy > c) return -1; // sorted: no later entry can match
        }
        return -1;
    }
    var lo: i32 = 0;
    var hi: i32 = @as(i32, @intCast(n)) - 1;
    while (lo <= hi) {
        const mid_i: i32 = @divTrunc(lo + hi, 2);
        const mid: usize = @intCast(mid_i);
        if (arr[mid].sym == c) return @intCast(mid_i);
        if (arr[mid].sym < c) lo = mid_i + 1 else hi = mid_i - 1;
    }
    return -1;
}

// Ensure the state's transition array has capacity for `need` entries
// (dafsa_state.c:215-246).  need <= INLINE_N: inline suffices.  Otherwise
// promote inline[4]→heap (copy live edges), then double until fit, capped at
// ALPHABET_SZ.  Returns 0 on success, -1 on OOM.
pub fn transReserve(s: *State, need: u32) i32 {
    if (need <= INLINE_N) return 0;

    if (s.trans_heap == null) {
        const th = transHeapAlloc(std.heap.c_allocator, need);
        // Wire trans_heap first so transArr(s) resolves to th->edges.
        s.trans_heap = th;
        const dst = internal.transArr(s);
        // Copy the live inline edges into the new heap (C: memcpy(th->edges,
        // s->trans, ntrans)).  The inline array holds at most INLINE_N valid
        // entries, and the persist-load path (persist.zig dafsaLoadImpl) sets
        // ntrans from the file header BEFORE reserving — so clamp to INLINE_N.
        // C reads OOB there (silent UB; the CSR fill loop overwrites every
        // edge right after, so the garbage is never observable); we clamp
        // instead of panicking — identical observable behavior.
        const copy_n: u32 = @min(s.ntrans, INLINE_N);
        @memcpy(dst[0..copy_n], s.trans[0..copy_n]);
        return 0;
    }

    if (need <= s.trans_heap.?.cap) return 0;

    var new_cap = s.trans_heap.?.cap;
    while (new_cap < need) new_cap *= 2; // need ≤ ALPHABET_SZ so no overflow
    if (new_cap > ALPHABET_SZ) new_cap = ALPHABET_SZ;
    const new_th = transHeapRealloc(std.heap.c_allocator, s.trans_heap.?, new_cap);
    s.trans_heap = new_th;
    return 0;
}

// Insert a transition, maintaining sorted order by sym (dafsa_state.c:249-282).
// On OOM (trans_reserve fails) abort like state_new.  Shift uses
// std.mem.copyBackwards (RIGHT-shift: dst > src; copyForwards would corrupt).
pub fn transAdd(s: *State, c: u8, tgt: u32) void {
    std.debug.assert(s.ntrans < ALPHABET_SZ);

    if (transReserve(s, s.ntrans + 1) != 0) {
        std.debug.print("dafsa: OOM growing transitions\n", .{});
        @panic("dafsa: OOM growing transitions");
    }
    // Re-fetch AFTER reserve — reserve may promote inline→heap, invalidating
    // any pointer derived from s.trans.
    const e = internal.transArr(s);
    var pos: u32 = 0;
    while (pos < s.ntrans and e[pos].sym < c) : (pos += 1) {}
    if (pos < s.ntrans and e[pos].sym == c) {
        e[pos].target = tgt; // update existing
        return;
    }
    // Shift e[pos..ntrans] right by one into e[pos+1..ntrans+1].
    // dst (e[pos+1..]) > src (e[pos..]) → copyBackwards avoids corruption.
    const ntail = s.ntrans - pos;
    std.mem.copyBackwards(Edge, e[pos + 1 .. pos + 1 + ntail], e[pos .. pos + ntail]);
    e[pos].sym = c;
    e[pos].target = tgt;
    s.ntrans += 1;
}
