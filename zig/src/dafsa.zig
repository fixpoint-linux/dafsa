// dafsa.zig — Lifecycle facade (mirrors dafsa.c): create / free / stats / abi.
// U3 scope: the incremental core (add/delete/lookup) lives in core.zig; this
// module owns the Dafsa handle lifecycle and the BFS stats computation.
// Later units (U4+) extend this with build_sorted/save/load/dot/etc.

const std = @import("std");
const internal = @import("internal.zig");
const state = @import("state.zig");
const Dafsa = internal.Dafsa;
const State = internal.State;
const Inode = internal.Inode;

// U9: C-ABI export layer.  This file is the `zig build-lib src/dafsa.zig
// -dynamic` root, so pulling abi.zig in here exports the full dafsa.h surface
// as libdafsa.so (SONAME derives from this root's basename).  Purely additive:
// the engine modules above are untouched.
const abi = @import("abi.zig");
comptime {
    _ = abi;
}

// ─── Lifecycle (dafsa.c:42-74) ───────────────────────────────────────────────

pub fn dafsaCreate() ?*Dafsa {
    const a = std.heap.c_allocator; // we link libc (plan: dafsa_create uses c_allocator)
    const d = a.create(Dafsa) catch return null;
    // Build the struct explicitly (slice fields can't be zeroed via zeroes).
    d.* = .{
        .allocator = a,
        .nstates = 0,
        .initial = 0,
        .states = internal.emptySlice(State),
        .states_cap = 0,
        .inodes = internal.emptySlice(Inode),
        .inodes_cap = 0,
        .inodes_used = 0,
        .reg_keys = internal.emptySlice(u64),
        .reg_vals = internal.emptySlice(u32),
        .reg_cap = 0,
        .reg_used = 0,
        .reg_probes = 0,
        .spath = internal.emptySlice(u32),
        .schars = internal.emptySlice(u8),
        .sparents = internal.emptySlice(u32),
        .scratch_cap = 0,
        .free_head = 0,
        .subtree = internal.emptySlice(u64),
        .subtree_cap = 0,
        .subtree_valid = 0,
    };

    d.states_cap = 4096;
    d.states = a.alloc(State, d.states_cap) catch {
        a.destroy(d);
        return null;
    };
    for (d.states) |*s| s.* = std.mem.zeroes(State);

    d.inodes_cap = 4096;
    d.inodes = a.alloc(Inode, d.inodes_cap) catch {
        a.free(d.states);
        a.destroy(d);
        return null;
    };
    for (d.inodes) |*ino| ino.* = std.mem.zeroes(Inode);

    d.reg_cap = 4093; // prime
    d.reg_keys = a.alloc(u64, d.reg_cap) catch {
        a.free(d.inodes);
        a.free(d.states);
        a.destroy(d);
        return null;
    };
    @memset(d.reg_keys, 0);
    d.reg_vals = a.alloc(u32, d.reg_cap) catch {
        a.free(d.reg_keys);
        a.free(d.inodes);
        a.free(d.states);
        a.destroy(d);
        return null;
    };
    @memset(d.reg_vals, 0);

    d.nstates = 1; // state 0 is "no state" sentinel
    d.initial = state.stateNew(d); // state 1 is the initial state
    d.inodes_used = 0; // state_new doesn't touch inodes_used (already 0); matches C
    d.reg_used = 0;
    d.reg_probes = 0;

    return d;
}

pub fn dafsaFree(d: ?*Dafsa) void {
    const dd = d orelse return;
    const a = dd.allocator;

    if (dd.spath.len != 0) a.free(dd.spath);
    if (dd.schars.len != 0) a.free(dd.schars);
    if (dd.sparents.len != 0) a.free(dd.sparents);

    if (dd.states.len != 0) {
        // free each state's trans_heap (already-freed slots have trans_heap=null)
        for (dd.states) |*s| state.freeStateTransHeap(dd, s);
        a.free(dd.states);
    }
    if (dd.inodes.len != 0) a.free(dd.inodes);
    if (dd.reg_keys.len != 0) a.free(dd.reg_keys);
    if (dd.reg_vals.len != 0) a.free(dd.reg_vals);
    if (dd.subtree.len != 0) a.free(dd.subtree);

    a.destroy(dd);
}

// ─── ABI version (dafsa.c:97-100) ────────────────────────────────────────────

pub fn dafsaAbiVersion() u32 {
    return internal.DAFSA_ABI_VERSION;
}

// ─── Statistics (dafsa.c:104-161) ───────────────────────────────────────────
//
// Fresh BFS on every call (no lazy cache).  OOM degrades to zeros.

pub fn dafsaStats(d: *Dafsa, out: *internal.DafsaStatsOut) void {
    out.* = .{};
    const a = d.allocator;
    const n = d.nstates;
    if (n == 0) return;

    const visited = a.alloc(u8, n) catch return;
    defer a.free(visited);
    @memset(visited, 0);
    const queue = a.alloc(u32, n) catch return;
    defer a.free(queue);

    var head: u32 = 0;
    var tail: u32 = 0;
    var reachable: u32 = 0;
    var finals: u32 = 0;
    var transitions: u32 = 0;

    queue[tail] = d.initial;
    tail += 1;
    visited[d.initial] = 1;

    while (head < tail) {
        const sid = queue[head];
        head += 1;
        const s = &d.states[sid];

        reachable += 1;
        if (s.is_final != 0) finals += 1;
        transitions += s.ntrans;
        var j: u32 = 0;
        while (j < s.ntrans) : (j += 1) {
            const tgt = internal.transArrC(s)[j].target;
            if (visited[tgt] == 0) {
                visited[tgt] = 1;
                queue[tail] = tgt;
                tail += 1;
            }
        }
    }

    out.n_states_total = d.nstates - 1; // exclude sink 0
    out.n_states_reachable = reachable;
    out.n_final = finals;
    out.n_trans = transitions;
    out.register_probes = d.reg_probes;
}
