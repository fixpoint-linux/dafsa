// internal.zig — Shared internals of the incremental-minimal DAFSA (mirrors dafsa_internal.h)
//
// STATE-ID-FAITHFUL Zig port of the Carrasco & Forcada (2002) incremental
// minimal acyclic DFA.  Every allocation order, free-list LIFO discipline,
// register growth schedule and wrapping-math site is replicated 1:1 with the
// C engine so that dafsa_stats (n_states_total + register_probes) is the
// state-faithfulness detector in the differential harness.
//
// I/O cheat-sheet (Zig 0.16, trimmed stdlib — see env-fact node
// zig-0.16-sandbox-stdlib-facts):
//   * std.io is REMOVED.  stdin = std.posix.read(0, ...) in a loop until n==0.
//   * stdout = raw std.os.linux.write(1, ptr, len), decoded via errno().
//   * std.debug.print -> STDERR, never use it for compared driver output.
//   * wrapping u64 multiply: use *%= (plain * panics in ReleaseSafe).

const std = @import("std");

// ─── Tunables (dafsa_internal.h:24-30) ──────────────────────────────────────
pub const DAFSA_MAX_STATES_HARD: u32 = 100_000_000;
pub const MAX_WORD_LEN: usize = 65536;
pub const ALPHABET_SZ: u32 = 256;
pub const FNV_OFFSET: u64 = 14695981039346656037;
pub const FNV_PRIME: u64 = 1099511628211;
pub const DAFSA_PDWG_VERSION: u32 = 4;
pub const DAFSA_INLINE_N: u32 = 4;
pub const DAFSA_ABI_VERSION: u32 = 1;

// ─── Data structures (dafsa_internal.h:42-70) ────────────────────────────────

pub const Edge = extern struct {
    sym: u8,
    target: u32,
};

// Singly-linked inode threaded through a flat array (index 0 = sentinel).
pub const Inode = extern struct {
    parent: u32,
    sym: u8,
    next: u32,
};

// TransHeap header trick (dafsa_internal.h:56): the C struct is
// `struct TransHeap { uint32_t cap; Edge edges[]; }` — a flexible-array
// header.  We add an explicit pad so edges land at offset 8 (8-byte aligned,
// friendlier than the C offset 4) and ALL pointer math is encapsulated in
// state.zig's transHeap* helpers.  The cap field is the only externally
// observable part; edge offset is internal.
pub const TransHeap = extern struct {
    cap: u32,
    // C (dafsa_internal.h:56): typedef struct TransHeap { uint32_t cap;
    // Edge edges[]; } — the flexible array member begins at offset 4 (Edge
    // alignment 4), so C's sizeof(TransHeap) == 4 and edges live at base+4.
    // All edge access goes through @sizeOf(TransHeap)-relative arithmetic
    // (transArr/transArrC here, transHeapAlloc/Realloc in state.zig), which
    // therefore matches C's offsetof(TransHeap, edges) byte-for-byte —
    // REQUIRED for consumers that inline trans_arr_c() from
    // dafsa_internal.h and dereference engine States directly (datalog).
    // (The port originally padded to 8, which only matters when C code
    // reads a Zig-engine State — found by datalog-dafsa in U9.)
};

pub const State = extern struct {
    refcount: u32 = 0, // @0  incoming transition count
    is_final: u8 = 0, // @4
    _pad0: [3]u8 = .{ 0, 0, 0 }, // @5
    ntrans: u32 = 0, // @8  live transition count
    in_head: u32 = 0, // @12 first Inode index, 0=none
    sig: u64 = 0, // @16 cached FNV-1a signature (0=invalid; reused as free-list next)
    trans_heap: ?*TransHeap = null, // @24 NULL => ≤4 edges inline in trans[]
    trans: [4]Edge = .{ .{ .sym = 0, .target = 0 }, .{ .sym = 0, .target = 0 }, .{ .sym = 0, .target = 0 }, .{ .sym = 0, .target = 0 } }, // @32
};

comptime {
    if (@sizeOf(State) != 64) @compileError("State must be exactly one cache line (64B)");
    if (@offsetOf(State, "trans") + DAFSA_INLINE_N * @sizeOf(Edge) > 64)
        @compileError("inline edges must fit in cache line");
}

// ─── Dafsa handle (dafsa_internal.h:76-115) ────────────────────────────────
//
// Regular (non-extern) struct: this is an internal handle, never crossing
// the C ABI.  Field order matches the C struct for side-by-side review.
// NB: no field defaults — slice fields ([*]T is non-nullable) cannot be zeroed
// via std.mem.zeroes/@memset, so dafsa_create builds the value explicitly.
pub const Dafsa = struct {
    allocator: std.mem.Allocator,
    nstates: u32, // state 0 = implicit dead/sink, unused
    initial: u32,

    states: []State,
    states_cap: usize,

    inodes: []Inode,
    inodes_cap: usize,
    inodes_used: u32, // index 0 = sentinel

    reg_keys: []u64,
    reg_vals: []u32,
    reg_cap: usize,
    reg_used: usize,
    reg_probes: u64,

    spath: []u32,
    schars: []u8,
    sparents: []u32,
    scratch_cap: usize,

    free_head: u32,

    subtree: []u64,
    subtree_cap: usize,
    subtree_valid: i32,
};

// Empty-slice sentinel usable as a field value (non-null ptr to a comptime
// zero-length array — avoids the non-nullable-pointer-zero issue).
pub fn emptySlice(comptime T: type) []T {
    return &[_]T{};
}

// ─── Statistics output (dafsa.h:72-78) ──────────────────────────────────────
pub const DafsaStatsOut = struct {
    n_states_total: u32 = 0,
    n_states_reachable: u32 = 0,
    n_final: u32 = 0,
    n_trans: u32 = 0,
    register_probes: u64 = 0,
};

// ─── Transition accessors (dafsa_internal.h:156-161) ────────────────────────
//
// edges live at offset @sizeOf(TransHeap) == 8 of the same allocation.
// Returns the FULL capacity slice ([0..cap] for heap, [0..4] for inline) so
// trans_add can index one past ntrans after trans_reserve guaranteed room.

inline fn transHeapEdgesPtr(th: *TransHeap) [*]Edge {
    const base: [*]u8 = @ptrCast(th);
    return @ptrCast(@alignCast(base + @sizeOf(TransHeap)));
}

pub fn transArr(s: *State) []Edge {
    if (s.trans_heap) |th| {
        return transHeapEdgesPtr(th)[0..th.cap];
    }
    return s.trans[0..];
}

// Const variant (read-only paths): same memory, const view.
pub fn transArrC(s: *const State) []const Edge {
    if (s.trans_heap) |th| {
        const base: [*]const u8 = @ptrCast(th);
        const edges: [*]const Edge = @ptrCast(@alignCast(base + @sizeOf(TransHeap)));
        return edges[0..th.cap];
    }
    return s.trans[0..];
}
