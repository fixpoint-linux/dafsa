// abi.zig — C-ABI export layer (U9): libdafsa.so surface.
//
// Exports EVERY public dafsa.h function plus the internal.h-declared symbols
// real consumers link against (dafsa_ensure_subtree, dafsa_view_subtree_counts,
// the rank/select/range_count family incl. the dafsa_view_* rank twins), so the
// Zig engine can drop in as libdafsa.so for datalog-dafsa and jing-meta with
// ZERO consumer source changes.  The consumers' own vendor/dafsa/dafsa.h stays
// the ABI source of truth; signatures here mirror it exactly.
//
// Design notes / corner cases:
//   * Handles are opaque *anyopaque on the C side; cast to the engine types.
//     All handles originate from these exports, so alignment is preserved.
//   * Key params arrive as (ptr, len); NULL-key semantics replicate the C
//     engine's defensive guards exactly (dafsa_core.c:399/536/633,
//     dafsa_wal.c:305, dafsa_rank.c:98/161, dafsa_view_rank.c:33/75/119/133):
//     add/del: NULL+len>0 → -1;  lookup: NULL+len>0 → 0;  wal append: NULL → -1;
//     rank/select/rangecount NULL params → 0 / -1 (or the empty key, which is
//     provably equivalent: no key sorts strictly below "").
//   * Callbacks (dafsa_enum_cb, dafsa_wal_replay_cb) cross via threadlocal
//     trampolines with save/restore, so nesting and multi-threaded use are safe.
//   * dafsa_view_subtree_counts returns a c_allocator-owned u64 array the
//     consumer frees with free() (mirrors dafsa_view_rank.c:29-43 calloc).
//   * dafsa_dot replicates dafsa.c:165-198 printf format verbatim (including
//     the %c quirk: sym in [32,127) else '?') via libc fprintf on the caller's
//     FILE* — we link libc, so FILE* is the consumer's libc stream.
//   * OOM on the temporary slice materialization in dafsa_build_sorted
//     degrades to NULL, mirroring the C NULL-on-OOM contract.

const std = @import("std");
const internal = @import("internal.zig");
const dafsa_mod = @import("dafsa.zig");
const core = @import("core.zig");
const build_mod = @import("dafsa_build.zig");
const persist = @import("persist.zig");
const view_mod = @import("view.zig");
const wal_mod = @import("wal.zig");
const rank_mod = @import("rank.zig");
const view_rank = @import("view_rank.zig");
const crc32_mod = @import("crc32.zig");
const state_mod = @import("state.zig");

const Dafsa = internal.Dafsa;
const DafsaView = view_mod.DafsaView;
const Wal = wal_mod.Wal;

// ─── libc (for dafsa_dot's FILE*) ───────────────────────────────────────────

extern fn fprintf(f: *anyopaque, fmt: [*:0]const u8, ...) c_int;

// ─── C callback types + trampolines ─────────────────────────────────────────

/// dafsa.h:55  int (*)(const unsigned char *payload, size_t len, void *user)
pub const CEnumCb = ?*const fn ([*c]const u8, usize, ?*anyopaque) callconv(.c) c_int;
/// dafsa.h:99  int (*)(uint8_t op, const unsigned char *key, uint32_t len, void *user)
pub const CReplayCb = ?*const fn (u8, [*c]const u8, u32, ?*anyopaque) callconv(.c) c_int;

// The engine's internal callback shapes take slices and a user pointer; the
// trampoline adapts.  Save/restore makes nested calls (a consumer callback
// that re-enters the engine) and cross-thread use safe.
threadlocal var t_enum_cb: CEnumCb = null;
threadlocal var t_enum_user: ?*anyopaque = null;

fn enumTrampoline(payload: []const u8, user: ?*anyopaque) i32 {
    _ = user;
    const cb = t_enum_cb orelse return 0;
    return cb(payload.ptr, payload.len, t_enum_user);
}

threadlocal var t_replay_cb: CReplayCb = null;
threadlocal var t_replay_user: ?*anyopaque = null;

fn replayTrampoline(op: u8, key: []const u8, user: ?*anyopaque) i32 {
    _ = user;
    const cb = t_replay_cb orelse return -1;
    return cb(op, key.ptr, @intCast(key.len), t_replay_user);
}

// ─── Cast / slice helpers ───────────────────────────────────────────────────

// ─── C-layout facades (datalog-dafsa reads struct fields directly) ─────────
//
// datalog-dafsa includes dafsa_internal.h and dereferences `d->states`,
// `d->initial`, `d->states[i].is_final`, `trans_arr_c(&d->states[i])`,
// `v->csr`, `v->state_off`, `v->final_bits` directly (iter.c, regexwalk.c,
// snapshot.c, relation.c).  The Zig engine's Dafsa/DafsaView are native
// structs (slices, arbitrary layout), so the C handle we hand out is a
// FACADE: an extern struct whose fields replicate struct dafsa /
// struct dafsa_view (dafsa_internal.h:76-115 / 141-152) byte-for-byte,
// followed by an `impl` pointer C code never sees (it sits past C's
// sizeof — C consumers only ever hold pointers we allocated).
// State/Edge/TransHeap/Inode are already extern and byte-identical, so
// `facade.states[i]` really is the engine's State.  Dafsa facades are
// re-synced after every mutating export (states can realloc); view facades
// mirror once at open (views are immutable).

pub const CFacade = extern struct {
    nstates: u32,
    initial: u32,
    states: ?[*]internal.State,
    states_cap: usize,
    inodes: ?[*]internal.Inode,
    inodes_cap: usize,
    inodes_used: u32,
    reg_keys: ?[*]u64,
    reg_vals: ?[*]u32,
    reg_cap: usize,
    reg_used: usize,
    reg_probes: u64,
    spath: ?[*]u32,
    schars: ?[*]u8,
    sparents: ?[*]u32,
    scratch_cap: usize,
    free_head: u32,
    subtree: ?[*]u64,
    subtree_cap: usize,
    subtree_valid: i32,
    impl: *Dafsa, // appended — past C's sizeof(struct dafsa) == 152
};

pub const CViewFacade = extern struct {
    map: ?[*]u8,
    map_len: usize,
    n_states: u32,
    initial: u32,
    final_bits: ?[*]const u8,
    csr: ?[*]const u8,
    state_off: ?[*]u64,
    ov: ?*anyopaque,
    impl: *DafsaView, // appended — past C's sizeof(struct dafsa_view) == 56
};

comptime {
    if (@offsetOf(CFacade, "impl") != 152)
        @compileError("CFacade must match struct dafsa layout (impl must land at C sizeof 152)");
    if (@offsetOf(CViewFacade, "impl") != 56)
        @compileError("CViewFacade must match struct dafsa_view layout (impl must land at C sizeof 56)");
}

fn syncDafsa(f: *CFacade) void {
    const m = f.impl;
    f.nstates = m.nstates;
    f.initial = m.initial;
    f.states = m.states.ptr;
    f.states_cap = m.states_cap;
    f.inodes = m.inodes.ptr;
    f.inodes_cap = m.inodes_cap;
    f.inodes_used = m.inodes_used;
    f.reg_keys = m.reg_keys.ptr;
    f.reg_vals = m.reg_vals.ptr;
    f.reg_cap = m.reg_cap;
    f.reg_used = m.reg_used;
    f.reg_probes = m.reg_probes;
    f.spath = m.spath.ptr;
    f.schars = m.schars.ptr;
    f.sparents = m.sparents.ptr;
    f.scratch_cap = m.scratch_cap;
    f.free_head = m.free_head;
    f.subtree = m.subtree.ptr;
    f.subtree_cap = m.subtree_cap;
    f.subtree_valid = m.subtree_valid;
}

fn wrapDafsa(impl: *Dafsa) *CFacade {
    const f = std.heap.c_allocator.create(CFacade) catch
        @panic("dafsa: OOM allocating C facade");
    f.impl = impl;
    syncDafsa(f);
    return f;
}

fn wrapView(impl: *DafsaView) *CViewFacade {
    const f = std.heap.c_allocator.create(CViewFacade) catch
        @panic("dafsa: OOM allocating C view facade");
    f.map = impl.map.ptr;
    f.map_len = impl.map_len;
    f.n_states = impl.n_states;
    f.initial = impl.initial;
    f.final_bits = impl.final_bits.ptr;
    f.csr = impl.csr.ptr;
    f.state_off = impl.state_off.ptr;
    f.ov = @ptrCast(impl.ov);
    f.impl = impl;
    return f;
}

inline fn h2f(h: ?*anyopaque) ?*CFacade {
    return @ptrCast(@alignCast(h));
}

inline fn h2vf(h: ?*const anyopaque) ?*const CViewFacade {
    return @ptrCast(@alignCast(h));
}

inline fn h2d(h: ?*anyopaque) ?*Dafsa {
    const f = h2f(h) orelse return null;
    return f.impl;
}

inline fn h2v(h: ?*const anyopaque) ?*const DafsaView {
    const f = h2vf(h) orelse return null;
    return f.impl;
}

inline fn h2w(h: ?*anyopaque) ?*Wal {
    return @ptrCast(@alignCast(h));
}

/// (ptr, len) → slice; null when the C pointer is NULL.
inline fn keySlice(p: [*c]const u8, len: usize) ?[]const u8 {
    if (p == null) return null;
    const q: [*]const u8 = @ptrCast(p);
    return q[0..len];
}

/// NUL-terminated C path → [:0] slice (coerces to []const u8); null on NULL.
inline fn pathSlice(p: [*c]const u8) ?[:0]const u8 {
    if (p == null) return null;
    const z: [*:0]const u8 = @ptrCast(p);
    return std.mem.span(z);
}

/// C dafsa_stats_out (dafsa.h:72-78) — extern so the layout is ABI-exact.
pub const CStatsOut = extern struct {
    n_states_total: u32,
    n_states_reachable: u32,
    n_final: u32,
    n_trans: u32,
    register_probes: u64,
};

// ─── Lifecycle (dafsa.h:22-23, 107-108) ─────────────────────────────────────

export fn dafsa_create() ?*CFacade {
    const impl = dafsa_mod.dafsaCreate() orelse return null;
    return wrapDafsa(impl);
}

export fn dafsa_free(d: ?*anyopaque) void {
    const f = h2f(d) orelse return;
    dafsa_mod.dafsaFree(f.impl);
    std.heap.c_allocator.destroy(f);
}

export fn dafsa_abi_version() u32 {
    return dafsa_mod.dafsaAbiVersion();
}

// ─── Bulk build (dafsa.h:32-33) ─────────────────────────────────────────────

export fn dafsa_build_sorted(
    keys: [*c]const [*c]const u8,
    lens: [*c]const usize,
    nkeys: usize,
) ?*CFacade {
    // dafsa_build.c:44-47: nkeys==0 → empty dafsa (even with NULL arrays).
    if (nkeys == 0) {
        const impl = dafsa_mod.dafsaCreate() orelse return null;
        return wrapDafsa(impl);
    }
    if (keys == null or lens == null) return null;

    const a = std.heap.c_allocator;
    const slices = a.alloc([]const u8, nkeys) catch return null;
    defer a.free(slices);

    const kp: [*]const [*c]const u8 = @ptrCast(keys);
    const lp: [*]const usize = @ptrCast(lens);
    var i: usize = 0;
    while (i < nkeys) : (i += 1) {
        const w = kp[i];
        const wl = lp[i];
        // dafsa_build.c:88-92: key must be non-NULL unless len==0.
        if (w == null and wl > 0) return null;
        slices[i] = keySlice(w, wl) orelse "";
    }
    const impl = build_mod.dafsaBuildSorted(slices) orelse return null;
    return wrapDafsa(impl);
}

// ─── Length-delimited key ops (dafsa.h:43-45) ───────────────────────────────

export fn dafsa_add_n(d: ?*anyopaque, key: [*c]const u8, len: usize) c_int {
    const f = h2f(d) orelse return -1;
    // C (dafsa_core.c:399): the empty-key branch runs BEFORE the NULL guard.
    if (key == null and len > 0) return -1;
    const r = core.dafsaAddN(f.impl, keySlice(key, len) orelse "");
    syncDafsa(f); // states/inodes/scratch may have reallocated
    return r;
}

export fn dafsa_lookup_n(d: ?*const anyopaque, key: [*c]const u8, len: usize) c_int {
    const dd = h2d(@constCast(d)) orelse return 0;
    if (key == null and len > 0) return 0; // dafsa_core.c:633
    return core.dafsaLookupN(dd, keySlice(key, len) orelse "");
}

export fn dafsa_delete_n(d: ?*anyopaque, key: [*c]const u8, len: usize) c_int {
    const f = h2f(d) orelse return -1;
    if (key == null and len > 0) return -1; // dafsa_core.c:536
    const r = core.dafsaDeleteN(f.impl, keySlice(key, len) orelse "");
    syncDafsa(f);
    return r;
}

// ─── NUL-terminated convenience (dafsa.h:49-51) ─────────────────────────────

export fn dafsa_add(d: ?*anyopaque, word: [*c]const u8) c_int {
    const w = pathSlice(word) orelse return -1;
    return dafsa_add_n(d, w.ptr, w.len);
}

export fn dafsa_lookup(d: ?*const anyopaque, word: [*c]const u8) c_int {
    const w = pathSlice(word) orelse return 0;
    return dafsa_lookup_n(d, w.ptr, w.len);
}

export fn dafsa_delete(d: ?*anyopaque, word: [*c]const u8) c_int {
    const w = pathSlice(word) orelse return -1;
    return dafsa_delete_n(d, w.ptr, w.len);
}

// ─── Prefix enumeration (dafsa.h:56-57) ─────────────────────────────────────

export fn dafsa_prefix_enum(
    d: ?*const anyopaque,
    prefix: [*c]const u8,
    prefix_len: usize,
    cb: CEnumCb,
    user: ?*anyopaque,
) c_long {
    const dd = h2d(@constCast(d)) orelse return -1;
    if (cb == null) return -1; // dafsa_view.c:492
    const pfx = keySlice(prefix, prefix_len) orelse "";
    const saved_cb = t_enum_cb;
    const saved_user = t_enum_user;
    t_enum_cb = cb;
    t_enum_user = user;
    defer {
        t_enum_cb = saved_cb;
        t_enum_user = saved_user;
    }
    return view_mod.dafsaPrefixEnum(dd, pfx, enumTrampoline, null);
}

// ─── Persistence (dafsa.h:37-39) ────────────────────────────────────────────

export fn dafsa_save(d: ?*const anyopaque, path: [*c]const u8) c_int {
    const dd = h2d(@constCast(d)) orelse return -1; // dafsa_persist.c:122
    const p = pathSlice(path) orelse return -1;
    return persist.dafsaSave(dd, p);
}

export fn dafsa_load(path: [*c]const u8) ?*CFacade {
    const p = pathSlice(path) orelse return null; // dafsa_persist.c:325
    const impl = persist.dafsaLoad(p) orelse return null;
    return wrapDafsa(impl);
}

export fn dafsa_load_readonly(path: [*c]const u8) ?*CFacade {
    const p = pathSlice(path) orelse return null;
    const impl = persist.dafsaLoadReadonly(p) orelse return null;
    return wrapDafsa(impl);
}

// ─── Statistics (dafsa.h:80) ────────────────────────────────────────────────

export fn dafsa_stats(d: ?*const anyopaque, out: [*c]CStatsOut) void {
    const dd = h2d(@constCast(d)) orelse return; // dafsa.c:111 (!d || !out)
    if (out == null) return;
    var st = internal.DafsaStatsOut{};
    dafsa_mod.dafsaStats(dd, &st);
    const o: *CStatsOut = @ptrCast(out);
    o.* = .{
        .n_states_total = st.n_states_total,
        .n_states_reachable = st.n_states_reachable,
        .n_final = st.n_final,
        .n_trans = st.n_trans,
        .register_probes = st.register_probes,
    };
}

// ─── Debug dot output (dafsa.h:112; format = dafsa.c:165-198) ──────────────

export fn dafsa_dot(d: ?*const anyopaque, f: ?*anyopaque) void {
    const dd = h2d(@constCast(d)) orelse return; // dafsa.c:169 (!d || !f)
    const ff = f orelse return;

    _ = fprintf(ff, "digraph DAFSA {\n");
    _ = fprintf(ff, "  rankdir=LR;\n");
    _ = fprintf(ff, "  node [shape=circle,fontsize=10];\n");
    _ = fprintf(ff, "  start [shape=point];\n");
    _ = fprintf(ff, "  start -> %u;\n", @as(c_uint, dd.initial));

    var i: u32 = 1;
    while (i < dd.nstates) : (i += 1) {
        const s = &dd.states[i];
        if (s.refcount == 0 and i != dd.initial) continue; // skip orphans

        const shape: [*:0]const u8 = if (s.is_final != 0) "doublecircle" else "circle";
        _ = fprintf(ff, "  %u [shape=%s,label=\"%u (rc=%u)\"];\n", @as(c_uint, i), shape, @as(c_uint, i), @as(c_uint, s.refcount));

        var j: u32 = 0;
        while (j < s.ntrans) : (j += 1) {
            const e = internal.transArrC(s)[j];
            _ = fprintf(ff, "  %u -> %u [label=\"%c\"];\n", @as(c_uint, i), @as(c_uint, e.target), @as(c_int, if (e.sym >= 32 and e.sym < 127) e.sym else '?'));
        }
    }
    _ = fprintf(ff, "}\n");
}

// ─── Zero-copy view (dafsa.h:62-68, 103) ────────────────────────────────────

export fn dafsa_view_open(path: [*c]const u8) ?*CViewFacade {
    const p = pathSlice(path) orelse return null; // dafsa_view.c:317
    const impl = view_mod.dafsaViewOpen(p) orelse return null;
    return wrapView(impl);
}

export fn dafsa_view_close(v: ?*anyopaque) void {
    const f = h2vf(v) orelse return;
    view_mod.dafsaViewClose(f.impl);
    std.heap.c_allocator.destroy(@constCast(f));
}

export fn dafsa_view_lookup_n(v: ?*const anyopaque, key: [*c]const u8, len: usize) c_int {
    const vv = h2v(v) orelse return 0; // dafsa_view.c:689
    if (key == null and len > 0) return 0; // dafsa_view.c:690
    return view_mod.dafsaViewLookupN(vv, keySlice(key, len) orelse "");
}

export fn dafsa_view_prefix_enum(
    v: ?*const anyopaque,
    prefix: [*c]const u8,
    prefix_len: usize,
    cb: CEnumCb,
    user: ?*anyopaque,
) c_long {
    const vv = h2v(v) orelse return -1; // dafsa_view.c:726
    if (cb == null) return -1;
    const pfx = keySlice(prefix, prefix_len) orelse "";
    const saved_cb = t_enum_cb;
    const saved_user = t_enum_user;
    t_enum_cb = cb;
    t_enum_user = user;
    defer {
        t_enum_cb = saved_cb;
        t_enum_user = saved_user;
    }
    return view_mod.dafsaViewPrefixEnum(vv, pfx, enumTrampoline, null);
}

export fn dafsa_view_open_layered(fst_path: [*c]const u8, wal_path: [*c]const u8) ?*CViewFacade {
    const fst = pathSlice(fst_path) orelse return null; // dafsa_view.c:764 guard
    const wal: ?[]const u8 = pathSlice(wal_path);
    const impl = view_mod.dafsaViewOpenLayered(fst, wal) orelse return null;
    return wrapView(impl);
}

// ─── Write-ahead log (dafsa.h:92-101) ───────────────────────────────────────

// (all three open functions return a dafsa_wal* — opaque on the C side)

export fn dafsa_wal_open(path: [*c]const u8) ?*Wal {
    const p = pathSlice(path) orelse return null; // dafsa_wal.c:185
    return wal_mod.dafsaWalOpen(p);
}

export fn dafsa_wal_open_rw(path: [*c]const u8) ?*Wal {
    const p = pathSlice(path) orelse return null; // dafsa_wal.c:250
    return wal_mod.dafsaWalOpenRw(p);
}

export fn dafsa_wal_open_ro(path: [*c]const u8) ?*Wal {
    const p = pathSlice(path) orelse return null;
    return wal_mod.dafsaWalOpenRo(p);
}

export fn dafsa_wal_append_add(w: ?*anyopaque, key: [*c]const u8, key_len: u32) c_int {
    const ww = h2w(w) orelse return -1; // dafsa_wal.c:305 (!w || !key)
    const k = keySlice(key, key_len) orelse return -1;
    return wal_mod.dafsaWalAppendAdd(ww, k);
}

export fn dafsa_wal_append_del(w: ?*anyopaque, key: [*c]const u8, key_len: u32) c_int {
    const ww = h2w(w) orelse return -1;
    const k = keySlice(key, key_len) orelse return -1;
    return wal_mod.dafsaWalAppendDel(ww, k);
}

export fn dafsa_wal_sync(w: ?*anyopaque) c_int {
    const ww = h2w(w) orelse return -1; // dafsa_wal.c:363
    return wal_mod.dafsaWalSync(ww);
}

export fn dafsa_wal_size(w: ?*const anyopaque) u64 {
    const ww: ?*const Wal = @ptrCast(@alignCast(w));
    const wv = ww orelse return 0; // dafsa_wal.c:369
    return wal_mod.dafsaWalSize(wv);
}

export fn dafsa_wal_replay(w: ?*anyopaque, cb: CReplayCb, user: ?*anyopaque) c_int {
    const ww = h2w(w) orelse return -1; // dafsa_wal.c:382 (!w || !cb)
    if (cb == null) return -1;
    const saved_cb = t_replay_cb;
    const saved_user = t_replay_user;
    t_replay_cb = cb;
    t_replay_user = user;
    defer {
        t_replay_cb = saved_cb;
        t_replay_user = saved_user;
    }
    return wal_mod.dafsaWalReplay(ww, replayTrampoline, null);
}

export fn dafsa_wal_close(w: ?*anyopaque) void {
    const ww = h2w(w);
    wal_mod.dafsaWalClose(ww);
}

// ─── Order statistics (dafsa_internal.h:218-235 — consumer-linked) ──────────

export fn dafsa_ensure_subtree(d: ?*anyopaque) u64 {
    const f = h2f(d) orelse return 0;
    const r = rank_mod.dafsaEnsureSubtree(f.impl);
    syncDafsa(f); // fills/refreshes the subtree array
    return r;
}

export fn dafsa_rank_n(d: ?*anyopaque, key: [*c]const u8, len: usize) u64 {
    const dd = h2d(d) orelse return 0; // dafsa_rank.c:139
    // C rank_from (!key → 0) is equivalent to the empty key (nothing < "").
    return rank_mod.dafsaRankN(dd, keySlice(key, len) orelse "");
}

export fn dafsa_rank_from(d: ?*anyopaque, s: u32, key: [*c]const u8, len: usize) u64 {
    const dd = h2d(d) orelse return 0; // dafsa_rank.c:98
    return rank_mod.dafsaRankFrom(dd, s, keySlice(key, len) orelse "");
}

export fn dafsa_select_n(d: ?*anyopaque, k: u64, key_out: [*c]u8, key_cap: usize) c_int {
    const dd = h2d(d) orelse return -1; // dafsa_rank.c:198
    if (key_out == null) return -1; // dafsa_rank.c:161 (!key_out)
    const ko: [*]u8 = @ptrCast(key_out);
    return rank_mod.dafsaSelectN(dd, k, ko[0..key_cap]);
}

export fn dafsa_select_from(d: ?*anyopaque, s: u32, k: u64, key_out: [*c]u8, key_cap: usize) c_int {
    const dd = h2d(d) orelse return -1;
    if (key_out == null) return -1;
    const ko: [*]u8 = @ptrCast(key_out);
    return rank_mod.dafsaSelectFrom(dd, s, k, ko[0..key_cap]);
}

export fn dafsa_range_count_n(
    d: ?*anyopaque,
    lo: [*c]const u8,
    lo_len: usize,
    hi: [*c]const u8,
    hi_len: usize,
) u64 {
    const dd = h2d(d) orelse return 0; // dafsa_rank.c:229
    // NULL lo/hi degrade to "" — same result as C's !key → rank 0 path.
    return rank_mod.dafsaRangeCountN(dd, keySlice(lo, lo_len) orelse "", keySlice(hi, hi_len) orelse "");
}

export fn dafsa_range_count_from(
    d: ?*anyopaque,
    s: u32,
    lo: [*c]const u8,
    lo_len: usize,
    hi: [*c]const u8,
    hi_len: usize,
) u64 {
    const dd = h2d(d) orelse return 0;
    return rank_mod.dafsaRangeCountFrom(dd, s, keySlice(lo, lo_len) orelse "", keySlice(hi, hi_len) orelse "");
}

// ─── View order statistics (dafsa_internal.h:257-265) ───────────────────────

export fn dafsa_view_subtree_counts(v: ?*const anyopaque, counts_out: [*c]?[*]u64) u64 {
    const vv = h2v(v) orelse return 0; // dafsa_view_rank.c:33 (!v || !counts_out)
    if (counts_out == null) return 0;
    const co: *?[*]u64 = @ptrCast(counts_out);
    var counts: []u64 = undefined;
    const r = view_rank.dafsaViewSubtreeCounts(vv, &counts);
    // c_allocator-owned → consumer frees with free(); NULL on the OOM path.
    co.* = if (counts.len != 0) counts.ptr else null;
    return r;
}

export fn dafsa_view_rank_n(v: ?*const anyopaque, key: [*c]const u8, len: usize) u64 {
    const vv = h2v(v) orelse return 0; // dafsa_view_rank.c:75
    // C: !key → 0; the empty key is rank 0 (nothing sorts below "").
    return view_rank.dafsaViewRankN(vv, keySlice(key, len) orelse "");
}

export fn dafsa_view_select_n(v: ?*const anyopaque, k: u64, key_out: [*c]u8, key_cap: usize) c_int {
    const vv = h2v(v) orelse return -1; // dafsa_view_rank.c:119
    if (key_out == null) return -1;
    const ko: [*]u8 = @ptrCast(key_out);
    return view_rank.dafsaViewSelectN(vv, k, ko[0..key_cap]);
}

export fn dafsa_view_range_count_n(
    v: ?*const anyopaque,
    lo: [*c]const u8,
    lo_len: usize,
    hi: [*c]const u8,
    hi_len: usize,
) u64 {
    const vv = h2v(v) orelse return 0; // dafsa_view_rank.c:133
    return view_rank.dafsaViewRangeCountN(vv, keySlice(lo, lo_len) orelse "", keySlice(hi, hi_len) orelse "");
}

// ─── crc32 helpers (dafsa_internal.h:237-242 / dafsa_crc32.c) ───────────────
// Consumers link these engine-internal helpers directly (jing-meta's
// dafsa_test.c and dafsa_build.c call them), so libdafsa.so must export them
// exactly as the vendored dafsa_crc32.o did.

export const crc32_table: [256]u32 = crc32_mod.table;

export fn crc32_init() callconv(.c) u32 {
    return crc32_mod.init();
}

export fn crc32_update(crc: u32, data: [*c]const u8, len: usize) callconv(.c) u32 {
    // C (dafsa_crc32.c) loops over len; NULL data with len>0 is UB there —
    // degrade to a no-op instead of crashing (strictly safer, same result
    // for every well-formed call).
    const s = keySlice(data, len) orelse return crc;
    return crc32_mod.update(crc, s);
}

export fn crc32_finalize(crc: u32) callconv(.c) u32 {
    return crc32_mod.finalize(crc);
}

export fn crc32_compute(data: [*c]const u8, len: usize) callconv(.c) u32 {
    const s = keySlice(data, len) orelse &[_]u8{};
    return crc32_mod.compute(s);
}

// ─── internal.h helper functions consumers link directly (datalog-dafsa) ───
// dafsa_internal.h:178 / 247-254: datalog's relation.c, iter.c, snapshot.c
// and regexwalk.c call these on handles obtained from the public API (which
// are the facades above), alongside direct struct-field reads.

export fn trans_find(s: ?*const anyopaque, c: u8) c_int {
    // `s` points into a facade's states[] — State is extern and
    // byte-identical to C's, so this is a direct engine call.
    const sp: ?*const internal.State = @ptrCast(@alignCast(s));
    const ss = sp orelse return -1;
    return state_mod.transFind(ss, c);
}

export fn view_trans_find(v: ?*const anyopaque, s: u32, sym: u8, target_out: [*c]u32) c_int {
    const f = h2vf(v) orelse return -1;
    const t: ?*u32 = @ptrCast(target_out);
    const tt = t orelse return -1;
    return view_mod.viewTransFind(f.impl, s, sym, tt);
}

export fn view_edge_next(
    v: ?*const anyopaque,
    s: u32,
    cursor: ?*[*c]const u8,
    sym_out: [*c]u8,
    target_out: [*c]u32,
) c_int {
    const f = h2vf(v) orelse return -1;
    const vv = f.impl;
    if (sym_out == null or target_out == null) return -1;
    const curp = cursor orelse return -1; // curp: *[*c]const u8
    const cur: [*c]const u8 = curp.*;
    if (cur == null) return -1;
    if (s > vv.n_states) return -1;
    // Rebuild the engine's cursor slice as [cur, csr+state_off[s+1]) —
    // C's per-state end bound.  The engine bounds purely on slice length,
    // so this reproduces dafsa_view.c's view_edge_next exactly.
    const start: [*]const u8 = @ptrCast(cur);
    const end_addr = @intFromPtr(vv.csr.ptr) + @as(usize, @intCast(vv.state_off[s + 1]));
    if (@intFromPtr(start) > end_addr) return -1;
    var cur_slice: []const u8 = start[0 .. end_addr - @intFromPtr(start)];
    const so: *u8 = @ptrCast(sym_out);
    const to: *u32 = @ptrCast(target_out);
    const r = view_mod.viewEdgeNext(vv, s, &cur_slice, so, to);
    curp.* = cur_slice.ptr; // write back the advanced cursor
    return r;
}

export fn view_enum_dfs(
    v: ?*const anyopaque,
    state: u32,
    buf: [*c]u8,
    depth: usize,
    cb: CEnumCb,
    user: ?*anyopaque,
    count: [*c]c_long,
) c_int {
    const f = h2vf(v) orelse return -1;
    if (buf == null or count == null or cb == null) return -1;
    const b: [*]u8 = @ptrCast(buf);
    const cp: *c_long = @ptrCast(count);
    const saved_cb = t_enum_cb;
    const saved_user = t_enum_user;
    t_enum_cb = cb;
    t_enum_user = user;
    defer {
        t_enum_cb = saved_cb;
        t_enum_user = saved_user;
    }
    var cnt: i64 = @intCast(cp.*);
    const r = view_mod.viewEnumDfs(f.impl, state, b[0..internal.MAX_WORD_LEN], depth, enumTrampoline, null, &cnt);
    cp.* = @intCast(cnt);
    return r;
}

// ─── Force symbol emission (belt & braces with `export fn`) ────────────────

comptime {
    _ = &dafsa_create;
    _ = &dafsa_free;
    _ = &dafsa_abi_version;
    _ = &dafsa_build_sorted;
    _ = &dafsa_add_n;
    _ = &dafsa_lookup_n;
    _ = &dafsa_delete_n;
    _ = &dafsa_add;
    _ = &dafsa_lookup;
    _ = &dafsa_delete;
    _ = &dafsa_prefix_enum;
    _ = &dafsa_save;
    _ = &dafsa_load;
    _ = &dafsa_load_readonly;
    _ = &dafsa_stats;
    _ = &dafsa_dot;
    _ = &dafsa_view_open;
    _ = &dafsa_view_close;
    _ = &dafsa_view_lookup_n;
    _ = &dafsa_view_prefix_enum;
    _ = &dafsa_view_open_layered;
    _ = &dafsa_wal_open;
    _ = &dafsa_wal_open_rw;
    _ = &dafsa_wal_open_ro;
    _ = &dafsa_wal_append_add;
    _ = &dafsa_wal_append_del;
    _ = &dafsa_wal_sync;
    _ = &dafsa_wal_size;
    _ = &dafsa_wal_replay;
    _ = &dafsa_wal_close;
    _ = &dafsa_ensure_subtree;
    _ = &dafsa_rank_n;
    _ = &dafsa_rank_from;
    _ = &dafsa_select_n;
    _ = &dafsa_select_from;
    _ = &dafsa_range_count_n;
    _ = &dafsa_range_count_from;
    _ = &dafsa_view_subtree_counts;
    _ = &dafsa_view_rank_n;
    _ = &dafsa_view_select_n;
    _ = &dafsa_view_range_count_n;
    _ = &crc32_table;
    _ = &crc32_init;
    _ = &crc32_update;
    _ = &crc32_finalize;
    _ = &crc32_compute;
    _ = &trans_find;
    _ = &view_trans_find;
    _ = &view_edge_next;
    _ = &view_enum_dfs;
}
