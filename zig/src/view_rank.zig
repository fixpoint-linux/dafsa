// view_rank.zig — Tier-2 order-statistics over a zero-copy dafsa_view.
// Faithful Zig port of dafsa_view_rank.c, operating over the mmap view's CSR.
//
// The view (view.zig) holds the CSR + final_bits bitmap + state_off[] offsets,
// so no State[]/Edge[] materialization is needed.  Subtree counts are computed
// on demand into a fresh array per call (the view is immutable / read-only; the
// C reference does the same: dafsa_view_subtree_counts allocates memo+computed,
// recurses, returns the memo and frees computed — the caller frees memo).

const std = @import("std");
const internal = @import("internal.zig");
const view = @import("view.zig");
const DafsaView = view.DafsaView;

fn viewIsFinal(v: *const DafsaView, s: u32) bool {
    return v.final_bits[s / 8] & (@as(u8, 1) << @intCast(s % 8)) != 0;
}

fn viewCountRecurse(v: *const DafsaView, s: u32, memo: []u64, computed: []u8) u64 {
    if (computed[s] != 0) return memo[s];
    var c: u64 = if (viewIsFinal(v, s)) 1 else 0;
    var cur: []const u8 = v.csr[v.state_off[s]..v.state_off[s + 1]];
    var sym: u8 = undefined;
    var tgt: u32 = undefined;
    while (view.viewEdgeNext(v, s, &cur, &sym, &tgt) == 0) {
        c +%= viewCountRecurse(v, tgt, memo, computed);
    }
    memo[s] = c;
    computed[s] = 1;
    return c;
}

// Compute the per-state subtree counts for a read-only view.  On success
// allocates and returns (via counts_out) a u64 array of size n_states+1
// (indexed by state id, 0..n_states; state 0 is unused) and returns the root
// count.  On OOM returns 0 and leaves *counts_out = empty (never aborts).
pub fn dafsaViewSubtreeCounts(v: *const DafsaView, counts_out: *[]u64) u64 {
    const a = std.heap.c_allocator;
    counts_out.* = internal.emptySlice(u64);
    const memo = a.alloc(u64, @as(usize, v.n_states) + 1) catch return 0;
    @memset(memo, 0);
    const computed = a.alloc(u8, @as(usize, v.n_states) + 1) catch {
        a.free(memo);
        return 0;
    };
    defer a.free(computed);
    @memset(computed, 0);
    _ = viewCountRecurse(v, v.initial, memo, computed);
    counts_out.* = memo;
    return memo[v.initial];
}

fn viewRankCore(v: *const DafsaView, s: u32, counts: []const u64, key: []const u8) u64 {
    var r: u64 = 0;
    var cur_s = s;
    for (key) |c| {
        if (viewIsFinal(v, cur_s)) r +%= 1;
        var cur: []const u8 = v.csr[v.state_off[cur_s]..v.state_off[cur_s + 1]];
        var sym: u8 = undefined;
        var tgt: u32 = undefined;
        var matched = false;
        var match_tgt: u32 = 0;
        while (view.viewEdgeNext(v, cur_s, &cur, &sym, &tgt) == 0) {
            if (sym < c) {
                r +%= counts[tgt];
            } else if (sym == c) {
                matched = true;
                match_tgt = tgt;
                break;
            } else {
                break;
            }
        }
        if (!matched) return r;
        cur_s = match_tgt;
    }
    return r;
}

pub fn dafsaViewRankN(v: *const DafsaView, key: []const u8) u64 {
    var counts: []u64 = undefined;
    _ = dafsaViewSubtreeCounts(v, &counts);
    if (counts.len == 0) return 0;
    defer std.heap.c_allocator.free(counts);
    return viewRankCore(v, v.initial, counts, key);
}

fn viewSelectCore(v: *const DafsaView, s: u32, counts: []const u64, k: u64, key_out: []u8) i32 {
    var pos: usize = 0;
    var kk = k;
    var cur_s = s;
    const total = counts[cur_s];
    if (kk >= total) return -1;
    while (true) {
        if (viewIsFinal(v, cur_s)) {
            if (kk == 0) return @intCast(pos);
            kk -%= 1;
        }
        var cur: []const u8 = v.csr[v.state_off[cur_s]..v.state_off[cur_s + 1]];
        var sym: u8 = undefined;
        var tgt: u32 = undefined;
        var descended = false;
        while (view.viewEdgeNext(v, cur_s, &cur, &sym, &tgt) == 0) {
            const cnt = counts[tgt];
            if (kk < cnt) {
                if (pos >= key_out.len) return -1;
                key_out[pos] = sym;
                pos += 1;
                cur_s = tgt;
                descended = true;
                break;
            }
            kk -%= cnt;
        }
        if (!descended) return -1;
    }
}

pub fn dafsaViewSelectN(v: *const DafsaView, k: u64, key_out: []u8) i32 {
    var counts: []u64 = undefined;
    _ = dafsaViewSubtreeCounts(v, &counts);
    if (counts.len == 0) return -1;
    defer std.heap.c_allocator.free(counts);
    return viewSelectCore(v, v.initial, counts, k, key_out);
}

pub fn dafsaViewRangeCountN(v: *const DafsaView, lo: []const u8, hi: []const u8) u64 {
    var counts: []u64 = undefined;
    _ = dafsaViewSubtreeCounts(v, &counts);
    if (counts.len == 0) return 0;
    defer std.heap.c_allocator.free(counts);
    const rhi = viewRankCore(v, v.initial, counts, hi);
    const rlo = viewRankCore(v, v.initial, counts, lo);
    return if (rhi > rlo) rhi - rlo else 0;
}
