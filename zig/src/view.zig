// view.zig — Zero-copy view + prefix enumeration + WAL overlay (mirrors dafsa_view.c)
//
// mmaps the on-disk PDWG file and indexes directly into the CSR (state_off[]
// byte offsets, final_bits bitmap) — no State[]/Edge[] materialization.
// Includes the WAL overlay machinery (wal_overlay structs + overlay_* helpers,
// nested upsert growth) and the layered open path (view_open_layered).
//
// I/O idioms (Zig 0.16, trimmed stdlib — see env-fact node
// zig-0.16-sandbox-stdlib-facts):
//   * open    = std.posix.openat(linux.AT.FDCWD, path_z, .{.ACCMODE=.RDONLY}, 0)
//   * size    = std.os.linux.statx on the opened fd (AT.EMPTY_PATH)
//   * mmap    = std.posix.mmap(null, fsize, .{.READ=true}, .{.TYPE=.PRIVATE}, fd, 0)
//               returns []align(page_size_min) u8 whose len == requested len;
//   * munmap  = std.posix.munmap(map)  — takes the page-aligned slice returned
//               by mmap (C's munmap(map,fsize) relies on kernel rounding; Zig
//               passes the slice len through to the syscall, kernel rounds up).
//   * close   = std.os.linux.close(fd).

const std = @import("std");
const internal = @import("internal.zig");
const persist = @import("persist.zig");
const crc32 = @import("crc32.zig");
const state = @import("state.zig");
const wal = @import("wal.zig");

const Dafsa = internal.Dafsa;
const State = internal.State;
const Edge = internal.Edge;
const MAX_WORD_LEN = internal.MAX_WORD_LEN;
const FNV_OFFSET = internal.FNV_OFFSET;
const FNV_PRIME = internal.FNV_PRIME;
const linux = std.os.linux;

// ─── WAL op codes (dafsa.h) ────────────────────────────────────────────────
const DAFSA_WAL_OP_ADD: u8 = 1;
const DAFSA_WAL_OP_DEL: u8 = 2;

// ─── Overlay data structures (dafsa_internal.h:123-137) ─────────────────────
// state: 0=empty, ADD=1, DEL=2
pub const WalSlot = extern struct {
    payload: [8]u8,
    state: u8,
};

pub const WalBucket = struct {
    word: ?[]u8,
    word_len: u32,
    slots: ?[]WalSlot,
    slots_cap: usize, // power of two
    slots_used: usize, // occupied (non-zero state)
};

pub const WalOverlay = struct {
    buckets: ?[]WalBucket,
    buckets_cap: usize,
    buckets_used: usize,
    table: ?[]u32, // outer hash index -> bucket index (UINT32_MAX = empty)
    table_cap: usize, // power of two
};

// ─── Overlay helpers (dafsa_view.c:4-302) ──────────────────────────────────

// FNV-1a hash of a byte sequence (same basis as sig_compute).
pub fn overlayHashBytes(data: []const u8) u64 {
    var h: u64 = FNV_OFFSET;
    for (data) |b| {
        h ^= b;
        h *%= FNV_PRIME;
    }
    return h;
}

// Find a payload in a bucket's inner hash table. Returns slot index or -1.
fn overlayBucketFind(b: *const WalBucket, payload: []const u8) i32 {
    if (b.slots_cap == 0) return -1;
    const slots = b.slots.?;
    const h: u64 = overlayHashBytes(payload);
    var idx: usize = @intCast(h & (b.slots_cap - 1));
    while (true) {
        if (slots[idx].state == 0) return -1;
        if (std.mem.eql(u8, &slots[idx].payload, payload)) return @intCast(idx);
        idx = (idx + 1) & (b.slots_cap - 1);
    }
}

// Insert or update a payload slot in a bucket. Grows slots if needed.
fn overlayBucketUpsert(b: *WalBucket, payload: []const u8, op: u8) i32 {
    const allocator = std.heap.c_allocator;

    if (b.slots_cap == 0) {
        // initial alloc: 4 slots
        b.slots_cap = 4;
        b.slots = allocator.alloc(WalSlot, b.slots_cap) catch return -1;
        @memset(b.slots.?, .{ .payload = [_]u8{0} ** 8, .state = 0 });
        b.slots_used = 0;
    }

    while (true) {
        // Grow proactively at 75% load factor so probing stays cheap
        // and the inner loop always finds a slot before wrapping.
        if (b.slots_used * 4 >= b.slots_cap * 3) {
            const new_cap = b.slots_cap * 2;
            const old_slots = b.slots.?;
            const old_cap = b.slots_cap;
            const new_slots = allocator.alloc(WalSlot, new_cap) catch return -1;
            @memset(new_slots, .{ .payload = [_]u8{0} ** 8, .state = 0 });

            b.slots = new_slots;
            b.slots_cap = new_cap;
            b.slots_used = 0;

            // rehash old entries
            var i: usize = 0;
            while (i < old_cap) : (i += 1) {
                if (old_slots[i].state != 0) {
                    if (overlayBucketUpsert(b, &old_slots[i].payload, old_slots[i].state) != 0) {
                        allocator.free(old_slots);
                        return -1;
                    }
                }
            }
            allocator.free(old_slots);
            // fall through: outer loop restarts with larger table
        }

        // try to find existing or empty slot
        const h: u64 = overlayHashBytes(payload);
        var idx: usize = @intCast(h & (b.slots_cap - 1));
        var probed: usize = 0;
        while (probed < b.slots_cap) : (probed += 1) {
            const slots = b.slots.?;
            if (slots[idx].state == 0) {
                // empty slot: insert
                @memcpy(&slots[idx].payload, payload);
                slots[idx].state = op;
                b.slots_used += 1;
                return 0;
            }
            if (std.mem.eql(u8, &slots[idx].payload, payload)) {
                // existing: overwrite state (last-op-wins)
                if (slots[idx].state == 0) b.slots_used += 1;
                slots[idx].state = op;
                return 0;
            }
            idx = (idx + 1) & (b.slots_cap - 1);
        }
        // Table is full (all slots occupied, none matching).
        // Outer loop will grow and retry.
    }
}

// Free a single bucket.
fn overlayBucketFree(b: *WalBucket) void {
    const allocator = std.heap.c_allocator;
    if (b.word) |w| allocator.free(w);
    if (b.slots) |s| allocator.free(s);
    b.* = .{ .word = null, .word_len = 0, .slots = null, .slots_cap = 0, .slots_used = 0 };
}

// Free the entire overlay.
fn overlayFree(ov: ?*WalOverlay) void {
    const o = ov orelse return;
    const allocator = std.heap.c_allocator;
    if (o.buckets) |buckets| {
        var i: usize = 0;
        while (i < o.buckets_cap) : (i += 1) {
            if (buckets[i].word != null) overlayBucketFree(&buckets[i]);
        }
        allocator.free(buckets);
    }
    if (o.table) |t| allocator.free(t);
    allocator.destroy(o);
}

// Callback for dafsa_wal_replay: build the overlay from WAL records.
const OverlayBuildCtx = struct {
    ov: *WalOverlay,
};

fn overlayBuildCb(op: u8, key: []const u8, user: ?*anyopaque) i32 {
    const ctx: *OverlayBuildCtx = @ptrCast(@alignCast(user.?));
    const ov = ctx.ov;
    const allocator = std.heap.c_allocator;

    // Split at first 0x00: must have word || 0x00 || 8-byte payload
    const nul_idx = std.mem.indexOfScalar(u8, key, 0x00) orelse return 0; // malformed: skip
    const word_len = nul_idx;
    if (key.len - word_len - 1 != 8) return 0; // wrong tail length: skip

    // Find or create outer bucket
    const h: u64 = overlayHashBytes(key[0..word_len]);

    // Grow outer table if needed (> 75% full)
    if (ov.buckets_used * 4 >= ov.table_cap * 3) {
        const new_cap = if (ov.table_cap != 0) ov.table_cap * 2 else 1024;
        const new_table = allocator.alloc(u32, new_cap) catch return -1;
        for (new_table) |*e| e.* = std.math.maxInt(u32);

        // Rehash existing buckets
        if (ov.buckets) |buckets| {
            var i: usize = 0;
            while (i < ov.buckets_cap) : (i += 1) {
                if (buckets[i].word != null) {
                    const bh = overlayHashBytes(buckets[i].word.?);
                    var bi: usize = @intCast(bh & (new_cap - 1));
                    while (new_table[bi] != std.math.maxInt(u32))
                        bi = (bi + 1) & (new_cap - 1);
                    new_table[bi] = @intCast(i);
                }
            }
        }

        if (ov.table) |t| allocator.free(t);
        ov.table = new_table;
        ov.table_cap = new_cap;
    }

    // Probe outer table for matching bucket
    var idx: usize = @intCast(h & (ov.table_cap - 1));
    while (true) {
        const bi = ov.table.?[idx];
        if (bi == std.math.maxInt(u32)) {
            // New bucket: allocate
            if (ov.buckets_used >= ov.buckets_cap) {
                const new_bcap = if (ov.buckets_cap != 0) ov.buckets_cap * 2 else 64;
                const nb = if (ov.buckets != null)
                    allocator.realloc(ov.buckets.?, new_bcap) catch return -1
                else
                    allocator.alloc(WalBucket, new_bcap) catch return -1;
                // zero-initialize the newly allocated tail
                const old_cap = ov.buckets_cap;
                for (nb[old_cap..new_bcap]) |*e|
                    e.* = .{ .word = null, .word_len = 0, .slots = null, .slots_cap = 0, .slots_used = 0 };
                ov.buckets = nb;
                ov.buckets_cap = new_bcap;
            }
            const new_bi = ov.buckets_used;
            const word_buf = allocator.dupe(u8, key[0..word_len]) catch return -1;
            ov.buckets.?[new_bi].word = word_buf;
            ov.buckets.?[new_bi].word_len = @intCast(word_len);
            ov.buckets.?[new_bi].slots = null;
            ov.buckets.?[new_bi].slots_cap = 0;
            ov.buckets.?[new_bi].slots_used = 0;
            ov.table.?[idx] = @intCast(new_bi);
            ov.buckets_used += 1;
            // fall through to insert/update slot
            return overlayBucketUpsert(&ov.buckets.?[new_bi], key[word_len + 1 ..], op);
        }
        // Check word match
        const bucket = &ov.buckets.?[bi];
        if (bucket.word_len == @as(u32, @intCast(word_len)) and
            std.mem.eql(u8, bucket.word.?, key[0..word_len]))
        {
            return overlayBucketUpsert(bucket, key[word_len + 1 ..], op);
        }
        idx = (idx + 1) & (ov.table_cap - 1);
    }
}

// Load overlay from a WAL file path. Returns NULL on any error.
fn overlayLoad(wal_path: []const u8) ?*WalOverlay {
    const w = wal.dafsaWalOpenRo(wal_path) orelse return null;
    const allocator = std.heap.c_allocator;

    const ov = allocator.create(WalOverlay) catch {
        wal.dafsaWalClose(w);
        return null;
    };
    ov.* = .{ .buckets = null, .buckets_cap = 0, .buckets_used = 0, .table = null, .table_cap = 0 };

    var ctx = OverlayBuildCtx{ .ov = ov };
    if (wal.dafsaWalReplay(w, overlayBuildCb, &ctx) != 0) {
        overlayFree(ov);
        wal.dafsaWalClose(w);
        return null;
    }

    wal.dafsaWalClose(w);
    return ov;
}

// Look up a composite key (word || 0x00 || 8-byte payload) in the overlay.
// Returns: ADD (1) if present as ADD, DEL (2) if tombstoned, 0 if not found.
fn overlayLookup(ov: *const WalOverlay, word: []const u8, payload: []const u8) i32 {
    if (ov.buckets_used == 0 or ov.table_cap == 0) return 0;

    const h: u64 = overlayHashBytes(word);
    var idx: usize = @intCast(h & (ov.table_cap - 1));

    while (true) {
        const bi = ov.table.?[idx];
        if (bi == std.math.maxInt(u32)) return 0; // empty -> not found

        const bucket = &ov.buckets.?[bi];
        if (bucket.word_len == @as(u32, @intCast(word.len)) and
            std.mem.eql(u8, bucket.word.?, word))
        {
            const slot = overlayBucketFind(bucket, payload);
            if (slot < 0) return 0;
            return bucket.slots.?[@intCast(slot)].state;
        }

        idx = (idx + 1) & (ov.table_cap - 1);
    }
}

// Find the overlay bucket for a word. Returns bucket pointer or null.
fn overlayFindBucket(ov: *const WalOverlay, word: []const u8) ?*const WalBucket {
    if (ov.buckets_used == 0 or ov.table_cap == 0) return null;

    const h: u64 = overlayHashBytes(word);
    var idx: usize = @intCast(h & (ov.table_cap - 1));

    while (true) {
        const bi = ov.table.?[idx];
        if (bi == std.math.maxInt(u32)) return null;

        const bucket = &ov.buckets.?[bi];
        if (bucket.word_len == @as(u32, @intCast(word.len)) and
            std.mem.eql(u8, bucket.word.?, word))
            return bucket;

        idx = (idx + 1) & (ov.table_cap - 1);
    }
}

// ─── Zero-copy search-only view (dafsa_internal.h:141-152) ────────────────

pub const DafsaView = struct {
    allocator: std.mem.Allocator,
    map: []align(std.heap.page_size_min) u8, // mmap'd file (aligned slice for munmap)
    map_len: usize,
    n_states: u32,
    initial: u32, // == 1
    final_bits: []const u8, // points into map (bitmap start)
    csr: []const u8, // points into map: first CSR byte
    state_off: []u64, // n_states+2 byte offsets into csr; off[0]=0; off[n_states+1]==total CSR bytes
    ov: ?*WalOverlay, // WAL overlay for layered read, or null
};

// Enumeration callback (dafsa.h:55).
pub const EnumCb = *const fn (payload: []const u8, user: ?*anyopaque) i32;

pub fn dafsaViewOpen(path: []const u8) ?*DafsaView {
    if (path.len == 0) return null;
    const allocator = std.heap.c_allocator;
    const path_z = allocator.dupeZ(u8, path) catch return null;
    defer allocator.free(path_z);

    var fd: i32 = -1;
    var map: ?[]align(std.heap.page_size_min) u8 = null;
    var state_off: ?[]u64 = null;
    var v: ?*DafsaView = null;
    var ok = false;
    defer if (!ok) {
        if (fd >= 0) _ = linux.close(fd);
        if (map) |m| std.posix.munmap(m);
        if (state_off) |so| allocator.free(so);
        if (v) |vv| allocator.destroy(vv);
    };

    fd = std.posix.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0) catch return null;

    // fstat via statx on the opened fd (AT.EMPTY_PATH)
    var sb: linux.Statx = undefined;
    const srx = linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &sb);
    if (linux.errno(srx) != .SUCCESS) return null;
    const fsize: usize = @intCast(sb.size);
    if (fsize < 28) return null; // minimum: header only

    const map_slice = std.posix.mmap(null, fsize, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0) catch return null;
    map = map_slice;
    _ = linux.close(fd);
    fd = -1;

    var p: []const u8 = map_slice;

    // header
    var magic: [4]u8 = undefined;
    if (!persist.mb_get_u8(&p, &magic[0])) return null;
    if (!persist.mb_get_u8(&p, &magic[1])) return null;
    if (!persist.mb_get_u8(&p, &magic[2])) return null;
    if (!persist.mb_get_u8(&p, &magic[3])) return null;
    if (magic[0] != 'P' or magic[1] != 'D' or magic[2] != 'W' or magic[3] != 'G') return null;

    var version: u32 = undefined;
    var n_states: u32 = undefined;
    var n_trans: u32 = undefined;
    var initial_id: u32 = undefined;
    var n_final: u32 = undefined;
    var reserved: u32 = undefined;
    if (!persist.mb_get_u32_le(&p, &version)) return null;
    if (!persist.mb_get_u32_le(&p, &n_states)) return null;
    if (!persist.mb_get_u32_le(&p, &n_trans)) return null;
    if (!persist.mb_get_u32_le(&p, &initial_id)) return null;
    if (!persist.mb_get_u32_le(&p, &n_final)) return null;
    if (!persist.mb_get_u32_le(&p, &reserved)) return null;
    _ = &reserved;
    if (version != 3 and version != 4) return null;
    if (initial_id != 1) return null;
    if (n_states == 0) return null;

    // state table: capture ntbl BEFORE advancing past it
    const ntbl = p; // slice into map: table start (sink u16 first)
    {
        var sink_nt: u16 = undefined;
        if (!persist.mb_get_u16_le(&p, &sink_nt)) return null;
        if (sink_nt != 0) return null;
    }
    // now p points past the sink u16; skip remaining n_states u16 entries
    if (@as(usize, n_states) > p.len / 2) return null;
    p = p[@as(usize, n_states) * 2 ..];

    // final bitmap
    const bitmap_bytes = (@as(usize, n_states) + 8) / 8;
    if (bitmap_bytes > p.len) return null;
    {
        // Validate n_final against popcount of the bitmap
        var finals: u32 = 0;
        var i: usize = 0;
        while (i < bitmap_bytes) : (i += 1) {
            var b = p[i];
            // popcount per byte via Brian Kernighan's method
            while (b != 0) {
                finals += 1;
                b &= b - 1;
            }
        }
        if (finals != n_final) return null;
    }
    const final_bits: []const u8 = p[0..bitmap_bytes];
    p = p[bitmap_bytes..];

    // build state_off: walk the CSR once, reading ntrans from ntbl.
    if (@as(usize, n_states) + 2 > std.math.maxInt(usize) / @sizeOf(u64)) return null;
    state_off = allocator.alloc(u64, @as(usize, n_states) + 2) catch return null;
    @memset(state_off.?, 0);

    {
        // p now points at first CSR byte
        var q = p;
        var nt_sum: u64 = 0;
        state_off.?[0] = 0;
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) {
            // ntbl points at table start; state i's u16 is at bytes 2*i, 2*i+1
            const nt: u16 = @as(u16, @intCast(ntbl[@as(usize, i) * 2])) |
                (@as(u16, @intCast(ntbl[@as(usize, i) * 2 + 1])) << 8);
            nt_sum += nt;
            state_off.?[@intCast(i)] = @intCast(q.ptr - p.ptr);
            var j: u32 = 0;
            while (j < nt) : (j += 1) {
                if (q.len == 0) return null;
                q = q[1..]; // sym byte
                var tgt: u32 = undefined;
                if (!persist.mb_get_uvarint(&q, &tgt)) return null;
                if (tgt > n_states) return null; // bounds check
            }
        }
        state_off.?[@as(usize, n_states) + 1] = @intCast(q.ptr - p.ptr);
        if (nt_sum != n_trans) return null; // header n_trans mismatch
        if (version == 4) {
            // v4: verify trailing CRC32. Covered region is [map, q). Stored CRC
            // sits in the final 4 bytes, little-endian.
            if (fsize < 32) return null; // header 28 + CRC 4
            if (q.len != 4) return null; // no trailing garbage after CRC
            const covered_len = fsize - 4;
            const stored = mbGetU32LeAt(map_slice, fsize - 4);
            const calc = crc32.compute(map_slice[0..covered_len]);
            if (calc != stored) return null;
        } else {
            if (q.len != 0) return null; // v3: CSR must end exactly at EOF
        }
    }

    v = allocator.create(DafsaView) catch return null;
    v.?.* = .{
        .allocator = allocator,
        .map = map_slice,
        .map_len = fsize,
        .n_states = n_states,
        .initial = initial_id,
        .final_bits = final_bits,
        .csr = p,
        .state_off = state_off.?,
        .ov = null, // no overlay for plain open
    };
    ok = true;
    return v.?;
}

fn mbGetU32LeAt(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) |
        (@as(u32, buf[off + 1]) << 8) |
        (@as(u32, buf[off + 2]) << 16) |
        (@as(u32, buf[off + 3]) << 24);
}

pub fn dafsaViewClose(v: ?*DafsaView) void {
    const vv = v orelse return;
    if (vv.ov) |ov| overlayFree(ov);
    std.posix.munmap(vv.map);
    vv.allocator.free(vv.state_off);
    vv.allocator.destroy(vv);
}

// ─── Prefix enumeration ────────────────────────────────────────────────────

// Recursive DFS from `state`, appending transition bytes into buf. Calls cb at
// each final state with the accumulated payload (bytes collected after the
// 0x00 edge). Returns non-zero to stop early.
pub fn enumDfs(d: *const Dafsa, state_id: u32, buf: []u8, depth: usize, cb: EnumCb, user: ?*anyopaque, count: *i64) i32 {
    const s = &d.states[state_id];

    if (s.is_final != 0) {
        count.* += 1;
        if (cb(buf[0..depth], user) != 0) return 1;
    }
    if (depth >= MAX_WORD_LEN) return 0;
    const arr = internal.transArrC(s);
    var j: u32 = 0;
    while (j < s.ntrans) : (j += 1) {
        const e = &arr[j];
        buf[depth] = e.sym;
        if (enumDfs(d, e.target, buf, depth + 1, cb, user, count) != 0) return 1;
    }
    return 0;
}

// Enumerate keys of form prefix || 0x00 || payload. Walks the prefix from the
// initial state, requires a 0x00 edge next (W\0 semantics), then DFS the
// payload states calling cb(payload, len). Returns the number of keys
// enumerated; 0 if the prefix is absent or not a key boundary.
pub fn dafsaPrefixEnum(d: *const Dafsa, prefix: []const u8, cb: EnumCb, user: ?*anyopaque) i64 {
    if (prefix.len > MAX_WORD_LEN) return 0;

    var current = d.initial;

    // walk the prefix
    for (prefix) |c| {
        const tr = state.transFind(&d.states[current], c);
        if (tr < 0) return 0;
        current = internal.transArrC(&d.states[current])[@intCast(tr)].target;
    }

    // W\0 semantics: a 0x00 edge must exist from the final prefix state
    {
        const tr = state.transFind(&d.states[current], 0x00);
        if (tr < 0) return 0;
        current = internal.transArrC(&d.states[current])[@intCast(tr)].target;
    }

    var buf: [MAX_WORD_LEN]u8 = undefined;
    var count: i64 = 0;
    _ = enumDfs(d, current, &buf, 0, cb, user, &count);
    return count;
}

// ─── Zero-copy view read helpers ───────────────────────────────────────────

pub fn viewTransFind(v: *const DafsaView, s: u32, sym: u8, target_out: *u32) i32 {
    const state_start = v.state_off[s];
    const state_end = v.state_off[s + 1];
    var p: []const u8 = v.csr[state_start..state_end];
    while (p.len > 0) {
        const e_sym = p[0];
        p = p[1..];
        if (e_sym == sym) {
            if (!persist.mb_get_uvarint(&p, target_out)) return -1;
            if (target_out.* > v.n_states) return -1;
            return 0;
        }
        if (mbSkipVarint(&p) != 0) return -1;
    }
    return -1;
}

// Skip a varint in place. Returns 0 on success, -1 on malformed/EOF.
fn mbSkipVarint(cursor: *[]const u8) i32 {
    while (true) {
        var b: u8 = undefined;
        if (!persist.mb_get_u8(cursor, &b)) return -1;
        if ((b & 0x80) == 0) return 0;
    }
}

pub fn viewEdgeNext(v: *const DafsaView, s: u32, cursor: *[]const u8, sym_out: *u8, target_out: *u32) i32 {
    const state_end = v.state_off[s + 1];
    _ = state_end;
    if (cursor.*.len == 0) return -1;
    if (!persist.mb_get_u8(cursor, sym_out)) return -1;
    if (!persist.mb_get_uvarint(cursor, target_out)) return -1;
    if (target_out.* > v.n_states) return -1;
    return 0;
}

// Recursive DFS for the view, mirroring enumDfs but reading edges via
// viewEdgeNext and checking final_bits directly.
pub fn viewEnumDfs(v: *const DafsaView, state_id: u32, buf: []u8, depth: usize, cb: EnumCb, user: ?*anyopaque, count: *i64) i32 {
    if (v.final_bits[state_id / 8] & (@as(u8, 1) << @intCast(state_id % 8)) != 0) {
        count.* += 1;
        if (cb(buf[0..depth], user) != 0) return 1;
    }
    if (depth >= MAX_WORD_LEN) return 0;
    var cur: []const u8 = v.csr[v.state_off[state_id]..v.state_off[state_id + 1]];
    var sym: u8 = undefined;
    var tgt: u32 = undefined;
    while (viewEdgeNext(v, state_id, &cur, &sym, &tgt) == 0) {
        buf[depth] = sym;
        if (viewEnumDfs(v, tgt, buf, depth + 1, cb, user, count) != 0) return 1;
    }
    return 0;
}

// Filtered DFS for layered prefix enumeration. Like viewEnumDfs, but at each
// final state, checks the overlay bucket: DEL -> suppress, ADD -> emit +
// mark slot in `emitted` bitmap. Payloads not 8 bytes long (legacy) are
// emitted unconditionally.
fn viewEnumDfsLayered(v: *const DafsaView, state_id: u32, buf: []u8, depth: usize, bucket: ?*const WalBucket, emitted: ?[]u8, cb: EnumCb, user: ?*anyopaque, count: *i64) i32 {
    if (v.final_bits[state_id / 8] & (@as(u8, 1) << @intCast(state_id % 8)) != 0) {
        var should_emit = true;

        if (depth == 8 and bucket != null) {
            const b = bucket.?;
            const slot = overlayBucketFind(b, buf[0..8]);
            if (slot >= 0) {
                const s = b.slots.?[@intCast(slot)].state;
                if (s == DAFSA_WAL_OP_DEL) {
                    should_emit = false;
                } else if (s == DAFSA_WAL_OP_ADD and emitted != null) {
                    const si: usize = @intCast(slot);
                    emitted.?[si / 8] |= @as(u8, 1) << @intCast(si % 8);
                }
            }
        }

        if (should_emit) {
            count.* += 1;
            if (cb(buf[0..depth], user) != 0) return 1;
        }
    }

    if (depth >= MAX_WORD_LEN) return 0;
    var cur: []const u8 = v.csr[v.state_off[state_id]..v.state_off[state_id + 1]];
    var sym: u8 = undefined;
    var tgt: u32 = undefined;
    while (viewEdgeNext(v, state_id, &cur, &sym, &tgt) == 0) {
        buf[depth] = sym;
        if (viewEnumDfsLayered(v, tgt, buf, depth + 1, bucket, emitted, cb, user, count) != 0) return 1;
    }
    return 0;
}

// Layered prefix enumeration: merge base FST + WAL overlay. Phase A walks the
// base graph (filtered through overlay); Phase B emits WAL-only ADDs. Does NOT
// early-return when the prefix is absent from the base.
fn viewPrefixEnumLayered(v: *const DafsaView, prefix: []const u8, cb: EnumCb, user: ?*anyopaque) i64 {
    const allocator = std.heap.c_allocator;
    var current = v.initial;
    var base_has_prefix = true;

    // Walk prefix in base graph (best-effort)
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        var target: u32 = undefined;
        if (viewTransFind(v, current, prefix[i], &target) != 0) {
            base_has_prefix = false;
            break;
        }
        current = target;
    }

    // Find overlay bucket for this prefix word
    const bucket = overlayFindBucket(v.ov.?, prefix);

    // Allocate emitted bitmap if there are overlay slots to track
    var emitted: ?[]u8 = null;
    defer if (emitted) |e| allocator.free(e);
    if (bucket != null and bucket.?.slots_cap > 0) {
        const bm_bytes = (bucket.?.slots_cap + 7) / 8;
        emitted = allocator.alloc(u8, bm_bytes) catch return -1;
        @memset(emitted.?, 0);
    }

    var count: i64 = 0;

    // Phase A: base DFS through the 0x00 edge (filtered by overlay)
    if (base_has_prefix) {
        var target: u32 = undefined;
        if (viewTransFind(v, current, 0x00, &target) == 0) {
            var buf: [MAX_WORD_LEN]u8 = undefined;
            _ = viewEnumDfsLayered(v, target, &buf, 0, bucket, emitted, cb, user, &count);
        }
    }

    // Phase B: emit WAL-only ADDs (overlay slots not emitted in Phase A)
    if (bucket != null) {
        const b = bucket.?;
        const slots = b.slots.?;
        var si: usize = 0;
        while (si < b.slots_cap) : (si += 1) {
            if (slots[si].state == DAFSA_WAL_OP_ADD) {
                if (emitted == null or
                    (emitted.?[si / 8] & (@as(u8, 1) << @intCast(si % 8))) == 0)
                {
                    count += 1;
                    if (cb(&slots[si].payload, user) != 0) {
                        return count;
                    }
                }
            }
        }
    }

    return count;
}

pub fn dafsaViewLookupN(v: *const DafsaView, key: []const u8) i32 {
    // Layered lookup: consult overlay first
    if (v.ov) |ov| {
        if (std.mem.indexOfScalar(u8, key, 0x00)) |nul_idx| {
            const word_len = nul_idx;
            if (key.len - word_len - 1 == 8) {
                const ov_state = overlayLookup(ov, key[0..word_len], key[word_len + 1 ..]);
                if (ov_state == DAFSA_WAL_OP_ADD) return 1;
                if (ov_state == DAFSA_WAL_OP_DEL) return 0;
                // absent: fall through to base
            }
        }
    }

    var current = v.initial;
    for (key) |c| {
        var target: u32 = undefined;
        if (viewTransFind(v, current, c, &target) != 0) return 0;
        current = target;
    }
    return if (v.final_bits[current / 8] & (@as(u8, 1) << @intCast(current % 8)) != 0) 1 else 0;
}

pub fn dafsaViewPrefixEnum(v: *const DafsaView, prefix: []const u8, cb: EnumCb, user: ?*anyopaque) i64 {
    if (prefix.len > MAX_WORD_LEN) return 0;

    // Layered path: merge base + overlay (no early-return on base miss)
    if (v.ov != null)
        return viewPrefixEnumLayered(v, prefix, cb, user);

    var current = v.initial;

    // walk the prefix
    for (prefix) |c| {
        var target: u32 = undefined;
        if (viewTransFind(v, current, c, &target) != 0) return 0;
        current = target;
    }

    // W\0 semantics: a 0x00 edge must exist from the final prefix state
    {
        var target: u32 = undefined;
        if (viewTransFind(v, current, 0x00, &target) != 0) return 0;
        current = target;
    }

    var buf: [MAX_WORD_LEN]u8 = undefined;
    var count: i64 = 0;
    _ = viewEnumDfs(v, current, &buf, 0, cb, user, &count);
    return count;
}

// ─── Layered open ──────────────────────────────────────────────────────────

pub fn dafsaViewOpenLayered(fst_path: []const u8, wal_path: ?[]const u8) ?*DafsaView {
    const allocator = std.heap.c_allocator;
    const v = dafsaViewOpen(fst_path) orelse return null;

    if (wal_path) |wp| {
        // Check if WAL file exists and is non-trivial
        const wp_z = allocator.dupeZ(u8, wp) catch {
            dafsaViewClose(v);
            return null;
        };
        defer allocator.free(wp_z);
        var sb: linux.Statx = undefined;
        const srx = linux.statx(linux.AT.FDCWD, wp_z, linux.AT.STATX_SYNC_AS_STAT, .BASIC_STATS, &sb);
        if (linux.errno(srx) == .SUCCESS and sb.size >= 16) {
            v.ov = overlayLoad(wp);
            if (v.ov == null) {
                // Overlay load failed — close view and return NULL
                dafsaViewClose(v);
                return null;
            }
        }
        // else: wal_path doesn't exist, is empty, or too small —
        // no overlay loaded (not an error)
    }

    return v;
}
