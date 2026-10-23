// view.zig — Zero-copy view + prefix enumeration + WAL overlay (mirrors dafsa_view.c)
//
// mmaps the on-disk PDWG file and indexes directly into the CSR (state_off[]
// byte offsets, final_bits bitmap) — no State[]/Edge[] materialization.
// Includes the WAL overlay machinery (wal_overlay structs + overlay_* helpers,
// nested upsert growth) and the layered open path (view_open_layered).
//
// Open needs state_off[] (n_states+2 byte offsets into the CSR) and, for a
// v4/v5 file, the whole-file CRC32 verification.  Both are full scans, so they
// are fused into ONE pass (buildStateOff), and a v5 file may also carry the
// table itself so no scan is needed at all (PDWG_FLAG_STATE_OFF, persist.zig).
// MEASURED on the agent store's 20,714,186-byte __postings__.dafsa (616,258
// states): 75.8 ms before, 19.3 ms rebuilt, 13.2 ms from the persisted table;
// on its 90,079,216-byte symbols.dafsa (12.9M states, table-less by design):
// 294.9 ms -> 88 ms.
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
const builtin = @import("builtin");
const internal = @import("internal.zig");
const persist = @import("persist.zig");
const crc32 = @import("crc32.zig");
const state = @import("state.zig");
const wal = @import("wal.zig");
// test-only: build corpora to save/open (view.zig itself needs neither)
const core = @import("core.zig");
const dafsa_mod = @import("dafsa.zig");

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
    // false => state_off ALIASES the mmap (the v5 persisted table): never write
    // through it and never free it.  true => heap table rebuilt from the CSR.
    state_off_owned: bool,
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
    var flags: u32 = undefined;
    if (!persist.mb_get_u32_le(&p, &version)) return null;
    if (!persist.mb_get_u32_le(&p, &n_states)) return null;
    if (!persist.mb_get_u32_le(&p, &n_trans)) return null;
    if (!persist.mb_get_u32_le(&p, &initial_id)) return null;
    if (!persist.mb_get_u32_le(&p, &n_final)) return null;
    if (!persist.mb_get_u32_le(&p, &flags)) return null;
    if (version < 3 or version > 5) return null;
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

    // ── state_off ─────────────────────────────────────────────────────────
    //
    // Two paths, and the writer decides which one a file uses:
    //
    //   * v5 with PDWG_FLAG_STATE_OFF: the offset table is persisted, 8-byte
    //     aligned right before the CSR, so the open is mmap + point at it.
    //     The writer emits it only when it is small next to the CSR it indexes
    //     (see dafsaSave) — MEASURED: on the agent store's __postings__.dafsa
    //     (20,714,186 bytes, 616,258 states, 31 bytes of CSR per state) the
    //     table is 4.9 MB (+24%) and the open drops 19.3 ms -> 13.2 ms.
    //   * everything else (v3/v4, or a v5 file the writer left table-less):
    //     rebuilt by one sequential walk of the CSR.  The walk reads every CSR
    //     byte anyway and the v4/v5 trailer CRC32 covers exactly those bytes,
    //     so the two scans are FUSED — the walk folds the CSR into the CRC in
    //     bulk chunks and only the header/state-table/bitmap prefix is hashed
    //     separately (19.3 ms vs 22.7 ms for two separate passes on
    //     __postings__.dafsa).  This is the only path that scales for a
    //     state-dense file: on the store's 90 MB symbols.dafsa (12.9M states) a
    //     103 MB table would be bigger than the CSR it indexes, so persisting
    //     it would make the open SLOWER (108 ms vs 88 ms) and the file 114%
    //     larger — which is why the writer only persists it when it pays.
    var csr: []const u8 = p;
    var persisted: ?[]u64 = null;
    if (version >= 5 and (flags & persist.PDWG_FLAG_STATE_OFF) != 0) {
        // zero padding up to the 8-byte-aligned table offset
        const pad = (8 - (map_slice.len - p.len) % 8) % 8;
        if (p.len < pad) return null;
        p = p[pad..];
        const tbl_entries = @as(usize, n_states) + 2;
        if (tbl_entries > p.len / 8) return null;
        const tbl_bytes = tbl_entries * @sizeOf(u64);
        if (p.len < tbl_bytes + 4) return null; // table + CSR + trailing CRC
        const csr_data_len = p.len - tbl_bytes - 4;
        if (comptime builtin.cpu.arch.endian() == .little) {
            // page-aligned mmap + 8-aligned file offset => the u64 slice is
            // properly aligned; it ALIASES the mapping (read-only by contract).
            const tbl_off = map_slice.len - p.len;
            const aligned: []align(8) u8 = @alignCast(map_slice[tbl_off .. tbl_off + tbl_bytes]);
            const tbl: []u64 = std.mem.bytesAsSlice(u64, aligned);
            // The trailer CRC covers the table's bytes, so this pass is not an
            // integrity check — it is a consistency check, so that a WRITER bug
            // cannot become a silently wrong traversal.
            if (!tableConsistent(tbl, ntbl, n_states, csr_data_len)) return null;
            persisted = tbl;
        }
        // (big-endian host: the table is little-endian, so fall through to the
        // walk below rather than misread it — correct, just not O(1).)
        p = p[tbl_bytes..];
        csr = p;
    }

    if (persisted) |_| {
        if (version >= 4) {
            if (fsize < 32) return null; // header 28 + CRC 4
            if (crc32.compute(map_slice[0 .. fsize - 4]) != mbGetU32LeAt(map_slice, fsize - 4)) return null;
        }
    } else {
        if (@as(usize, n_states) + 2 > std.math.maxInt(usize) / @sizeOf(u64)) return null;
        var crc_reg: u32 = crc32.init();
        if (version >= 4) {
            if (fsize < 32) return null; // header 28 + CRC 4
            // prefix: everything before the CSR region
            crc_reg = crc32.update(crc_reg, map_slice[0 .. map_slice.len - csr.len]);
        }
        state_off = buildStateOff(
            allocator,
            csr,
            ntbl,
            n_states,
            n_trans,
            csrRegionLen(csr, version),
            if (version >= 4) &crc_reg else null,
        ) catch return null;
        if (version >= 4) {
            // The walk folded the CSR in; compare against the stored trailer.
            if (crc32.finalize(crc_reg) != mbGetU32LeAt(map_slice, fsize - 4)) return null;
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
        .csr = csr,
        .state_off = if (persisted) |t| t else state_off.?,
        .state_off_owned = persisted == null,
        .ov = null, // no overlay for plain open
    };
    ok = true;
    return v.?;
}

/// CSR region length as it sits in the file: a v4 file keeps its 4-byte CRC
/// trailer at the end of the region, a v3 file ends at EOF.
fn csrRegionLen(region: []const u8, version: u32) usize {
    return region.len - (if (version >= 4) @as(usize, 4) else 0);
}

/// Is the persisted v5 table consistent with the rest of the file?  The
/// trailer CRC already covers the table's bytes (so rot is caught); this checks
/// that the offsets can be INDEXED safely, so that a writer bug cannot become a
/// silently wrong traversal — the failure mode state_off governs.  One
/// sequential pass:
///   * endpoints — off[0] == 0, off[n_states+1] == the CSR's byte length;
///   * monotonicity — off[i] <= off[i+1] for every state;
///   * lower bound — a state's slice holds >= 2 bytes per transition
///     (a sym byte plus a >=1-byte varint), per the ntbl count.
fn tableConsistent(tbl: []const u64, ntbl: []const u8, n_states: u32, csr_data_len: usize) bool {
    const n = @as(usize, n_states) + 2;
    if (tbl.len != n) return false;
    if (tbl[0] != 0) return false;
    if (tbl[n - 1] != csr_data_len) return false;
    var i: usize = 1;
    while (i <= n_states) : (i += 1) {
        const start = tbl[i];
        const end = tbl[i + 1];
        if (end < start) return false;
        if (end - start < 2 * @as(u64, ntAt(ntbl, i))) return false;
    }
    return true;
}

fn ntAt(ntbl: []const u8, i: usize) u16 {
    return @as(u16, @intCast(ntbl[i * 2])) |
        (@as(u16, @intCast(ntbl[i * 2 + 1])) << 8);
}

/// Rebuild state_off by walking the CSR once.  `csr` is the CSR region as it
/// sits in the file (a v4 file keeps its 4-byte CRC trailer inside it;
/// `csr_data_len` excludes that).  Returns an owned table, or an error on a
/// malformed CSR.
///
/// The varints are SKIPPED, not decoded: the offsets need only their byte
/// lengths, and every consumer bounds-checks the target it reads
/// (viewTransFind / viewEdgeNext / view_rank), so decoding each value here
/// bought no safety — only work.  The walk still validates the structure: each
/// varint is well-formed (<= 5 bytes, the u32 LEB128 limit), the transitions
/// accounted for equal the header's n_trans, and the CSR ends exactly where the
/// format says it does.
///
/// When `crc` is non-null it is the running CRC32 register covering everything
/// before the CSR; the walk folds the CSR bytes it consumes into it (in bulk
/// chunks, so the folding is a slicing-by-8 continuation rather than a per-byte
/// fold).  The caller finalizes and compares — that is the v4/v5 integrity
/// check, paid inside the walk it already had to do.
fn buildStateOff(
    allocator: std.mem.Allocator,
    csr: []const u8,
    ntbl: []const u8,
    n_states: u32,
    n_trans: u32,
    csr_data_len: usize,
    crc: ?*u32,
) ![]u64 {
    const tbl = try allocator.alloc(u64, @as(usize, n_states) + 2);
    errdefer allocator.free(tbl);
    @memset(tbl, 0);

    var q = csr;
    var nt_sum: u64 = 0;
    var folded: usize = 0;
    var i: u32 = 1;
    while (i <= n_states) : (i += 1) {
        const nt = ntAt(ntbl, i);
        nt_sum += nt;
        tbl[@intCast(i)] = q.ptr - csr.ptr;
        var j: u32 = 0;
        while (j < nt) : (j += 1) {
            if (q.len == 0) return error.MalformedCsr;
            q = q[1..]; // sym byte
            if (!skipUvarint(&q)) return error.MalformedCsr;
        }
        // Fold the bytes consumed so far in bulk (every 256 states, and for the
        // last one below) — one slicing-by-8 call per chunk, not per transition.
        if (crc != null and (i & 0xFF) == 0) {
            const cur = q.ptr - csr.ptr;
            crc.?.* = crc32.update(crc.?.*, csr[folded..cur]);
            folded = cur;
        }
    }
    const consumed = q.ptr - csr.ptr;
    tbl[@as(usize, n_states) + 1] = consumed;
    if (nt_sum != n_trans) return error.MalformedCsr; // header n_trans mismatch
    if (consumed != csr_data_len) return error.MalformedCsr;
    if (crc) |c| c.* = crc32.update(c.*, csr[folded..consumed]);
    return tbl;
}

/// Skip one LEB128 u32 in place (up to 5 bytes).  Returns false on EOF or a
/// varint longer than a u32 can be — the same limit persist.mb_get_uvarint
/// enforces, so a malformed tail is still rejected.
fn skipUvarint(cursor: *[]const u8) bool {
    var len: u32 = 1;
    while (true) {
        if (cursor.*.len == 0) return false;
        const b = cursor.*[0];
        cursor.* = cursor.*[1..];
        if ((b & 0x80) == 0) return true;
        len += 1;
        if (len > 5) return false;
    }
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
    // The persisted table aliases `map` (already unmapped above); only a
    // rebuilt table is ours to free.
    if (vv.state_off_owned) vv.allocator.free(vv.state_off);
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
    const state_start = @as(usize, @intCast(v.state_off[s]));
    const state_end = @as(usize, @intCast(v.state_off[s + 1]));
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
    const state_end = @as(usize, @intCast(v.state_off[s + 1]));
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
    var cur: []const u8 = v.csr[@intCast(v.state_off[state_id])..@intCast(v.state_off[state_id + 1])];
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
    var cur: []const u8 = v.csr[@intCast(v.state_off[state_id])..@intCast(v.state_off[state_id + 1])];
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

// ─── Tests: state_off correctness (persisted table AND rebuilt) + integrity ──
//
// Two corpora, one on each side of the writer's "persist the offset table only
// when it pays" threshold (table <= csr/2):
//   * WIDE  — every <a><b><c> over a 16-symbol alphabet, each followed by a
//             run of 'd' as long as <a>: 50 states, 545 transitions, ~30 CSR
//             bytes per state => table persisted.
//   * DENSE — 204 keys forming a 200-deep chain: ~6 CSR bytes per state =>
//             no table (the state_off rebuild is cheaper than checksumming a
//             table bigger than the CSR it indexes).

const testing = std.testing;

fn buildWideCorpus() ?*Dafsa {
    const d = dafsa_mod.dafsaCreate() orelse return null;
    _ = core.dafsaAddN(d, "");
    var key: [32]u8 = undefined;
    var a: u8 = 'a';
    while (a <= 'p') : (a += 1) {
        var b: u8 = 'a';
        while (b <= 'p') : (b += 1) {
            var c: u8 = 'a';
            while (c <= 'p') : (c += 1) {
                key[0] = a;
                key[1] = b;
                key[2] = c;
                const tail: usize = a - 'a';
                @memset(key[3 .. 3 + tail], 'd');
                _ = core.dafsaAddN(d, key[0 .. 3 + tail]);
            }
        }
    }
    _ = core.dafsaAddN(d, "a\x00z");
    return d;
}

fn buildDenseCorpus() ?*Dafsa {
    const d = dafsa_mod.dafsaCreate() orelse return null;
    _ = core.dafsaAddN(d, "");
    var key: [MAX_WORD_LEN]u8 = undefined;
    var i: u32 = 0;
    while (i <= 200) : (i += 1) {
        key[0] = 'a';
        key[1] = @intCast(i);
        @memset(key[2 .. 2 + i], 'b');
        _ = core.dafsaAddN(d, key[0 .. 2 + i]);
    }
    _ = core.dafsaAddN(d, "a\x00");
    _ = core.dafsaAddN(d, "a\x00c");
    return d;
}

fn writeFileBytes(path: [:0]const u8, bytes: []const u8) !void {
    const fd = try std.posix.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + off, bytes.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => continue,
            else => {
                _ = linux.close(fd);
                return error.WriteFailed;
            },
        }
    }
    _ = linux.close(fd);
}

fn readFileBytes(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    const fd = try std.posix.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = linux.close(fd);
    var sb: linux.Statx = undefined;
    const srx = linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &sb);
    if (linux.errno(srx) != .SUCCESS) return error.StatFailed;
    const buf = try allocator.alloc(u8, @intCast(sb.size));
    errdefer allocator.free(buf);
    var got: usize = 0;
    while (got < buf.len) {
        const nr = try std.posix.read(fd, buf[got..]);
        if (nr == 0) break;
        got += nr;
    }
    return buf[0..got];
}

fn testPath(allocator: std.mem.Allocator, name: []const u8) ![:0]u8 {
    var buf: [128]u8 = undefined;
    const s = try std.fmt.bufPrint(&buf, "/tmp/dafsa_view_test_{d}_{s}.pdwg", .{ linux.getpid(), name });
    return allocator.dupeZ(u8, s);
}

/// File layout of a saved DAFSA, read independently of view.zig: header fields,
/// the CSR start (skipping the optional persisted table), and the CSR length.
const Layout = struct {
    version: u32,
    flags: u32,
    n_states: u32,
    n_trans: u32,
    ntbl_off: usize = 28,
    csr_off: usize,
    csr_len: usize,
};

fn parseLayout(bytes: []const u8) !Layout {
    if (bytes.len < 32 or !std.mem.eql(u8, bytes[0..4], "PDWG")) return error.NotPdwg;
    const version = std.mem.readInt(u32, bytes[4..8], .little);
    const n_states = std.mem.readInt(u32, bytes[8..12], .little);
    const n_trans = std.mem.readInt(u32, bytes[12..16], .little);
    const flags = std.mem.readInt(u32, bytes[24..28], .little);
    var off = 28 + 2 * (@as(usize, n_states) + 1) + (@as(usize, n_states) + 8) / 8;
    if (version >= 5 and (flags & persist.PDWG_FLAG_STATE_OFF) != 0) {
        off += (8 - off % 8) % 8;
        off += 8 * (@as(usize, n_states) + 2);
    }
    const trailer: usize = if (version >= 4) 4 else 0;
    if (bytes.len < off + trailer) return error.Truncated;
    return .{
        .version = version,
        .flags = flags,
        .n_states = n_states,
        .n_trans = n_trans,
        .csr_off = off,
        .csr_len = bytes.len - off - trailer,
    };
}

/// Independent rebuild of state_off from the file bytes: same walk the engine
/// does, but DECODING each varint (persist.mb_get_uvarint) instead of skipping
/// it, so an off-by-one in the skip logic cannot agree with it by construction.
fn independentStateOff(allocator: std.mem.Allocator, bytes: []const u8, l: Layout) ![]u64 {
    const tbl = try allocator.alloc(u64, @as(usize, l.n_states) + 2);
    errdefer allocator.free(tbl);
    @memset(tbl, 0);
    const ntbl = bytes[l.ntbl_off..];
    var cur: []const u8 = bytes[l.csr_off .. l.csr_off + l.csr_len];
    var total: u64 = 0;
    var i: u32 = 1;
    while (i <= l.n_states) : (i += 1) {
        const nt = @as(u16, @intCast(ntbl[@as(usize, i) * 2])) |
            (@as(u16, @intCast(ntbl[@as(usize, i) * 2 + 1])) << 8);
        tbl[@intCast(i)] = cur.ptr - bytes[l.csr_off ..].ptr;
        var j: u32 = 0;
        while (j < nt) : (j += 1) {
            if (cur.len == 0) return error.Truncated;
            cur = cur[1..];
            var tgt: u32 = undefined;
            if (!persist.mb_get_uvarint(&cur, &tgt)) return error.Truncated;
            if (tgt > l.n_states) return error.BadTarget;
            total += 1;
        }
    }
    tbl[@as(usize, l.n_states) + 1] = cur.ptr - bytes[l.csr_off ..].ptr;
    if (total != l.n_trans) return error.BadCount;
    return tbl;
}

/// Re-serialize a v5 file the way a pre-v5 writer wrote it: version=4, no
/// flags, no pad/table, the same state table/bitmap/CSR, then a v4 trailer.
fn stripToV4(allocator: std.mem.Allocator, v5: []const u8) ![]u8 {
    const l = try parseLayout(v5);
    if (l.version < 5) return error.NotV5;
    const pre_table = 28 + 2 * (@as(usize, l.n_states) + 1) + (@as(usize, l.n_states) + 8) / 8;
    const out = try allocator.alloc(u8, pre_table + l.csr_len + 4);
    errdefer allocator.free(out);
    @memcpy(out[0..pre_table], v5[0..pre_table]);
    std.mem.writeInt(u32, out[4..8], 4, .little); // version
    std.mem.writeInt(u32, out[24..28], 0, .little); // no flags
    @memcpy(out[pre_table .. pre_table + l.csr_len], v5[l.csr_off .. l.csr_off + l.csr_len]);
    const crc = crc32.compute(out[0 .. pre_table + l.csr_len]);
    std.mem.writeInt(u32, out[pre_table + l.csr_len ..][0..4], crc, .little);
    return out;
}

// Digest of an enumeration: FNV-1a over (len, payload) pairs, so two views
// agree only if they produce the SAME payloads in the same order.
const EnumDigest = struct {
    count: i64 = 0, // filled by the enumerator's out-param, not by cb()
    h: u64 = FNV_OFFSET,

    fn cb(payload: []const u8, user: ?*anyopaque) i32 {
        const self: *EnumDigest = @ptrCast(@alignCast(user.?));
        self.h ^= payload.len;
        self.h *%= FNV_PRIME;
        for (payload) |b| {
            self.h ^= b;
            self.h *%= FNV_PRIME;
        }
        return 0;
    }
};

fn digestAll(v: *const DafsaView) EnumDigest {
    var dg: EnumDigest = .{};
    var buf: [MAX_WORD_LEN]u8 = undefined;
    _ = viewEnumDfs(v, v.initial, &buf, 0, EnumDigest.cb, &dg, &dg.count);
    return dg;
}

/// Save `d`, then assert that the view's state_off equals an INDEPENDENT parse
/// of the same bytes and that both the persisted-table path and the rebuilt
/// path (the same content re-serialized as a pre-v5 file) answer identically.
fn checkBothPaths(allocator: std.mem.Allocator, d: *Dafsa, name: []const u8, want_table: bool) !void {
    const path = try testPath(allocator, name);
    defer allocator.free(path);
    defer _ = linux.unlinkat(linux.AT.FDCWD, path, 0);
    try testing.expectEqual(@as(i32, 0), persist.dafsaSave(d, path));

    const bytes = try readFileBytes(allocator, path);
    defer allocator.free(bytes);
    const l = try parseLayout(bytes);
    try testing.expectEqual(@as(u32, 5), l.version);
    try testing.expectEqual(@as(u32, if (want_table) persist.PDWG_FLAG_STATE_OFF else 0), l.flags);

    const v = dafsaViewOpen(path) orelse return error.OpenFailed;
    defer dafsaViewClose(v);
    // The writer's threshold decides which path this file takes.
    try testing.expectEqual(want_table, !v.state_off_owned);
    if (want_table) {
        // aliases the mapping, 8-aligned, no allocation
        try testing.expect(@intFromPtr(v.state_off.ptr) >= @intFromPtr(v.map.ptr));
        try testing.expect(@intFromPtr(v.state_off.ptr) < @intFromPtr(v.map.ptr) + v.map.len);
        try testing.expect(@intFromPtr(v.state_off.ptr) % 8 == 0);
    }

    // The offsets must equal an independent walk of the same bytes.
    const want = try independentStateOff(allocator, bytes, l);
    defer allocator.free(want);
    try testing.expectEqualSlices(u64, want, v.state_off);

    // Same content as a pre-v5 file => the rebuild path; identical table.
    const v4_bytes = try stripToV4(allocator, bytes);
    defer allocator.free(v4_bytes);
    const v4_path = try testPath(allocator, "stripped");
    defer allocator.free(v4_path);
    defer _ = linux.unlinkat(linux.AT.FDCWD, v4_path, 0);
    try writeFileBytes(v4_path, v4_bytes);
    const v4v = dafsaViewOpen(v4_path) orelse return error.OpenFailed;
    defer dafsaViewClose(v4v);
    try testing.expect(v4v.state_off_owned);
    try testing.expectEqualSlices(u64, v.state_off, v4v.state_off);
    const a = digestAll(v);
    const b = digestAll(v4v);
    try testing.expectEqual(a.count, b.count);
    try testing.expectEqual(a.h, b.h);
    try testing.expect(a.count > 0);

    // Every key the DAFSA holds must be found identically through both.
    var key: [MAX_WORD_LEN]u8 = undefined;
    var i: u32 = 0;
    while (i <= 200) : (i += 1) {
        key[0] = 'a';
        key[1] = @intCast(i);
        @memset(key[2 .. 2 + i], 'b');
        try testing.expectEqual(dafsaViewLookupN(v, key[0 .. 2 + i]), dafsaViewLookupN(v4v, key[0 .. 2 + i]));
    }
    try testing.expectEqual(@as(i32, 0), dafsaViewLookupN(v, "definitely-absent"));
}

test "state_off: persisted table (wide corpus) == independent parse == rebuilt" {
    const allocator = testing.allocator;
    const d = buildWideCorpus() orelse return error.OutOfMemory;
    defer dafsa_mod.dafsaFree(d);
    try checkBothPaths(allocator, d, "wide", true);
}

test "state_off: state-dense corpus gets no table and the rebuild matches" {
    const allocator = testing.allocator;
    const d = buildDenseCorpus() orelse return error.OutOfMemory;
    defer dafsa_mod.dafsaFree(d);
    try checkBothPaths(allocator, d, "dense", false);
}

test "integrity: a corrupt CSR byte is rejected by the fused CRC pass" {
    const allocator = testing.allocator;
    const d = buildWideCorpus() orelse return error.OutOfMemory;
    defer dafsa_mod.dafsaFree(d);

    const path = try testPath(allocator, "corrupt");
    defer allocator.free(path);
    defer _ = linux.unlinkat(linux.AT.FDCWD, path, 0);
    try testing.expectEqual(@as(i32, 0), persist.dafsaSave(d, path));

    const good = try readFileBytes(allocator, path);
    defer allocator.free(good);
    const l = try parseLayout(good);

    // (a) table-bearing file, corrupt one CSR byte
    {
        const bad = try allocator.dupe(u8, good);
        defer allocator.free(bad);
        bad[l.csr_off + l.csr_len / 2] ^= 0x01;
        try writeFileBytes(path, bad);
        try testing.expect(dafsaViewOpen(path) == null);
    }
    // (b) table-bearing file, corrupt one byte of the persisted table
    {
        const bad = try allocator.dupe(u8, good);
        defer allocator.free(bad);
        const tbl_off = 28 + 2 * (@as(usize, l.n_states) + 1) + (@as(usize, l.n_states) + 8) / 8;
        const aligned = tbl_off + (8 - tbl_off % 8) % 8;
        bad[aligned + 8 * 3] ^= 0x01; // low byte of state 3's offset
        try writeFileBytes(path, bad);
        try testing.expect(dafsaViewOpen(path) == null);
    }
    // (c) the same corruption in a table-less (pre-v5) file: the walk folds the
    //     CSR into the CRC, so it must be rejected there too.
    {
        const v4_bytes = try stripToV4(allocator, good);
        defer allocator.free(v4_bytes);
        const l4 = try parseLayout(v4_bytes);
        v4_bytes[l4.csr_off + l4.csr_len / 2] ^= 0x01;
        try writeFileBytes(path, v4_bytes);
        try testing.expect(dafsaViewOpen(path) == null);
    }
    // (d) untouched file still opens
    try writeFileBytes(path, good);
    const v = dafsaViewOpen(path) orelse return error.OpenFailed;
    dafsaViewClose(v);
}

test "degenerate: empty DAFSA and single-key DAFSA" {
    const allocator = testing.allocator;
    const cases = [_]struct { name: []const u8, key: ?[]const u8 }{
        .{ .name = "empty", .key = null },
        .{ .name = "single", .key = "k" },
    };
    for (cases) |c| {
        const d = dafsa_mod.dafsaCreate() orelse return error.OutOfMemory;
        defer dafsa_mod.dafsaFree(d);
        if (c.key) |k| _ = core.dafsaAddN(d, k);

        const path = try testPath(allocator, c.name);
        defer allocator.free(path);
        defer _ = linux.unlinkat(linux.AT.FDCWD, path, 0);
        try testing.expectEqual(@as(i32, 0), persist.dafsaSave(d, path));

        const bytes = try readFileBytes(allocator, path);
        defer allocator.free(bytes);
        const l = try parseLayout(bytes);
        // tiny files are state-dense: no table, the rebuild is trivial
        try testing.expectEqual(@as(u32, 0), l.flags);

        const v = dafsaViewOpen(path) orelse return error.OpenFailed;
        defer dafsaViewClose(v);
        try testing.expect(v.state_off_owned);
        try testing.expectEqual(@as(u64, l.csr_len), v.state_off[v.n_states + 1]);
        const want = try independentStateOff(allocator, bytes, l);
        defer allocator.free(want);
        try testing.expectEqualSlices(u64, want, v.state_off);
        if (c.key) |k| {
            try testing.expectEqual(@as(i32, 1), dafsaViewLookupN(v, k));
        }
        try testing.expectEqual(@as(i32, 0), dafsaViewLookupN(v, "absent"));

        // and through the mutable loader too
        const loaded = persist.dafsaLoad(path) orelse return error.LoadFailed;
        defer dafsa_mod.dafsaFree(loaded);
        if (c.key) |k| try testing.expectEqual(@as(i32, 1), core.dafsaLookupN(loaded, k));
        try testing.expectEqual(@as(i32, 0), core.dafsaLookupN(loaded, "absent"));
    }
}
