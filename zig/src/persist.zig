// persist.zig — PDWG v4 serialization primitives (mirrors dafsa_persist.c)
// Byte layout: little-endian, LEB128 varints, trailing CRC32 (v4)

const std = @import("std");
const crc32 = @import("crc32.zig");
const internal = @import("internal.zig");
const state = @import("state.zig");
const core = @import("core.zig");
const dafsa_mod = @import("dafsa.zig");
const Dafsa = internal.Dafsa;
const State = internal.State;
const Edge = internal.Edge;

const linux = std.os.linux;

// PDWG v4 magic and constants
const PDWG_MAGIC = [_]u8{ 'P', 'D', 'W', 'G' };
const PDWG_VERSION: u32 = 4;

// Put helpers: append to ArrayList(u8) with streaming CRC32

pub fn put_u8(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u8, crc: ?*u32) void {
    list.append(allocator, value) catch @panic("OOM");
    if (crc) |c| {
        c.* = crc32.table[(c.* ^ @as(u32, @intCast(value))) & 0xFF] ^ (c.* >> 8);
    }
}

pub fn put_u16_le(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u16, crc: ?*u32) void {
    put_u8(list, allocator, @as(u8, @intCast(value & 0xFF)), crc);
    put_u8(list, allocator, @as(u8, @intCast((value >> 8) & 0xFF)), crc);
}

pub fn put_u32_le(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32, crc: ?*u32) void {
    var v = value;
    for (0..4) |_| {
        put_u8(list, allocator, @as(u8, @intCast(v & 0xFF)), crc);
        v >>= 8;
    }
}

pub fn put_uvarint(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32, crc: ?*u32) void {
    // LEB128
    var v = value;
    while (true) {
        const byte = @as(u8, @intCast(v & 0x7F));
        v >>= 7;
        if (v != 0) {
            put_u8(list, allocator, byte | 0x80, crc);
        } else {
            put_u8(list, allocator, byte, crc);
            break;
        }
    }
}

// Memory-buffer (cursor) get helpers over []const u8
// Return: true on success, false on EOF/overflow

pub fn mb_get_u8(cursor: *[]const u8, out: *u8) bool {
    if (cursor.*.len == 0) return false;
    out.* = cursor.*[0];
    cursor.* = cursor.*[1..];
    return true;
}

pub fn mb_get_u16_le(cursor: *[]const u8, out: *u16) bool {
    var lo: u8 = undefined;
    var hi: u8 = undefined;
    if (!mb_get_u8(cursor, &lo)) return false;
    if (!mb_get_u8(cursor, &hi)) return false;
    out.* = @as(u16, @intCast(lo)) | (@as(u16, @intCast(hi)) << 8);
    return true;
}

pub fn mb_get_u32_le(cursor: *[]const u8, out: *u32) bool {
    var v: u32 = 0;
    var i: u5 = 0;
    while (i < 4) : (i +%= 1) {
        var b: u8 = undefined;
        if (!mb_get_u8(cursor, &b)) return false;
        v |= @as(u32, @intCast(b)) << (@as(u5, i) * 8);
    }
    out.* = v;
    return true;
}

pub fn mb_get_uvarint(cursor: *[]const u8, out: *u32) bool {
    var v: u32 = 0;
    var shift: u6 = 0; // up to 35; u5 wraps at 32, defeating the >28 guard
    while (true) {
        var b: u8 = undefined;
        if (!mb_get_u8(cursor, &b)) return false;
        const val = @as(u32, @intCast(b & 0x7F));
        v |= val << @as(u5, @intCast(shift));
        if ((b & 0x80) == 0) {
            out.* = v;
            return true;
        }
        shift += 7;
        if (shift > 28) return false; // overflow / malformed
    }
}

// ─── Low-level file I/O (raw Linux syscalls, errno-decoded) ────────────────
// Proven Zig 0.16 idioms (env-fact node zig-0.16-sandbox-stdlib-facts):
//   * open   = std.posix.openat(linux.AT.FDCWD, path, flags, mode)
//   * read   = std.posix.read(fd, buf)  (retries EINTR internally)
//   * write/fsync/ftruncate/renameat/unlinkat/close = raw linux.* + errno()
//   * path args to linux.* syscalls take [*:0]const u8 → pass a null-terminated
//     slice's ptr (the caller holds the underlying allocation).

// Write all bytes; retries on partial writes / EINTR.  Returns 0 on success.
fn writeAll(fd: i32, data: []const u8) i32 {
    var off: usize = 0;
    while (off < data.len) {
        const rc = linux.write(fd, data.ptr + off, data.len - off);
        switch (linux.errno(rc)) {
            .SUCCESS => off += rc,
            .INTR => continue,
            else => return -1,
        }
    }
    return 0;
}

// Open the directory containing `path` and fsync it, so a prior rename of a
// file into it is made durable.  Returns 0 on success, -1 on error.
// dirname(path) without modifying path: everything up to the last '/'.  Mirrors
// dafsa_persist.c fsync_dir_of (uses O_DIRECTORY + fsync(fd)).
pub fn fsyncDirOf(path: []const u8) i32 {
    if (path.len == 0) return -1;
    const allocator = std.heap.c_allocator;

    // Compute dirname: up to (not including) the last '/'.
    var dir: []const u8 = undefined;
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |idx| {
        if (idx == 0) {
            dir = "/";
        } else {
            dir = path[0..idx];
        }
    } else {
        dir = ".";
    }
    const dir_z = allocator.dupeZ(u8, dir) catch return -1;
    defer allocator.free(dir_z);

    const fd = std.posix.openat(
        linux.AT.FDCWD,
        dir_z,
        .{ .ACCMODE = .RDONLY, .DIRECTORY = true },
        0,
    ) catch return -1;
    const frc = linux.fsync(fd);
    _ = linux.close(fd);
    return if (linux.errno(frc) == .SUCCESS) 0 else -1;
}

// ─── Save: BFS-renumber reachable states 1..N, atomic tmp+fsync+rename ──────
// Port of dafsa_save (dafsa_persist.c:109-240).  `d` is const and never
// mutated.  Builds the entire byte stream into an ArrayList via the put_*
// helpers (streaming CRC32), then writes it out — byte-identical to the C
// FILE* streaming version.  Returns 0 on success, -1 on any error.

pub fn dafsaSave(d: *const Dafsa, path: []const u8) i32 {
    if (path.len == 0) return -1;
    const allocator = std.heap.c_allocator;

    // BFS from initial, renumber reachable states in BFS order 1..N.
    const n = d.nstates;
    const old_to_new = allocator.alloc(u32, n) catch return -1;
    defer allocator.free(old_to_new);
    @memset(old_to_new, 0);
    const queue = allocator.alloc(u32, n) catch return -1;
    defer allocator.free(queue);
    const visited = allocator.alloc(u8, n) catch return -1;
    defer allocator.free(visited);
    @memset(visited, 0);

    var n_reach: u32 = 0;
    var n_trans: u32 = 0;
    var n_final: u32 = 0;
    var head: usize = 0;
    var tail: usize = 0;
    queue[tail] = d.initial;
    tail += 1;
    visited[d.initial] = 1;
    while (head < tail) {
        const old = queue[head];
        head += 1;
        const s = &d.states[old];
        n_reach += 1;
        old_to_new[old] = n_reach;
        if (s.is_final != 0) n_final += 1;
        n_trans += s.ntrans;
        const arr = internal.transArrC(s);
        var j: u32 = 0;
        while (j < s.ntrans) : (j += 1) {
            const tgt = arr[j].target;
            if (visited[tgt] == 0) {
                visited[tgt] = 1;
                queue[tail] = tgt;
                tail += 1;
            }
        }
    }

    // Build the whole buffer.
    var list = std.ArrayList(u8).empty;
    defer list.deinit(allocator);
    var crc: u32 = crc32.init();

    // header: magic 'PDWG'; u32 version; n_states; n_trans; initial_id=1;
    // n_final; reserved=0
    for (PDWG_MAGIC) |b| put_u8(&list, allocator, b, &crc);
    put_u32_le(&list, allocator, PDWG_VERSION, &crc);
    put_u32_le(&list, allocator, n_reach, &crc);
    put_u32_le(&list, allocator, n_trans, &crc);
    put_u32_le(&list, allocator, 1, &crc);
    put_u32_le(&list, allocator, n_final, &crc);
    put_u32_le(&list, allocator, 0, &crc);

    // state table: (n_states+1) x u16 LE ntrans (entry 0 = 0)
    put_u16_le(&list, allocator, 0, &crc);
    {
        var i: u32 = 1;
        while (i <= n_reach) : (i += 1) {
            const s = &d.states[queue[i - 1]];
            put_u16_le(&list, allocator, @intCast(s.ntrans), &crc);
        }
    }

    // final bitmap: ceil((n_states+1)/8) bytes; bit 0 always 0
    {
        const nb = (n_reach + 8) / 8;
        var i: u32 = 0;
        while (i < nb) : (i += 1) {
            var byte: u8 = 0;
            var j: u32 = 0;
            while (j < 8) : (j += 1) {
                const idx = i * 8 + j;
                if (idx >= 1 and idx <= n_reach and d.states[queue[idx - 1]].is_final != 0)
                    byte |= @as(u8, 1) << @intCast(j);
            }
            put_u8(&list, allocator, byte, &crc);
        }
    }

    // CSR: transitions grouped by state in state-table order (sym asc)
    {
        var i: u32 = 1;
        while (i <= n_reach) : (i += 1) {
            const s = &d.states[queue[i - 1]];
            const arr = internal.transArrC(s);
            var j: u32 = 0;
            while (j < s.ntrans) : (j += 1) {
                put_u8(&list, allocator, arr[j].sym, &crc);
                put_uvarint(&list, allocator, old_to_new[arr[j].target], &crc);
            }
        }
    }

    // v4: append the trailing CRC32 (finalized; the CRC field is NOT checksummed).
    const final_crc = crc32.finalize(crc);
    put_u32_le(&list, allocator, final_crc, null);

    // atomic commit: write path.tmp, fsync, close, rename onto path.
    const tmp_path = std.fmt.allocPrint(allocator, "{s}.tmp", .{path}) catch return -1;
    defer allocator.free(tmp_path);
    const tmp_path_z = allocator.dupeZ(u8, tmp_path) catch return -1;
    defer allocator.free(tmp_path_z);
    const path_z = allocator.dupeZ(u8, path) catch return -1;
    defer allocator.free(path_z);

    const fd = std.posix.openat(
        linux.AT.FDCWD,
        tmp_path_z,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    ) catch return -1;
    if (writeAll(fd, list.items) != 0) {
        _ = linux.close(fd);
        _ = linux.unlinkat(linux.AT.FDCWD, tmp_path_z, 0);
        return -1;
    }
    const frc = linux.fsync(fd);
    _ = linux.close(fd);
    if (linux.errno(frc) != .SUCCESS) {
        _ = linux.unlinkat(linux.AT.FDCWD, tmp_path_z, 0);
        return -1;
    }
    const rrc = linux.renameat(linux.AT.FDCWD, tmp_path_z, linux.AT.FDCWD, path_z);
    if (linux.errno(rrc) != .SUCCESS) {
        _ = linux.unlinkat(linux.AT.FDCWD, tmp_path_z, 0);
        return -1;
    }
    if (fsyncDirOf(path) != 0) return -1;
    return 0;
}

// ─── Load: read whole file into memory, parse, rebuild ─────────────────────
// Port of dafsa_load_impl (dafsa_persist.c:313-493).  Reads the entire file
// into a heap buffer (functionally equivalent to the C mmap for parsing);
// reconstructs a fully mutable DAFSA for `mutable`, or skips the incoming-edge
// + register rebuild for the fast read-only load.  Returns the handle or null
// on any error (partial handle freed).

// Read the whole file into a freshly allocated buffer (caller frees).
fn readWholeFile(path_z: []const u8, allocator: std.mem.Allocator) ?[]u8 {
    const fd = std.posix.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0) catch return null;
    var cap: usize = 65536;
    var buf = allocator.alloc(u8, cap) catch {
        _ = linux.close(fd);
        return null;
    };
    var len: usize = 0;
    var chunk: [65536]u8 = undefined;
    while (true) {
        const nr = std.posix.read(fd, &chunk) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => {
                _ = linux.close(fd);
                allocator.free(buf);
                return null;
            },
        };
        if (nr == 0) break;
        if (len + nr > cap) {
            while (len + nr > cap) cap *= 2;
            buf = allocator.realloc(buf, cap) catch {
                _ = linux.close(fd);
                allocator.free(buf);
                return null;
            };
        }
        @memcpy(buf[len .. len + nr], chunk[0..nr]);
        len += nr;
    }
    _ = linux.close(fd);
    return buf[0..len];
}

pub fn dafsaLoad(path: []const u8) ?*Dafsa {
    return dafsaLoadImpl(path, true);
}

pub fn dafsaLoadReadonly(path: []const u8) ?*Dafsa {
    return dafsaLoadImpl(path, false);
}

pub fn dafsaLoadImpl(path: []const u8, mutable: bool) ?*Dafsa {
    if (path.len == 0) return null;
    const allocator = std.heap.c_allocator;
    const path_z = allocator.dupeZ(u8, path) catch return null;
    defer allocator.free(path_z);

    const buf = readWholeFile(path_z, allocator) orelse return null;
    defer allocator.free(buf);
    const fsize = buf.len;
    if (fsize == 0) return null;

    var cursor: []const u8 = buf;

    // header: magic + six u32 fields
    var magic: [4]u8 = undefined;
    if (!mb_get_u8(&cursor, &magic[0])) return null;
    if (!mb_get_u8(&cursor, &magic[1])) return null;
    if (!mb_get_u8(&cursor, &magic[2])) return null;
    if (!mb_get_u8(&cursor, &magic[3])) return null;
    if (magic[0] != 'P' or magic[1] != 'D' or magic[2] != 'W' or magic[3] != 'G') return null;

    var version: u32 = undefined;
    var n_states: u32 = undefined;
    var n_trans: u32 = undefined;
    var initial_id: u32 = undefined;
    var n_final: u32 = undefined;
    var reserved: u32 = undefined;
    if (!mb_get_u32_le(&cursor, &version)) return null;
    if (!mb_get_u32_le(&cursor, &n_states)) return null;
    if (!mb_get_u32_le(&cursor, &n_trans)) return null;
    if (!mb_get_u32_le(&cursor, &initial_id)) return null;
    if (!mb_get_u32_le(&cursor, &n_final)) return null;
    if (!mb_get_u32_le(&cursor, &reserved)) return null;
    _ = &reserved;
    if (version != 3 and version != 4) return null;
    if (initial_id != 1) return null;
    if (n_states == 0) return null;
    if (n_states > internal.DAFSA_MAX_STATES_HARD) return null;

    var d = dafsa_mod.dafsaCreate() orelse return null;
    var ok = false;
    defer if (!ok) dafsa_mod.dafsaFree(d);

    // grow states array to hold n_states+1 entries (round to power of two)
    if (@as(usize, n_states) + 1 > d.states_cap) {
        const need = @as(usize, n_states) + 1;
        var new_cap = d.states_cap;
        while (new_cap < need) new_cap *= 2;
        const new_states = allocator.realloc(d.states, new_cap) catch return null;
        for (new_states[d.states_cap..new_cap]) |*s| s.* = std.mem.zeroes(State);
        d.states = new_states;
        d.states_cap = new_cap;
    }
    d.nstates = n_states + 1;
    d.initial = 1;

    // zero sink + live states
    for (d.states[0 .. n_states + 1]) |*s| s.* = std.mem.zeroes(State);

    // state table: (n_states+1) x u16 LE ntrans (entry 0 = 0). Offsets implied.
    {
        var sink_nt: u16 = undefined;
        if (!mb_get_u16_le(&cursor, &sink_nt)) return null;
        if (sink_nt != 0) return null;
    }
    {
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) {
            var nt: u16 = undefined;
            if (!mb_get_u16_le(&cursor, &nt)) return null;
            d.states[i].ntrans = @as(u32, @intCast(nt));
        }
    }
    var running: u32 = 0;
    {
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) running += d.states[i].ntrans;
    }
    if (running != n_trans) return null;

    // final bitmap
    const bitmap_bytes = (n_states + 8) / 8;
    if (cursor.len < bitmap_bytes) return null;
    var finals: u32 = 0;
    {
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) {
            const byte = cursor[i / 8];
            if ((byte & (@as(u8, 1) << @intCast(i % 8))) != 0) {
                d.states[i].is_final = 1;
                finals += 1;
            }
        }
    }
    if (finals != n_final) return null;
    cursor = cursor[bitmap_bytes..];

    // CSR: direct copy into trans[] (already sorted, no trans_add)
    {
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) {
            const s = &d.states[i];
            if (s.ntrans > 0 and state.transReserve(s, s.ntrans) != 0) return null;
            const arr = internal.transArr(s);
            var j: u32 = 0;
            while (j < s.ntrans) : (j += 1) {
                var sym: u8 = undefined;
                var target: u32 = undefined;
                if (!mb_get_u8(&cursor, &sym)) return null;
                if (!mb_get_uvarint(&cursor, &target)) return null;
                if (target > n_states) return null; // 0 = sink, else 1..N
                arr[j].sym = sym;
                arr[j].target = target;
            }
        }
    }

    if (version == 4) {
        // v4: verify trailing CRC32 over [buf, cursor).  Stored CRC is the last
        // 4 bytes, little-endian.
        if (fsize < 32) return null;
        if (cursor.len != 4) return null; // no trailing garbage after CRC
        const covered_len = buf.len - cursor.len;
        const stored = mbGetU32LeAt(buf, fsize - 4);
        const calc = crc32.compute(buf[0..covered_len]);
        if (calc != stored) return null;
    } else {
        if (cursor.len != 0) return null; // v3: reject trailing bytes after CSR
    }

    // Rebuild incoming edges + register ONLY for a mutable handle.
    if (mutable) {
        var i: u32 = 1;
        while (i <= n_states) : (i += 1) {
            const s = &d.states[i];
            const arr = internal.transArrC(s);
            var j: u32 = 0;
            while (j < s.ntrans) : (j += 1) {
                core.incomingAdd(d, i, arr[j].sym, arr[j].target);
            }
        }
        var i_reg: u32 = 1;
        while (i_reg <= n_states) : (i_reg += 1) {
            const s = &d.states[i_reg];
            const sig = core.sigCompute(s);
            s.sig = sig;
            core.regInsert(d, sig, i_reg);
        }
    }

    ok = true;
    return d;
}

fn mbGetU32LeAt(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) |
        (@as(u32, buf[off + 1]) << 8) |
        (@as(u32, buf[off + 2]) << 16) |
        (@as(u32, buf[off + 3]) << 24);
}

// Unit tests: roundtrip + golden vectors

const testing = std.testing;

fn roundtripPutGet(comptime T: type, values: []const T, putFn: anytype, getFn: anytype) !void {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();
    for (values) |v| {
        putFn(&list, testing.allocator, v, &crc);
    }

    var cursor: []const u8 = list.items;
    for (values) |expected| {
        var got: T = undefined;
        if (!getFn(&cursor, &got)) @panic("EOF");
        try testing.expectEqual(expected, got);
    }
    try testing.expectEqual(@as(usize, 0), cursor.len);
}

fn roundtripUvarint(values: []const u32) !void {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();
    for (values) |v| {
        put_uvarint(&list, testing.allocator, v, &crc);
    }

    var cursor: []const u8 = list.items;
    for (values) |expected| {
        var got: u32 = undefined;
        if (!mb_get_uvarint(&cursor, &got)) @panic("EOF");
        try testing.expectEqual(expected, got);
    }
    try testing.expectEqual(@as(usize, 0), cursor.len);
}

test "put_u8 / mb_get_u8 roundtrip" {
    try roundtripPutGet(u8, &[_]u8{ 0, 1, 127, 255 }, put_u8, mb_get_u8);
}

test "put_u16_le / mb_get_u16_le roundtrip" {
    try roundtripPutGet(u16, &[_]u16{ 0, 1, 255, 256, 65535 }, put_u16_le, mb_get_u16_le);
}

test "put_u32_le / mb_get_u32_le roundtrip" {
    try roundtripPutGet(u32, &[_]u32{ 0, 1, 255, 256, 65535, 0xFFFFFFFF }, put_u32_le, mb_get_u32_le);
}

test "put_uvarint / mb_get_uvarint roundtrip" {
    try roundtripUvarint(&[_]u32{ 0, 1, 127, 128, 255, 256, 300, 0x7F_FF_FF_FF });
}

test "golden vectors: PDWG v4 header fields" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();

    // Magic
    for (PDWG_MAGIC) |b| {
        put_u8(&list, testing.allocator, b, &crc);
    }
    // Version
    put_u32_le(&list, testing.allocator, PDWG_VERSION, &crc);
    // n_states
    put_u32_le(&list, testing.allocator, 3, &crc);
    // n_trans
    put_u32_le(&list, testing.allocator, 5, &crc);
    // initial_id
    put_u32_le(&list, testing.allocator, 1, &crc);
    // n_final
    put_u32_le(&list, testing.allocator, 2, &crc);
    // reserved
    put_u32_le(&list, testing.allocator, 0, &crc);

    // Expected bytes (LE):
    // Magic: 'P','D','W','G' = [80, 68, 87, 71]
    // Version: 4 LE = [4,0,0,0]
    // n_states: 3 LE = [3,0,0,0]
    // n_trans: 5 LE = [5,0,0,0]
    // initial_id: 1 LE = [1,0,0,0]
    // n_final: 2 LE = [2,0,0,0]
    // reserved: 0 LE = [0,0,0,0]
    const expected = [_]u8{
        80, 68, 87, 71,
        4, 0, 0, 0,
        3, 0, 0, 0,
        5, 0, 0, 0,
        1, 0, 0, 0,
        2, 0, 0, 0,
        0, 0, 0, 0,
    };

    try testing.expectEqualSlices(u8, &expected, list.items);
}

test "golden vectors: uvarint edge cases" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();

    // Write 0, 1, 127, 128, 300, 0xFFFFFFFF
    put_uvarint(&list, testing.allocator, 0, &crc);
    put_uvarint(&list, testing.allocator, 1, &crc);
    put_uvarint(&list, testing.allocator, 127, &crc);
    put_uvarint(&list, testing.allocator, 128, &crc);
    put_uvarint(&list, testing.allocator, 300, &crc);
    put_uvarint(&list, testing.allocator, 0xFFFFFFFF, &crc);

    // Expected LEB128 bytes:
    // 0 = 0x00
    // 1 = 0x01
    // 127 = 0x7F
    // 128 = 0x80 0x01 (LEB128: 10000000 00000001)
    // 300 = 0xAC 0x02 (LEB128: 10101100 00000010)
    // 0xFFFFFFFF = 0xFF 0xFF 0xFF 0xFF 0x0F (five LEB128 bytes)
    const expected = [_]u8{ 0, 1, 127, 0x80, 0x01, 0xAC, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F };
    try testing.expectEqualSlices(u8, &expected, list.items);
}

test "golden vectors: mixed types roundtrip" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();

    // Write a mix: u8, u16, u32, uvarint
    put_u8(&list, testing.allocator, 42, &crc);
    put_u16_le(&list, testing.allocator, 0xBEEF, &crc);
    put_u32_le(&list, testing.allocator, 0xDEADBEEF, &crc);
    put_uvarint(&list, testing.allocator, 12345, &crc);

    // Read back
    var cursor: []const u8 = list.items;
    var v8: u8 = undefined;
    var v16: u16 = undefined;
    var v32: u32 = undefined;
    var vvar: u32 = undefined;

    if (!mb_get_u8(&cursor, &v8)) @panic("EOF");
    try testing.expectEqual(42, v8);
    if (!mb_get_u16_le(&cursor, &v16)) @panic("EOF");
    try testing.expectEqual(0xBEEF, v16);
    if (!mb_get_u32_le(&cursor, &v32)) @panic("EOF");
    try testing.expectEqual(0xDEADBEEF, v32);
    if (!mb_get_uvarint(&cursor, &vvar)) @panic("EOF");
    try testing.expectEqual(12345, vvar);
    try testing.expectEqual(@as(usize, 0), cursor.len);
}

test "CRC32 streaming matches compute" {
    var list = std.ArrayList(u8).empty;
    defer list.deinit(testing.allocator);

    var crc: u32 = crc32.init();

    // Write some bytes
    put_u8(&list, testing.allocator, 'h', &crc);
    put_u8(&list, testing.allocator, 'e', &crc);
    put_u16_le(&list, testing.allocator, 0x1234, &crc);
    put_u32_le(&list, testing.allocator, 0xDEADBEEF, &crc);

    // Finalize CRC
    const final_crc = crc32.finalize(crc);

    // Compute over the same bytes
    const expected_crc = crc32.compute(list.items);

    try testing.expectEqual(expected_crc, final_crc);
}
