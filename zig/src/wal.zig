// wal.zig — Write-ahead log for incremental DAFSA updates (mirrors dafsa_wal.c)
//
// Append-only self-framing record format (index.wal):
//   HEADER (16 B): magic "DAWL" | version:u32LE=1 | flags:u32LE=0 | header_crc:u32LE
//   RECORD: op:u8 | key_len:u32LE | key[key_len] | rec_crc:u32LE
//
// rec_crc = crc32(op || key_len_le || key)
// No footer. Torn tail detected by validation failure -> ftruncate.
//
// This is unit U7: replaces the U6 stub with the faithful C port.  The C record
// format uses a FIXED 4-byte LE key_len (NOT a uvarint) — byte-equality with the
// C engine is the S11 gate, so we replicate the C exactly.
//
// I/O idioms (Zig 0.16 trimmed stdlib — see env-fact node
// zig-0.16-sandbox-stdlib-facts):
//   * open   = std.posix.openat(linux.AT.FDCWD, path_z, .{flags}, mode)
//   * size   = std.os.linux.statx(fd, "", AT.EMPTY_PATH, .BASIC_STATS, &sb)
//   * mmap   = std.posix.mmap(null, len, .{.READ=true}, .{.TYPE=.PRIVATE}, fd, 0)
//   * munmap = std.posix.munmap(map)
//   * write/fsync/ftruncate/close = raw linux.* + errno() decode.

const std = @import("std");
const linux = std.os.linux;
const crc32 = @import("crc32.zig");
const internal = @import("internal.zig");

const MAX_KEY_LEN: usize = internal.MAX_WORD_LEN + 9; // 65545

const DAFSA_WAL_OP_ADD: u8 = 1;
const DAFSA_WAL_OP_DEL: u8 = 2;

// Replay callback: op (ADD/DEL), key bytes, user context. Returns 0 to
// continue, non-zero to stop.  Same contract as the C dafsa_wal_replay_cb.
pub const ReplayCb = *const fn (op: u8, key: []const u8, user: ?*anyopaque) i32;

// Opaque WAL handle (dafsa_internal.h:119): `struct dafsa_wal { int fd; uint64_t size; }`.
// extern struct: consumers (datalog-dafsa rel_compact) read ->fd / ->size
// directly off the handle returned by dafsa_wal_open*, so the field offsets
// MUST match the C struct (fd@0, size@8).  A plain `struct` lets Zig reorder
// the fields (size@0, fd@8), which silently corrupts ftruncate(w->fd, ...).
pub const Wal = extern struct {
    fd: i32,
    size: u64,
};

// ─── Shared helpers ──────────────────────────────────────────────────────

// Read a little-endian u32 from the head of `p`; null if fewer than 4 bytes.
fn readU32(p: []const u8) ?u32 {
    if (p.len < 4) return null;
    return @as(u32, p[0]) |
        (@as(u32, p[1]) << 8) |
        (@as(u32, p[2]) << 16) |
        (@as(u32, p[3]) << 24);
}

// Validate one record at `rem` (the bytes available).
// Returns:
//    0  — valid record: *op / *key / *consumed set (record length)
//   -1  — corrupt record (bad op, bad key_len, or CRC mismatch)
//   -2  — torn/partial record (not enough bytes for a complete record)
//
// This is the single validation function used everywhere — open-time scan,
// replay, and any future reader.  Mirrors wal_validate_record (dafsa_wal.c:36).
fn walValidateRecord(rem: []const u8, op: *u8, key: *[]const u8, consumed: *u32) i32 {
    // Minimum: op(1) + key_len(4) + key[1] + crc(4) = 10 bytes
    if (rem.len < 10) return -2;

    if (rem[0] != DAFSA_WAL_OP_ADD and rem[0] != DAFSA_WAL_OP_DEL) return -1;

    const klen = readU32(rem[1..]) orelse return -2;
    const k: usize = klen;
    if (klen < 1 or klen > MAX_KEY_LEN) return -1;

    if (k + 9 > rem.len) return -2; // need op(1) + klen(4) + key(k) + crc(4) = 9+k

    // Validate CRC over op(1) || key_len(4 LE) || key(k)
    const stored = readU32(rem[5 + k ..]) orelse return -2;
    const calc = crc32.compute(rem[0 .. 5 + k]);
    if (calc != stored) return -1;

    op.* = rem[0];
    key.* = rem[5 .. 5 + k];
    consumed.* = @intCast(1 + 4 + k + 4);
    return 0;
}

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

// ─── Header I/O ──────────────────────────────────────────────────────────

// Write a fresh header and fsync. Returns 0 on success, -1 on error.
fn walWriteHeader(fd: i32) i32 {
    var hdr: [16]u8 = undefined;
    hdr[0] = 'D';
    hdr[1] = 'A';
    hdr[2] = 'W';
    hdr[3] = 'L';
    hdr[4] = 1;
    hdr[5] = 0;
    hdr[6] = 0;
    hdr[7] = 0;
    hdr[8] = 0;
    hdr[9] = 0;
    hdr[10] = 0;
    hdr[11] = 0;

    const crc = crc32.compute(hdr[0..12]);
    hdr[12] = @truncate(crc);
    hdr[13] = @truncate(crc >> 8);
    hdr[14] = @truncate(crc >> 16);
    hdr[15] = @truncate(crc >> 24);

    if (writeAll(fd, &hdr) != 0) return -1;
    const frc = linux.fsync(fd);
    return if (linux.errno(frc) == .SUCCESS) 0 else -1;
}

// Validate the header at `map`.  On success, scans forward from byte 16 to
// find the first invalid/torn record and sets *good_bytes_out to the file
// offset at the START of that first bad record (safe to ftruncate to).
//
// Returns 0 on success, -1 on hard error (bad magic, bad version, or header
// CRC mismatch on a non-empty file).  Mirrors wal_validate_header (dafsa_wal.c:131).
fn walValidateHeader(map: []const u8, good_bytes_out: *usize) i32 {
    if (map.len < 16) return -1;
    if (map[0] != 'D' or map[1] != 'A' or map[2] != 'W' or map[3] != 'L') return -1;

    const version = readU32(map[4..]) orelse return -1;
    if (version != 1) return -1;

    const flags = readU32(map[8..]) orelse return -1;
    _ = flags;

    const calc = crc32.compute(map[0..12]);
    const stored = readU32(map[12..]) orelse return -1;
    if (calc != stored) return -1; // hard error on non-empty

    // Scan records from byte 16; stop at first invalid record.
    // good_bytes_out = start offset of the first bad record = truncation point.
    var p: []const u8 = map[16..];
    while (p.len > 0) {
        const before = map.len - p.len;
        var op: u8 = undefined;
        var key: []const u8 = undefined;
        var consumed: u32 = undefined;
        const rc = walValidateRecord(p, &op, &key, &consumed);
        if (rc == 0) {
            p = p[consumed..];
            continue;
        }
        // rc == -1 or -2: record is bad -> truncate at its start
        good_bytes_out.* = before;
        return 0;
    }
    good_bytes_out.* = map.len;
    return 0;
}

// fstat an open fd's size via statx on the empty path.  null on error.
fn fstatSize(fd: i32) ?usize {
    var sb: linux.Statx = undefined;
    const srx = linux.statx(fd, "", linux.AT.EMPTY_PATH, .BASIC_STATS, &sb);
    if (linux.errno(srx) != .SUCCESS) return null;
    return @intCast(sb.size);
}

// ─── WAL lifecycle ───────────────────────────────────────────────────────

// Writer-side open: O_RDWR|O_CREAT|O_APPEND.  May write a fresh header or
// ftruncate a torn tail.  Use this for update() / compact() paths only.
// Mirrors dafsa_wal_open_rw (dafsa_wal.c:179).
pub fn dafsaWalOpenRw(path: []const u8) ?*Wal {
    if (path.len == 0) return null;
    const allocator = std.heap.c_allocator;
    const path_z = allocator.dupeZ(u8, path) catch return null;
    defer allocator.free(path_z);

    var fd: i32 = -1;
    var w: ?*Wal = null;
    var map: ?[]align(std.heap.page_size_min) u8 = null;
    var ok = false;
    defer if (!ok) {
        if (fd >= 0) _ = linux.close(fd);
        if (map) |m| std.posix.munmap(m);
        if (w) |ww| allocator.destroy(ww);
    };

    fd = std.posix.openat(
        linux.AT.FDCWD,
        path_z,
        .{ .ACCMODE = .RDWR, .CREAT = true, .APPEND = true },
        0o644,
    ) catch return null;

    const fsize = fstatSize(fd) orelse return null;

    w = allocator.create(Wal) catch return null;
    w.?.fd = fd;
    w.?.size = 0;

    if (fsize == 0) {
        if (walWriteHeader(fd) != 0) return null;
        w.?.size = 16;
    } else {
        const map_slice = std.posix.mmap(null, fsize, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0) catch return null;
        map = map_slice;

        var good_bytes: usize = undefined;
        if (walValidateHeader(map_slice, &good_bytes) != 0) {
            std.posix.munmap(map_slice);
            map = null;
            // Header-only file (16 bytes) with corrupt header: a crash during
            // initial header write left garbage.  Reinitialize.
            if (fsize == 16) {
                if (linux.errno(linux.ftruncate(fd, 0)) != .SUCCESS) return null;
                if (walWriteHeader(fd) != 0) return null;
                w.?.size = 16;
                ok = true;
                return w.?;
            }
            // Non-empty file with corrupt header: hard error
            return null;
        }

        if (good_bytes < fsize) {
            if (linux.errno(linux.ftruncate(fd, @intCast(good_bytes))) != .SUCCESS) return null;
        }
        std.posix.munmap(map_slice);
        map = null;
        w.?.size = @intCast(good_bytes);
    }

    ok = true;
    return w.?;
}

// Reader-side open: O_RDONLY, no O_CREAT, never mutates the file.
// Validates the header, scans for torn tail but does NOT ftruncate — the
// self-framing record format already handles torn tails by stopping at the
// first invalid CRC.  Returns NULL if the file is missing, empty, or has a
// corrupt header.  Mirrors dafsa_wal_open_ro (dafsa_wal.c:244).
pub fn dafsaWalOpenRo(path: []const u8) ?*Wal {
    if (path.len == 0) return null;
    const allocator = std.heap.c_allocator;
    const path_z = allocator.dupeZ(u8, path) catch return null;
    defer allocator.free(path_z);

    var fd: i32 = -1;
    var w: ?*Wal = null;
    var map: ?[]align(std.heap.page_size_min) u8 = null;
    var ok = false;
    defer if (!ok) {
        if (fd >= 0) _ = linux.close(fd);
        if (map) |m| std.posix.munmap(m);
        if (w) |ww| allocator.destroy(ww);
    };

    fd = std.posix.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0) catch return null;

    const fsize = fstatSize(fd) orelse return null;
    if (fsize < 16) {
        // Too small to contain a valid header — not a usable WAL.
        return null;
    }

    w = allocator.create(Wal) catch return null;
    w.?.fd = fd;
    w.?.size = 0;

    const map_slice = std.posix.mmap(null, fsize, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0) catch return null;
    map = map_slice;

    var good_bytes: usize = undefined;
    if (walValidateHeader(map_slice, &good_bytes) != 0) {
        // Corrupt header: reader cannot repair — return error.
        return null;
    }
    std.posix.munmap(map_slice);
    map = null;
    // Remember where the valid records end; replay stops at the first invalid
    // record anyway, so a torn tail is harmless.
    w.?.size = @intCast(good_bytes);

    ok = true;
    return w.?;
}

// Back-compat alias: writer-side open (same as dafsaWalOpenRw).
pub fn dafsaWalOpen(path: []const u8) ?*Wal {
    return dafsaWalOpenRw(path);
}

// ─── Append ──────────────────────────────────────────────────────────────

// Append one record.  Mirrors wal_append_op (dafsa_wal.c:297).  key.len is the
// record key length.  Returns 0 on success, -1 on error.
fn walAppendOp(w: *Wal, op: u8, key: []const u8) i32 {
    const k: usize = key.len;
    if (k < 1 or k > MAX_KEY_LEN) return -1;

    const total = 1 + 4 + k + 4;
    const allocator = std.heap.c_allocator;
    const buf = allocator.alloc(u8, total) catch return -1;
    defer allocator.free(buf);

    buf[0] = op;
    buf[1] = @truncate(k);
    buf[2] = @truncate(k >> 8);
    buf[3] = @truncate(k >> 16);
    buf[4] = @truncate(k >> 24);
    @memcpy(buf[5 .. 5 + k], key);

    const crc = crc32.compute(buf[0 .. 5 + k]);
    buf[5 + k] = @truncate(crc);
    buf[5 + k + 1] = @truncate(crc >> 8);
    buf[5 + k + 2] = @truncate(crc >> 16);
    buf[5 + k + 3] = @truncate(crc >> 24);

    // Write via O_APPEND; writeAll retries partial writes.
    if (writeAll(w.fd, buf) != 0) return -1;

    w.size += total;
    return 0;
}

pub fn dafsaWalAppendAdd(w: *Wal, key: []const u8) i32 {
    return walAppendOp(w, DAFSA_WAL_OP_ADD, key);
}

pub fn dafsaWalAppendDel(w: *Wal, key: []const u8) i32 {
    return walAppendOp(w, DAFSA_WAL_OP_DEL, key);
}

// ─── Sync / Size ─────────────────────────────────────────────────────────

pub fn dafsaWalSync(w: *Wal) i32 {
    const frc = linux.fsync(w.fd);
    return if (linux.errno(frc) == .SUCCESS) 0 else -1;
}

pub fn dafsaWalSize(w: *const Wal) u64 {
    return w.size;
}

// ─── Replay ──────────────────────────────────────────────────────────────

// Replay all valid records to cb, stopping at the first invalid/torn record.
// Returns 0 on success, -1 on error (or if cb returned non-zero).
// Mirrors dafsa_wal_replay (dafsa_wal.c:375).
pub fn dafsaWalReplay(w: *Wal, cb: ReplayCb, user: ?*anyopaque) i32 {
    const map_size = fstatSize(w.fd) orelse return -1;
    if (map_size < 16) return -1;

    const map = std.posix.mmap(null, map_size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, w.fd, 0) catch return -1;
    defer std.posix.munmap(map);

    var p: []const u8 = map[16..];
    while (p.len > 0) {
        var op: u8 = undefined;
        var key: []const u8 = undefined;
        var consumed: u32 = undefined;
        const rc = walValidateRecord(p, &op, &key, &consumed);
        if (rc != 0) break;
        if (cb(op, key, user) != 0) return -1;
        p = p[consumed..];
    }
    return 0;
}

// ─── Close ───────────────────────────────────────────────────────────────

pub fn dafsaWalClose(w: ?*Wal) void {
    const ww = w orelse return;
    if (ww.fd >= 0) _ = linux.close(ww.fd);
    std.heap.c_allocator.destroy(ww);
}
