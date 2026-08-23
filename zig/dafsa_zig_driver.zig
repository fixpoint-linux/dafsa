// dafsa_zig_driver.zig — Protocol driver for the op protocol (Zig engine side)
//
// U3 implements: create, free, abi, add, lookup, del, stats — mirroring the
// C oracle driver's dispatch exactly (including the `d != NULL` guard and
// the invalid-hex error results).  All other ops print '= error NOTIMPL'
// (matching the C driver's unknown-op path); later units implement them.
//
// Proven stdio idioms (see crc32_zig_driver.zig + env-fact node
// zig-0.16-sandbox-stdlib-facts):
//   - read ALL of stdin via std.posix.read(0,...) loop into a growing buffer,
//     then split into lines (newline scan starts at pos, NOT 0);
//   - emit stdout via std.os.linux.write(1,...) (NOT std.debug.print -> stderr).

const std = @import("std");

const internal = @import("src/internal.zig");
const dafsa_mod = @import("src/dafsa.zig");
const core = @import("src/core.zig");
const dafsa_build = @import("src/dafsa_build.zig");
const persist = @import("src/persist.zig");
const view_mod = @import("src/view.zig");
const wal = @import("src/wal.zig");
const rank_mod = @import("src/rank.zig");
const view_rank = @import("src/view_rank.zig");
const state_mod = @import("src/state.zig");
const Dafsa = internal.Dafsa;
const DafsaStatsOut = internal.DafsaStatsOut;

fn writeStdout(s: []const u8) !void {
    const linux = std.os.linux;
    var written: usize = 0;
    while (written < s.len) {
        const rc = linux.write(1, s.ptr + written, s.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}

// ─── Hex key parsing (mirrors dafsa_c_driver.c:12-32) ───────────────────────
//
// "" → valid empty key (len 0).  Odd length or non-hex char → invalid.
// Accepts both upper- and lower-case hex (C isxdigit + tolower equivalent).
// Returns the parsed buffer (caller frees) or null on invalid.

fn isHexDigit(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn hexVal(c: u8) u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10; // uppercase
}

const ParsedKey = struct {
    valid: bool,
    buf: []u8, // owned by the parser's allocator; len 0 for empty key
};

fn parseHexKey(allocator: std.mem.Allocator, s: []const u8) ParsedKey {
    if (s.len == 0) {
        // valid empty key; allocate a zero-length slice so free is uniform.
        const empty = allocator.alloc(u8, 0) catch return .{ .valid = false, .buf = &.{} };
        return .{ .valid = true, .buf = empty };
    }
    if (s.len % 2 != 0) return .{ .valid = false, .buf = &.{} };
    const n = s.len / 2;
    const buf = allocator.alloc(u8, n) catch return .{ .valid = false, .buf = &.{} };
    for (0..n) |i| {
        const hi = s[2 * i];
        const lo = s[2 * i + 1];
        if (!isHexDigit(hi) or !isHexDigit(lo)) {
            allocator.free(buf);
            return .{ .valid = false, .buf = &.{} };
        }
        buf[i] = (hexVal(hi) << 4) | hexVal(lo);
    }
    return .{ .valid = true, .buf = buf };
}

// ─── view ops (U6) ──────────────────────────────────────────────────────────
// vprefix payload collector: mirrors the C driver's vpfx_cb (accumulates hex
// payload lines so we can print the count line first, then the payload lines).
const VpfxCtx = struct {
    allocator: std.mem.Allocator,
    lines: *std.ArrayList([]u8), // each owned hex string
};

fn vpfxCb(payload: []const u8, user: ?*anyopaque) i32 {
    const ctx: *VpfxCtx = @ptrCast(@alignCast(user.?));
    const hexdigits = "0123456789abcdef";
    const buf = ctx.allocator.alloc(u8, payload.len * 2) catch return 1;
    for (payload, 0..) |b, i| {
        buf[i * 2] = hexdigits[b >> 4];
        buf[i * 2 + 1] = hexdigits[b & 0x0f];
    }
    ctx.lines.append(ctx.allocator, buf) catch {
        ctx.allocator.free(buf);
        return 1;
    };
    return 0;
}

fn vpfxFreeLines(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8)) void {
    for (lines.items) |l| allocator.free(l);
    lines.clearRetainingCapacity();
}

// ─── WAL ops (U7) ───────────────────────────────────────────────────────────
// wreplay collector: mirrors the C driver's wreplay_cb (builds "<op> <hex>\n"
// payload lines so we can print the count line first, then the payload lines).
const WreplayCtx = struct {
    allocator: std.mem.Allocator,
    lines: *std.ArrayList([]u8),
};

fn wreplayCb(op: u8, key: []const u8, user: ?*anyopaque) i32 {
    const ctx: *WreplayCtx = @ptrCast(@alignCast(user.?));
    const hexdigits = "0123456789abcdef";
    // line = "<op> " + hex (op is ADD=1 or DEL=2)
    const buf = ctx.allocator.alloc(u8, key.len * 2 + 2) catch return 1;
    buf[0] = if (op == 1) '1' else '2';
    buf[1] = ' ';
    for (key, 0..) |b, i| {
        buf[2 + i * 2] = hexdigits[b >> 4];
        buf[2 + i * 2 + 1] = hexdigits[b & 0x0f];
    }
    ctx.lines.append(ctx.allocator, buf) catch {
        ctx.allocator.free(buf);
        return 1;
    };
    return 0;
}

fn wrepFreeLines(allocator: std.mem.Allocator, lines: *std.ArrayList([]u8)) void {
    for (lines.items) |l| allocator.free(l);
    lines.clearRetainingCapacity();
}

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.page_allocator;

    // Workdir = argv[1], like the C oracle driver (setenv WORKDIR=argv[1]).
    const workdir: []const u8 = if (init.args.vector.len >= 2)
        std.mem.sliceTo(init.args.vector[1], 0)
    else
        ".";

    // Growing buffer for the full stdin contents.
    var cap: usize = 65536;
    var data: []u8 = try allocator.alloc(u8, cap);
    defer allocator.free(data);
    var len: usize = 0;

    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(0, &chunk) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };
        if (n == 0) break; // EOF
        if (len + n > cap) {
            while (len + n > cap) cap *= 2;
            data = try allocator.realloc(data, cap);
        }
        @memcpy(data[len .. len + n], chunk[0..n]);
        len += n;
    }

    var d: ?*Dafsa = null;
    var g_view: ?*view_mod.DafsaView = null;
    var g_wal: ?*wal.Wal = null;
    var g_from_state: u32 = 0; // rank/select/rancount start state (0 = use initial)
    var vpfx_lines = std.ArrayList([]u8).empty;
    var wrep_lines = std.ArrayList([]u8).empty;
    var line_buf: [256]u8 = undefined; // ample for result lines

    // ─── build op state (Daciuk bulk construction) ─────────────────────────
    // Grammar (op_protocol.md): 'buildbegin' / 'bkey HEX'* / 'buildend' →
    // '= build 1|0'.  Collected keys feed dafsa_build_sorted (which requires a
    // SORTED, DEDUPLICATED list).  On success the handle REPLACES the current
    // one — mirrors dafsa_c_driver.c exactly (incl. '= build 0' on invalid hex
    // or a NULL build result, and '= build 1' even for an empty key list).
    var build_keys = std.ArrayList([]u8).empty;
    var build_active = false;
    var build_valid = true;

    // Faithful fgets(line, 4096) emulation: the C oracle driver reads stdin
    // via `char line[4096]; fgets(line, sizeof(line), stdin)`, which returns
    // at most 4095 chars per call, stopping at a newline (included) or at the
    // 4095-char limit (whichever first).  A logical line longer than 4095 chars
    // is therefore split into multiple driver "lines" — long keys (≥2046
    // bytes, hex ≥4092 chars + "add ") get truncated and re-dispatched by the
    // C driver.  To stay byte-faithful to the oracle on EVERY input (incl. the
    // S7 long-key / 4097-rejection case), the Zig driver replicates this exact
    // chunking: each "line" is ≤4095 chars; a newline is consumed only when it
    // falls strictly within the 4095-char window.
    const FGETS_CAP: usize = 4095; // fgets reads at most size-1 = 4095 chars
    var pos: usize = 0;
    while (pos < len) {
        var end: usize = pos;
        while (end < len and (end - pos) < FGETS_CAP and data[end] != '\n') : (end += 1) {}
        const chunk_len = end - pos;
        const newline_in_window = (end < len and data[end] == '\n' and chunk_len < FGETS_CAP);
        const line_slice: []u8 = if (newline_in_window) blk: {
            // newline within the 4095-char window: fgets includes it, driver strips it
            const l = data[pos..end];
            pos = end + 1; // consume newline
            break :blk l;
        } else blk: {
            // EOF, or chunk full at 4095 chars (no newline in this window) —
            // the newline (if any at data[end]) is left for the next chunk,
            // exactly like fgets hitting its size limit mid-line.
            const l = data[pos..end];
            pos = end;
            break :blk l;
        };

        // Trim leading whitespace (mirrors C driver's isspace skip).
        var p: usize = 0;
        while (p < line_slice.len and std.ascii.isWhitespace(line_slice[p])) p += 1;
        if (p >= line_slice.len) continue; // empty line
        const line = line_slice[p..];

        if (std.mem.eql(u8, line, "buildbegin")) {
            // reset collected keys, start a build block
            for (build_keys.items) |k| allocator.free(k);
            build_keys.clearRetainingCapacity();
            build_valid = true;
            build_active = true;
        } else if (build_active and std.mem.startsWith(u8, line, "bkey ")) {
            const arg = line[5..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                build_valid = false;
            } else {
                if (build_valid) {
                    build_keys.append(allocator, pk.buf) catch {
                        allocator.free(pk.buf);
                        build_valid = false;
                    };
                } else {
                    allocator.free(pk.buf);
                }
            }
        } else if (std.mem.eql(u8, line, "buildend")) {
            const ok = build_valid;
            build_active = false;
            var nd: ?*Dafsa = null;
            if (ok) {
                nd = dafsa_build.dafsaBuildSorted(build_keys.items);
            }
            for (build_keys.items) |k| allocator.free(k);
            build_keys.clearRetainingCapacity();
            if (nd == null) {
                try writeStdout("= build 0\n");
            } else {
                if (d) |old| dafsa_mod.dafsaFree(old);
                d = nd;
                try writeStdout("= build 1\n");
            }
        } else if (std.mem.eql(u8, line, "create")) {
            d = dafsa_mod.dafsaCreate();
            try writeStdout(if (d != null) "= create 1\n" else "= create 0\n");
        } else if (std.mem.eql(u8, line, "free")) {
            dafsa_mod.dafsaFree(d);
            d = null;
            try writeStdout("= free 1\n");
        } else if (std.mem.startsWith(u8, line, "vopen ")) {
            const arg = line[6..];
            const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                try writeStdout("= vopen 0\n");
                continue;
            };
            defer allocator.free(path);
            const nv = view_mod.dafsaViewOpen(path);
            if (nv == null) {
                try writeStdout("= vopen 0\n");
            } else {
                if (g_view) |old| view_mod.dafsaViewClose(old);
                g_view = nv;
                try writeStdout("= vopen 1\n");
            }
        } else if (std.mem.startsWith(u8, line, "vlookup ")) {
            const arg = line[8..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                try writeStdout("= vlookup 0\n");
            } else {
                const rc = if (g_view) |v| view_mod.dafsaViewLookupN(v, pk.buf) else 0;
                const out = try std.fmt.bufPrint(&line_buf, "= vlookup {d}\n", .{rc});
                try writeStdout(out);
                allocator.free(pk.buf);
            }
        } else if (std.mem.startsWith(u8, line, "vprefix ")) {
            const arg = line[8..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                try writeStdout("= vprefix 0\n");
            } else {
                vpfxFreeLines(allocator, &vpfx_lines);
                var vctx = VpfxCtx{ .allocator = allocator, .lines = &vpfx_lines };
                const count = if (g_view) |v|
                    view_mod.dafsaViewPrefixEnum(v, pk.buf, vpfxCb, &vctx)
                else
                    0;
                const out = try std.fmt.bufPrint(&line_buf, "= vprefix {d}\n", .{count});
                try writeStdout(out);
                for (vpfx_lines.items) |l| {
                    try writeStdout(l);
                    try writeStdout("\n");
                }
                vpfxFreeLines(allocator, &vpfx_lines);
                allocator.free(pk.buf);
            }
        } else if (std.mem.startsWith(u8, line, "vrank ")) {
            const arg = line[6..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                try writeStdout("= vrank 0\n");
            } else {
                const r: u64 = if (g_view) |v| view_rank.dafsaViewRankN(v, pk.buf) else 0;
                const out = try std.fmt.bufPrint(&line_buf, "= vrank {d}\n", .{r});
                try writeStdout(out);
                allocator.free(pk.buf);
            }
        } else if (std.mem.startsWith(u8, line, "vselect ")) {
            const arg = line[8..];
            const k: u64 = std.fmt.parseInt(u64, arg, 10) catch 0;
            var key_out: [4096]u8 = undefined;
            const r: i32 = if (g_view) |v|
                view_rank.dafsaViewSelectN(v, k, key_out[0..])
            else
                -1;
            if (r < 0) {
                try writeStdout("= vselect -1\n");
            } else {
                var buf: [8192]u8 = undefined;
                const header = try std.fmt.bufPrint(&buf, "= vselect {d} ", .{r});
                var o: usize = header.len;
                const hexdigits = "0123456789abcdef";
                for (key_out[0..@intCast(r)]) |b| {
                    buf[o] = hexdigits[b >> 4];
                    buf[o + 1] = hexdigits[b & 0x0f];
                    o += 2;
                }
                buf[o] = '\n';
                o += 1;
                try writeStdout(buf[0..o]);
            }
        } else if (std.mem.startsWith(u8, line, "vrancount ")) {
            const args = line[10..];
            const sp = std.mem.indexOfScalar(u8, args, ' ') orelse {
                try writeStdout("= vrc 0\n");
                continue;
            };
            const lo_arg = args[0..sp];
            const hi_arg = args[sp + 1 ..];
            const lo = parseHexKey(allocator, lo_arg);
            defer if (lo.valid) allocator.free(lo.buf);
            const hi = parseHexKey(allocator, hi_arg);
            defer if (hi.valid) allocator.free(hi.buf);
            if (!lo.valid or !hi.valid) {
                try writeStdout("= vrc 0\n");
            } else {
                const r: u64 = if (g_view) |v| view_rank.dafsaViewRangeCountN(v, lo.buf, hi.buf) else 0;
                const out = try std.fmt.bufPrint(&line_buf, "= vrc {d}\n", .{r});
                try writeStdout(out);
            }
        } else if (std.mem.eql(u8, line, "vclose")) {
            if (g_view) |v| view_mod.dafsaViewClose(v);
            g_view = null;
            try writeStdout("= vclose\n");
        } else if (std.mem.eql(u8, line, "wclose")) {
            if (g_wal) |w| wal.dafsaWalClose(w);
            g_wal = null;
            try writeStdout("= wclose\n");
        } else if (std.mem.startsWith(u8, line, "wopen ")) {
            const arg = line[6..];
            const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                try writeStdout("= wopen 0\n");
                continue;
            };
            defer allocator.free(path);
            const nw = wal.dafsaWalOpenRw(path);
            if (nw == null) {
                try writeStdout("= wopen 0\n");
            } else {
                if (g_wal) |w| wal.dafsaWalClose(w);
                g_wal = nw;
                try writeStdout("= wopen 1\n");
            }
        } else if (std.mem.startsWith(u8, line, "wopenro ")) {
            const arg = line[8..];
            const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                try writeStdout("= wopenro 0\n");
                continue;
            };
            defer allocator.free(path);
            const nw = wal.dafsaWalOpenRo(path);
            if (nw == null) {
                try writeStdout("= wopenro 0\n");
            } else {
                if (g_wal) |w| wal.dafsaWalClose(w);
                g_wal = nw;
                try writeStdout("= wopenro 1\n");
            }
        } else if (std.mem.startsWith(u8, line, "wadd ")) {
            const arg = line[5..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                try writeStdout("= wadd -1\n");
            } else {
                const rc = if (g_wal) |w| wal.dafsaWalAppendAdd(w, pk.buf) else -1;
                const out = try std.fmt.bufPrint(&line_buf, "= wadd {d}\n", .{rc});
                try writeStdout(out);
                allocator.free(pk.buf);
            }
        } else if (std.mem.startsWith(u8, line, "wdel ")) {
            const arg = line[5..];
            const pk = parseHexKey(allocator, arg);
            if (!pk.valid) {
                try writeStdout("= wdel -1\n");
            } else {
                const rc = if (g_wal) |w| wal.dafsaWalAppendDel(w, pk.buf) else -1;
                const out = try std.fmt.bufPrint(&line_buf, "= wdel {d}\n", .{rc});
                try writeStdout(out);
                allocator.free(pk.buf);
            }
        } else if (std.mem.eql(u8, line, "wsize")) {
            const sz: u64 = if (g_wal) |w| wal.dafsaWalSize(w) else 0;
            const out = try std.fmt.bufPrint(&line_buf, "= wsize {d}\n", .{sz});
            try writeStdout(out);
        } else if (std.mem.eql(u8, line, "wreplay")) {
            wrepFreeLines(allocator, &wrep_lines);
            var wctx = WreplayCtx{ .allocator = allocator, .lines = &wrep_lines };
            _ = if (g_wal) |w| wal.dafsaWalReplay(w, wreplayCb, &wctx) else -1;
            const out = try std.fmt.bufPrint(&line_buf, "= wreplay {d}\n", .{wrep_lines.items.len});
            try writeStdout(out);
            for (wrep_lines.items) |l| {
                try writeStdout(l);
                try writeStdout("\n");
            }
            wrepFreeLines(allocator, &wrep_lines);
        } else if (std.mem.startsWith(u8, line, "lopen ")) {
            // two args: FST WAL
            const args = line[6..];
            const sp = std.mem.indexOfScalar(u8, args, ' ') orelse {
                try writeStdout("= lopen 0\n");
                continue;
            };
            const fst = args[0..sp];
            const warg = args[sp + 1 ..];
            const fst_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, fst }) catch {
                try writeStdout("= lopen 0\n");
                continue;
            };
            defer allocator.free(fst_path);
            const w_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, warg }) catch {
                try writeStdout("= lopen 0\n");
                continue;
            };
            defer allocator.free(w_path);
            const nv = view_mod.dafsaViewOpenLayered(fst_path, w_path);
            if (nv == null) {
                try writeStdout("= lopen 0\n");
            } else {
                if (g_view) |v| view_mod.dafsaViewClose(v);
                g_view = nv;
                try writeStdout("= lopen 1\n");
            }
        } else if (d) |dd| {
            if (std.mem.eql(u8, line, "abi")) {
                const abi = dafsa_mod.dafsaAbiVersion();
                const out = try std.fmt.bufPrint(&line_buf, "= abi {d}\n", .{abi});
                try writeStdout(out);
            } else if (std.mem.startsWith(u8, line, "add ")) {
                const arg = line[4..];
                const pk = parseHexKey(allocator, arg);
                if (!pk.valid) {
                    try writeStdout("= add -1\n");
                } else {
                    const rc = core.dafsaAddN(dd, pk.buf);
                    const out = try std.fmt.bufPrint(&line_buf, "= add {d}\n", .{rc});
                    try writeStdout(out);
                    allocator.free(pk.buf);
                }
            } else if (std.mem.startsWith(u8, line, "lookup ")) {
                const arg = line[7..];
                const pk = parseHexKey(allocator, arg);
                if (!pk.valid) {
                    try writeStdout("= lookup 0\n");
                } else {
                    const rc = core.dafsaLookupN(dd, pk.buf);
                    const out = try std.fmt.bufPrint(&line_buf, "= lookup {d}\n", .{rc});
                    try writeStdout(out);
                    allocator.free(pk.buf);
                }
            } else if (std.mem.startsWith(u8, line, "del ")) {
                const arg = line[4..];
                const pk = parseHexKey(allocator, arg);
                if (!pk.valid) {
                    try writeStdout("= del -1\n");
                } else {
                    const rc = core.dafsaDeleteN(dd, pk.buf);
                    const out = try std.fmt.bufPrint(&line_buf, "= del {d}\n", .{rc});
                    try writeStdout(out);
                    allocator.free(pk.buf);
                }
            } else if (std.mem.eql(u8, line, "stats")) {
                var st: DafsaStatsOut = .{};
                dafsa_mod.dafsaStats(dd, &st);
                const out = try std.fmt.bufPrint(&line_buf, "= stats {d} {d} {d} {d} {d}\n", .{
                    st.n_states_total, st.n_states_reachable, st.n_final, st.n_trans, st.register_probes,
                });
                try writeStdout(out);
            } else if (std.mem.startsWith(u8, line, "loadro ")) {
                const arg = line[7..];
                const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                    try writeStdout("= loadro 0\n");
                    continue;
                };
                defer allocator.free(path);
                const nd = persist.dafsaLoadReadonly(path);
                if (nd == null) {
                    try writeStdout("= loadro 0\n");
                } else {
                    dafsa_mod.dafsaFree(dd);
                    d = nd;
                    try writeStdout("= loadro 1\n");
                }
            } else if (std.mem.startsWith(u8, line, "load ")) {
                const arg = line[5..];
                const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                    try writeStdout("= load 0\n");
                    continue;
                };
                defer allocator.free(path);
                const nd = persist.dafsaLoad(path);
                if (nd == null) {
                    try writeStdout("= load 0\n");
                } else {
                    dafsa_mod.dafsaFree(dd);
                    d = nd;
                    try writeStdout("= load 1\n");
                }
            } else if (std.mem.startsWith(u8, line, "save ")) {
                const arg = line[5..];
                const path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ workdir, arg }) catch {
                    try writeStdout("= save -1\n");
                    continue;
                };
                defer allocator.free(path);
                const rc = persist.dafsaSave(dd, path);
                try writeStdout(if (rc == 0) "= save 0\n" else "= save -1\n");
            } else if (std.mem.startsWith(u8, line, "fromstate ")) {
                const arg = line[10..];
                const pk = parseHexKey(allocator, arg);
                if (!pk.valid) {
                    try writeStdout("= fromstate 0\n");
                } else {
                    var s = dd.initial;
                    var ok = true;
                    for (pk.buf) |c| {
                        const tr = state_mod.transFind(&dd.states[s], c);
                        if (tr < 0) {
                            ok = false;
                            break;
                        }
                        s = internal.transArrC(&dd.states[s])[@intCast(tr)].target;
                    }
                    if (ok and s != 0) {
                        g_from_state = s;
                        try writeStdout("= fromstate 1\n");
                    } else {
                        g_from_state = 0;
                        try writeStdout("= fromstate 0\n");
                    }
                    allocator.free(pk.buf);
                }
            } else if (std.mem.startsWith(u8, line, "rancount ")) {
                const args = line[9..];
                const sp = std.mem.indexOfScalar(u8, args, ' ') orelse {
                    try writeStdout("= rc 0\n");
                    continue;
                };
                const lo_arg = args[0..sp];
                const hi_arg = args[sp + 1 ..];
                const lo = parseHexKey(allocator, lo_arg);
                defer if (lo.valid) allocator.free(lo.buf);
                const hi = parseHexKey(allocator, hi_arg);
                defer if (hi.valid) allocator.free(hi.buf);
                if (!lo.valid or !hi.valid) {
                    try writeStdout("= rc 0\n");
                } else {
                    const r: u64 = if (g_from_state != 0)
                        rank_mod.dafsaRangeCountFrom(dd, g_from_state, lo.buf, hi.buf)
                    else
                        rank_mod.dafsaRangeCountN(dd, lo.buf, hi.buf);
                    const out = try std.fmt.bufPrint(&line_buf, "= rc {d}\n", .{r});
                    try writeStdout(out);
                }
            } else if (std.mem.startsWith(u8, line, "rank ")) {
                const arg = line[5..];
                const pk = parseHexKey(allocator, arg);
                if (!pk.valid) {
                    try writeStdout("= rank 0\n");
                } else {
                    const r: u64 = if (g_from_state != 0)
                        rank_mod.dafsaRankFrom(dd, g_from_state, pk.buf)
                    else
                        rank_mod.dafsaRankN(dd, pk.buf);
                    const out = try std.fmt.bufPrint(&line_buf, "= rank {d}\n", .{r});
                    try writeStdout(out);
                    allocator.free(pk.buf);
                }
            } else if (std.mem.startsWith(u8, line, "select ")) {
                const arg = line[7..];
                const k: u64 = std.fmt.parseInt(u64, arg, 10) catch 0;
                var key_out: [4096]u8 = undefined;
                const r: i32 = if (g_from_state != 0)
                    rank_mod.dafsaSelectFrom(dd, g_from_state, k, key_out[0..])
                else
                    rank_mod.dafsaSelectN(dd, k, key_out[0..]);
                if (r < 0) {
                    try writeStdout("= select -1\n");
                } else {
                    var buf: [8192]u8 = undefined;
                    const header = try std.fmt.bufPrint(&buf, "= select {d} ", .{r});
                    var o: usize = header.len;
                    const hexdigits = "0123456789abcdef";
                    for (key_out[0..@intCast(r)]) |b| {
                        buf[o] = hexdigits[b >> 4];
                        buf[o + 1] = hexdigits[b & 0x0f];
                        o += 2;
                    }
                    buf[o] = '\n';
                    o += 1;
                    try writeStdout(buf[0..o]);
                }
            } else {
                try writeStdout("= error NOTIMPL\n");
            }
        } else {
            try writeStdout("= error NOTIMPL\n");
        }
    }

    if (g_view) |v| view_mod.dafsaViewClose(v);
    if (g_wal) |w| wal.dafsaWalClose(w);
    if (d) |dd| dafsa_mod.dafsaFree(dd);
}
