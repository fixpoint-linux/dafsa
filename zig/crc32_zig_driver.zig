// crc32_zig_driver.zig — Tiny Zig driver that reads stdin and prints CRC32 using crc32.zig
// Zig 0.16.0 stdio: std.io / std.fs.cwd() were removed by the async-I/O reorg.
// Version-stable idiom: std.posix.read(0, &buf) loop into a growing buffer.
const std = @import("std");
const crc32 = @import("crc32.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Growing buffer for the full stdin contents.
    var cap: usize = 65536;
    var data: []u8 = try allocator.alloc(u8, cap);
    defer allocator.free(data);
    var len: usize = 0;

    // Read stdin (fd 0) in a loop until EOF (n == 0).
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(0, &chunk) catch |err| {
            // Spurious wakeups on non-blocking fds: retry.
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

    const hash = crc32.compute(data[0..len]);
    // std.posix.write is absent in this trimmed Zig 0.16 stdlib, and
    // std.debug.print writes to stderr; the differential harness captures
    // stdout (fd 1) via `>`. Emit through the raw Linux syscall to match the
    // C driver's printf-to-stdout, decoding errno like std.posix.read does.
    var out_buf: [9]u8 = undefined;
    const out = try std.fmt.bufPrint(&out_buf, "{x:0>8}\n", .{hash});
    const linux = std.os.linux;
    var written: usize = 0;
    while (written < out.len) {
        const rc = linux.write(1, out.ptr + written, out.len - written);
        switch (linux.errno(rc)) {
            .SUCCESS => written += rc,
            .INTR => continue,
            else => return error.WriteFailed,
        }
    }
}
