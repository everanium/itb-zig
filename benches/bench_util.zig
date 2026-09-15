//! Shared config + timing + reporting helpers for the Zig binding
//! micro-benchmarks. Wall-clock via clock_gettime(CLOCK_MONOTONIC);
//! output is a fixed-width table:
//!
//!   bench             size     mb_per_sec
//!   message           1 MiB    <n>
//!   ...

const std = @import("std");
const itb = @import("itb3");

/// Iteration floor per case.
const min_iters: usize = 3;

/// Per-case wall-clock budget (seconds, env: ITB_BENCH_MIN_SEC).
pub fn minSeconds(env: *const std.process.Environ.Map) f64 {
    if (env.get("ITB_BENCH_MIN_SEC")) |raw| {
        if (raw.len > 0) {
            const v = std.fmt.parseFloat(f64, raw) catch return 5.0;
            if (v > 0.0) return v;
        }
    }
    return 5.0;
}

fn envOr(env: *const std.process.Environ.Map, key: []const u8, fallback: []const u8) []const u8 {
    if (env.get(key)) |raw| {
        if (raw.len > 0) return raw;
    }
    return fallback;
}

/// Reads the bench-shape env vars and builds an `Opts`. Defaults
/// match root Go BENCH3.md so numbers are directly comparable.
/// `arena` backs the NUL-terminated copies of env values.
pub fn buildOpts(arena: std.mem.Allocator, env: *const std.process.Environ.Map) !itb.Opts {
    const opts = try itb.Opts.init();
    errdefer opts.deinit();
    try opts.set("nonceBits", try arena.dupeZ(u8, envOr(env, "ITB_NONCE_BITS", "512")));
    try opts.set("keyBits", try arena.dupeZ(u8, envOr(env, "ITB_KEY_BITS", "1024")));
    try opts.set("withParallax", boolStr(env, "ITB_WITH_PARALLAX"));
    try opts.set("withWrapper", boolStr(env, "ITB_WITH_WRAPPER"));
    const hash = envOr(env, "ITB_INNER_HASH", "");
    if (hash.len > 0) try opts.set("innerHash", try arena.dupeZ(u8, hash));
    const mac_name = envOr(env, "ITB_MAC_NAME", "");
    if (mac_name.len > 0) try opts.set("macName", try arena.dupeZ(u8, mac_name));
    return opts;
}

fn boolStr(env: *const std.process.Environ.Map, key: []const u8) [:0]const u8 {
    const raw = envOr(env, key, "false");
    const on = std.mem.eql(u8, raw, "true") or std.mem.eql(u8, raw, "1");
    return if (on) "true" else "false";
}

/// `ITB_PROFILE` override, or the shape's fallback profile name.
pub fn profileName(
    arena: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    fallback: [:0]const u8,
) ![:0]const u8 {
    const raw = envOr(env, "ITB_PROFILE", "");
    if (raw.len == 0) return fallback;
    return arena.dupeZ(u8, raw);
}

/// CSPRNG-fill so plaintext content matches the root Go bench
/// (crypto/rand). getrandom returns at most ~33 MiB per call on
/// Linux, so loop until the whole buffer is filled.
pub fn randomFill(buf: []u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        const r = std.c.getrandom(buf[off..].ptr, buf.len - off, 0);
        if (r <= 0) return error.GetrandomFailed;
        off += @intCast(r);
    }
}

pub fn now() f64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(f64, @floatFromInt(ts.sec)) + @as(f64, @floatFromInt(ts.nsec)) / 1e9;
}

const Out = struct {
    io: std.Io,

    fn print(self: Out, comptime fmt: []const u8, args: anytype) !void {
        var buf: [256]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, fmt, args);
        try std.Io.File.stdout().writeStreamingAll(self.io, line);
    }
};

pub fn header(io: std.Io) !void {
    const out = Out{ .io = io };
    try out.print("{s:<17} {s:<8} {s}\n", .{ "bench", "size", "mb_per_sec" });
}

fn sizeLabel(buf: []u8, size: usize) ![]const u8 {
    if (size >= (1 << 20)) {
        return std.fmt.bufPrint(buf, "{d} MiB", .{size >> 20});
    }
    return std.fmt.bufPrint(buf, "{d} KiB", .{size >> 10});
}

/// Runs `runFn(ctx)` until the wall-clock budget is spent (with an
/// iteration floor + one untimed warm-up), then prints one table row.
pub fn benchCase(
    io: std.Io,
    budget_sec: f64,
    name: []const u8,
    size: usize,
    ctx: anytype,
    comptime runFn: anytype,
) !void {
    try runFn(ctx); // warm-up
    const start = now();
    var elapsed: f64 = 0.0;
    var iters: usize = 0;
    while (elapsed < budget_sec or iters < min_iters) {
        try runFn(ctx);
        iters += 1;
        elapsed = now() - start;
    }
    const mb = @as(f64, @floatFromInt(size)) * @as(f64, @floatFromInt(iters)) /
        (1024.0 * 1024.0);
    var label_buf: [32]u8 = undefined;
    const label = try sizeLabel(&label_buf, size);
    const out = Out{ .io = io };
    try out.print("{s:<17} {s:<8} {d:.1}\n", .{ name, label, mb / elapsed });
}
