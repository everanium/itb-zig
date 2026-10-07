//! Size and duration parsing, the monotonic clock, and the human
//! renderings of sizes, rates and durations. Every rendering here is
//! part of the output contract shared with the Go harness and the
//! other bindings' loop utilities, so the formats are fixed to the
//! character, not to taste.

const std = @import("std");

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary
/// multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B
/// or none = bytes; matching is case-insensitive and surrounding
/// whitespace is trimmed. Returns null on a malformed or negative
/// value.
pub fn parseSize(s: []const u8) ?i64 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len >= 64) return null;
    var upper: [64]u8 = undefined;
    for (trimmed, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    const text = upper[0..trimmed.len];

    const table = [_]struct { suffix: []const u8, mult: i64 }{
        .{ .suffix = "KIB", .mult = 1 << 10 },
        .{ .suffix = "KB", .mult = 1 << 10 },
        .{ .suffix = "K", .mult = 1 << 10 },
        .{ .suffix = "MIB", .mult = 1 << 20 },
        .{ .suffix = "MB", .mult = 1 << 20 },
        .{ .suffix = "M", .mult = 1 << 20 },
        .{ .suffix = "GIB", .mult = 1 << 30 },
        .{ .suffix = "GB", .mult = 1 << 30 },
        .{ .suffix = "G", .mult = 1 << 30 },
        .{ .suffix = "B", .mult = 1 },
    };
    var mult: i64 = 1;
    var digits = text.len;
    for (table) |row| {
        if (text.len >= row.suffix.len and
            std.mem.eql(u8, text[text.len - row.suffix.len ..], row.suffix))
        {
            mult = row.mult;
            digits = text.len - row.suffix.len;
            break;
        }
    }
    while (digits > 0 and (text[digits - 1] == ' ' or text[digits - 1] == '\t')) digits -= 1;
    if (digits == 0) return null;
    var value: i64 = 0;
    for (text[0..digits]) |c| {
        if (!std.ascii.isDigit(c)) return null;
        value = std.math.mul(i64, value, 10) catch return null;
        value = std.math.add(i64, value, @as(i64, c - '0')) catch return null;
    }
    if (mult > 1 and value > @divTrunc(std.math.maxInt(i64), mult)) return null;
    return value * mult;
}

/// Parses the Go duration grammar — a sequence of decimal numbers each
/// followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
/// "1h30m", "1.5s" — into nanoseconds. Returns null on a malformed
/// string.
pub fn parseDuration(s: []const u8) ?i64 {
    const units = [_]struct { unit: []const u8, ns: f64 }{
        .{ .unit = "ns", .ns = 1.0 },
        .{ .unit = "us", .ns = 1e3 },
        .{ .unit = "ms", .ns = 1e6 },
        .{ .unit = "s", .ns = 1e9 },
        .{ .unit = "m", .ns = 60e9 },
        .{ .unit = "h", .ns = 3600e9 },
    };
    if (s.len == 0) return null;
    var rest = s;
    var total: f64 = 0.0;
    while (rest.len > 0) {
        if (!std.ascii.isDigit(rest[0]) and rest[0] != '.') return null;
        var end: usize = 0;
        var seen_dot = false;
        while (end < rest.len) : (end += 1) {
            if (std.ascii.isDigit(rest[end])) continue;
            if (rest[end] == '.' and !seen_dot) {
                seen_dot = true;
                continue;
            }
            break;
        }
        const v = std.fmt.parseFloat(f64, rest[0..end]) catch return null;
        if (v < 0.0) return null;
        rest = rest[end..];
        var mult: f64 = 0.0;
        for (units) |u| {
            if (rest.len < u.unit.len) continue;
            if (!std.mem.eql(u8, rest[0..u.unit.len], u.unit)) continue;
            // A longer alphabetic run is a different unit, not this
            // one with trailing text.
            if (rest.len > u.unit.len and std.ascii.isAlphabetic(rest[u.unit.len])) continue;
            mult = u.ns;
            rest = rest[u.unit.len..];
            break;
        }
        if (mult == 0.0) return null;
        total += v * mult;
    }
    if (total > 9.2e18) return null;
    return @intFromFloat(total);
}

/// Monotonic wall clock in nanoseconds.
pub fn nowNanos() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1_000_000_000 + @as(i64, @intCast(ts.nsec));
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
pub fn humanBytes(out: []u8, n: i64) []const u8 {
    const f: f64 = @floatFromInt(n);
    if (n >= (1 << 30)) return std.fmt.bufPrint(out, "{d:.1}GiB", .{f / (1 << 30)}) catch "?";
    if (n >= (1 << 20)) return std.fmt.bufPrint(out, "{d:.1}MiB", .{f / (1 << 20)}) catch "?";
    if (n >= (1 << 10)) return std.fmt.bufPrint(out, "{d:.1}KiB", .{f / (1 << 10)}) catch "?";
    return std.fmt.bufPrint(out, "{d}B", .{n}) catch "?";
}

/// Renders a possibly-negative byte delta with an explicit sign.
pub fn humanBytesSigned(out: []u8, n: i64) []const u8 {
    var mag: [32]u8 = undefined;
    if (n < 0) return std.fmt.bufPrint(out, "-{s}", .{humanBytes(&mag, -n)}) catch "?";
    return std.fmt.bufPrint(out, "+{s}", .{humanBytes(&mag, n)}) catch "?";
}

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
pub fn mbPerSec(bytes: i64, ns: i64) f64 {
    if (ns <= 0) return 0.0;
    const b: f64 = @floatFromInt(bytes);
    const t: f64 = @floatFromInt(ns);
    return b / @as(f64, 1 << 20) / (t / 1e9);
}

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
pub fn humanRate(out: []u8, bytes: i64, ns: i64) []const u8 {
    if (ns <= 0) return "n/a";
    return std.fmt.bufPrint(out, "{d:.1}MB/s", .{mbPerSec(bytes, ns)}) catch "?";
}

/// Writes the fractional part of a nanosecond remainder (0 ..< 1e9)
/// as ".ddd" with trailing zeros removed; writes nothing for zero.
fn fractionInto(out: []u8, frac_ns: i64) usize {
    if (frac_ns == 0) return 0;
    var digits: [16]u8 = undefined;
    // Zig-specific. The zero-padded form of a signed integer carries
    // an explicit sign, so the remainder is narrowed to unsigned
    // before it is padded to nine digits.
    var text = std.fmt.bufPrint(&digits, "{d:0>9}", .{@as(u64, @intCast(frac_ns))}) catch return 0;
    while (text.len > 0 and text[text.len - 1] == '0') text = text[0 .. text.len - 1];
    const s = std.fmt.bufPrint(out, ".{s}", .{text}) catch return 0;
    return s.len;
}

/// Renders a duration the way Go's time.Duration prints: below one
/// second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
/// where the hour part appears when non-zero, the minute part when the
/// hour part appears or the minutes are non-zero, and the seconds
/// carry their fraction with trailing zeros removed ("5s", "5.003s",
/// "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
pub fn humanDuration(out: []u8, nanos: i64) []const u8 {
    const ns = if (nanos < 0) -nanos else nanos;
    if (ns == 0) return "0s";
    var w: usize = 0;
    if (ns < 1_000_000_000) {
        w += (std.fmt.bufPrint(out[w..], "{d}", .{@divTrunc(ns, 1_000_000)}) catch return "?").len;
        w += fractionInto(out[w..], @mod(ns, 1_000_000) * 1000); // scale to 9 digits
        w += (std.fmt.bufPrint(out[w..], "ms", .{}) catch return "?").len;
        return out[0..w];
    }
    const hours = @divTrunc(ns, 3_600_000_000_000);
    var rem = @mod(ns, 3_600_000_000_000);
    const minutes = @divTrunc(rem, 60_000_000_000);
    rem = @mod(rem, 60_000_000_000);
    const seconds = @divTrunc(rem, 1_000_000_000);
    const frac = @mod(rem, 1_000_000_000);
    if (hours > 0) {
        w += (std.fmt.bufPrint(out[w..], "{d}h", .{hours}) catch return "?").len;
    }
    if (hours > 0 or minutes > 0) {
        w += (std.fmt.bufPrint(out[w..], "{d}m", .{minutes}) catch return "?").len;
    }
    w += (std.fmt.bufPrint(out[w..], "{d}", .{seconds}) catch return "?").len;
    w += fractionInto(out[w..], frac);
    w += (std.fmt.bufPrint(out[w..], "s", .{}) catch return "?").len;
    return out[0..w];
}
