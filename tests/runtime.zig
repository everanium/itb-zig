//! Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
//! heap-profile writer, the pool-counter snapshot and its slot layout,
//! the hash-registry enumeration, the numeric code behind an `Error`,
//! and the diagnostic's survival of a text wider than the relay
//! layer's inline buffer.

const std = @import("std");
const itb = @import("itb3");

// The libc entry is declared here by its symbol: std.c does not
// re-export it on this target.
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "GOMAXPROCS: zero queries, a positive value sets and returns the previous" {
    const orig = itb.setGomaxprocs(0);
    try std.testing.expect(orig > 0);
    try std.testing.expectEqual(orig, itb.setGomaxprocs(-3));
    try std.testing.expectEqual(orig, itb.setGomaxprocs(orig + 1));
    try std.testing.expectEqual(orig + 1, itb.setGomaxprocs(0));
    try std.testing.expectEqual(orig + 1, itb.setGomaxprocs(orig));
}

test "heap profile: a real path yields a non-empty file, an empty path is rejected" {
    const gpa = std.testing.allocator;
    const path = try std.fmt.allocPrintSentinel(
        gpa,
        "/tmp/itb-zig-heap-{d}.pprof",
        .{std.c.getpid()},
        0,
    );
    defer gpa.free(path);
    defer _ = std.c.unlink(path.ptr);

    try itb.writeHeapProfile(path);
    const fd = std.c.open(path.ptr, .{ .ACCMODE = .RDONLY });
    try std.testing.expect(fd >= 0);
    defer _ = std.c.close(fd);
    var probe: [16]u8 = undefined;
    try std.testing.expect(std.c.read(fd, &probe, probe.len) > 0);

    // The environment fallback must not stand in for the empty path.
    _ = unsetenv("ITB_MEMPROFILE");
    try std.testing.expectError(error.BadInput, itb.writeHeapProfile(""));
}

test "pool counters: the length query sizes the buffer and slot 0 carries the tier count" {
    const gpa = std.testing.allocator;
    const len = itb.poolStatsLen();
    try std.testing.expect(len >= 9);
    const slots = try itb.poolStats(gpa);
    defer gpa.free(slots);
    try std.testing.expectEqual(len, slots.len);
    const tiers: usize = @intCast(slots[0]);
    try std.testing.expect(tiers > 0);
    try std.testing.expectEqual(len, 1 + 5 * tiers + 8);
}

test "hash registry: canonical order, led by the Non-PRF inner primitive" {
    const gpa = std.testing.allocator;
    const json = try itb.hashNames(gpa);
    defer gpa.free(json);
    try std.testing.expect(std.mem.startsWith(u8, json, "[\"aesitb128\""));
    try std.testing.expect(std.mem.indexOf(u8, json, "\"areion512\"") != null);
}

test "auto DRBG tier: one of the two fill ciphers, resolved per host" {
    const tier = itb.drbgAutoTier();
    try std.testing.expect(std.mem.eql(u8, tier, "aes-256-ctr") or std.mem.eql(u8, tier, "chacha20"));
}

test "an Error carries its numeric code back through the binding" {
    const gpa = std.testing.allocator;
    const e = itb.Pipeline.init(gpa, "no-such-profile", null);
    try std.testing.expectError(error.UnknownProfile, e);
    try std.testing.expectEqual(itb.Status.unknown_profile, itb.statusOf(error.UnknownProfile));
    try std.testing.expectEqual(@as(c_uint, 13), itb.statusOf(error.UnknownProfile).code());
    try std.testing.expectEqual(@as(c_uint, 99), itb.statusOf(error.Internal).code());
}

test "a diagnostic wider than the inline buffer survives the boundary" {
    const gpa = std.testing.allocator;
    const tail = "zzzz-tail-marker";
    // The library echoes the caller's own path inside the os
    // diagnostic, so the caller sets the length. The relay layer
    // snapshots into an inline 2 KiB buffer and widens on the
    // short-buffer return; an intact tail proves the widening branch
    // ran rather than the text having been clipped at the boundary.
    const path = try std.fmt.allocPrintSentinel(
        gpa,
        "/tmp/{s}" ++ tail,
        .{"a" ** 4000},
        0,
    );
    defer gpa.free(path);

    try std.testing.expectError(error.BadInput, itb.writeHeapProfile(path));
    const msg = itb.lastError();
    try std.testing.expect(msg.len > 2048);
    try std.testing.expect(std.mem.indexOf(u8, msg, tail) != null);
    try std.testing.expect(std.mem.endsWith(u8, msg, "file name too long"));
}
