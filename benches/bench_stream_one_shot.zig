//! encryptStreamOneShot throughput vs plaintext size (streaming
//! Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times the
//! whole-buffer path (a single FFI round trip through the Pipeline's
//! stream chain).

const std = @import("std");
const itb = @import("itb3");
const util = @import("bench_util.zig");

const Ctx = struct {
    pipe: *const itb.Pipeline,
    plain: []const u8,
};

const DecCtx = struct {
    pipe: *const itb.Pipeline,
    wire: []const u8,
};

fn runStreamOneShot(ctx: *const Ctx) !void {
    const wire = try ctx.pipe.encryptStreamOneShot(ctx.plain);
    ctx.pipe.allocator.free(wire);
}

fn runStreamOneShotDec(ctx: *const DecCtx) !void {
    const plain = try ctx.pipe.decryptStreamOneShot(ctx.wire);
    ctx.pipe.allocator.free(plain);
}

pub fn main(init: std.process.Init) !void {
    // Bench-scale allocation churn leaks Go scratch heap unboundedly
    // without a soft memory cap + aggressive GC; the return values
    // report the previous settings, not an error.
    _ = itb.setMemoryLimit(4 << 30); // 4 GiB soft cap
    _ = itb.setGcPercent(100); // balanced GC

    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const env = init.environ_map;

    const opts = try util.buildOpts(arena, env);
    defer opts.deinit();
    var pipe = try itb.Pipeline.init(
        gpa,
        try util.profileName(arena, env, "streaming-noaead-triple-v1"),
        opts,
    );
    defer pipe.deinit();

    try util.header(init.io);
    const budget = util.minSeconds(env);
    const sizes = [_]usize{ 1 << 20, 16 << 20, 64 << 20 };
    for (sizes) |size| {
        const plain = try gpa.alloc(u8, size);
        defer gpa.free(plain);
        try util.randomFill(plain); // not in the timing loop
        const ctx = Ctx{ .pipe = &pipe, .plain = plain };
        try util.benchCase(init.io, budget, "stream_one_shot", size, &ctx, runStreamOneShot);
        const dec_wire = try pipe.encryptStreamOneShot(plain);
        defer gpa.free(dec_wire);
        const dctx = DecCtx{ .pipe = &pipe, .wire = dec_wire };
        try util.benchCase(init.io, budget, "stream_one_shot-dec", size, &dctx, runStreamOneShotDec);
    }
}
