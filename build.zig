//! Build for the ITB Zig binding (thin proxy over the C binding).
//!
//! Targets:
//!   zig build          — eitb CLI + loop harness + bench binaries
//!                        into zig-out/bin/
//!   zig build loop     — the loop stress harness alone
//!   zig build test     — the tests/*.zig integration suite (one
//!                        process per test file, run sequentially)
//!   zig build bench    — runs bench_message + bench_stream +
//!                        bench_stream_one_shot
//!
//! Prerequisites (built by build.sh): dist/linux-amd64/libitb3.so
//! (Go c-shared) and bindings/c/build/libitb3_c.a (the C binding
//! static archive this binding links). Link inputs are compile-time:
//! libitb3_c.a as an object plus `-litb3` with an absolute RPATH into
//! dist/, so no loader environment is needed at runtime.

const std = @import("std");

const test_names = [_][]const u8{
    "smoke",
    "message",
    "errors",
    "rekey",
    "persist",
    "stream_pump",
    "stream_one_shot",
    "stream_incremental",
    "stream_cancel",
    "stream_sticky",
    "runtime",
};

const bench_names = [_][]const u8{ "bench_message", "bench_stream", "bench_stream_one_shot" };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // Sibling C binding header + static archive, and the Go shared
    // library. The RPATH must be absolute so the produced binaries
    // run from any directory.
    const c_include = b.path("../c/include");
    const libitb3_c_a = b.path("../c/build/libitb3_c.a");
    const dist_abs = b.pathFromRoot("../../dist/linux-amd64");
    const dist: std.Build.LazyPath = .{ .cwd_relative = dist_abs };

    // Library module: the single @cImport site lives here, so the C
    // include path and every link input attach to this module and
    // propagate to each compilation that imports it.
    const itb_mod = b.addModule("itb3", .{
        .root_source_file = b.path("src/itb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    itb_mod.addIncludePath(c_include);
    itb_mod.addObjectFile(libitb3_c_a);
    itb_mod.addLibraryPath(dist);
    itb_mod.addRPath(dist);
    itb_mod.linkSystemLibrary("itb3", .{});

    // eitb CLI.
    const eitb = b.addExecutable(.{
        .name = "eitb",
        .root_module = b.createModule(.{
            .root_source_file = b.path("eitb/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "itb3", .module = itb_mod }},
        }),
    });
    b.installArtifact(eitb);

    // Long-run stress harness. It installs with everything else so
    // `zig build` produces it, and carries its own step so the fleet
    // entry point can build the utility alone.
    const loop = b.addExecutable(.{
        .name = "loop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("loop/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "itb3", .module = itb_mod }},
        }),
    });
    const loop_install = b.addInstallArtifact(loop, .{});
    b.getInstallStep().dependOn(&loop_install.step);
    const loop_step = b.step("loop", "Build the loop stress harness");
    loop_step.dependOn(&loop_install.step);

    // Integration tests: one binary per tests/<name>.zig, run
    // sequentially so every file gets a fresh libitb3 global state
    // and deterministic output ordering.
    const test_step = b.step("test", "Run the integration test suite");
    var prev_test: ?*std.Build.Step = null;
    for (test_names) |name| {
        const t = b.addTest(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("tests/{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "itb3", .module = itb_mod }},
            }),
        });
        const run = b.addRunArtifact(t);
        if (prev_test) |p| run.step.dependOn(p);
        test_step.dependOn(&run.step);
        prev_test = &run.step;
    }

    // Micro-benchmarks: always ReleaseFast — Debug-mode throughput
    // numbers are meaningless.
    const bench_step = b.step("bench", "Run the micro-benchmarks");
    var prev_bench: ?*std.Build.Step = null;
    for (bench_names) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("benches/{s}.zig", .{name})),
                .target = target,
                .optimize = .ReleaseFast,
                .imports = &.{.{ .name = "itb3", .module = itb_mod }},
            }),
        });
        b.installArtifact(exe);
        const run = b.addRunArtifact(exe);
        if (prev_bench) |p| run.step.dependOn(p);
        bench_step.dependOn(&run.step);
        prev_bench = &run.step;
    }
}
