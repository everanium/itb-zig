//! Long-run stress harness. The loop utility holds one Pipeline handle
//! per exercised cipher surface for minutes, hammers it with
//! concurrent encrypt → decrypt → compare round-trips from N worker
//! threads, rotates the outer masters and reopens the handle from its
//! session blob on a schedule, and reports whether the process
//! survived with every byte intact. It is the Zig binding's
//! counterpart of the Go harness under tools/loop: the same flags, the
//! same round structure, the same summary in both renderings.
//!
//! The default shape is full production: the Streaming AEAD profile
//! with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
//! inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
//! driven through a stream session by three workers for five minutes
//! on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
//! plaintext held for the whole run, so any cross-call state leakage
//! inside the Pipeline surfaces as a data mismatch between workers
//! rather than cancelling out.
//!
//! A failure is one of two things. A cipher, rekey or load call that
//! returns a non-OK status is a worker error: the run stops, the
//! summary lists it, the verdict is FAIL and the exit code 1. A
//! round-trip that returns without error but with different bytes is a
//! data mismatch: the process terminates on the spot with exit code 3,
//! printing the worker, the iteration and the first differing offset,
//! and no summary — the state that produced the wrong bytes is the
//! evidence. A crash inside the shared library or the host runtime has
//! no exit code of its own here; surfacing it is what the utility is
//! for.
//!
//! Usage:
//!
//!   ./run_loop.sh --duration 5m --goroutines 3 --shape stream \
//!                 --hash areion512 --mac hmac-blake3 \
//!                 --payload-size 16MB --memlimit auto \
//!                 --parallax on --wrapper on
//!
//! Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
//! then the partial summary prints.

const std = @import("std");
const itb = @import("itb3");

const payload = @import("payload.zig");
const size = @import("size.zig");
const summary = @import("summary.zig");
const worker_mod = @import("worker.zig");

const Config = worker_mod.Config;
const PayloadMode = payload.PayloadMode;
const RunState = worker_mod.RunState;
const Shape = worker_mod.Shape;
const Worker = worker_mod.Worker;

/// Profiles the shape-based pair is built against when --profile is
/// empty.
const default_stream_profile = "streaming-aead-triple-mac-v1";
const default_message_profile = "singlemsg-triple-mac-v1";

/// The primitive supplied for the parallax palette and the outer
/// cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
/// so it is sound outside the Interlocked Barrier, and it is the
/// closest relative of the AES-based inner primitive whose profiles
/// need this fill.
const keystream_fill_cipher = "aescmac";

// MARK: logging
//
// A line and its newline leave the process in one write: workers log
// concurrently during maintenance, and a writer that emitted the text
// and the newline separately would let another worker's line land
// between them.
//
// Zig-specific. The C reference declares these in the shared header
// and defines them here; Zig has no header, so the other units reach
// them through `@import("root")`, which resolves to this file.
/// Writes the whole slice to the descriptor in as few calls as the
/// kernel allows; one call for any line this utility produces.
pub fn writeAll(fd: c_int, bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
}

/// Prints one prefixed status line to stdout.
pub fn line(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "[loop] " ++ fmt ++ "\n", args) catch {
        allocLine(1, "[loop] " ++ fmt ++ "\n", args);
        return;
    };
    writeAll(1, text);
}

/// Prints one prefixed error line to stderr.
pub fn err(comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "loop: " ++ fmt ++ "\n", args) catch {
        allocLine(2, "loop: " ++ fmt ++ "\n", args);
        return;
    };
    writeAll(2, text);
}

/// Writes a raw slice to stdout unchanged (the JSON summary).
pub fn raw(bytes: []const u8) void {
    writeAll(1, bytes);
}

/// A line wider than the stack buffer — a diagnostic echoing a long
/// caller-supplied path is the case that reaches here. The text is
/// never clipped to make it fit.
fn allocLine(fd: c_int, comptime fmt: []const u8, args: anytype) void {
    const text = std.fmt.allocPrint(std.heap.c_allocator, fmt, args) catch return;
    defer std.heap.c_allocator.free(text);
    writeAll(fd, text);
}

fn onOff(b: bool) []const u8 {
    return if (b) "on" else "off";
}

/// Renders an encoder policy env value for the summary: the raw string
/// when set, "default" when the shipped ladder applies.
fn policyLabel(name: [*:0]const u8) []const u8 {
    const value = std.c.getenv(name) orelse return "default";
    const text = std.mem.trimStart(u8, std.mem.span(value), " \t");
    return if (text.len == 0) "default" else text;
}

// MARK: flags

const FlagKind = enum { int, int64, uint64, string, boolean };

/// One command-line flag: its name, its help text, and which raw slot
/// the value lands in. Values are validated after the whole line is
/// parsed.
const Flag = struct {
    name: []const u8,
    type_label: []const u8,
    kind: FlagKind,
    help: []const u8,
};

/// The raw flag values before validation. String defaults are
/// literals; strings given on the command line point into argv.
const RawFlags = struct {
    barrier_fill: i32 = 0,
    blob_cycle_every: i64 = 0,
    blob_mode: i32 = 1,
    chunk_size: []const u8 = "0",
    drbg: []const u8 = "",
    duration: []const u8 = "5m",
    gogc: i32 = 0,
    gomaxprocs: i32 = 0,
    goroutines: i32 = 3,
    hash: []const u8 = "areion512",
    iterations: i64 = 0,
    json_output: bool = false,
    key_bits: i32 = 0,
    mac: []const u8 = "hmac-blake3",
    memlimit: []const u8 = "auto",
    memprofile: []const u8 = "",
    nonce_bits: i32 = 0,
    parallax: []const u8 = "on",
    payload_mode: []const u8 = "fixed",
    payload_size: []const u8 = "16MB",
    profile: []const u8 = "",
    rekey_every: i64 = 0,
    seed: u64 = 0,
    shape: []const u8 = "stream",
    wrapper: []const u8 = "on",

    fn intSlot(self: *RawFlags, name: []const u8) ?*i32 {
        if (std.mem.eql(u8, name, "barrier-fill")) return &self.barrier_fill;
        if (std.mem.eql(u8, name, "blob-mode")) return &self.blob_mode;
        if (std.mem.eql(u8, name, "gogc")) return &self.gogc;
        if (std.mem.eql(u8, name, "gomaxprocs")) return &self.gomaxprocs;
        if (std.mem.eql(u8, name, "goroutines")) return &self.goroutines;
        if (std.mem.eql(u8, name, "key-bits")) return &self.key_bits;
        if (std.mem.eql(u8, name, "nonce-bits")) return &self.nonce_bits;
        return null;
    }

    fn int64Slot(self: *RawFlags, name: []const u8) ?*i64 {
        if (std.mem.eql(u8, name, "blob-cycle-every")) return &self.blob_cycle_every;
        if (std.mem.eql(u8, name, "iterations")) return &self.iterations;
        if (std.mem.eql(u8, name, "rekey-every")) return &self.rekey_every;
        return null;
    }

    fn stringSlot(self: *RawFlags, name: []const u8) ?*[]const u8 {
        if (std.mem.eql(u8, name, "chunk-size")) return &self.chunk_size;
        if (std.mem.eql(u8, name, "drbg")) return &self.drbg;
        if (std.mem.eql(u8, name, "duration")) return &self.duration;
        if (std.mem.eql(u8, name, "hash")) return &self.hash;
        if (std.mem.eql(u8, name, "mac")) return &self.mac;
        if (std.mem.eql(u8, name, "memlimit")) return &self.memlimit;
        if (std.mem.eql(u8, name, "memprofile")) return &self.memprofile;
        if (std.mem.eql(u8, name, "parallax")) return &self.parallax;
        if (std.mem.eql(u8, name, "payload-mode")) return &self.payload_mode;
        if (std.mem.eql(u8, name, "payload-size")) return &self.payload_size;
        if (std.mem.eql(u8, name, "profile")) return &self.profile;
        if (std.mem.eql(u8, name, "shape")) return &self.shape;
        if (std.mem.eql(u8, name, "wrapper")) return &self.wrapper;
        return null;
    }

    /// Parses one value into its flag slot; false on a malformed
    /// value.
    fn assign(self: *RawFlags, f: Flag, value: []const u8) bool {
        switch (f.kind) {
            .int => {
                const slot = self.intSlot(f.name) orelse return false;
                slot.* = std.fmt.parseInt(i32, value, 10) catch return false;
                return true;
            },
            .int64 => {
                const slot = self.int64Slot(f.name) orelse return false;
                slot.* = std.fmt.parseInt(i64, value, 10) catch return false;
                return true;
            },
            .uint64 => {
                if (value.len > 0 and value[0] == '-') return false;
                self.seed = std.fmt.parseInt(u64, value, 10) catch return false;
                return true;
            },
            .string => {
                const slot = self.stringSlot(f.name) orelse return false;
                slot.* = value;
                return true;
            },
            .boolean => {
                if (std.mem.eql(u8, value, "true")) {
                    self.json_output = true;
                } else if (std.mem.eql(u8, value, "false")) {
                    self.json_output = false;
                } else {
                    return false;
                }
                return true;
            },
        }
    }

    /// The default-value suffix the usage prints for this flag: an
    /// integer when non-zero, a string when non-empty, nothing
    /// otherwise.
    fn defaultSuffix(self: *RawFlags, out: []u8, f: Flag) []const u8 {
        switch (f.kind) {
            .int => {
                const slot = self.intSlot(f.name) orelse return "";
                if (slot.* == 0) return "";
                return std.fmt.bufPrint(out, " (default {d})", .{slot.*}) catch "";
            },
            .string => {
                const slot = self.stringSlot(f.name) orelse return "";
                if (slot.*.len == 0) return "";
                return std.fmt.bufPrint(out, " (default \"{s}\")", .{slot.*}) catch "";
            },
            else => return "",
        }
    }
};

/// The flag table, in alphabetical order (the order the usage prints).
const flag_table = [_]Flag{
    .{ .name = "barrier-fill", .type_label = "int", .kind = .int, .help = "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)" },
    .{ .name = "blob-cycle-every", .type_label = "int", .kind = .int64, .help = "reopen each pipeline from its session blob every N iterations per worker; 0 = never" },
    .{ .name = "blob-mode", .type_label = "int", .kind = .int, .help = "container floor sizing mode: 1 (per-region, default) | 2 (per-container)" },
    .{ .name = "chunk-size", .type_label = "string", .kind = .string, .help = "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape" },
    .{ .name = "drbg", .type_label = "string", .kind = .string, .help = "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)" },
    .{ .name = "duration", .type_label = "duration", .kind = .string, .help = "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0" },
    .{ .name = "gogc", .type_label = "int", .kind = .int, .help = "GC trigger percentage; 0 = leave the runtime default" },
    .{ .name = "gomaxprocs", .type_label = "int", .kind = .int, .help = "Go runtime GOMAXPROCS override; 0 = inherit from the environment" },
    .{ .name = "goroutines", .type_label = "int", .kind = .int, .help = "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1" },
    .{ .name = "hash", .type_label = "string", .kind = .string, .help = "inner ITB hash primitive name" },
    .{ .name = "iterations", .type_label = "int", .kind = .int64, .help = "fixed per-worker iteration count; 0 = duration-based" },
    .{ .name = "json-output", .type_label = "", .kind = .boolean, .help = "print the final summary as one compact JSON object instead of log lines" },
    .{ .name = "key-bits", .type_label = "int", .kind = .int, .help = "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)" },
    .{ .name = "mac", .type_label = "string", .kind = .string, .help = "MAC primitive name" },
    .{ .name = "memlimit", .type_label = "string", .kind = .string, .help = "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)" },
    .{ .name = "memprofile", .type_label = "string", .kind = .string, .help = "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none" },
    .{ .name = "nonce-bits", .type_label = "int", .kind = .int, .help = "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)" },
    .{ .name = "parallax", .type_label = "string", .kind = .string, .help = "parallax layer: on | off" },
    .{ .name = "payload-mode", .type_label = "string", .kind = .string, .help = "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii" },
    .{ .name = "payload-size", .type_label = "string", .kind = .string, .help = "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)" },
    .{ .name = "profile", .type_label = "string", .kind = .string, .help = "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair" },
    .{ .name = "rekey-every", .type_label = "int", .kind = .int64, .help = "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never" },
    .{ .name = "seed", .type_label = "uint", .kind = .uint64, .help = "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts" },
    .{ .name = "shape", .type_label = "string", .kind = .string, .help = "cipher surface to exercise: stream | message | stream_one_shot | both" },
    .{ .name = "wrapper", .type_label = "string", .kind = .string, .help = "wrapper layer: on | off" },
};

fn usage() void {
    var defaults = RawFlags{};
    const gpa = std.heap.c_allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    out.print(gpa, "Usage of loop:\n", .{}) catch return;
    var suffix: [256]u8 = undefined;
    for (flag_table) |f| {
        out.print(gpa, "  -{s}{s}{s}\n", .{ f.name, if (f.type_label.len > 0) " " else "", f.type_label }) catch return;
        out.print(gpa, "    \t{s}{s}\n", .{ f.help, defaults.defaultSuffix(&suffix, f) }) catch return;
    }
    writeAll(2, out.items);
}

// MARK: signals

/// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
/// while it waits for the workers; it turns the flag into the stop
/// request every worker checks before starting an iteration, so a
/// signal interrupts nothing mid-call — the in-flight encrypt /
/// decrypt / compare completes, the worker returns, and the partial
/// summary prints with the verdict the completed iterations earned.
var signal_seen = std.atomic.Value(bool).init(false);

extern "c" fn signal(sig: c_int, handler: ?*const fn (c_int) callconv(.c) void) callconv(.c) ?*anyopaque;

fn onSignal(_: c_int) callconv(.c) void {
    signal_seen.store(true, .monotonic);
}

// MARK: profile records

/// Integer value of key in a profile JSON record; 0 when absent.
fn recordInt(obj: std.json.ObjectMap, key: []const u8) i64 {
    const v = obj.get(key) orelse return 0;
    return switch (v) {
        .integer => |i| i,
        else => 0,
    };
}

/// String value of key in a profile JSON record, or "-" when absent or
/// empty.
fn recordStr(obj: std.json.ObjectMap, key: []const u8) []const u8 {
    const v = obj.get(key) orelse return "-";
    return switch (v) {
        .string => |s| if (s.len == 0) "-" else s,
        else => "-",
    };
}

/// Boolean value of key in a profile JSON record; false when absent.
fn recordBool(obj: std.json.ObjectMap, key: []const u8) bool {
    const v = obj.get(key) orelse return false;
    return switch (v) {
        .bool => |b| b,
        else => false,
    };
}

// MARK: the run

const ParseResult = enum { ok, help, fail };

fn parseOnOff(v: []const u8) ?bool {
    if (std.mem.eql(u8, v, "on")) return true;
    if (std.mem.eql(u8, v, "off")) return false;
    return null;
}

/// Whether name is in the shipped hash registry the binding
/// enumerates. Names are restricted to [a-z0-9-], so a quoted run is
/// one complete name.
fn hashRegistered(gpa: std.mem.Allocator, name: []const u8) bool {
    const json = itb.hashNames(gpa) catch return false;
    defer gpa.free(json);
    var quoted: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&quoted, "\"{s}\"", .{name}) catch return false;
    return std.mem.indexOf(u8, json, needle) != null;
}

/// Parses argv into the raw flag values. Accepts -name value,
/// --name value, -name=value and --name=value; a boolean flag takes no
/// value unless given as -name=true / -name=false.
fn parseArgv(argv: []const [*:0]const u8, f: *RawFlags) ParseResult {
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const arg = std.mem.span(argv[i]);
        if (arg.len < 2 or arg[0] != '-') {
            err("unexpected positional arguments: [{s}]", .{arg});
            return .fail;
        }
        var name: []const u8 = arg[if (arg.len > 1 and arg[1] == '-') 2 else 1..];
        if (std.mem.eql(u8, name, "h") or std.mem.eql(u8, name, "help")) {
            usage();
            return .help;
        }
        var value: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, name, '=')) |eq| {
            value = name[eq + 1 ..];
            name = name[0..eq];
        }
        var flag: ?Flag = null;
        for (flag_table) |candidate| {
            if (std.mem.eql(u8, candidate.name, name)) {
                flag = candidate;
                break;
            }
        }
        if (flag == null) {
            err("flag provided but not defined: -{s}", .{name});
            usage();
            return .fail;
        }
        if (value == null) {
            if (flag.?.kind == .boolean) {
                value = "true";
            } else if (i + 1 < argv.len) {
                i += 1;
                value = std.mem.span(argv[i]);
            } else {
                err("flag needs an argument: -{s}", .{flag.?.name});
                return .fail;
            }
        }
        if (!f.assign(flag.?, value.?)) {
            err("invalid value \"{s}\" for flag -{s}", .{ value.?, flag.?.name });
            return .fail;
        }
    }
    return .ok;
}

/// Resolves a registered profile to the shape family its record's mode
/// exposes by reading the record through the binding's lookup: a mode
/// beginning with "streaming" exposes the stream surfaces, one
/// beginning with "singlemsg" the message surface, "blob-only" none.
/// Prints the validation message and returns null on rejection.
fn profileSurface(gpa: std.mem.Allocator, name: [:0]const u8) ?Shape {
    const json = itb.lookup(gpa, name) catch {
        err("--profile \"{s}\" is not a registered triple profile", .{name});
        return null;
    };
    defer gpa.free(json);
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch {
        err("--profile \"{s}\" carries no cipher surface (blob-only mode)", .{name});
        return null;
    };
    defer parsed.deinit();
    const mode = recordStr(parsed.value.object, "mode");
    if (std.mem.startsWith(u8, mode, "streaming")) return .stream;
    if (std.mem.startsWith(u8, mode, "singlemsg")) return .message;
    err("--profile \"{s}\" carries no cipher surface (blob-only mode)", .{name});
    return null;
}

/// Applies a --profile's surface to the requested shape: a
/// message-surface profile forces message; a stream-surface profile
/// keeps stream or stream_one_shot as requested and turns message or
/// both into stream.
fn narrowShape(requested: Shape, surface: Shape) Shape {
    if (surface == .message) return .message;
    return if (requested == .stream_one_shot) .stream_one_shot else .stream;
}

/// Builds the resolved config from argv. Prints "loop: <message>" for
/// the first failing rule.
fn parseFlags(gpa: std.mem.Allocator, argv: []const [*:0]const u8, cfg: *Config, profile_z: *[:0]const u8) ParseResult {
    var f = RawFlags{};
    const rc = parseArgv(argv, &f);
    if (rc != .ok) return rc;

    const duration_ns = size.parseDuration(f.duration) orelse 0;
    if (duration_ns <= 0) {
        err("--duration must be positive, got {s}", .{f.duration});
        return .fail;
    }
    cfg.duration_ns = duration_ns;
    cfg.iterations = f.iterations;
    if (cfg.iterations < 0) {
        err("--iterations must be >= 0, got {d}", .{cfg.iterations});
        return .fail;
    }
    if (f.goroutines < 1 or f.goroutines > @as(i32, @intCast(worker_mod.max_workers))) {
        err("--goroutines must be in 1..{d}, got {d}", .{ worker_mod.max_workers, f.goroutines });
        return .fail;
    }
    // Concurrency mode. This binding runs shared-handle: OS threads
    // call into one Pipeline handle concurrently, which the shared
    // library permits after construction and the binding's Pipeline
    // struct allows (it adds no synchronisation of its own), so
    // --goroutines is the thread count verbatim, never clamped.
    cfg.workers_requested = @intCast(f.goroutines);
    cfg.workers = @intCast(f.goroutines);
    cfg.shape = Shape.parse(f.shape) orelse {
        err("--shape must be stream | message | stream_one_shot | both, got \"{s}\"", .{f.shape});
        return .fail;
    };
    if (!hashRegistered(gpa, f.hash)) {
        err("--hash \"{s}\" is not a registered hash primitive", .{f.hash});
        return .fail;
    }
    cfg.hash = f.hash;
    cfg.mac = f.mac; // validated by Init: no MAC-name enumeration exists
    cfg.payload_bytes = size.parseSize(f.payload_size) orelse {
        err("--payload-size: invalid size \"{s}\"", .{f.payload_size});
        return .fail;
    };
    if (cfg.payload_bytes < 1) {
        err("--payload-size must be at least 1 byte", .{});
        return .fail;
    }
    if (std.mem.eql(u8, f.memlimit, "auto")) {
        cfg.memlimit_auto = true;
        cfg.memlimit = if (cfg.workers <= 3) (1 << 30) else (256 << 20);
    } else {
        cfg.memlimit = size.parseSize(f.memlimit) orelse {
            err("--memlimit: invalid size \"{s}\"", .{f.memlimit});
            return .fail;
        };
    }
    cfg.gogc = f.gogc;
    if (cfg.gogc < 0) {
        err("--gogc must be >= 0, got {d}", .{cfg.gogc});
        return .fail;
    }
    cfg.parallax = parseOnOff(f.parallax) orelse {
        err("--parallax must be on | off, got \"{s}\"", .{f.parallax});
        return .fail;
    };
    cfg.wrapper = parseOnOff(f.wrapper) orelse {
        err("--wrapper must be on | off, got \"{s}\"", .{f.wrapper});
        return .fail;
    };
    cfg.profile = f.profile;
    if (cfg.profile.len > 0) {
        const z = gpa.dupeZ(u8, cfg.profile) catch {
            err("out of memory", .{});
            return .fail;
        };
        profile_z.* = z;
        const surface = profileSurface(gpa, z) orelse return .fail;
        cfg.shape = narrowShape(cfg.shape, surface);
    }
    cfg.key_bits = f.key_bits;
    switch (cfg.key_bits) {
        0, 512, 1024, 2048 => {},
        else => {
            err("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got {d}", .{cfg.key_bits});
            return .fail;
        },
    }
    cfg.nonce_bits = f.nonce_bits;
    switch (cfg.nonce_bits) {
        0, 128, 256, 512 => {},
        else => {
            err("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got {d}", .{cfg.nonce_bits});
            return .fail;
        },
    }
    cfg.blob_mode = f.blob_mode;
    switch (cfg.blob_mode) {
        1, 2 => {},
        else => {
            err("--blob-mode must be 1 (per-region) | 2 (per-container), got {d}", .{cfg.blob_mode});
            return .fail;
        },
    }
    cfg.barrier_fill = f.barrier_fill;
    switch (cfg.barrier_fill) {
        0, 1, 2, 4, 8, 16, 32 => {},
        else => {
            err("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got {d}", .{cfg.barrier_fill});
            return .fail;
        },
    }
    cfg.drbg = f.drbg; // validated by Init: no DRBG-name enumeration exists
    cfg.chunk_size = size.parseSize(f.chunk_size) orelse {
        err("--chunk-size: invalid size \"{s}\"", .{f.chunk_size});
        return .fail;
    };
    cfg.gomaxprocs = f.gomaxprocs;
    if (cfg.gomaxprocs < 0) {
        err("--gomaxprocs must be > 0 when specified, got {d}", .{cfg.gomaxprocs});
        return .fail;
    }
    cfg.rekey_every = f.rekey_every;
    if (cfg.rekey_every < 0) {
        err("--rekey-every must be >= 0, got {d}", .{cfg.rekey_every});
        return .fail;
    }
    cfg.blob_cycle_every = f.blob_cycle_every;
    if (cfg.blob_cycle_every < 0) {
        err("--blob-cycle-every must be >= 0, got {d}", .{cfg.blob_cycle_every});
        return .fail;
    }
    cfg.payload_mode = PayloadMode.parse(f.payload_mode) orelse {
        err("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"{s}\"", .{f.payload_mode});
        return .fail;
    };
    cfg.seed = f.seed;
    cfg.json_output = f.json_output;
    cfg.memprofile = f.memprofile;
    return .ok;
}

// MARK: pipelines

/// Folds a keystream primitive into opts for any layer the named
/// profile leaves unfilled but the operator asked for.
///
/// A profile built around a primitive that is safe only inside the
/// Interlocked Barrier ships with no parallax palette and no outer
/// cipher: both layers run outside the barrier, where that primitive
/// would stand bare, so the recipe leaves them unnamed rather than
/// naming a primitive that must not key them. Engaging either layer
/// therefore needs a keystream-capable primitive supplied from outside
/// the recipe; without it construction fails on a palette below its
/// minimum or an unnamed outer cipher, and the primitive that most
/// deserves stressing becomes the one that cannot be stressed with
/// those layers engaged.
///
/// Overrides fold into the resolved record the blob carries, so the
/// receiver rebuilds the same shape from the blob alone.
///
/// Returns 1 when a layer was filled, 0 when none needed it, -1 on a
/// lookup failure (message already printed).
fn fillKeystreamLayers(
    gpa: std.mem.Allocator,
    name: [:0]const u8,
    opts: itb.Opts,
    want_parallax: bool,
    want_wrapper: bool,
) i32 {
    const json = itb.lookup(gpa, name) catch {
        err("--profile \"{s}\" is not a registered triple profile", .{name});
        return -1;
    };
    defer gpa.free(json);
    var filled: i32 = 0;
    // Zig-specific. The record is probed by substring the way the C
    // reference does: this binding hands the record back as the JSON
    // text libitb3 produced, and the encoder omits both keys when they
    // are unset, so an absent key is the unfilled state.
    if (want_parallax and std.mem.indexOf(u8, json, "\"palette\":") == null) {
        opts.set("parallaxPalette", keystream_fill_cipher ++ "," ++ keystream_fill_cipher ++ "," ++ keystream_fill_cipher) catch {};
        if (std.mem.indexOf(u8, json, "\"segment\":") == null) {
            // A recipe that never carried a palette never carried a
            // segment size either, and the schedule rejects zero.
            opts.set("parallaxSegmentSize", "4093") catch {};
        }
        filled = 1;
    }
    if (want_wrapper and std.mem.indexOf(u8, json, "\"outer\":") == null) {
        opts.set("outerCipher", keystream_fill_cipher) catch {};
        filled = 1;
    }
    return filled;
}

/// Prints the construction line with the recipe read back from the
/// blob the Pipeline handed out, not echoed from the flags: every
/// construction override is proven to have reached the library by the
/// value the receiver would see. Record values that are empty (a No
/// MAC profile's MAC, a mixed profile's single hash) print as "-".
fn logPipelineInitialised(gpa: std.mem.Allocator, profile: []const u8, blob: []const u8) void {
    const json = itb.inspect(gpa, blob) catch {
        line("pipeline initialised: profile={s} blob={d} bytes (inspect: {s})", .{
            profile, blob.len, itb.lastError(),
        });
        return;
    };
    defer gpa.free(json);
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch {
        line("pipeline initialised: profile={s} blob={d} bytes (inspect: {s})", .{
            profile, blob.len, "record is not a JSON object",
        });
        return;
    };
    defer parsed.deinit();
    const obj = parsed.value.object;
    var tail_buf: [128]u8 = undefined;
    var tail_len: usize = 0;
    const container_mode = recordInt(obj, "container_mode");
    if (container_mode == 2) {
        if (std.fmt.bufPrint(tail_buf[tail_len..], " container-mode={d}", .{container_mode})) |t| tail_len += t.len else |_| {}
    }
    const drbg = recordStr(obj, "drbg");
    if (!std.mem.eql(u8, drbg, "-")) {
        if (std.fmt.bufPrint(tail_buf[tail_len..], " drbg={s}", .{drbg})) |t| tail_len += t.len else |_| {}
    }
    line(
        "pipeline initialised: profile={s} blob={d} bytes hash={s} key-bits={d} nonce-bits={d} barrier-fill={d} chunk-size={d} mac={s} parallax={s} wrapper={s}{s}",
        .{
            profile,
            blob.len,
            recordStr(obj, "hash"),
            recordInt(obj, "keybits"),
            recordInt(obj, "nonce_bits"),
            recordInt(obj, "barrier_fill"),
            recordInt(obj, "chunk"),
            recordStr(obj, "mac"),
            onOff(recordBool(obj, "parallax")),
            onOff(recordBool(obj, "wrapper")),
            tail_buf[0..tail_len],
        },
    );
}

/// Sets the inner blob's "mode" field of a wrap-layer session blob to
/// target_mode (1 = per-region, 2 = per-container) in place. The wrap
/// layer's profile record carries its own "mode" (a string), so the
/// search starts at the inner blob ("ib"); both shipped modes are one
/// digit wide, so the blob length does not change and the key material
/// in blob is never copied. Returns false when the inner blob or its
/// mode field is not found.
fn editInnerBlobMode(blob: []u8, target_mode: u8) bool {
    const ib_key = "\"ib\":{";
    const mode_key = "\"mode\":";
    const ib = std.mem.indexOf(u8, blob, ib_key) orelse return false;
    const off = ib + ib_key.len;
    const mode = std.mem.indexOf(u8, blob[off..], mode_key) orelse return false;
    const at = off + mode + mode_key.len;
    if (at + 1 >= blob.len or blob[at] < '1' or blob[at] > '2' or std.ascii.isDigit(blob[at + 1])) return false;
    blob[at] = '0' + target_mode;
    return true;
}

/// Constructs one Pipeline against profile with every flag-carried
/// override in the opts string (zero values included — the shared
/// library treats zero as "profile default"), then obtains the Init
/// blob once through save: the binding's init entry does not hand the
/// blob back, and the bytes are the ones Init produced. Later blob
/// reopens use the retained blob; save is never called again.
fn buildPipeline(
    gpa: std.mem.Allocator,
    cfg: Config,
    profile: [:0]const u8,
    profile_z: [:0]const u8,
    out_pipe: *?itb.Pipeline,
    out_blob: *[]u8,
) bool {
    const opts = itb.Opts.init() catch {
        err("out of memory", .{});
        return false;
    };
    defer opts.deinit();
    var num: [32]u8 = undefined;
    const hash_z = gpa.dupeZ(u8, cfg.hash) catch return false;
    defer gpa.free(hash_z);
    const mac_z = gpa.dupeZ(u8, cfg.mac) catch return false;
    defer gpa.free(mac_z);
    const drbg_z = gpa.dupeZ(u8, cfg.drbg) catch return false;
    defer gpa.free(drbg_z);
    opts.set("innerHash", hash_z) catch {};
    opts.set("macName", mac_z) catch {};
    opts.set("withParallax", if (cfg.parallax) "true" else "false") catch {};
    opts.set("withWrapper", if (cfg.wrapper) "true" else "false") catch {};
    setNum(opts, "keyBits", &num, cfg.key_bits);
    setNum(opts, "nonceBits", &num, cfg.nonce_bits);
    setNum(opts, "barrierFill", &num, cfg.barrier_fill);
    opts.set("drbg", drbg_z) catch {};
    setNum(opts, "chunkSize", &num, cfg.chunk_size);

    if (cfg.profile.len > 0) {
        const filled = fillKeystreamLayers(gpa, profile_z, opts, cfg.parallax, cfg.wrapper);
        if (filled < 0) return false;
        if (filled > 0) {
            err("{s} leaves the requested keystream layers unnamed; {s} supplied for them", .{
                cfg.profile, keystream_fill_cipher,
            });
        }
    }

    var pipe = itb.Pipeline.init(gpa, profile, opts) catch |e| {
        err("Init({s}): status {d}: {s}", .{ profile, itb.statusOf(e).code(), itb.lastError() });
        return false;
    };
    const blob = pipe.save() catch |e| {
        err("Save({s}): status {d}: {s}", .{ profile, itb.statusOf(e).code(), itb.lastError() });
        pipe.deinit();
        return false;
    };
    if (cfg.blob_mode == 2) {
        // The sizing mode is not an Opts knob: the Init blob is edited
        // and the pipeline reopened from it, so the retained blob (the
        // one blob-cycle reopens from) carries the edited mode.
        if (!editInnerBlobMode(blob, 2)) {
            err("rewrite blob mode: inner blob mode field not found", .{});
            pipe.deinit();
            gpa.free(blob);
            return false;
        }
        pipe.deinit();
        pipe = itb.Pipeline.load(gpa, blob, null) catch |e| {
            err("reload Mode 2 blob: status {d}: {s}", .{ itb.statusOf(e).code(), itb.lastError() });
            gpa.free(blob);
            return false;
        };
    }
    out_pipe.* = pipe;
    out_blob.* = blob;
    logPipelineInitialised(gpa, profile, blob);
    return true;
}

fn setNum(opts: itb.Opts, key: [:0]const u8, buf: []u8, value: anytype) void {
    const text = std.fmt.bufPrintZ(buf, "{d}", .{value}) catch return;
    opts.set(key, text) catch {};
}

fn run(gpa: std.mem.Allocator, argv: []const [*:0]const u8) u8 {
    var cfg = Config{};
    var profile_z: [:0]const u8 = "";
    switch (parseFlags(gpa, argv, &cfg, &profile_z)) {
        .help => return 0,
        .fail => return 2,
        .ok => {},
    }
    defer if (profile_z.len > 0) gpa.free(profile_z);

    // Runtime shaping. A long run under allocation churn grows the Go
    // heap inside the shared library without bound unless a soft limit
    // paces the collector, so a limit is always in force: an explicit
    // --memlimit is set as given, and auto caps the heap only when the
    // runtime reports no limit at all (a limit already installed from
    // the environment is left standing). The GC percentage and
    // GOMAXPROCS are set only when their flag is non-zero — a zero
    // flag skips the setter rather than calling it with zero, because
    // zero is a real value to the GC-percent setter, and a call would
    // clobber whatever the environment installed. All of it lands
    // before any Pipeline exists so the baselines are taken under the
    // shaped runtime.
    if (cfg.memlimit_auto) {
        if (itb.setMemoryLimit(-1) == std.math.maxInt(i64)) {
            _ = itb.setMemoryLimit(cfg.memlimit);
        }
    } else {
        _ = itb.setMemoryLimit(cfg.memlimit);
    }
    cfg.memlimit = itb.setMemoryLimit(-1);
    if (cfg.gogc > 0) _ = itb.setGcPercent(cfg.gogc);
    if (cfg.gomaxprocs > 0) _ = itb.setGomaxprocs(cfg.gomaxprocs);

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    var c: [64]u8 = undefined;
    line(
        "start: duration={s} iterations={d} goroutines={d} workers={d} concurrency={s} shape={s} hash={s} mac={s} payload={s} memlimit={s} parallax={s} wrapper={s}",
        .{
            size.humanDuration(&a, cfg.duration_ns), cfg.iterations,  cfg.workers_requested,
            cfg.workers,                             worker_mod.concurrency, cfg.shape.name(),
            cfg.hash,                                cfg.mac,         size.humanBytes(&b, cfg.payload_bytes),
            size.humanBytes(&c, cfg.memlimit),       onOff(cfg.parallax), onOff(cfg.wrapper),
        },
    );
    line(
        "overrides: profile=\"{s}\" key-bits={d} nonce-bits={d} chunk-size={s} barrier-fill={d} gomaxprocs={d} rekey-every={d} blob-cycle-every={d} payload-mode={s} seed={d} json-output={s}{s}{s}{s}",
        .{
            cfg.profile,     cfg.key_bits,    cfg.nonce_bits,
            size.humanBytes(&a, cfg.chunk_size), cfg.barrier_fill, cfg.gomaxprocs,
            cfg.rekey_every, cfg.blob_cycle_every, cfg.payload_mode.name(),
            cfg.seed,        if (cfg.json_output) "true" else "false",
            if (cfg.blob_mode != 1) (std.fmt.bufPrint(&b, " blob-mode={d}", .{cfg.blob_mode}) catch "") else "",
            if (cfg.drbg.len > 0) " drbg=" else "",
            cfg.drbg,
        },
    );
    const microbatch = policyLabel("ITB_MICROBATCH_TIERS");
    const hashpool = policyLabel("ITB_HASHPOOL_STARTERS");
    line("policy: microbatch-tiers={s} hashpool-starters={s}", .{ microbatch, hashpool });

    var r = RunState{ .gpa = gpa, .cfg = cfg };

    // Pipeline construction — one shared handle per exercised shape.
    // stream and stream_one_shot share the streaming handle.
    r.stream_profile = if (cfg.profile.len > 0) cfg.profile else default_stream_profile;
    r.msg_profile = if (cfg.profile.len > 0) cfg.profile else default_message_profile;
    const stream_z: [:0]const u8 = if (cfg.profile.len > 0) profile_z else default_stream_profile;
    const msg_z: [:0]const u8 = if (cfg.profile.len > 0) profile_z else default_message_profile;
    if (cfg.shape == .stream or cfg.shape == .stream_one_shot or cfg.shape == .both) {
        if (!buildPipeline(gpa, cfg, stream_z, profile_z, &r.stream_pipe, &r.stream_blob)) return 1;
    }
    if (cfg.shape == .message or cfg.shape == .both) {
        if (!buildPipeline(gpa, cfg, msg_z, profile_z, &r.msg_pipe, &r.msg_blob)) return 1;
    }
    defer {
        if (r.stream_pipe != null) r.stream_pipe.?.deinit();
        if (r.msg_pipe != null) r.msg_pipe.?.deinit();
        gpa.free(r.stream_blob);
        gpa.free(r.msg_blob);
    }

    // Allocation posture. Per-worker plaintexts are allocated once and
    // held for the whole run (rotating mode refills them in place per
    // iteration); the pump accumulators live inside each worker and
    // are reused across iterations; the message and one-shot outputs
    // are handed back by the binding per call and released per
    // iteration. Under the default fixed CSPRNG mode every worker's
    // buffer is distinct, so cross-worker data crossover is
    // detectable; pattern modes trade that property for content
    // edge-case coverage.
    var allocated: usize = 0;
    defer {
        for (r.workers[0..allocated]) |*w| {
            gpa.free(w.plaintext);
            w.wire.deinit(gpa);
            w.plain.deinit(gpa);
        }
    }
    while (allocated < cfg.workers) : (allocated += 1) {
        const plaintext = gpa.alloc(u8, @intCast(cfg.payload_bytes)) catch {
            err("payload alloc: out of memory", .{});
            return 1;
        };
        r.workers[allocated] = .{
            .id = allocated,
            .run = &r,
            .plaintext = plaintext,
            .payload_mode = cfg.payload_mode,
            .seeded = cfg.seed != 0,
            .rng = payload.seedWorker(cfg.seed, allocated),
        };
        const w = &r.workers[allocated];
        if (!payload.fillPayload(cfg.payload_mode, w.seeded, &w.rng, w.plaintext)) {
            err("payload fill: csprng", .{});
            allocated += 1;
            return 1;
        }
    }

    if (itb.poolStatsLen() == 0) {
        err("pool snapshot alloc failed", .{});
        return 1;
    }

    _ = signal(@intFromEnum(std.c.SIG.INT), onSignal);
    _ = signal(@intFromEnum(std.c.SIG.TERM), onSignal);
    r.warmup_done = worker_mod.Barrier.init(cfg.workers + 1);
    r.release = worker_mod.Barrier.init(cfg.workers + 1);
    r.active = cfg.workers;

    // Warmup barrier. Every worker runs one iteration and waits; the
    // clock starts only once all of them have paid their first-call
    // costs (pool warm-up, lazy kernel dispatch, page faults on the
    // payload buffers), and the RSS and pool baselines taken here
    // describe a process that has already run the whole cipher path
    // once per worker.
    const warmup_start = size.nowNanos();
    var spawned: usize = 0;
    while (spawned < cfg.workers) : (spawned += 1) {
        r.workers[spawned].thread = std.Thread.spawn(.{}, worker_mod.workerMain, .{&r.workers[spawned]}) catch {
            err("thread spawn failed", .{});
            return 1;
        };
    }
    r.warmup_done.wait();
    const rss0 = summary.readRss();
    r.rss_warmup = rss0.current;
    r.rss_peak = rss0.peak;
    r.pool_warmup = summary.poolSnapshot(gpa);
    defer gpa.free(r.pool_warmup);
    const warmup_ns = size.nowNanos() - warmup_start;
    line("warmup: {d} workers x 1 iter completed in {s} (baseline rss={s})", .{
        cfg.workers,
        size.humanDuration(&a, @divTrunc(warmup_ns + 50_000_000, 100_000_000) * 100_000_000),
        size.humanBytes(&b, @intCast(r.rss_warmup)),
    });

    // Open the gate; the duration timer is a deadline the waiter below
    // enforces in duration mode.
    r.start_ns = size.nowNanos();
    r.finish_ns = r.start_ns;
    r.release.wait();

    // Wait for every worker, polling every 100 ms so the deadline and
    // a signal are both noticed promptly.
    _ = std.c.pthread_mutex_lock(&r.done_mu);
    while (r.active > 0) {
        if (signal_seen.load(.monotonic)) r.stop.store(true, .monotonic);
        if (cfg.iterations == 0 and size.nowNanos() - r.start_ns >= cfg.duration_ns) {
            r.stop.store(true, .monotonic);
        }
        var until: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &until);
        until.nsec += 100_000_000;
        if (until.nsec >= 1_000_000_000) {
            until.sec += 1;
            until.nsec -= 1_000_000_000;
        }
        _ = std.c.pthread_cond_timedwait(&r.done_cv, &r.done_mu, &until);
    }
    _ = std.c.pthread_mutex_unlock(&r.done_mu);
    for (r.workers[0..cfg.workers]) |*w| {
        if (w.thread) |t| t.join();
    }
    const elapsed_ns = r.finish_ns - r.start_ns;
    const rss1 = summary.readRss();
    r.rss_final = rss1.current;
    r.rss_peak = rss1.peak;
    r.pool_steady = summary.poolSnapshot(gpa);
    defer gpa.free(r.pool_steady);

    if (cfg.memprofile.len > 0) {
        const path = gpa.dupeZ(u8, cfg.memprofile) catch {
            err("memprofile: out of memory", .{});
            return 1;
        };
        defer gpa.free(path);
        if (itb.writeHeapProfile(path)) |_| {
            line("memprofile: heap profile written to {s}", .{cfg.memprofile});
        } else |_| {
            err("memprofile: {s}", .{itb.lastError()});
        }
    }

    r.cfg = cfg;
    return summary.finalSummary(&r, elapsed_ns, microbatch, hashpool);
}

/// Zig-specific. The allocator is libc's rather than the one the
/// process hands over: every worker thread allocates from it
/// concurrently, and libc's is thread-safe without a wrapper.
pub fn main(init: std.process.Init) u8 {
    // Zig-specific. The standard library's threaded I/O layer installs
    // an empty handler for SIGPIPE while it starts, so a write to a
    // closed stdout returns an error the writer drops and the process
    // runs on, exiting 0 with its verdict undelivered. Restoring the
    // signal's default disposition (a null handler) before the first
    // line is printed ends the process on the first such write, which
    // is what every other implementation does and what a fleet driver
    // expects.
    _ = signal(@intFromEnum(std.c.SIG.PIPE), null);
    return run(std.heap.c_allocator, init.minimal.args.vector);
}
