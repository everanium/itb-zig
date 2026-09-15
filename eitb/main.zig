//! eitb — command-line demonstrator for the ITB Zig binding.
//!
//! Subcommands:
//!
//!   eitb version                                   library + binding versions
//!   eitb profiles                                  registered profile catalogue
//!   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//!   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//!
//! `encrypt` prints the session blob to stderr as hex; feed that hex
//! back to `decrypt` on the receiving side. The blob-hex argument is
//! parsed tolerantly: case-insensitive, optional `0x` prefix, and
//! embedded whitespace are all accepted. `profiles` lists the
//! registered profile catalogue one name per line; the profiles that
//! carry a cipher surface are the ones `encrypt` / `decrypt` accept.

const std = @import("std");
const itb = @import("itb3");

fn usage() u8 {
    std.debug.print(
        \\usage: eitb version
        \\       eitb profiles
        \\       eitb encrypt <profile> <in-file> <out-file>
        \\       eitb decrypt <profile> <blob-hex> <in-file> <out-file>
        \\
    , .{});
    return 2;
}

fn failWith(what: []const u8, e: itb.Error) u8 {
    std.debug.print("eitb: {s}: {t}: {s}\n", .{ what, e, itb.lastError() });
    return 1;
}

fn print(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, fmt, args);
    try std.Io.File.stdout().writeStreamingAll(io, line);
}

/// Defensive Go-runtime pacing for cipher workloads on large files:
/// a soft memory cap + aggressive GC keep the scratch heap bounded.
/// The setter return values report the previous settings, not an
/// error.
fn capGoRuntime() void {
    _ = itb.setMemoryLimit(4 << 30); // 4 GiB soft cap
    _ = itb.setGcPercent(100); // balanced GC
}

/// Profiles whose canonical name begins with "streaming-" route
/// through the one-shot streaming buffered pair instead of the
/// Single Message pair.
fn isStreamingProfile(profile: []const u8) bool {
    return std.mem.startsWith(u8, profile, "streaming-");
}

/// Recursively create the parent directory of `path` (mkdir -p).
/// In Zig 0.16 `std.fs.cwd()` is gone; the cwd handle lives on
/// `std.Io.Dir` and mkdir-p is spelled `createDirPath(io, sub_path)`
/// which returns success when the path already exists.
fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const dir = std.fs.path.dirname(path) orelse return;
    if (dir.len == 0) return;
    try std.Io.Dir.cwd().createDirPath(io, dir);
}

fn cmdVersion(io: std.Io) !u8 {
    const v = itb.version();
    if (v.len == 0) {
        std.debug.print("eitb: cannot read libitb3 version\n", .{});
        return 1;
    }
    try print(io, "libitb3 {s}\n", .{v});
    try print(io, "itb-zig {s}\n", .{itb.binding_version});
    return 0;
}

/// Prints the registered profile catalogue one name per line in the
/// sorted order `itb.profiles` returns. The catalogue arrives as a
/// JSON array of strings; profile names are restricted to [a-z0-9-],
/// so each quoted run is one complete name and no escape handling is
/// needed.
fn cmdProfiles(gpa: std.mem.Allocator, io: std.Io) !u8 {
    const json = itb.profiles(gpa) catch |e| return failWith("profiles", e);
    defer gpa.free(json);
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, json, pos, '"')) |open| {
        const close = std.mem.indexOfScalarPos(u8, json, open + 1, '"') orelse break;
        try print(io, "{s}\n", .{json[open + 1 .. close]});
        pos = close + 1;
    }
    return 0;
}

fn cmdEncrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    profile: [:0]const u8,
    infile: []const u8,
    outfile: []const u8,
) !u8 {
    capGoRuntime();
    const plain = std.Io.Dir.cwd().readFileAlloc(io, infile, gpa, .unlimited) catch {
        std.debug.print("eitb: cannot read {s}\n", .{infile});
        return 1;
    };
    defer gpa.free(plain);

    var pipe = itb.Pipeline.init(gpa, profile, null) catch |e| return failWith("init", e);
    defer pipe.deinit();

    const wire = if (isStreamingProfile(profile))
        pipe.encryptStreamPump(plain) catch |e| return failWith("encrypt", e)
    else
        pipe.encryptMessage(plain) catch |e| return failWith("encrypt", e);
    defer gpa.free(wire);

    ensureParentDir(io, outfile) catch {
        std.debug.print("eitb: cannot mkdir -p for {s}\n", .{outfile});
        return 1;
    };
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = outfile, .data = wire }) catch {
        std.debug.print("eitb: cannot write {s}\n", .{outfile});
        return 1;
    };

    const blob = pipe.save() catch |e| return failWith("save", e);
    defer gpa.free(blob);
    const blob_hex = try gpa.alloc(u8, blob.len * 2);
    defer gpa.free(blob_hex);
    for (blob, 0..) |b, i| {
        _ = std.fmt.bufPrint(blob_hex[2 * i ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    }
    std.debug.print("{s}\n", .{blob_hex});
    try print(io, "encrypted {s} -> {s} ({d} -> {d} bytes)\n", .{
        infile, outfile, plain.len, wire.len,
    });
    return 0;
}

fn hexNibble(ch: u8) ?u4 {
    return switch (ch) {
        '0'...'9' => @truncate(ch - '0'),
        'a'...'f' => @truncate(ch - 'a' + 10),
        'A'...'F' => @truncate(ch - 'A' + 10),
        else => null,
    };
}

/// Tolerant blob-hex parse: whitespace stripped, optional 0x prefix,
/// case-insensitive. Caller frees the result.
fn parseBlobHex(gpa: std.mem.Allocator, raw: []const u8) ?[]u8 {
    var digits: std.ArrayList(u8) = .empty;
    defer digits.deinit(gpa);
    for (raw) |ch| {
        if (std.ascii.isWhitespace(ch)) continue;
        digits.append(gpa, ch) catch return null;
    }
    var hex: []const u8 = digits.items;
    if (hex.len >= 2 and hex[0] == '0' and (hex[1] == 'x' or hex[1] == 'X')) {
        hex = hex[2..];
    }
    if (hex.len == 0 or hex.len % 2 != 0) return null;
    const blob = gpa.alloc(u8, hex.len / 2) catch return null;
    for (blob, 0..) |*b, i| {
        const hi = hexNibble(hex[2 * i]) orelse {
            gpa.free(blob);
            return null;
        };
        const lo = hexNibble(hex[2 * i + 1]) orelse {
            gpa.free(blob);
            return null;
        };
        b.* = (@as(u8, hi) << 4) | lo;
    }
    return blob;
}

fn cmdDecrypt(
    gpa: std.mem.Allocator,
    io: std.Io,
    profile: [:0]const u8,
    blob_hex: []const u8,
    infile: []const u8,
    outfile: []const u8,
) !u8 {
    capGoRuntime();
    const blob = parseBlobHex(gpa, blob_hex) orelse {
        std.debug.print("eitb: invalid blob hex\n", .{});
        return 1;
    };
    defer gpa.free(blob);

    const wire = std.Io.Dir.cwd().readFileAlloc(io, infile, gpa, .unlimited) catch {
        std.debug.print("eitb: cannot read {s}\n", .{infile});
        return 1;
    };
    defer gpa.free(wire);

    // The profile shape travels inside the blob; the profile argument
    // only selects the Single Message or streaming cipher pair.
    var pipe = itb.Pipeline.load(gpa, blob, null) catch |e|
        return failWith("load", e);
    defer pipe.deinit();

    const plain = if (isStreamingProfile(profile))
        pipe.decryptStreamPump(wire) catch |e| return failWith("decrypt", e)
    else
        pipe.decryptMessage(wire) catch |e| return failWith("decrypt", e);
    defer gpa.free(plain);

    ensureParentDir(io, outfile) catch {
        std.debug.print("eitb: cannot mkdir -p for {s}\n", .{outfile});
        return 1;
    };
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = outfile, .data = plain }) catch {
        std.debug.print("eitb: cannot write {s}\n", .{outfile});
        return 1;
    };
    try print(io, "decrypted {s} -> {s} ({d} -> {d} bytes)\n", .{
        infile, outfile, wire.len, plain.len,
    });
    return 0;
}

pub fn main(init: std.process.Init) !u8 {
    const argv = init.minimal.args.vector;
    const gpa = init.gpa;
    const io = init.io;
    if (argv.len < 2) return usage();
    const cmd = std.mem.span(argv[1]);
    if (std.mem.eql(u8, cmd, "version") and argv.len == 2) {
        return cmdVersion(io);
    }
    if (std.mem.eql(u8, cmd, "profiles") and argv.len == 2) {
        return cmdProfiles(gpa, io);
    }
    if (std.mem.eql(u8, cmd, "encrypt") and argv.len == 5) {
        return cmdEncrypt(gpa, io, std.mem.span(argv[2]), std.mem.span(argv[3]), std.mem.span(argv[4]));
    }
    if (std.mem.eql(u8, cmd, "decrypt") and argv.len == 6) {
        return cmdDecrypt(gpa, io, std.mem.span(argv[2]), std.mem.span(argv[3]), std.mem.span(argv[4]), std.mem.span(argv[5]));
    }
    return usage();
}
