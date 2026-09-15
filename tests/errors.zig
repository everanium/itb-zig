//! Error-mapping surface: opaque-string relay, unknown profile,
//! opts-builder rendering, profile registration, duplicate-profile
//! status.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

test "unknown profile is rejected Go-side" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(
        error.UnknownProfile,
        itb.Pipeline.init(gpa, "no-such-profile", null),
    );
    try std.testing.expect(itb.lastError().len > 0);
    try std.testing.expectError(
        error.UnknownProfile,
        itb.lookup(gpa, "no-such-profile"),
    );
}

test "negative maxWorkers opts value is clamped" {
    const gpa = std.testing.allocator;
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try opts.set("maxWorkers", "-1");
    var pipe = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", opts);
    defer pipe.deinit();
}

test "unknown opts key is rejected Go-side" {
    const gpa = std.testing.allocator;
    const opts = try itb.Opts.init();
    defer opts.deinit();
    // Typoed lowercase s — the builder itself performs no validation.
    try opts.set("chunksize", "4096");
    try std.testing.expectError(
        error.BadInput,
        itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", opts),
    );
}

test "unknown inner hash name is relayed and rejected" {
    const gpa = std.testing.allocator;
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try opts.set("innerHash", "no-such-hash");
    const result = itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", opts);
    try std.testing.expect(if (result) |_| false else |_| true);
}

test "opts builder renders insertion order and percent-encodes" {
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try std.testing.expectEqualStrings("", opts.query());
    try opts.set("chunkSize", "4096");
    try opts.set("parallaxPalette", "aescmac,chacha20,blake3");
    try std.testing.expectEqualStrings(
        "chunkSize=4096&parallaxPalette=aescmac,chacha20,blake3",
        opts.query(),
    );

    const enc = try itb.Opts.init();
    defer enc.deinit();
    try enc.set("mode", "a b&c=d%");
    try std.testing.expectEqualStrings("mode=a%20b%26c%3Dd%25", enc.query());
}

test "register profile, use it, duplicate is ProfileExists" {
    const gpa = std.testing.allocator;

    // 8-entry width-256 hashes constellation, layers off; the record
    // is a profile JSON object.
    const reg =
        \\{"mode":"singlemsg-nomac","width":256,
        \\"hashes":["blake3","blake2s","areion256","blake2b256",
        \\"chacha20","blake3","blake2s","areion256"],
        \\"keybits":1024,"wrapper":false,"parallax":false}
    ;
    try itb.register("zig-binding-test-mixed", reg);

    // The registered record reads back with its name filled in.
    const looked = try itb.lookup(gpa, "zig-binding-test-mixed");
    defer gpa.free(looked);
    try std.testing.expect(std.mem.indexOf(u8, looked, "\"name\":\"zig-binding-test-mixed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, looked, "\"hashes\":[\"blake3\",\"blake2s\"") != null);

    // A non-empty name inside the record must equal the argument.
    try std.testing.expectError(error.BadInput, itb.register(
        "zig-binding-test-mismatch",
        \\{"name":"other","mode":"singlemsg-nomac","width":512,"hash":"areion512",
        \\"keybits":1024,"wrapper":false,"parallax":false}
    ,
    ));

    var sender = try itb.Pipeline.init(gpa, "zig-binding-test-mixed", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = "custom profile";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);

    try std.testing.expectError(
        error.ProfileExists,
        itb.register("zig-binding-test-mixed", reg),
    );
}
