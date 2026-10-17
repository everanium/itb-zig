//! Init → save → load → encryptMessage → decryptMessage round trip.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

test "smoke round trip" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    const blob = try sender.save();
    defer gpa.free(blob);
    try std.testing.expect(blob.len > 0);

    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = "smoke round-trip payload";

    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len != plain.len or !std.mem.eql(u8, wire, plain));

    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}

test "initKeys determinism and errors" {
    const gpa = std.testing.allocator;

    const k0 = [_]u8{0x11} ** 32;
    const k1 = [_]u8{0x22} ** 32;
    const k2 = [_]u8{0x33} ** 32;
    const k3 = [_]u8{0x44} ** 32;
    const k4 = [_]u8{0x55} ** 32;
    const k5 = [_]u8{0x66} ** 32;
    const k6 = [_]u8{0x77} ** 32;
    const k7 = [_]u8{0x88} ** 32;
    const masters = [_][]const u8{ &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7 };

    var p1 = try itb.Pipeline.initKeys(gpa, "singlemsg-triple-mac-v1", null, &masters);
    defer p1.deinit();
    var p2 = try itb.Pipeline.initKeys(gpa, "singlemsg-triple-mac-v1", null, &masters);
    defer p2.deinit();

    const b1 = try p1.save();
    defer gpa.free(b1);
    const b2 = try p2.save();
    defer gpa.free(b2);
    try std.testing.expectEqualSlices(u8, b1, b2);

    const plain = "initKeys determinism payload";
    const wire = try p1.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try p2.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);

    const dup = [_][]const u8{ &k0, &k0, &k2, &k3, &k4, &k5, &k6, &k7 };
    try std.testing.expectError(
        error.BadInput,
        itb.Pipeline.initKeys(gpa, "singlemsg-triple-mac-v1", null, &dup),
    );

    const short_k = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const short = [_][]const u8{ &short_k, &k1, &k2, &k3, &k4, &k5, &k6, &k7 };
    try std.testing.expectError(
        error.BadInput,
        itb.Pipeline.initKeys(gpa, "singlemsg-triple-mac-v1", null, &short),
    );
}
