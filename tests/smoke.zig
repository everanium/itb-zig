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
