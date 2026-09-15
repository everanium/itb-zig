//! Init → rekey → load receiver with the rotated blob → round trip.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

test "rekey refreshes the blob and the pair still round-trips" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();

    const before = try sender.save();
    defer gpa.free(before);

    const perm = [_]u8{0x11} ** 32;
    const wrap = [_]u8{0x22} ** 32;
    const rotated = try sender.rekey(&perm, &wrap);
    defer gpa.free(rotated);
    try std.testing.expect(!std.mem.eql(u8, before, rotated));
    const after = try sender.save();
    defer gpa.free(after);
    try std.testing.expectEqualSlices(u8, rotated, after);

    var receiver = try itb.Pipeline.load(gpa, rotated, null);
    defer receiver.deinit();

    const plain = "post-rekey payload";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
