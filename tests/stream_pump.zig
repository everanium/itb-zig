//! Round trip through the whole-buffer stream pumps on a Streaming
//! AEAD profile at 1 MiB.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

test "stream pump round trip" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const size: usize = 1 << 20;
    const plain = try gpa.alloc(u8, size);
    defer gpa.free(plain);
    var x: u64 = 0x9E3779B9;
    for (plain) |*b| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b.* = @truncate(x);
    }

    const wire = try sender.encryptStreamPump(plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len > 0);

    const back = try receiver.decryptStreamPump(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
