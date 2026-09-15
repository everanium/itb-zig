//! Round trip through the whole-buffer stream one-shot pair on a
//! Streaming AEAD profile, wire interchangeability with the stream
//! pumps, and tamper rejection.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

fn fillPayload(buf: []u8, seed: u64) void {
    var x: u64 = seed | 1;
    for (buf) |*b| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b.* = @truncate(x);
    }
}

test "stream one-shot round trip" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(plain);
    fillPayload(plain, 0x51D3A7C1);

    const wire = try sender.encryptStreamOneShot(plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len > 0);

    const back = try receiver.decryptStreamOneShot(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}

test "stream one-shot wire interchanges with the pump" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = try gpa.alloc(u8, 65536);
    defer gpa.free(plain);
    fillPayload(plain, 0xB005EED1);

    // The one-shot wire is a stream wire: the pump decrypts it, and
    // the one-shot decrypts a pump-produced wire.
    const wire = try sender.encryptStreamOneShot(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptStreamPump(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);

    const pump_wire = try sender.encryptStreamPump(plain);
    defer gpa.free(pump_wire);
    const back2 = try receiver.decryptStreamOneShot(pump_wire);
    defer gpa.free(back2);
    try std.testing.expectEqualSlices(u8, plain, back2);
}

test "stream one-shot rejects a tampered wire" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = try gpa.alloc(u8, 65536);
    defer gpa.free(plain);
    fillPayload(plain, 0x0E5B);

    const wire = try sender.encryptStreamOneShot(plain);
    defer gpa.free(wire);

    // A single bit flip can land in the container's CSPRNG residue,
    // where the decrypt legitimately completes clean — probe
    // successive positions until one lands in authenticated content.
    // The probe is black-box.
    var seen_failure = false;
    var attempt: usize = 0;
    while (attempt < 32 and !seen_failure) : (attempt += 1) {
        const flip_pos = (wire.len * 3 / 4 + attempt * 1031) % wire.len;
        const tampered = try gpa.dupe(u8, wire);
        defer gpa.free(tampered);
        tampered[flip_pos] ^= 0x01;

        if (receiver.decryptStreamOneShot(tampered)) |back| {
            // Flip landed in unauthenticated residue.
            defer gpa.free(back);
            try std.testing.expectEqualSlices(u8, plain, back);
        } else |e| {
            try std.testing.expectEqual(error.MacFailure, e);
            seen_failure = true;
        }
    }
    try std.testing.expect(seen_failure);

    // The untampered wire still round-trips.
    const back = try receiver.decryptStreamOneShot(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
