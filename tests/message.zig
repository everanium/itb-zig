//! Single Message round trip across every shipped cipher-bearing
//! profile at small (4 KiB) and medium (256 KiB) payloads.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

/// Deterministic non-trivial payload (xorshift fill). Caller frees.
fn payload(gpa: std.mem.Allocator, n: usize, seed: u64) ![]u8 {
    const buf = try gpa.alloc(u8, n);
    var x = seed | 1;
    for (buf) |*b| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        b.* = @truncate(x);
    }
    return buf;
}

fn roundTrip(profile: [:0]const u8, size: usize) !void {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, profile, null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const plain = try payload(gpa, size, size);
    defer gpa.free(plain);

    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}

test "message round trip per profile and size" {
    const profiles = [_][:0]const u8{
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    };
    const sizes = [_]usize{ 4 * 1024, 256 * 1024 };
    for (profiles) |profile| {
        for (sizes) |size| {
            try roundTrip(profile, size);
        }
    }
}

test "empty plaintext is rejected with BadInput" {
    // Go core rejects zero-length plaintext uniformly with
    // ErrEmptyInput -> error.BadInput before any wire is produced. An
    // empty message has no cover story: it is always distinguishable
    // at some layer (wire length, timing, traffic count). Callers for
    // whom an empty signal is meaningful send a marker byte instead.
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();

    try std.testing.expectError(
        error.BadInput,
        sender.encryptMessage(&.{}),
    );
}
