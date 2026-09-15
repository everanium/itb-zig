//! A decrypt session fed a tampered wire fails with a sticky
//! `error.MacFailure`.
//!
//! A single bit flip can land in the container's CSPRNG residue —
//! over-sized container area that carries no payload — where the
//! decrypt legitimately completes clean. The test therefore probes
//! successive flip positions, each against a fresh session on a
//! fresh copy of the wire, until one lands in authenticated content;
//! the observed failure must be MAC failure and must be sticky. The
//! probe is black-box — no wire-layout knowledge is used.

const std = @import("std");
const itb = @import("itb3");

/// Save → Load handshake: a receiver reconstructed from the sender's
/// current blob.
fn loadFrom(gpa: std.mem.Allocator, sender: *const itb.Pipeline) !itb.Pipeline {
    const blob = try sender.save();
    defer gpa.free(blob);
    return itb.Pipeline.load(gpa, blob, null);
}

/// Feeds one tampered wire copy through a fresh decrypt session.
/// Returns false when the session finishes clean (flip landed in
/// unauthenticated residue), true when it failed with the expected
/// sticky MAC failure; any other failure shape is a test error.
fn probeOnce(
    gpa: std.mem.Allocator,
    receiver: *itb.Pipeline,
    wire: []const u8,
    flip_pos: usize,
) !bool {
    const tampered = try gpa.dupe(u8, wire);
    defer gpa.free(tampered);
    tampered[flip_pos] ^= 0x01;

    var sess = try receiver.decryptStream();
    defer sess.deinit();

    // The failure may surface on write (chain already failed) or on
    // a later read — either way a read must eventually report it.
    sess.write(tampered) catch {};
    sess.end() catch {};

    var buf: [4096]u8 = undefined;
    while (true) {
        const r = sess.read(&buf) catch |first| {
            try std.testing.expectEqual(error.MacFailure, first);
            // Sticky: a subsequent read reports the same error.
            try std.testing.expectError(error.MacFailure, sess.read(&buf));
            return true;
        };
        if (r.finished) return false;
    }
}

test "tampered wire fails with sticky MacFailure" {
    const gpa = std.testing.allocator;

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();
    var receiver = try loadFrom(gpa, &sender);
    defer receiver.deinit();

    const size: usize = 65536;
    const plain = try gpa.alloc(u8, size);
    defer gpa.free(plain);
    for (plain, 0..) |*b, i| b.* = @truncate(i % 227);

    const wire = try sender.encryptStreamPump(plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len > 0);

    var seen_failure = false;
    var attempt: usize = 0;
    while (attempt < 32 and !seen_failure) : (attempt += 1) {
        const flip_pos = (wire.len * 3 / 4 + attempt * 1031) % wire.len;
        seen_failure = try probeOnce(gpa, &receiver, wire, flip_pos);
    }
    try std.testing.expect(seen_failure);
}
