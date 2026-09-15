//! Explicit write / end / read round trip with pathological batch
//! sizes (17-byte feed, 23-byte drain) across multiple chunks.

const std = @import("std");
const itb = @import("itb3");

/// Feeds src in 17-byte writes, ends, drains in 23-byte reads.
/// Caller frees the returned buffer.
fn feedDrain(
    gpa: std.mem.Allocator,
    session: anytype,
    src: []const u8,
) ![]u8 {
    var off: usize = 0;
    while (off < src.len) {
        const n = @min(src.len - off, 17);
        try session.write(src[off .. off + n]);
        off += n;
    }
    try session.end();

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (true) {
        var piece: [23]u8 = undefined;
        const r = try session.read(&piece);
        try out.appendSlice(gpa, piece[0..r.n]);
        if (r.finished) return out.toOwnedSlice(gpa);
    }
}

test "incremental sessions with pathological batch sizes" {
    const gpa = std.testing.allocator;

    // Small chunk size so the 64 KiB payload spans many chunks.
    const opts = try itb.Opts.init();
    defer opts.deinit();
    try opts.set("chunkSize", "4096");

    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", opts);
    defer sender.deinit();
    const blob = try sender.save();
    defer gpa.free(blob);
    var receiver = try itb.Pipeline.load(gpa, blob, null);
    defer receiver.deinit();

    const size: usize = 65536;
    const plain = try gpa.alloc(u8, size);
    defer gpa.free(plain);
    for (plain, 0..) |*b, i| b.* = @truncate(i % 241);

    var enc = try sender.encryptStream();
    defer enc.deinit();
    const wire = try feedDrain(gpa, &enc, plain);
    defer gpa.free(wire);
    try std.testing.expect(wire.len > 0);

    var dec = try receiver.decryptStream();
    defer dec.deinit();
    const back = try feedDrain(gpa, &dec, wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}
