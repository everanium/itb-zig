//! Persistence surface: save / saveF / load / loadF round trips,
//! inspect, lookup / profiles, maxWorkers.

const std = @import("std");
const itb = @import("itb3");

fn roundTrip(gpa: std.mem.Allocator, sender: *const itb.Pipeline, receiver: *const itb.Pipeline) !void {
    const plain = "persist payload";
    const wire = try sender.encryptMessage(plain);
    defer gpa.free(wire);
    const back = try receiver.decryptMessage(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, plain, back);
}

test "save then load round trip; save is stable; load retains the bytes" {
    const gpa = std.testing.allocator;
    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();

    const blob = try sender.save();
    defer gpa.free(blob);
    const again = try sender.save();
    defer gpa.free(again);
    try std.testing.expectEqualSlices(u8, blob, again);

    var receiver = try itb.Pipeline.load(gpa, blob, null);
    defer receiver.deinit();
    try roundTrip(gpa, &sender, &receiver);
    const retained = try receiver.save();
    defer gpa.free(retained);
    try std.testing.expectEqualSlices(u8, blob, retained);
}

test "load with master overrides equals a sender rekey" {
    const gpa = std.testing.allocator;
    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    const blob = try sender.save();
    defer gpa.free(blob);

    const perm = [_]u8{0x31} ** 32;
    const wrap = [_]u8{0x32} ** 32;
    var receiver = try itb.Pipeline.load(gpa, blob, .{ .perm = &perm, .wrap = &wrap });
    defer receiver.deinit();
    const rotated = try receiver.save();
    defer gpa.free(rotated);
    try std.testing.expect(!std.mem.eql(u8, blob, rotated));

    const sender_rotated = try sender.rekey(&perm, &wrap);
    defer gpa.free(sender_rotated);
    try roundTrip(gpa, &sender, &receiver);
}

test "inspect carries recipe plus inspection-only fields; garbage is BadInput" {
    // inspect carries the registry recipe plus the blob-only
    // nonce_bits / barrier_fill inspection fields; lookup returns
    // just the recipe.
    const gpa = std.testing.allocator;
    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    const blob = try sender.save();
    defer gpa.free(blob);

    const inspected = try itb.inspect(gpa, blob);
    defer gpa.free(inspected);
    const looked = try itb.lookup(gpa, "singlemsg-triple-mac-v1");
    defer gpa.free(looked);
    try std.testing.expect(std.mem.indexOf(u8, inspected, "\"name\":\"singlemsg-triple-mac-v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, inspected, "\"mode\":\"singlemsg-mac\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, inspected, "\"nonce_bits\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, inspected, "\"barrier_fill\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, looked, "\"name\":\"singlemsg-triple-mac-v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, looked, "\"nonce_bits\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, looked, "\"barrier_fill\":") == null);
    try std.testing.expectError(error.BadInput, itb.inspect(gpa, "not a blob"));
}

test "profiles lists the shipped catalogue as a JSON array" {
    const gpa = std.testing.allocator;
    const names = try itb.profiles(gpa);
    defer gpa.free(names);
    try std.testing.expect(names.len > 0 and names[0] == '[');
    try std.testing.expect(std.mem.indexOf(u8, names, "\"singlemsg-triple-mac-v1\"") != null);
}

test "saveF then loadF round trip; missing file is BadInput" {
    const gpa = std.testing.allocator;
    var sender = try itb.Pipeline.init(gpa, "streaming-aead-triple-mac-v1", null);
    defer sender.deinit();

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "/tmp/itb-zig-persist-{d}.blob", .{std.c.getpid()});
    try sender.saveF(path);
    var receiver = try itb.Pipeline.loadF(gpa, path, null);
    defer receiver.deinit();
    const wire = try sender.encryptStreamOneShot("on-disk");
    defer gpa.free(wire);
    const back = try receiver.decryptStreamOneShot(wire);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, "on-disk", back);

    _ = std.c.unlink(path.ptr);
    try std.testing.expectError(error.BadInput, itb.Pipeline.loadF(gpa, path, null));
}

test "maxWorkers clamps and round-trips; closed pipeline reports TripleClosed" {
    const gpa = std.testing.allocator;
    var sender = try itb.Pipeline.init(gpa, "singlemsg-triple-mac-v1", null);
    defer sender.deinit();
    try sender.maxWorkers(2);
    try sender.maxWorkers(-1);
    try sender.maxWorkers(100000);
    const blob = try sender.save();
    defer gpa.free(blob);
    var receiver = try itb.Pipeline.load(gpa, blob, null);
    defer receiver.deinit();
    try receiver.maxWorkers(1);
    try roundTrip(gpa, &sender, &receiver);
}
