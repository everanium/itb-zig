//! Status codes relayed from the C binding / libitb3.

const std = @import("std");
const ffi = @import("ffi.zig").c;

/// Mirrors the C binding's `itb_status` numerically. Codes 11..13 are
/// the Triple blob-record / registry sentinels, 14..17 a reserved
/// block; 19..22 belong to the native Blob surface
/// (not wrapped here but relayed verbatim if libitb3 ever returns
/// them). The enum is non-exhaustive so an unknown future code is
/// carried through rather than trapping.
pub const Status = enum(c_uint) {
    ok = 0,
    bad_hash = 1,
    bad_key_bits = 2,
    bad_handle = 3,
    bad_input = 4,
    buffer_too_small = 5,
    encrypt_failed = 6,
    decrypt_failed = 7,
    seed_width_mix = 8,
    bad_mac = 9,
    mac_failure = 10,
    blob_malformed_recipe = 11,
    recipe_primitive_unknown = 12,
    unknown_profile = 13,
    reserved_14 = 14,
    reserved_15 = 15,
    reserved_16 = 16,
    reserved_17 = 17,
    blob_mode_mismatch = 19,
    blob_malformed = 20,
    blob_version_too_new = 21,
    blob_too_many_opts = 22,
    stream_truncated = 23,
    stream_after_final = 24,
    triple_closed = 25,
    profile_exists = 26,
    internal = 99,
    _,

    /// Wraps a raw C return code without validation.
    pub fn fromRaw(rc: c_uint) Status {
        return @enumFromInt(rc);
    }

    /// The numeric code this status carries. The printed form of a
    /// failure quotes the number beside the library's own sentence,
    /// so a caller reads it here rather than keeping a table.
    pub fn code(self: Status) c_uint {
        return @intFromEnum(self);
    }
};
