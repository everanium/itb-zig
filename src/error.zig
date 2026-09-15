//! Error mapping: `itb_status` return codes → a Zig error set.

const std = @import("std");
const ffi = @import("ffi.zig").c;
const Status = @import("status.zig").Status;

/// One error per non-OK `Status` name, plus `OutOfMemory` from the
/// allocator side of the wrapper. The reserved sentinel block and any
/// unknown future code collapse to `Internal`; the precise numeric
/// code for those is available via `lastError` context on the C side.
pub const Error = error{
    BadHash,
    BadKeyBits,
    BadHandle,
    BadInput,
    BufferTooSmall,
    EncryptFailed,
    DecryptFailed,
    SeedWidthMix,
    BadMac,
    MacFailure,
    BlobMalformedRecipe,
    RecipePrimitiveUnknown,
    UnknownProfile,
    BlobModeMismatch,
    BlobMalformed,
    BlobVersionTooNew,
    BlobTooManyOpts,
    StreamTruncated,
    StreamAfterFinal,
    TripleClosed,
    ProfileExists,
    Internal,
    OutOfMemory,
};

/// Maps a raw C return code to `Error` (`{}` for OK).
pub fn check(rc: c_uint) Error!void {
    return switch (Status.fromRaw(rc)) {
        .ok => {},
        .bad_hash => Error.BadHash,
        .bad_key_bits => Error.BadKeyBits,
        .bad_handle => Error.BadHandle,
        .bad_input => Error.BadInput,
        .buffer_too_small => Error.BufferTooSmall,
        .encrypt_failed => Error.EncryptFailed,
        .decrypt_failed => Error.DecryptFailed,
        .seed_width_mix => Error.SeedWidthMix,
        .bad_mac => Error.BadMac,
        .mac_failure => Error.MacFailure,
        .blob_malformed_recipe => Error.BlobMalformedRecipe,
        .recipe_primitive_unknown => Error.RecipePrimitiveUnknown,
        .unknown_profile => Error.UnknownProfile,
        .blob_mode_mismatch => Error.BlobModeMismatch,
        .blob_malformed => Error.BlobMalformed,
        .blob_version_too_new => Error.BlobVersionTooNew,
        .blob_too_many_opts => Error.BlobTooManyOpts,
        .stream_truncated => Error.StreamTruncated,
        .stream_after_final => Error.StreamAfterFinal,
        .triple_closed => Error.TripleClosed,
        .profile_exists => Error.ProfileExists,
        else => Error.Internal,
    };
}

/// The Go-side diagnostic recorded by the most recent failing libitb3
/// call ("" when no diagnostic). The underlying store is
/// process-global last-write-wins — fetch it immediately after the
/// failing call; under concurrent use the text may belong to a
/// different call, while the error value itself is always
/// attributable to the immediate return.
pub fn lastError() [:0]const u8 {
    return std.mem.span(ffi.itb_last_error());
}
