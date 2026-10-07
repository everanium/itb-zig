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

/// The `Status` an `Error` value was mapped from — the inverse of
/// `check`, for a caller that has to quote the numeric code beside the
/// library's diagnostic.
///
/// The mapping `check` performs is lossy at its edges: the reserved
/// block 14..17 and any code the table does not name both arrive as
/// `Error.Internal`, so both come back as `.internal` (99). Every code
/// the table names round-trips exactly. `OutOfMemory` originates on
/// the Zig side of the wrapper rather than in the library and has no
/// code of its own, so it maps to `.internal` too.
pub fn statusOf(e: Error) Status {
    return switch (e) {
        Error.BadHash => .bad_hash,
        Error.BadKeyBits => .bad_key_bits,
        Error.BadHandle => .bad_handle,
        Error.BadInput => .bad_input,
        Error.BufferTooSmall => .buffer_too_small,
        Error.EncryptFailed => .encrypt_failed,
        Error.DecryptFailed => .decrypt_failed,
        Error.SeedWidthMix => .seed_width_mix,
        Error.BadMac => .bad_mac,
        Error.MacFailure => .mac_failure,
        Error.BlobMalformedRecipe => .blob_malformed_recipe,
        Error.RecipePrimitiveUnknown => .recipe_primitive_unknown,
        Error.UnknownProfile => .unknown_profile,
        Error.BlobModeMismatch => .blob_mode_mismatch,
        Error.BlobMalformed => .blob_malformed,
        Error.BlobVersionTooNew => .blob_version_too_new,
        Error.BlobTooManyOpts => .blob_too_many_opts,
        Error.StreamTruncated => .stream_truncated,
        Error.StreamAfterFinal => .stream_after_final,
        Error.TripleClosed => .triple_closed,
        Error.ProfileExists => .profile_exists,
        Error.Internal, Error.OutOfMemory => .internal,
    };
}
