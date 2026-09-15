//! Triple Pipeline session over the C binding's `itb_pipeline` handle.

const std = @import("std");
const ffi = @import("ffi.zig").c;
const err = @import("error.zig");
const opts_mod = @import("opts.zig");
const stream = @import("stream.zig");

const Allocator = std.mem.Allocator;
const Opts = opts_mod.Opts;

/// Explicit master override pair for `Pipeline.load` / `loadF`. Both
/// slices must be non-empty (a half-supplied pair is rejected
/// Go-side).
pub const Masters = struct {
    perm: []const u8,
    wrap: []const u8,
};

/// A Triple Pipeline session. Every output buffer the cipher calls
/// return is owned by the caller and allocated from the `Allocator`
/// handed to `init` / `load` — release with `allocator.free`. Buffer
/// sizing and the BufferTooSmall retry-once dance live entirely in
/// the C layer; the Zig side performs no sizing of its own.
///
/// The wrapper adds no synchronisation: the Go-side Pipeline is safe
/// for concurrent cipher calls, and the Zig calls proxy straight
/// through, so the same posture holds — except `rekey` and `deinit`,
/// which must not run concurrently with cipher calls or open stream
/// sessions on the same Pipeline.
///
/// Streaming-decrypt caveat: chunked Streaming AEAD verifies per
/// chunk, so plaintext of verified chunks is released before a later
/// chunk can fail authentication.
pub const Pipeline = struct {
    allocator: Allocator,
    handle: *ffi.itb_pipeline,

    /// Constructs a fresh Pipeline against the named profile. `opts`
    /// is `null` for pure profile defaults. Release with `deinit`.
    pub fn init(allocator: Allocator, profile: [:0]const u8, opts: ?Opts) err.Error!Pipeline {
        var handle: ?*ffi.itb_pipeline = null;
        try err.check(ffi.itb_pipeline_init(profile.ptr, optsHandle(opts), &handle));
        return .{ .allocator = allocator, .handle = handle.? };
    }

    /// Reconstructs a Pipeline from a blob produced by `save` /
    /// `rekey`. `masters` is `null` to use the blob-embedded masters,
    /// or a pair to override them. The profile shape travels inside
    /// the blob — no profile name, no opts. A blob whose record names
    /// a primitive absent from the local build fails with
    /// `error.RecipePrimitiveUnknown`.
    pub fn load(allocator: Allocator, blob_bytes: []const u8, masters: ?Masters) err.Error!Pipeline {
        const m = masters orelse Masters{ .perm = &.{}, .wrap = &.{} };
        var handle: ?*ffi.itb_pipeline = null;
        try err.check(ffi.itb_pipeline_load(
            blob_bytes.ptr,
            blob_bytes.len,
            m.perm.ptr,
            m.perm.len,
            m.wrap.ptr,
            m.wrap.len,
            &handle,
        ));
        return .{ .allocator = allocator, .handle = handle.? };
    }

    /// `load` for a blob stored at `path`; the file is read inside
    /// libitb3 (a missing or unreadable file is `error.BadInput`).
    pub fn loadF(allocator: Allocator, path: [:0]const u8, masters: ?Masters) err.Error!Pipeline {
        const m = masters orelse Masters{ .perm = &.{}, .wrap = &.{} };
        var handle: ?*ffi.itb_pipeline = null;
        try err.check(ffi.itb_pipeline_load_f(
            path.ptr,
            m.perm.ptr,
            m.perm.len,
            m.wrap.ptr,
            m.wrap.len,
            &handle,
        ));
        return .{ .allocator = allocator, .handle = handle.? };
    }

    /// Closes (zeroing key material Go-side) and releases the handle.
    /// Call exactly once; the Pipeline must not be used afterwards,
    /// and no stream session may outlive it.
    pub fn deinit(self: *Pipeline) void {
        ffi.itb_pipeline_free(self.handle);
        self.handle = undefined;
    }

    /// The current session-bundle blob for the receiver side (the
    /// init blob, or the bytes of the latest `rekey`). Caller owns the
    /// result — release with `allocator.free`.
    pub fn save(self: *const Pipeline) err.Error![]u8 {
        var out: [*c]u8 = null;
        var out_len: usize = 0;
        const rc = ffi.itb_pipeline_save(self.handle, &out, &out_len);
        defer ffi.itb_bytes_free(out);
        try err.check(rc);
        return self.copyOut(out, out_len);
    }

    /// Writes the current blob to `path` inside libitb3 (mode 0600; the
    /// containing directory must exist).
    pub fn saveF(self: *const Pipeline, path: [:0]const u8) err.Error!void {
        try err.check(ffi.itb_pipeline_save_f(self.handle, path.ptr));
    }

    /// Sets the worker cap for every subsequent cipher call. `n` is
    /// clamped by libitb3 (`<= 0` selects auto, `> 256` becomes 256);
    /// only the handle state is reported.
    pub fn maxWorkers(self: *const Pipeline, n: i32) err.Error!void {
        try err.check(ffi.itb_pipeline_max_workers(self.handle, n));
    }

    /// Rotates the parallax + wrapper masters and returns the fresh
    /// blob (also available through `save`). Caller owns the result.
    /// Must not run concurrently with cipher calls or open stream
    /// sessions on the same Pipeline.
    pub fn rekey(self: *Pipeline, perm: []const u8, wrap: []const u8) err.Error![]u8 {
        var out: [*c]u8 = null;
        var out_len: usize = 0;
        const rc = ffi.itb_pipeline_rekey(
            self.handle,
            perm.ptr,
            perm.len,
            wrap.ptr,
            wrap.len,
            &out,
            &out_len,
        );
        defer ffi.itb_bytes_free(out);
        try err.check(rc);
        return self.copyOut(out, out_len);
    }

    /// Single Message encrypt: one call, one self-contained wire.
    /// Caller owns the result — release with `allocator.free`.
    pub fn encryptMessage(self: *const Pipeline, plain: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_encrypt_message, plain);
    }

    /// Receive-side counterpart of `encryptMessage`.
    pub fn decryptMessage(self: *const Pipeline, wire: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_decrypt_message, wire);
    }

    /// One-shot stream encrypt for callers holding the whole
    /// plaintext in memory: a single buffer-in / buffer-out FFI round
    /// trip through the Pipeline's stream chain. For bounded-memory
    /// streaming use `encryptStream` / `encryptStreamPump`. Caller
    /// owns the result — release with `allocator.free`.
    pub fn encryptStreamOneShot(self: *const Pipeline, plain: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_encrypt_stream_one_shot, plain);
    }

    /// Receive-side counterpart of `encryptStreamOneShot`.
    pub fn decryptStreamOneShot(self: *const Pipeline, wire: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_decrypt_stream_one_shot, wire);
    }

    /// Pumps the whole plaintext through an incremental encrypt
    /// session with bounded feed / drain slices C-side and returns
    /// the concatenated wire. Caller owns the result.
    pub fn encryptStreamPump(self: *const Pipeline, plain: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_encrypt_stream_pump, plain);
    }

    /// Receive-side counterpart of `encryptStreamPump`.
    pub fn decryptStreamPump(self: *const Pipeline, wire: []const u8) err.Error![]u8 {
        return self.cipher(ffi.itb_pipeline_decrypt_stream_pump, wire);
    }

    /// Opens an incremental encrypt session (plaintext in, wire out).
    /// Release with the session's `deinit` before this Pipeline's.
    pub fn encryptStream(self: *Pipeline) err.Error!stream.EncryptStream {
        return stream.EncryptStream.begin(self);
    }

    /// Opens an incremental decrypt session (wire in, plaintext out).
    pub fn decryptStream(self: *Pipeline) err.Error!stream.DecryptStream {
        return stream.DecryptStream.begin(self);
    }

    /// Shared body for the six buffer-in / buffer-out cipher
    /// entries: run the C call (which allocates the output and
    /// handles retry-once internally), copy into an allocator-owned
    /// slice, release the C buffer.
    fn cipher(
        self: *const Pipeline,
        func: CipherFn,
        src: []const u8,
    ) err.Error![]u8 {
        var out: [*c]u8 = null;
        var out_len: usize = 0;
        const rc = func(self.handle, src.ptr, src.len, &out, &out_len);
        defer ffi.itb_bytes_free(out); // NULL-safe; out is NULL on failure
        try err.check(rc);
        return self.copyOut(out, out_len);
    }

    fn copyOut(self: *const Pipeline, out: [*c]u8, out_len: usize) err.Error![]u8 {
        const copy = try self.allocator.alloc(u8, out_len);
        if (out_len > 0) @memcpy(copy, out[0..out_len]);
        return copy;
    }
};

const CipherFn = *const fn (
    ?*const ffi.itb_pipeline,
    [*c]const u8,
    usize,
    [*c][*c]u8,
    [*c]usize,
) callconv(.c) ffi.itb_status;

fn optsHandle(opts: ?Opts) ?*const ffi.itb_opts {
    return if (opts) |o| o.handle else null;
}
