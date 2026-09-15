//! Incremental stream sessions over an open `Pipeline`.
//!
//! A session is a dumb byte pump: `EncryptStream` takes plaintext in
//! through `write` and yields wire through `read` / `drainAll`;
//! `DecryptStream` is the mirror (wire in, plaintext out). All
//! chunking, MAC, envelope, and wire-format decisions stay inside
//! libitb3. `deinit` cancels a still-running session; the `parent`
//! pointer pins the Pipeline a session belongs to — the session must
//! be deinited before its Pipeline.

const std = @import("std");
const ffi = @import("ffi.zig").c;
const err = @import("error.zig");
const pipeline = @import("pipeline.zig");

const Pipeline = pipeline.Pipeline;

/// Result of one `read` drain.
pub const ReadResult = struct {
    /// Bytes written into `dst` (0 when nothing was available).
    n: usize,
    /// True once the session has ended AND the output is fully
    /// drained. Partial drains (`finished == false`) are the normal
    /// mode.
    finished: bool,
};

/// Drain slice size used by `drainAll`.
const drain_buf_len: usize = 1 << 20;

const Direction = enum { encrypt, decrypt };

fn Session(comptime direction: Direction) type {
    return struct {
        /// The Pipeline this session was begun on. The session must
        /// not outlive it; `drainAll` allocates from its allocator.
        parent: *Pipeline,
        handle: *ffi.itb_stream,
        ended: bool = false,

        const Self = @This();

        pub fn begin(parent: *Pipeline) err.Error!Self {
            var handle: ?*ffi.itb_stream = null;
            const rc = switch (direction) {
                .encrypt => ffi.itb_pipeline_encrypt_stream_begin(parent.handle, &handle),
                .decrypt => ffi.itb_pipeline_decrypt_stream_begin(parent.handle, &handle),
            };
            try err.check(rc);
            return .{ .parent = parent, .handle = handle.? };
        }

        /// Feeds `src` into the session. Blocks until the cipher
        /// chain accepts the bytes; errors are sticky. An empty
        /// `src` is a no-op.
        pub fn write(self: *Self, src: []const u8) err.Error!void {
            try err.check(ffi.itb_stream_write(self.handle, src.ptr, src.len));
        }

        /// Signals end-of-input. Idempotent; `write` after `end`
        /// fails with `error.BadInput`.
        pub fn end(self: *Self) err.Error!void {
            try err.check(ffi.itb_stream_end(self.handle));
            self.ended = true;
        }

        /// Drains up to `dst.len` produced bytes into `dst`. After
        /// `end`, an empty-spool read blocks until the terminal
        /// bytes arrive or the session errors.
        pub fn read(self: *Self, dst: []u8) err.Error!ReadResult {
            var n: usize = 0;
            var finished: c_int = 0;
            try err.check(ffi.itb_stream_read(self.handle, dst.ptr, dst.len, &n, &finished));
            return .{ .n = n, .finished = finished != 0 };
        }

        /// Calls `end` (if not yet called) and returns every
        /// remaining output byte in one buffer allocated from the
        /// parent Pipeline's allocator. Caller owns the result.
        pub fn drainAll(self: *Self) err.Error![]u8 {
            if (!self.ended) try self.end();
            const gpa = self.parent.allocator;
            const scratch = try gpa.alloc(u8, drain_buf_len);
            defer gpa.free(scratch);
            var out: std.ArrayList(u8) = .empty;
            errdefer out.deinit(gpa);
            while (true) {
                const r = try self.read(scratch);
                try out.appendSlice(gpa, scratch[0..r.n]);
                if (r.finished) return out.toOwnedSlice(gpa);
            }
        }

        /// Cancels (if still running) and releases the session. Safe
        /// from any state — mid-flight, mid-error, or after a clean
        /// drain. Call exactly once.
        pub fn deinit(self: *Self) void {
            ffi.itb_stream_free(self.handle);
            self.handle = undefined;
        }
    };
}

/// Incremental encrypt session: plaintext in, wire out.
pub const EncryptStream = Session(.encrypt);

/// Incremental decrypt session: wire in, plaintext out.
pub const DecryptStream = Session(.decrypt);
