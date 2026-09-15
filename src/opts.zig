//! URL-query opts builder — a thin handle over the C `itb_opts`
//! builder. The builder performs no validation; Go rejects unknown
//! keys and bad values with a diagnostic relayed through `lastError`.

const ffi = @import("ffi.zig").c;
const std = @import("std");
const err = @import("error.zig");

pub const Opts = struct {
    handle: *ffi.itb_opts,

    /// Allocates an empty builder (C-side allocation — no Zig
    /// allocator involved). Release with `deinit`.
    pub fn init() err.Error!Opts {
        const handle = ffi.itb_opts_new() orelse return err.Error.OutOfMemory;
        return .{ .handle = handle };
    }

    /// Releases the builder. Call exactly once.
    pub fn deinit(self: Opts) void {
        ffi.itb_opts_free(self.handle);
    }

    /// Appends one key=value pair (both percent-encoded as needed).
    pub fn set(self: Opts, key: [:0]const u8, value: [:0]const u8) err.Error!void {
        try err.check(ffi.itb_opts_set(self.handle, key.ptr, value.ptr));
    }

    /// The built query string ("" for an empty builder). Owned by the
    /// builder — valid until the next `set` / `deinit` on it.
    pub fn query(self: Opts) [:0]const u8 {
        return std.mem.span(ffi.itb_opts_query(self.handle));
    }
};
