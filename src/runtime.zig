//! Profile records (inspect / register / lookup / profiles), Go
//! runtime knobs, and registry diagnostics.
//!
//! A profile record is the JSON object libitb3 accepts in `register`,
//! returns from `lookup` / `inspect`, and embeds in every blob.
//! Optional keys are omitted when empty / zero. The binding treats
//! the record as an opaque string; every field rule is enforced by
//! libitb3.

const std = @import("std");
const ffi = @import("ffi.zig").c;
const err = @import("error.zig");

const Allocator = std.mem.Allocator;

/// Decodes the profile record embedded in `blob_bytes` without
/// constructing a Pipeline. Caller owns the result — release with
/// `allocator.free`.
pub fn inspect(allocator: Allocator, blob_bytes: []const u8) err.Error![]u8 {
    var out: [*c]u8 = null;
    const rc = ffi.itb_inspect(blob_bytes.ptr, blob_bytes.len, &out);
    defer ffi.itb_string_free(out);
    try err.check(rc);
    return allocator.dupe(u8, std.mem.span(out));
}

/// Registers a user-defined Triple profile under `name` from a
/// profile JSON record (a non-empty "name" key inside the record must
/// equal `name`). A duplicate name fails with `error.ProfileExists`.
pub fn register(name: [:0]const u8, profile_json: [:0]const u8) err.Error!void {
    try err.check(ffi.itb_register(name.ptr, profile_json.ptr));
}

/// The profile registered under `name` as its JSON record. An
/// unregistered name fails with `error.UnknownProfile`. Caller owns
/// the result.
pub fn lookup(allocator: Allocator, name: [:0]const u8) err.Error![]u8 {
    var out: [*c]u8 = null;
    const rc = ffi.itb_lookup(name.ptr, &out);
    defer ffi.itb_string_free(out);
    try err.check(rc);
    return allocator.dupe(u8, std.mem.span(out));
}

/// The sorted list of every registered profile name as a JSON array
/// of strings. Caller owns the result.
pub fn profiles(allocator: Allocator) err.Error![]u8 {
    var out: [*c]u8 = null;
    const rc = ffi.itb_profiles(&out);
    defer ffi.itb_string_free(out);
    try err.check(rc);
    return allocator.dupe(u8, std.mem.span(out));
}

/// The libitb3 library version string ("" if libitb3 misbehaves).
/// Thread-local C-side buffer — copy before the next call if kept.
pub fn version() [:0]const u8 {
    const v = ffi.itb_version();
    return if (v != null) std.mem.span(v) else "";
}

/// Sets the Go runtime's soft heap limit in bytes; returns the
/// previous limit. A negative value queries without changing.
pub fn setMemoryLimit(bytes: i64) i64 {
    return ffi.itb_set_memory_limit(bytes);
}

/// Sets the Go GC trigger percentage; returns the previous value. A
/// negative value queries without changing.
pub fn setGcPercent(pct: i32) i32 {
    return ffi.itb_set_gc_percent(pct);
}
