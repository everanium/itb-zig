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

/// The shipped hash-primitive registry in canonical order as a JSON
/// array of strings. The list is what a profile's inner-hash name is
/// resolved against, so a caller validates a primitive name without
/// constructing a Pipeline. Caller owns the result.
pub fn hashNames(allocator: Allocator) err.Error![]u8 {
    var out: [*c]u8 = null;
    const rc = ffi.itb_hash_names(&out);
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

/// The fill cipher the auto DRBG tier selected on this host
/// ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
/// drbg option is empty, resolved per host and recorded in no blob
/// ("" if libitb3 misbehaves). Thread-local C-side buffer — copy
/// before the next call if kept.
pub fn drbgAutoTier() [:0]const u8 {
    const v = ffi.itb_drbg_auto_tier();
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

/// Sets the Go runtime's GOMAXPROCS; returns the previous value. Zero
/// or a negative value queries without changing.
pub fn setGomaxprocs(n: i32) i32 {
    return ffi.itb_set_gomaxprocs(n);
}

/// Writes the Go runtime's heap profile (pprof format) to `path` after
/// one forced garbage collection. An empty path falls back to the
/// ITB_MEMPROFILE environment variable; a path that is still empty, or
/// a file-system failure, is `error.BadInput` with the diagnostic in
/// `lastError`.
pub fn writeHeapProfile(path: [:0]const u8) err.Error!void {
    try err.check(ffi.itb_write_heap_profile(path.ptr));
}

/// The number of i64 slots `poolStats` fills. Size a buffer from this
/// call, never from a constant.
pub fn poolStatsLen() usize {
    return ffi.itb_pool_stats_len();
}

/// The library's pool hit / miss counters. Every counter is a
/// monotonically increasing total since library load — difference two
/// snapshots. Slot layout, with T the tier count in slot 0: tier i
/// holds starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated at slots 1 + 5*i .. 1 + 5*i + 4;
/// the scratch byte pool's get / new / regrow / regrow-bytes follow at
/// 1 + 5*T, and the parallax chunk pool's at 1 + 5*T + 4. Caller owns
/// the result.
pub fn poolStats(allocator: Allocator) err.Error![]i64 {
    const cap = poolStatsLen();
    const slots = try allocator.alloc(i64, cap);
    errdefer allocator.free(slots);
    if (cap == 0) return slots;
    var written: usize = 0;
    try err.check(ffi.itb_pool_stats(slots.ptr, cap, &written));
    return allocator.realloc(slots, written) catch slots[0..written];
}
