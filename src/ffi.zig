//! Centralised C ABI declarations for the ITB C binding's public header
//! (`itb3.h`).
//!
//! Every other module reaches the C ABI exclusively through `ffi.c`.
//! Declared directly via `extern "c"` for compatibility across Zig 0.16
//! and Zig 0.17+ (which removed `@cImport`). The link inputs
//! (`libitb3_c.a` + `-litb3` with an embedded RPATH into `dist/`) are
//! wired by `build.zig`.

pub const c = struct {
    pub const itb_status = c_uint;

    pub const ITB_STATUS_OK: c_uint = 0;
    pub const ITB_STATUS_BAD_HASH: c_uint = 1;
    pub const ITB_STATUS_BAD_KEY_BITS: c_uint = 2;
    pub const ITB_STATUS_BAD_HANDLE: c_uint = 3;
    pub const ITB_STATUS_BAD_INPUT: c_uint = 4;
    pub const ITB_STATUS_BUFFER_TOO_SMALL: c_uint = 5;
    pub const ITB_STATUS_ENCRYPT_FAILED: c_uint = 6;
    pub const ITB_STATUS_DECRYPT_FAILED: c_uint = 7;
    pub const ITB_STATUS_SEED_WIDTH_MIX: c_uint = 8;
    pub const ITB_STATUS_BAD_MAC: c_uint = 9;
    pub const ITB_STATUS_MAC_FAILURE: c_uint = 10;
    pub const ITB_STATUS_BLOB_MALFORMED_RECIPE: c_uint = 11;
    pub const ITB_STATUS_RECIPE_PRIMITIVE_UNKNOWN: c_uint = 12;
    pub const ITB_STATUS_UNKNOWN_PROFILE: c_uint = 13;
    pub const ITB_STATUS_RESERVED_14: c_uint = 14;
    pub const ITB_STATUS_RESERVED_15: c_uint = 15;
    pub const ITB_STATUS_RESERVED_16: c_uint = 16;
    pub const ITB_STATUS_RESERVED_17: c_uint = 17;
    pub const ITB_STATUS_BLOB_MODE_MISMATCH: c_uint = 19;
    pub const ITB_STATUS_BLOB_MALFORMED: c_uint = 20;
    pub const ITB_STATUS_BLOB_VERSION_TOO_NEW: c_uint = 21;
    pub const ITB_STATUS_BLOB_TOO_MANY_OPTS: c_uint = 22;
    pub const ITB_STATUS_STREAM_TRUNCATED: c_uint = 23;
    pub const ITB_STATUS_STREAM_AFTER_FINAL: c_uint = 24;
    pub const ITB_STATUS_TRIPLE_CLOSED: c_uint = 25;
    pub const ITB_STATUS_PROFILE_EXISTS: c_uint = 26;
    pub const ITB_STATUS_INTERNAL: c_uint = 99;

    pub const itb_pipeline = opaque {};
    pub const itb_stream = opaque {};
    pub const itb_opts = opaque {};

    pub extern "c" fn itb_opts_new() ?*itb_opts;
    pub extern "c" fn itb_opts_free(opts: ?*itb_opts) void;
    pub extern "c" fn itb_opts_set(opts: ?*itb_opts, key: [*c]const u8, value: [*c]const u8) itb_status;
    pub extern "c" fn itb_opts_query(opts: ?*const itb_opts) [*c]const u8;

    pub extern "c" fn itb_pipeline_init(profile: [*c]const u8, opts: ?*const itb_opts, out: [*c]?*itb_pipeline) itb_status;
    pub extern "c" fn itb_pipeline_init_keys(
        profile: [*c]const u8,
        opts: ?*const itb_opts,
        masters_flat: ?*const anyopaque,
        masters_flat_len: usize,
        master_lens: [*c]const usize,
        masters_count: usize,
        out: [*c]?*itb_pipeline,
    ) itb_status;
    pub extern "c" fn itb_pipeline_load(
        blob: [*c]const u8,
        blob_len: usize,
        perm_master: [*c]const u8,
        perm_master_len: usize,
        wrap_master: [*c]const u8,
        wrap_master_len: usize,
        out: [*c]?*itb_pipeline,
    ) itb_status;
    pub extern "c" fn itb_pipeline_load_f(
        path: [*c]const u8,
        perm_master: [*c]const u8,
        perm_master_len: usize,
        wrap_master: [*c]const u8,
        wrap_master_len: usize,
        out: [*c]?*itb_pipeline,
    ) itb_status;
    pub extern "c" fn itb_pipeline_free(pipe: ?*itb_pipeline) void;
    pub extern "c" fn itb_pipeline_save(pipe: ?*const itb_pipeline, blob_out: [*c][*c]u8, blob_len_out: [*c]usize) itb_status;
    pub extern "c" fn itb_pipeline_save_f(pipe: ?*const itb_pipeline, path: [*c]const u8) itb_status;
    pub extern "c" fn itb_pipeline_max_workers(pipe: ?*const itb_pipeline, n: c_int) itb_status;
    pub extern "c" fn itb_pipeline_rekey(
        pipe: ?*itb_pipeline,
        perm: [*c]const u8,
        perm_len: usize,
        wrap: [*c]const u8,
        wrap_len: usize,
        blob_out: [*c][*c]u8,
        blob_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_encrypt_message(
        pipe: ?*const itb_pipeline,
        plain: [*c]const u8,
        plain_len: usize,
        wire_out: [*c][*c]u8,
        wire_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_decrypt_message(
        pipe: ?*const itb_pipeline,
        wire: [*c]const u8,
        wire_len: usize,
        plain_out: [*c][*c]u8,
        plain_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_encrypt_stream_pump(
        pipe: ?*const itb_pipeline,
        plain: [*c]const u8,
        plain_len: usize,
        wire_out: [*c][*c]u8,
        wire_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_decrypt_stream_pump(
        pipe: ?*const itb_pipeline,
        wire: [*c]const u8,
        wire_len: usize,
        plain_out: [*c][*c]u8,
        plain_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_encrypt_stream_one_shot(
        pipe: ?*const itb_pipeline,
        plain: [*c]const u8,
        plain_len: usize,
        wire_out: [*c][*c]u8,
        wire_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_decrypt_stream_one_shot(
        pipe: ?*const itb_pipeline,
        wire: [*c]const u8,
        wire_len: usize,
        plain_out: [*c][*c]u8,
        plain_len_out: [*c]usize,
    ) itb_status;
    pub extern "c" fn itb_pipeline_encrypt_stream_begin(pipe: ?*const itb_pipeline, out: [*c]?*itb_stream) itb_status;
    pub extern "c" fn itb_pipeline_decrypt_stream_begin(pipe: ?*const itb_pipeline, out: [*c]?*itb_stream) itb_status;

    pub extern "c" fn itb_stream_write(stream: ?*itb_stream, src: [*c]const u8, src_len: usize) itb_status;
    pub extern "c" fn itb_stream_end(stream: ?*itb_stream) itb_status;
    pub extern "c" fn itb_stream_read(
        stream: ?*itb_stream,
        dst: [*c]u8,
        dst_cap: usize,
        n_read: [*c]usize,
        finished: [*c]c_int,
    ) itb_status;
    pub extern "c" fn itb_stream_free(stream: ?*itb_stream) void;

    pub extern "c" fn itb_inspect(blob: [*c]const u8, blob_len: usize, json_out: [*c][*c]u8) itb_status;
    pub extern "c" fn itb_register(name: [*c]const u8, profile_json: [*c]const u8) itb_status;
    pub extern "c" fn itb_lookup(name: [*c]const u8, json_out: [*c][*c]u8) itb_status;
    pub extern "c" fn itb_profiles(json_out: [*c][*c]u8) itb_status;
    pub extern "c" fn itb_hash_names(json_out: [*c][*c]u8) itb_status;

    pub extern "c" fn itb_last_error() [*c]const u8;
    pub extern "c" fn itb_version() [*c]const u8;
    pub extern "c" fn itb_drbg_auto_tier() [*c]const u8;
    pub extern "c" fn itb_set_memory_limit(bytes: i64) i64;
    pub extern "c" fn itb_set_gc_percent(pct: i32) i32;
    pub extern "c" fn itb_set_gomaxprocs(n: i32) i32;
    pub extern "c" fn itb_write_heap_profile(path: [*c]const u8) itb_status;
    pub extern "c" fn itb_pool_stats_len() usize;
    pub extern "c" fn itb_pool_stats(out: [*c]i64, cap: usize, len_out: [*c]usize) itb_status;

    pub extern "c" fn itb_bytes_free(bytes: [*c]u8) void;
    pub extern "c" fn itb_string_free(str: [*c]u8) void;
};
