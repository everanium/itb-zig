//! Thin Zig proxy over the ITB C binding (`bindings/c`), which in
//! turn wraps the libitb3 shared library's Triple Pipeline surface.
//!
//! The module `@cImport`s the C binding's public `itb3.h` and links
//! `libitb3_c.a` + `libitb3.so` at compile time — no runtime symbol
//! loading. Every hash-name / MAC-name / cipher-name / profile-name
//! is an opaque string passed through to Go for validation; the
//! binding carries no ITB construction logic. Buffer sizing and the
//! BufferTooSmall retry-once dance live in the C layer.
//!
//!     const itb = @import("itb3");
//!
//!     var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", null);
//!     defer sender.deinit();
//!     const blob = try sender.save();
//!     defer allocator.free(blob);
//!     var receiver = try itb.Pipeline.load(allocator, blob, null);
//!     defer receiver.deinit();
//!
//!     const wire = try sender.encryptMessage("hello");
//!     defer allocator.free(wire);
//!     const plain = try receiver.decryptMessage(wire);
//!     defer allocator.free(plain);

/// Zig binding version. Tracks the Zig wrapper; call `version` for
/// the underlying libitb3 library version.
pub const binding_version: [:0]const u8 = "0.5.1";

pub const ffi = @import("ffi.zig");

pub const Status = @import("status.zig").Status;

const error_mod = @import("error.zig");
pub const Error = error_mod.Error;
pub const check = error_mod.check;
pub const lastError = error_mod.lastError;

pub const Opts = @import("opts.zig").Opts;

const pipeline_mod = @import("pipeline.zig");
pub const Pipeline = pipeline_mod.Pipeline;
pub const Masters = pipeline_mod.Masters;

const stream_mod = @import("stream.zig");
pub const EncryptStream = stream_mod.EncryptStream;
pub const DecryptStream = stream_mod.DecryptStream;
pub const ReadResult = stream_mod.ReadResult;

const runtime_mod = @import("runtime.zig");
pub const inspect = runtime_mod.inspect;
pub const register = runtime_mod.register;
pub const lookup = runtime_mod.lookup;
pub const profiles = runtime_mod.profiles;
pub const version = runtime_mod.version;
pub const setMemoryLimit = runtime_mod.setMemoryLimit;
pub const setGcPercent = runtime_mod.setGcPercent;
