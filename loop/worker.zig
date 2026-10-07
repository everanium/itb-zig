//! The worker: its thread body (one warmup iteration, the warmup
//! barrier, the main loop), one iteration, the session pump loop the
//! stream shape drives, and the round-trip comparison that decides
//! between a worker error and a data mismatch. The state a worker
//! shares with the others lives here too — the C reference keeps it in
//! a header because C has no modules; a Zig module needs no such unit,
//! so it sits with the code that uses it.

const std = @import("std");
const itb = @import("itb3");

const log = @import("root");
const ops = @import("ops.zig");
const payload = @import("payload.zig");
const size = @import("size.zig");

const PayloadMode = payload.PayloadMode;

/// Cipher surfaces the --shape flag selects.
pub const Shape = enum(u8) {
    stream, // session pump: begin / write / read / end
    message, // Single Message: one whole-buffer call
    stream_one_shot, // stream surface, one whole-buffer call
    both, // all three, rotating by iteration number

    pub const names = [_][]const u8{ "stream", "message", "stream_one_shot", "both" };

    pub fn name(self: Shape) []const u8 {
        return names[@intFromEnum(self)];
    }

    pub fn parse(s: []const u8) ?Shape {
        for (names, 0..) |n, i| {
            if (std.mem.eql(u8, s, n)) return @enumFromInt(i);
        }
        return null;
    }
};

/// --goroutines ceiling; the harness targets modest hosts and each
/// worker pins payload-sized buffers for the whole run.
pub const max_workers: usize = 10;

/// The concurrency mode this binding implements, as the summary
/// reports it (shared-handle / independent-handles / single).
pub const concurrency = "shared-handle";

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
pub const pump_slice: usize = 1 << 20;

/// Worker-error text capacity.
pub const error_text: usize = 512;

/// The resolved command line.
pub const Config = struct {
    duration_ns: i64 = 0, // run duration; ignored when iterations > 0
    iterations: i64 = 0, // per-worker count incl. warmup; 0 = duration-based
    workers_requested: usize = 0, // the --goroutines value as given
    workers: usize = 0, // the effective worker count
    shape: Shape = .stream,
    hash: []const u8 = "",
    mac: []const u8 = "",
    payload_bytes: i64 = 0, // bytes per iteration
    memlimit: i64 = 0, // resolved bytes; the effective limit once shaped
    memlimit_auto: bool = false, // --memlimit auto: cap only when the runtime has no limit
    gogc: i32 = 0, // 0 = leave the runtime default
    parallax: bool = true,
    wrapper: bool = true,

    profile: []const u8 = "", // empty = shape-based profile pair
    key_bits: i32 = 0, // 0 = profile default
    nonce_bits: i32 = 0, // 0 = profile default
    blob_mode: i32 = 1, // container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    chunk_size: i64 = 0, // 0 = profile default
    barrier_fill: i32 = 0, // 0 = profile default
    drbg: []const u8 = "", // DRBG fill primitive; "" = profile default (auto tier)
    gomaxprocs: i32 = 0, // 0 = inherit from the environment
    rekey_every: i64 = 0, // per-worker iterations between rotations; 0 = never
    blob_cycle_every: i64 = 0, // per-worker iterations between reopens; 0 = never
    payload_mode: PayloadMode = .fixed,
    seed: u64 = 0, // 0 = OS CSPRNG plaintexts
    json_output: bool = false,
    memprofile: []const u8 = "", // empty = none
};

// MARK: locks

/// Zig-specific. The standard library's reader / writer lock belongs
/// to the async-IO interface and wants an `Io` instance; this utility
/// is plain threads over libc, so it takes the pthread lock directly —
/// the same primitive, and the same one the C reference uses.
pub const RwLock = struct {
    raw: std.c.pthread_rwlock_t = .{},

    pub fn readLock(self: *RwLock) void {
        _ = std.c.pthread_rwlock_rdlock(&self.raw);
    }

    pub fn writeLock(self: *RwLock) void {
        _ = std.c.pthread_rwlock_wrlock(&self.raw);
    }

    pub fn unlock(self: *RwLock) void {
        _ = std.c.pthread_rwlock_unlock(&self.raw);
    }
};

/// Zig-specific. A counting barrier over a pthread mutex and
/// condition: libc ships pthread_barrier but the standard library does
/// not bind it, and the generation counter is what keeps a fast
/// arrival from consuming the next round's release.
pub const Barrier = struct {
    mu: std.c.pthread_mutex_t = .{},
    cv: std.c.pthread_cond_t = .{},
    count: usize,
    waiting: usize = 0,
    generation: u64 = 0,

    pub fn init(count: usize) Barrier {
        return .{ .count = count };
    }

    pub fn wait(self: *Barrier) void {
        _ = std.c.pthread_mutex_lock(&self.mu);
        const gen = self.generation;
        self.waiting += 1;
        if (self.waiting == self.count) {
            self.waiting = 0;
            self.generation +%= 1;
            _ = std.c.pthread_cond_broadcast(&self.cv);
        } else {
            while (self.generation == gen) {
                _ = std.c.pthread_cond_wait(&self.cv, &self.mu);
            }
        }
        _ = std.c.pthread_mutex_unlock(&self.mu);
    }
};

// MARK: worker and run state

/// One worker's private state: its plaintext, its reusable output
/// buffers, its generator, its counters, and the error it stopped on.
pub const Worker = struct {
    id: usize,
    run: *RunState,
    thread: ?std.Thread = null,

    plaintext: []u8,
    payload_mode: PayloadMode,
    seeded: bool,
    rng: u64,

    /// Pump-loop accumulators, reused across iterations.
    wire: std.ArrayList(u8) = .empty,
    plain: std.ArrayList(u8) = .empty,

    /// Counters read by the summary after every worker has returned.
    iters: std.atomic.Value(i64) = .init(0),
    bytes_enc: std.atomic.Value(i64) = .init(0),
    bytes_dec: std.atomic.Value(i64) = .init(0),
    nanos_enc: std.atomic.Value(i64) = .init(0),
    nanos_dec: std.atomic.Value(i64) = .init(0),

    failed: bool = false,
    error_buf: [error_text]u8 = undefined,
    error_len: usize = 0,

    pub fn errorText(self: *const Worker) []const u8 {
        return self.error_buf[0..self.error_len];
    }

    /// Records the worker's error text (first error wins) and requests
    /// a stop of the whole run. The text is composed into the worker's
    /// own storage here and now: the library's diagnostic arrives as a
    /// pointer the relay layer owns only until this thread's next
    /// fetch, so it is copied rather than kept.
    pub fn fail(self: *Worker, comptime fmt: []const u8, args: anytype) void {
        if (!self.failed) {
            const text = std.fmt.bufPrint(&self.error_buf, fmt, args) catch
                self.error_buf[0..self.error_buf.len];
            self.error_len = text.len;
            self.failed = true;
        }
        self.run.stop.store(true, .monotonic);
    }
};

/// The state every worker shares: the Pipeline handles, the retained
/// blobs, the lock that keeps iterations clear of handle mutation, the
/// stop request, the barriers, and the baselines the summary reads.
pub const RunState = struct {
    gpa: std.mem.Allocator,
    cfg: Config,

    stream_pipe: ?itb.Pipeline = null, // null unless the shape uses it
    msg_pipe: ?itb.Pipeline = null, // null unless the shape uses it
    stream_profile: []const u8 = "",
    msg_profile: []const u8 = "",

    /// Handle mutation. Iterations hold the read side for their whole
    /// encrypt → decrypt → compare; rekey and blob reopen take the
    /// write side, so no cipher call is in flight while a handle's
    /// keying changes or the handle itself is swapped, and no encrypt
    /// is separated from its decrypt by either.
    pipe_lock: RwLock = .{},

    /// The blob Init handed out, replaced by every rekey; the input of
    /// the next blob reopen. Guarded by pipe_lock.
    stream_blob: []u8 = &.{},
    msg_blob: []u8 = &.{},

    /// Rotation and reopen tallies. Both are bumped under the write
    /// lock, so no atomic is needed.
    rekeys: i64 = 0,
    blob_cycles: i64 = 0,

    workers: [max_workers]Worker = undefined,

    /// Warmup barrier: workers arrive at warmup_done after iteration 0
    /// and at release once main has taken the baselines.
    warmup_done: Barrier = Barrier.init(0),
    release: Barrier = Barrier.init(0),

    /// Set by the duration timer, by a signal, or by a failing worker;
    /// checked by every worker before it starts an iteration.
    stop: std.atomic.Value(bool) = .init(false),

    /// Main waits on done_cv for active to reach zero; the last
    /// returning worker stamps finish_ns so elapsed excludes the
    /// wake-up latency of the waiter.
    done_mu: std.c.pthread_mutex_t = .{},
    done_cv: std.c.pthread_cond_t = .{},
    active: usize = 0,
    start_ns: i64 = 0,
    finish_ns: i64 = 0,

    /// Baselines taken after the warmup barrier and at shutdown.
    rss_warmup: u64 = 0,
    rss_peak: u64 = 0,
    rss_final: u64 = 0,
    pool_warmup: []i64 = &.{},
    pool_steady: []i64 = &.{},
};

// MARK: stream pump

/// A cipher call that came back non-OK, carrying the name of the step
/// inside a multi-call surface so the worker error names what failed.
const CallFailure = struct {
    what: []const u8,
    err: itb.Error,
};

const PumpError = error{PumpFailed};

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the binding's session
/// surface has no reader / writer entry, so the caller drives it: open
/// a session, feed slices of at most 1 MiB, drain whatever the session
/// has produced after every write (a read before end never blocks),
/// end, then drain until the session reports finished (after end, a
/// read on an empty spool blocks until the terminal bytes arrive). The
/// whole produced output lands in the worker's reusable accumulator.
/// The loop is written here rather than delegated to the binding's
/// pump convenience (`encryptStreamPump` / `drainAll`) so it stands in
/// the utility, at the same place, in every language.
fn pump(
    gpa: std.mem.Allocator,
    pipe: *itb.Pipeline,
    comptime encrypt: bool,
    src: []const u8,
    out: *std.ArrayList(u8),
    scratch: []u8,
    fail: *CallFailure,
) PumpError!void {
    var session = (if (encrypt) pipe.encryptStream() else pipe.decryptStream()) catch |e| {
        fail.* = .{ .what = "StreamBegin", .err = e };
        return PumpError.PumpFailed;
    };
    defer session.deinit();

    out.clearRetainingCapacity();
    var off: usize = 0;
    while (off < src.len) {
        const slice = @min(src.len - off, pump_slice);
        session.write(src[off .. off + slice]) catch |e| {
            fail.* = .{ .what = "StreamWrite", .err = e };
            return PumpError.PumpFailed;
        };
        off += slice;
        while (true) {
            const r = session.read(scratch) catch |e| {
                fail.* = .{ .what = "StreamRead", .err = e };
                return PumpError.PumpFailed;
            };
            if (r.n == 0) break;
            out.appendSlice(gpa, scratch[0..r.n]) catch |e| {
                fail.* = .{ .what = "append", .err = e };
                return PumpError.PumpFailed;
            };
        }
    }
    session.end() catch |e| {
        fail.* = .{ .what = "StreamEnd", .err = e };
        return PumpError.PumpFailed;
    };
    while (true) {
        const r = session.read(scratch) catch |e| {
            fail.* = .{ .what = "StreamRead", .err = e };
            return PumpError.PumpFailed;
        };
        out.appendSlice(gpa, scratch[0..r.n]) catch |e| {
            fail.* = .{ .what = "append", .err = e };
            return PumpError.PumpFailed;
        };
        if (r.finished) break;
    }
}

// MARK: one iteration

/// First offset at which a and b differ; the shorter length when one
/// is a prefix of the other.
fn firstDifference(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (a[i] != b[i]) return i;
    }
    return n;
}

/// Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
/// has no bytes there.
fn hexWindow(out: []u8, buf: []const u8, off: usize) []const u8 {
    if (off >= buf.len) return "-";
    const end = @min(off + 16, buf.len);
    var w: usize = 0;
    for (buf[off..end]) |b| {
        const s = std.fmt.bufPrint(out[w..], "{x:0>2}", .{b}) catch break;
        w += s.len;
    }
    return out[0..w];
}

/// Records a worker error for a failed cipher call. The printed detail
/// is the numeric code the binding's own status surface carries for
/// the error value, followed by the sentence the library left behind.
fn cipherFail(w: *Worker, iter: i64, shape: Shape, direction: []const u8, f: CallFailure) void {
    const code = itb.statusOf(f.err).code();
    if (std.mem.eql(u8, f.what, direction)) {
        w.fail("g{d} iter {d} shape={s}: {s}: status {d}: {s}", .{
            w.id, iter, shape.name(), direction, code, itb.lastError(),
        });
    } else {
        w.fail("g{d} iter {d} shape={s}: {s}: {s}: status {d}: {s}", .{
            w.id, iter, shape.name(), direction, f.what, code, itb.lastError(),
        });
    }
}

/// One iteration. In order: refill the plaintext under rotating mode;
/// take the read lock; pick the surface; encrypt (timed); decrypt
/// (timed); compare the round-trip with the plaintext; bump the
/// counters; release the lock. The whole round-trip runs under the
/// read lock so handle-mutating maintenance (rekey, blob reopen) never
/// lands between an encrypt and its matching decrypt — maintenance
/// runs after this returns, from the worker loop. Returns false after
/// recording the worker error.
fn iterate(w: *Worker, iter: i64, scratch: []u8) bool {
    const r = w.run;
    const gpa = r.gpa;

    if (w.payload_mode == .rotating) {
        if (!payload.fillPayload(.rotating, w.seeded, &w.rng, w.plaintext)) {
            w.fail("g{d} iter {d}: payload refill: csprng", .{ w.id, iter });
            return false;
        }
    }

    r.pipe_lock.readLock();
    defer r.pipe_lock.unlock();

    // Shape dispatch. message is one whole-buffer call on the Single
    // Message Pipeline; stream_one_shot is one whole-buffer call on
    // the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
    // which routes to the same one-shot stream entry the Go harness
    // calls by name); stream opens a session on the same streaming
    // Pipeline and drives the chunk loop from here. Under both the
    // three rotate by iteration number so the session path and the
    // whole-buffer path alternate on one handle inside every worker —
    // the cross-path state-reuse hazard this harness exists to catch.
    var shape = r.cfg.shape;
    if (shape == .both) {
        shape = switch (@mod(iter, 3)) {
            0 => .stream,
            1 => .message,
            else => .stream_one_shot,
        };
    }

    // Zig-specific. The message and one-shot entries hand back an
    // allocator-owned slice per call, released at the end of the
    // iteration; the pump accumulators are the worker's own and are
    // reused across iterations.
    var round_trip: ?[]u8 = null;
    defer if (round_trip) |p| gpa.free(p);
    var fail: CallFailure = .{ .what = "", .err = itb.Error.Internal };

    switch (shape) {
        .stream => {
            var t0 = size.nowNanos();
            pump(gpa, &r.stream_pipe.?, true, w.plaintext, &w.wire, scratch, &fail) catch {
                cipherFail(w, iter, shape, "encrypt", fail);
                return false;
            };
            _ = w.nanos_enc.fetchAdd(size.nowNanos() - t0, .monotonic);
            t0 = size.nowNanos();
            pump(gpa, &r.stream_pipe.?, false, w.wire.items, &w.plain, scratch, &fail) catch {
                cipherFail(w, iter, shape, "decrypt", fail);
                return false;
            };
            _ = w.nanos_dec.fetchAdd(size.nowNanos() - t0, .monotonic);
        },
        .message, .stream_one_shot => {
            const pipe = if (shape == .message) &r.msg_pipe.? else &r.stream_pipe.?;
            var t0 = size.nowNanos();
            const wire = (if (shape == .message)
                pipe.encryptMessage(w.plaintext)
            else
                pipe.encryptStreamOneShot(w.plaintext)) catch |e| {
                cipherFail(w, iter, shape, "encrypt", .{ .what = "encrypt", .err = e });
                return false;
            };
            defer gpa.free(wire);
            _ = w.nanos_enc.fetchAdd(size.nowNanos() - t0, .monotonic);
            t0 = size.nowNanos();
            round_trip = (if (shape == .message)
                pipe.decryptMessage(wire)
            else
                pipe.decryptStreamOneShot(wire)) catch |e| {
                cipherFail(w, iter, shape, "decrypt", .{ .what = "decrypt", .err = e });
                return false;
            };
            _ = w.nanos_dec.fetchAdd(size.nowNanos() - t0, .monotonic);
        },
        .both => unreachable, // resolved above
    }

    // Failure model. A cipher call that returns a non-OK status is a
    // worker error: it is recorded, the run is asked to stop, the
    // other workers finish their in-flight iteration, and the error is
    // listed in the summary with the FAIL verdict. A round-trip that
    // returns OK with different bytes is a data mismatch: the process
    // terminates here, without summary or cleanup, because the
    // Pipeline state that produced the wrong bytes is the evidence and
    // nothing that runs afterwards may touch it.
    const got: []const u8 = round_trip orelse w.plain.items;
    if (!std.mem.eql(u8, got, w.plaintext)) {
        const off = firstDifference(w.plaintext, got);
        var want_hex: [40]u8 = undefined;
        var got_hex: [40]u8 = undefined;
        log.err(
            "DATA MISMATCH g{d} iter {d} shape={s}: want {d} bytes, got {d} bytes, " ++
                "first difference at offset {d}: want {s} got {s}",
            .{
                w.id,                                  iter,
                shape.name(),                          w.plaintext.len,
                got.len,                               off,
                hexWindow(&want_hex, w.plaintext, off), hexWindow(&got_hex, got, off),
            },
        );
        std.c._exit(3);
    }

    _ = w.iters.fetchAdd(1, .monotonic);
    _ = w.bytes_enc.fetchAdd(@intCast(w.plaintext.len), .monotonic);
    _ = w.bytes_dec.fetchAdd(@intCast(got.len), .monotonic);
    return true;
}

/// Marks this worker returned; the last one to return stamps the
/// finish instant and wakes main.
fn workerDone(r: *RunState) void {
    _ = std.c.pthread_mutex_lock(&r.done_mu);
    r.active -= 1;
    if (r.active == 0) {
        r.finish_ns = size.nowNanos();
        _ = std.c.pthread_cond_signal(&r.done_cv);
    }
    _ = std.c.pthread_mutex_unlock(&r.done_mu);
}

/// The worker thread body: one warmup iteration, the warmup barrier,
/// then the main loop until a stop is requested or the fixed
/// per-worker iteration budget (warmup included) is spent. A failing
/// warmup still passes both barriers so the launcher never waits on a
/// worker that has already given up.
pub fn workerMain(w: *Worker) void {
    const r = w.run;
    const scratch = r.gpa.alloc(u8, pump_slice) catch {
        w.fail("g{d}: pump scratch: out of memory", .{w.id});
        r.warmup_done.wait();
        r.release.wait();
        workerDone(r);
        return;
    };
    defer r.gpa.free(scratch);

    // Warmup iteration — counted in the totals; its completion feeds
    // the post-warmup baselines.
    const ok = iterate(w, 0, scratch);
    r.warmup_done.wait();
    r.release.wait();
    if (!ok) {
        workerDone(r);
        return;
    }

    var iter: i64 = 1;
    while (true) : (iter += 1) {
        if (r.cfg.iterations > 0 and iter >= r.cfg.iterations) break;
        if (r.stop.load(.monotonic)) break;
        if (!iterate(w, iter, scratch)) break;
        if (!ops.workerMaintenance(w, iter)) break;
    }
    workerDone(r);
}
