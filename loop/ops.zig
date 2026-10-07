//! The maintenance operations that mutate a live Pipeline handle
//! between iterations: master rotation (--rekey-every) and blob reopen
//! (--blob-cycle-every).

const std = @import("std");
const itb = @import("itb3");

const log = @import("root");
const payload = @import("payload.zig");
const worker_mod = @import("worker.zig");

const Worker = worker_mod.Worker;

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
const rekey_master_size: usize = 32;

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed blob
/// for subsequent blob reopens. Masters are drawn fresh from the OS
/// CSPRNG on every rotation regardless of --seed (master rotation is
/// pipeline keying, not plaintext content); a disabled layer passes no
/// bytes, which Rekey ignores. The eight inner seeds and the MAC key
/// are untouched by design — Rekey targets only the two outer-layer
/// master secrets.
fn rekeyPipes(w: *Worker, iter: i64) bool {
    const r = w.run;
    var perm_buf: [rekey_master_size]u8 = undefined;
    var wrap_buf: [rekey_master_size]u8 = undefined;
    var perm: []const u8 = &.{};
    var wrap: []const u8 = &.{};

    if (r.cfg.parallax) {
        if (!payload.fillRandom(&perm_buf)) {
            w.fail("g{d} iter {d}: csprng: parallax master", .{ w.id, iter });
            return false;
        }
        perm = &perm_buf;
    }
    if (r.cfg.wrapper) {
        if (!payload.fillRandom(&wrap_buf)) {
            w.fail("g{d} iter {d}: csprng: wrapper master", .{ w.id, iter });
            return false;
        }
        wrap = &wrap_buf;
    }

    r.pipe_lock.writeLock();
    defer r.pipe_lock.unlock();
    if (r.stream_pipe != null) {
        const blob = r.stream_pipe.?.rekey(perm, wrap) catch |e| {
            w.fail("g{d} iter {d}: Rekey({s}): status {d}: {s}", .{
                w.id, iter, r.stream_profile, itb.statusOf(e).code(), itb.lastError(),
            });
            return false;
        };
        r.gpa.free(r.stream_blob);
        r.stream_blob = blob;
    }
    if (r.msg_pipe != null) {
        const blob = r.msg_pipe.?.rekey(perm, wrap) catch |e| {
            w.fail("g{d} iter {d}: Rekey({s}): status {d}: {s}", .{
                w.id, iter, r.msg_profile, itb.statusOf(e).code(), itb.lastError(),
            });
            return false;
        };
        r.gpa.free(r.msg_blob);
        r.msg_blob = blob;
    }
    r.rekeys += 1;
    log.line("rekey: g{d} iter {d} rotated parallax + wrapper masters (rekey #{d})", .{
        w.id, iter, r.rekeys,
    });
    return true;
}

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is released, and the fresh one is swapped in, so
/// every later iteration round-trips through seeds and masters that
/// survived a blob crossing. The input is the blob Init or the latest
/// Rekey handed out, not a fresh Save: that is what a receiver holds,
/// and reopening from it proves the handed-out bytes rather than the
/// live state. The blob carries the Pipeline's full shape, so no
/// override reaches the reopen. On a Load failure the running handle
/// stays and the failure aborts the run.
fn blobCyclePipes(w: *Worker, iter: i64) bool {
    const r = w.run;
    r.pipe_lock.writeLock();
    defer r.pipe_lock.unlock();
    if (r.stream_pipe != null) {
        const fresh = itb.Pipeline.load(r.gpa, r.stream_blob, null) catch |e| {
            w.fail("g{d} iter {d}: Load({s}): status {d}: {s}", .{
                w.id, iter, r.stream_profile, itb.statusOf(e).code(), itb.lastError(),
            });
            return false;
        };
        r.stream_pipe.?.deinit();
        r.stream_pipe = fresh;
    }
    if (r.msg_pipe != null) {
        const fresh = itb.Pipeline.load(r.gpa, r.msg_blob, null) catch |e| {
            w.fail("g{d} iter {d}: Load({s}): status {d}: {s}", .{
                w.id, iter, r.msg_profile, itb.statusOf(e).code(), itb.lastError(),
            });
            return false;
        };
        r.msg_pipe.?.deinit();
        r.msg_pipe = fresh;
    }
    r.blob_cycles += 1;
    log.line("blob-cycle: g{d} iter {d} reopened from session blob (cycle #{d})", .{
        w.id, iter, r.blob_cycles,
    });
    return true;
}

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher
/// calls on other workers drain before anything changes and no encrypt
/// is separated from its decrypt by either. Returns false after
/// recording the worker error.
pub fn workerMaintenance(w: *Worker, iter: i64) bool {
    const cfg = w.run.cfg;
    if (cfg.rekey_every > 0 and @mod(iter, cfg.rekey_every) == 0) {
        if (!rekeyPipes(w, iter)) return false;
    }
    if (cfg.blob_cycle_every > 0 and @mod(iter, cfg.blob_cycle_every) == 0) {
        if (!blobCyclePipes(w, iter)) return false;
    }
    return true;
}
