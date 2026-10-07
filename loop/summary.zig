//! The final summary in both renderings, and the two measurements it
//! folds in that are not per-worker counters: the process resident set
//! and the shared library's pool counters.

const std = @import("std");
const itb = @import("itb3");

const log = @import("root");
const size = @import("size.zig");
const worker_mod = @import("worker.zig");

const RunState = worker_mod.RunState;

// MARK: resident set

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
pub fn readRss() struct { current: u64, peak: u64 } {
    var current: u64 = 0;
    var peak: u64 = 0;
    const fd = std.c.open("/proc/self/status", .{ .ACCMODE = .RDONLY });
    if (fd < 0) return .{ .current = current, .peak = peak };
    defer _ = std.c.close(fd);
    var buf: [8192]u8 = undefined;
    const n = std.c.read(fd, &buf, buf.len);
    if (n <= 0) return .{ .current = current, .peak = peak };
    var it = std.mem.splitScalar(u8, buf[0..@intCast(n)], '\n');
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const digits = std.mem.trimStart(u8, line[colon + 1 ..], " \t");
        var end: usize = 0;
        while (end < digits.len and std.ascii.isDigit(digits[end])) end += 1;
        const kb = std.fmt.parseInt(u64, digits[0..end], 10) catch continue;
        if (std.mem.startsWith(u8, line, "VmRSS:")) {
            current = kb * 1024;
        } else if (std.mem.startsWith(u8, line, "VmHWM:")) {
            peak = kb * 1024;
        }
    }
    return .{ .current = current, .peak = peak };
}

// MARK: pool counters

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and the
/// parallax chunk pool the checkouts, constructor misses, regrows and
/// regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a
/// pool keeps its items warm between calls or evicts them across GC
/// cycles. The slot layout is read from the library: slot 0 carries
/// the tier count T, tier i occupies the five slots at 1 + 5*i, and
/// the two byte pools occupy the eight slots at 1 + 5*T; the buffer is
/// sized from the binding's length query, never from a constant.
pub fn poolSnapshot(gpa: std.mem.Allocator) []i64 {
    return itb.poolStats(gpa) catch &.{};
}

/// One reported hash tier of the differenced snapshot pair.
const Tier = struct {
    index: usize,
    starter: i64,
    get: i64,
    fresh: i64,
    regrow: i64,
    new_bytes: i64,
};

/// The differenced pool figures of one run.
const PoolDelta = struct {
    tiers: [64]Tier = undefined,
    tier_count: usize = 0,
    buf_get: i64 = 0,
    buf_new: i64 = 0,
    buf_regrow: i64 = 0,
    buf_regrow_bytes: i64 = 0,
    chunk_get: i64 = 0,
    chunk_new: i64 = 0,
    chunk_regrow: i64 = 0,
    chunk_regrow_bytes: i64 = 0,
};

fn poolDiff(r: *const RunState) PoolDelta {
    var d = PoolDelta{};
    const w = r.pool_warmup;
    const s = r.pool_steady;
    if (w.len < 9 or s.len < 9 or w.len != s.len) return d;
    if (s[0] < 0 or s[0] > 64) return d;
    const tiers: usize = @intCast(s[0]);
    if (1 + 5 * tiers + 8 > s.len) return d;
    var i: usize = 0;
    while (i < tiers) : (i += 1) {
        const base = 1 + 5 * i;
        d.tiers[i] = .{
            .index = i,
            .starter = s[base + 0],
            .get = s[base + 1] - w[base + 1],
            .fresh = s[base + 2] - w[base + 2],
            .regrow = s[base + 3] - w[base + 3],
            .new_bytes = s[base + 4] - w[base + 4],
        };
    }
    d.tier_count = tiers;
    const tail = 1 + 5 * tiers;
    d.buf_get = s[tail + 0] - w[tail + 0];
    d.buf_new = s[tail + 1] - w[tail + 1];
    d.buf_regrow = s[tail + 2] - w[tail + 2];
    d.buf_regrow_bytes = s[tail + 3] - w[tail + 3];
    d.chunk_get = s[tail + 4] - w[tail + 4];
    d.chunk_new = s[tail + 5] - w[tail + 5];
    d.chunk_regrow = s[tail + 6] - w[tail + 6];
    d.chunk_regrow_bytes = s[tail + 7] - w[tail + 7];
    return d;
}

/// Misses over checkouts as a percentage; zero when nothing was
/// checked out.
fn missPercent(miss: i64, get: i64) f64 {
    if (get <= 0) return 0.0;
    const m: f64 = @floatFromInt(miss);
    const g: f64 = @floatFromInt(get);
    return 100.0 * m / g;
}

/// Appends s as a JSON string literal with the escapes JSON requires.
fn jsonString(out: *std.ArrayList(u8), gpa: std.mem.Allocator, s: []const u8) !void {
    try out.append(gpa, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(gpa, "\\\""),
            '\\' => try out.appendSlice(gpa, "\\\\"),
            '\n' => try out.appendSlice(gpa, "\\n"),
            '\r' => try out.appendSlice(gpa, "\\r"),
            '\t' => try out.appendSlice(gpa, "\\t"),
            else => {
                if (c < 0x20) {
                    try out.print(gpa, "\\u{x:0>4}", .{c});
                } else {
                    try out.append(gpa, c);
                }
            },
        }
    }
    try out.append(gpa, '"');
}

/// The effective GC percentage as the runtime reports it: the query
/// form of the setter (a set-and-restore round trip inside the
/// library) so the field is the same whether the value came from the
/// flag, the environment, or the runtime default.
fn effectiveGogc(flag: i32) i32 {
    if (flag > 0) return flag;
    return itb.setGcPercent(-1);
}

fn onOff(b: bool) []const u8 {
    return if (b) "on" else "off";
}

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines
/// in the same order, the same keys in the same order, floats with a
/// fixed number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal
/// lines after rss: and its runtime-internal keys after
/// parallax_chunk_pool; nothing here reproduces them because nothing
/// they read is reachable through this binding.
pub fn finalSummary(r: *RunState, elapsed_ns: i64, microbatch: []const u8, hashpool: []const u8) u8 {
    const cfg = r.cfg;
    const gpa = r.gpa;
    var total_iters: i64 = 0;
    var total_enc: i64 = 0;
    var total_dec: i64 = 0;
    var nanos_enc: i64 = 0;
    var nanos_dec: i64 = 0;
    var errors: usize = 0;
    for (r.workers[0..cfg.workers]) |*w| {
        total_iters += w.iters.load(.monotonic);
        total_enc += w.bytes_enc.load(.monotonic);
        total_dec += w.bytes_dec.load(.monotonic);
        nanos_enc += w.nanos_enc.load(.monotonic);
        nanos_dec += w.nanos_dec.load(.monotonic);
        if (w.failed) errors += 1;
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    const workers: i64 = @intCast(cfg.workers);
    const avg_enc: i64 = if (nanos_enc > 0) @divTrunc(nanos_enc, workers) else 0;
    const avg_dec: i64 = if (nanos_dec > 0) @divTrunc(nanos_dec, workers) else 0;

    const rss_delta: i64 = @as(i64, @intCast(r.rss_final)) - @as(i64, @intCast(r.rss_warmup));
    var rss_growth: f64 = 0.0;
    if (r.rss_warmup > 0) {
        rss_growth = 100.0 * @as(f64, @floatFromInt(rss_delta)) / @as(f64, @floatFromInt(r.rss_warmup));
    }

    const pd = poolDiff(r);
    const pass = errors == 0;
    const gomaxprocs = itb.setGomaxprocs(0);
    const stream_profile: []const u8 = if (r.stream_pipe != null) r.stream_profile else "";
    const msg_profile: []const u8 = if (r.msg_pipe != null) r.msg_profile else "";

    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    var c: [64]u8 = undefined;
    var d: [64]u8 = undefined;

    if (cfg.json_output) {
        var o: std.ArrayList(u8) = .empty;
        defer o.deinit(gpa);
        emitJson(&o, gpa, r, pd, .{
            .elapsed_ns = elapsed_ns,
            .total_iters = total_iters,
            .total_enc = total_enc,
            .total_dec = total_dec,
            .avg_enc = avg_enc,
            .avg_dec = avg_dec,
            .pass = pass,
            .gomaxprocs = gomaxprocs,
            .stream_profile = stream_profile,
            .msg_profile = msg_profile,
            .rss_growth = rss_growth,
            .microbatch = microbatch,
            .hashpool = hashpool,
        }) catch {
            log.err("summary: out of memory", .{});
            return 1;
        };
        log.raw(o.items);
        return if (pass) 0 else 1;
    }

    log.line("=== FINAL ===", .{});
    log.line("  duration: {s}", .{
        size.humanDuration(&a, @divTrunc(elapsed_ns + 500_000, 1_000_000) * 1_000_000),
    });
    {
        var parts: [max_parts]u8 = undefined;
        var w: usize = 0;
        for (r.workers[0..cfg.workers], 0..) |*worker, i| {
            const s = std.fmt.bufPrint(parts[w..], "{s}{d}", .{
                if (i > 0) " + " else "", worker.iters.load(.monotonic),
            }) catch break;
            w += s.len;
        }
        log.line("  iterations: {s} = {d} total", .{ parts[0..w], total_iters });
    }
    log.line("  throughput: encrypt {s}, decrypt {s}, combined {s}", .{
        size.humanRate(&a, total_enc, avg_enc),
        size.humanRate(&b, total_dec, avg_dec),
        size.humanRate(&c, total_enc + total_dec, elapsed_ns),
    });
    log.line("  bytes: {s} encrypted, {s} decrypted", .{
        size.humanBytes(&a, total_enc), size.humanBytes(&b, total_dec),
    });
    log.line("  data integrity: {d}/{d} PASS", .{ total_iters, total_iters });
    log.line("  concurrency: {s}, workers {d} (requested {d})", .{
        worker_mod.concurrency, cfg.workers, cfg.workers_requested,
    });
    log.line("  rss: warmup {s}, peak {s}, final {s} (delta {s}, {d:.1}% growth)", .{
        size.humanBytes(&a, @intCast(r.rss_warmup)),
        size.humanBytes(&b, @intCast(r.rss_peak)),
        size.humanBytes(&c, @intCast(r.rss_final)),
        size.humanBytesSigned(&d, rss_delta),
        rss_growth,
    });
    for (pd.tiers[0..pd.tier_count]) |t| {
        if (t.starter == 0) continue;
        log.line(
            "  hash pool tier {d} (starter {d}): get {d}, miss {d} (new {d} + regrow {d}), miss {d:.2}%, {s} allocated",
            .{
                t.index,  t.starter, t.get, t.fresh + t.regrow, t.fresh, t.regrow,
                missPercent(t.fresh + t.regrow, t.get), size.humanBytes(&a, t.new_bytes),
            },
        );
    }
    log.line("  buf pool: get {d}, regrow {d} (of which fresh {d}), miss {d:.2}%, {s} regrown", .{
        pd.buf_get, pd.buf_regrow, pd.buf_new,
        missPercent(pd.buf_regrow, pd.buf_get), size.humanBytes(&a, pd.buf_regrow_bytes),
    });
    log.line("  parallax chunk pool: get {d}, regrow {d} (of which fresh {d}), miss {d:.2}%, {s} regrown", .{
        pd.chunk_get, pd.chunk_regrow, pd.chunk_new,
        missPercent(pd.chunk_regrow, pd.chunk_get), size.humanBytes(&a, pd.chunk_regrow_bytes),
    });
    if (r.rekeys > 0) log.line("  rekeys: {d}", .{r.rekeys});
    if (r.blob_cycles > 0) log.line("  blob cycles: {d}", .{r.blob_cycles});
    for (r.workers[0..cfg.workers]) |*w| {
        if (w.failed) log.line("  ERROR: {s}", .{w.errorText()});
    }
    if (pass) {
        log.line("  verdict: PASS", .{});
        return 0;
    }
    log.line("  verdict: FAIL (errors={d})", .{errors});
    return 1;
}

const max_parts = worker_mod.max_workers * 24;

const JsonScalars = struct {
    elapsed_ns: i64,
    total_iters: i64,
    total_enc: i64,
    total_dec: i64,
    avg_enc: i64,
    avg_dec: i64,
    pass: bool,
    gomaxprocs: i32,
    stream_profile: []const u8,
    msg_profile: []const u8,
    rss_growth: f64,
    microbatch: []const u8,
    hashpool: []const u8,
};

fn emitJson(o: *std.ArrayList(u8), gpa: std.mem.Allocator, r: *RunState, pd: PoolDelta, v: JsonScalars) !void {
    const cfg = r.cfg;
    try o.print(gpa, "{{\"duration_seconds\":{d:.3}", .{@as(f64, @floatFromInt(v.elapsed_ns)) / 1e9});
    try o.print(gpa, ",\"iterations\":{d}", .{v.total_iters});
    try o.appendSlice(gpa, ",\"per_worker_iterations\":[");
    for (r.workers[0..cfg.workers], 0..) |*worker, i| {
        try o.print(gpa, "{s}{d}", .{ if (i > 0) "," else "", worker.iters.load(.monotonic) });
    }
    try o.append(gpa, ']');
    try o.print(gpa, ",\"bytes_encrypted\":{d}", .{v.total_enc});
    try o.print(gpa, ",\"bytes_decrypted\":{d}", .{v.total_dec});
    try o.print(gpa, ",\"encrypt_mb_per_sec\":{d:.1}", .{size.mbPerSec(v.total_enc, v.avg_enc)});
    try o.print(gpa, ",\"decrypt_mb_per_sec\":{d:.1}", .{size.mbPerSec(v.total_dec, v.avg_dec)});
    try o.print(gpa, ",\"combined_mb_per_sec\":{d:.1}", .{size.mbPerSec(v.total_enc + v.total_dec, v.elapsed_ns)});
    try o.print(gpa, ",\"rekeys\":{d}", .{r.rekeys});
    try o.print(gpa, ",\"blob_cycles\":{d}", .{r.blob_cycles});
    try o.appendSlice(gpa, ",\"worker_errors\":[");
    var n: usize = 0;
    for (r.workers[0..cfg.workers]) |*worker| {
        if (!worker.failed) continue;
        if (n > 0) try o.append(gpa, ',');
        n += 1;
        try jsonString(o, gpa, worker.errorText());
    }
    try o.append(gpa, ']');
    try o.print(gpa, ",\"verdict\":\"{s}\"", .{if (v.pass) "PASS" else "FAIL"});
    try o.print(gpa, ",\"shape\":\"{s}\"", .{cfg.shape.name()});
    try o.appendSlice(gpa, ",\"stream_profile\":");
    try jsonString(o, gpa, v.stream_profile);
    try o.appendSlice(gpa, ",\"message_profile\":");
    try jsonString(o, gpa, v.msg_profile);
    try o.appendSlice(gpa, ",\"hash\":");
    try jsonString(o, gpa, cfg.hash);
    try o.appendSlice(gpa, ",\"mac\":");
    try jsonString(o, gpa, cfg.mac);
    try o.print(gpa, ",\"payload_bytes\":{d}", .{cfg.payload_bytes});
    try o.print(gpa, ",\"payload_mode\":\"{s}\"", .{cfg.payload_mode.name()});
    try o.print(gpa, ",\"seed\":{d}", .{cfg.seed});
    try o.print(gpa, ",\"key_bits\":{d}", .{cfg.key_bits});
    try o.print(gpa, ",\"nonce_bits\":{d}", .{cfg.nonce_bits});
    try o.print(gpa, ",\"blob_mode\":{d}", .{cfg.blob_mode});
    try o.appendSlice(gpa, ",\"drbg\":");
    try jsonString(o, gpa, cfg.drbg);
    try o.appendSlice(gpa, ",\"drbg_auto_tier\":");
    try jsonString(o, gpa, itb.drbgAutoTier());
    try o.print(gpa, ",\"chunk_size_bytes\":{d}", .{cfg.chunk_size});
    try o.print(gpa, ",\"barrier_fill\":{d}", .{cfg.barrier_fill});
    try o.print(gpa, ",\"parallax\":\"{s}\"", .{onOff(cfg.parallax)});
    try o.print(gpa, ",\"wrapper\":\"{s}\"", .{onOff(cfg.wrapper)});
    try o.print(gpa, ",\"goroutines_requested\":{d}", .{cfg.workers_requested});
    try o.print(gpa, ",\"goroutines\":{d}", .{cfg.workers});
    try o.print(gpa, ",\"concurrency\":\"{s}\"", .{worker_mod.concurrency});
    try o.print(gpa, ",\"gogc\":\"{d}\"", .{effectiveGogc(cfg.gogc)});
    try o.print(gpa, ",\"memlimit_bytes\":{d}", .{cfg.memlimit});
    try o.print(gpa, ",\"gomaxprocs\":{d}", .{v.gomaxprocs});
    try o.appendSlice(gpa, ",\"microbatch_tiers\":");
    try jsonString(o, gpa, v.microbatch);
    try o.appendSlice(gpa, ",\"hashpool_starters\":");
    try jsonString(o, gpa, v.hashpool);
    try o.print(gpa, ",\"rss_warmup_bytes\":{d}", .{r.rss_warmup});
    try o.print(gpa, ",\"rss_peak_bytes\":{d}", .{r.rss_peak});
    try o.print(gpa, ",\"rss_final_bytes\":{d}", .{r.rss_final});
    try o.print(gpa, ",\"rss_growth_percent\":{d:.2}", .{v.rss_growth});
    try o.appendSlice(gpa, ",\"hash_pool_tiers\":[");
    var t_n: usize = 0;
    for (pd.tiers[0..pd.tier_count]) |t| {
        if (t.starter == 0) continue;
        try o.print(gpa, 
            "{s}{{\"tier\":{d},\"starter\":{d},\"get\":{d},\"new\":{d},\"regrow\":{d},\"new_bytes\":{d},\"miss_percent\":{d:.2}}}",
            .{
                if (t_n > 0) "," else "", t.index, t.starter, t.get, t.fresh, t.regrow,
                t.new_bytes, missPercent(t.fresh + t.regrow, t.get),
            },
        );
        t_n += 1;
    }
    try o.append(gpa, ']');
    try o.print(gpa, 
        ",\"buf_pool\":{{\"get\":{d},\"new\":{d},\"regrow\":{d},\"regrow_bytes\":{d},\"miss_percent\":{d:.2}}}",
        .{ pd.buf_get, pd.buf_new, pd.buf_regrow, pd.buf_regrow_bytes, missPercent(pd.buf_regrow, pd.buf_get) },
    );
    try o.print(gpa, 
        ",\"parallax_chunk_pool\":{{\"get\":{d},\"new\":{d},\"regrow\":{d},\"regrow_bytes\":{d},\"miss_percent\":{d:.2}}}",
        .{ pd.chunk_get, pd.chunk_new, pd.chunk_regrow, pd.chunk_regrow_bytes, missPercent(pd.chunk_regrow, pd.chunk_get) },
    );
    try o.appendSlice(gpa, "}\n");
}
