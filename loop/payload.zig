//! Plaintext content: the payload modes, the seeded per-worker
//! generator, and the buffer fill from the operating-system CSPRNG.

const std = @import("std");

/// Payload mode selector values for the --payload-mode flag.
///
///   - fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - pattern_zero / pattern_ff: degenerate constant fills (all 0x00
///     / all 0xFF) probing minimum-entropy plaintext handling.
///   - pattern_ascii: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
pub const PayloadMode = enum(u8) {
    fixed,
    rotating,
    pattern_zero,
    pattern_ff,
    pattern_ascii,

    pub const names = [_][]const u8{
        "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
    };

    pub fn name(self: PayloadMode) []const u8 {
        return names[@intFromEnum(self)];
    }

    pub fn parse(s: []const u8) ?PayloadMode {
        for (names, 0..) |n, i| {
            if (std.mem.eql(u8, s, n)) return @enumFromInt(i);
        }
        return null;
    }
};

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
pub fn seedWorker(seed: u64, worker_id: usize) u64 {
    return seed +% @as(u64, worker_id) +% 1;
}

fn splitmix64(state: *u64) u64 {
    state.* +%= 0x9E37_79B9_7F4A_7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
    z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
    return z ^ (z >> 31);
}

/// Fills `buf` from the operating-system CSPRNG. Zig-specific: the
/// libc entry returns at most ~33 MiB per call and may return short on
/// a signal, so the fill loops until every byte is in place. The libc
/// entry is used rather than the raw syscall so that anything counting
/// CSPRNG draws from outside the process sees them. Returns false on
/// failure.
pub fn fillRandom(buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const r = std.c.getrandom(buf.ptr + off, buf.len - off, 0);
        if (r <= 0) return false;
        off += @intCast(r);
    }
    return true;
}

/// Writes one plaintext buffer according to the payload mode. The
/// fixed and rotating modes draw from the seeded generator when the
/// run is seeded and from the OS CSPRNG otherwise; the pattern modes
/// are deterministic regardless of the seed. Returns false when the
/// CSPRNG fails.
pub fn fillPayload(mode: PayloadMode, seeded: bool, rng: *u64, buf: []u8) bool {
    switch (mode) {
        .fixed, .rotating => {
            if (!seeded) return fillRandom(buf);
            var i: usize = 0;
            while (i < buf.len) : (i += 8) {
                const v = splitmix64(rng);
                const bytes = std.mem.asBytes(&v);
                const take = @min(buf.len - i, 8);
                @memcpy(buf[i .. i + take], bytes[0..take]);
            }
            return true;
        },
        .pattern_zero => {
            @memset(buf, 0x00);
            return true;
        },
        .pattern_ff => {
            @memset(buf, 0xFF);
            return true;
        },
        .pattern_ascii => {
            for (buf, 0..) |*b, i| b.* = @intCast('A' + (i % 26));
            return true;
        },
    }
}
