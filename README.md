## ITB Zig Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin Zig proxy over the ITB C binding (`bindings/c`), which in turn
wraps the libitb3 shared library's `ITB_Triple_*` surface
(`cmd/cshared`). The binding `@cImport`s the C binding's public
`itb3.h` and **links `libitb3_c.a` + `libitb3.so` at compile time** (an
absolute RPATH into `dist/` is embedded) — no runtime symbol loading.
Every hash-name / MAC-name / cipher-name / profile-name is an opaque
string passed through to Go for validation; the binding carries no
ITB construction logic, and buffer sizing plus the BufferTooSmall
retry-once dance live in the C layer. The public surface is an
allocator-parametric `Pipeline` (init / load / save / rekey / deinit,
Single Message encrypt / decrypt, whole-buffer stream entries
(`encryptStreamOneShot` and the pumps), incremental
`EncryptStream` / `DecryptStream` sessions with write / end / read /
drainAll), an `Opts` query-string builder for init overrides, the
profile-record entries (`register` / `lookup` / `profiles` /
`inspect`), a Zig `error{...}` set mirroring the C status codes, and
the Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make zig
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, and Zig
0.16+ (the build uses the current `std.Build` module API).

## Build

The convenience driver builds `libitb3.so`, the C binding static
archive, and the Zig binaries (eitb + benches) in one step:

```bash
./bindings/zig/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
make -C bindings/c build/libitb3_c.a
cd bindings/zig && zig build
```

## Add to a Zig project

`build.zig` exposes the library as a named module `itb3`; from another
project, create the module against `src/itb.zig` with the C include
path, the `libitb3_c.a` object, and the `-litb3` link input attached:

```zig
const itb_mod = b.createModule(.{
    .root_source_file = b.path("path/to/bindings/zig/src/itb.zig"),
    .target = target,
    .optimize = optimize,
    .link_libc = true,
});
itb_mod.addIncludePath(b.path("path/to/bindings/c/include"));
itb_mod.addObjectFile(b.path("path/to/bindings/c/build/libitb3_c.a"));
itb_mod.addLibraryPath(dist); // dist/linux-amd64 with libitb3.so
itb_mod.addRPath(dist);       // absolute, so binaries run anywhere
itb_mod.linkSystemLibrary("itb3", .{});
exe.root_module.addImport("itb3", itb_mod);
```

## Usage example

```zig
const itb = @import("itb3");

var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", null);
defer sender.deinit();

const blob = try sender.save();
defer allocator.free(blob);
var receiver = try itb.Pipeline.load(allocator, blob, null);
defer receiver.deinit();

const wire = try sender.encryptMessage("data");
defer allocator.free(wire);

const plain = try receiver.decryptMessage(wire);
defer allocator.free(plain);
```

`Opts` overrides the profile default at init (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap); every setter goes through `set(key, value)`. The resolved shape
travels inside the blob, so the receiver needs no options of its own:

```zig
var opts = try itb.Opts.init();
defer opts.deinit();
try opts.set("chunkSize", "65536");
try opts.set("withWrapper", "false");
try opts.set("maxWorkers", "4");
var sender = try itb.Pipeline.init(allocator, "singlemsg-triple-mac-v1", opts);
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```zig
const rotated = try sender.rekey(&[_]u8{0x11} ** 32, &[_]u8{0x22} ** 32);
defer allocator.free(rotated);
var receiver2 = try itb.Pipeline.load(allocator, rotated, null);
```

The same rotation is available on the receiver side as a master
override pair on load: `itb.Pipeline.load(allocator, blob, .{ .perm
= &perm, .wrap = &wrap })` reopens the blob with fresh masters folded
in.

## Persisting sessions

The blob returned by `save` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `load` reconstructs a Pipeline from it
without naming a profile.

```zig
const blob = try sender.save();                          // current blob bytes
var receiver = try itb.Pipeline.load(allocator, blob, null); // reopen from bytes
try sender.saveF("session.blob");                        // write to a file (mode 0600)
var receiver2 = try itb.Pipeline.loadF(allocator, "session.blob", null); // reopen from a file
const profile = try itb.inspect(allocator, blob);        // profile record, no Pipeline
// profile: {"name":"singlemsg-triple-mac-v1","mode":"singlemsg-mac",...}
```

`itb.inspect` decodes the embedded profile record (a JSON object)
without constructing a Pipeline. `saveF` / `loadF` perform the file
access inside libitb3. Every returned slice is allocator-owned —
release with `allocator.free`.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding surfaces `error.RecipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after `load`:

```zig
try receiver.maxWorkers(4);   // clamped by libitb3; <= 0 selects auto
```

## Profile registry

`itb.register` installs a user-defined profile under a new name from
a profile JSON record; `itb.lookup` reads a registered record back;
`itb.profiles` lists every registered name as a JSON array. The
record's field rules are enforced by libitb3; the binding treats the
JSON as an opaque string.

```zig
try itb.register("my-nomac-plain",
    \\{"mode":"singlemsg-nomac","width":512,"hash":"areion512",
    \\"keybits":1024,"wrapper":false,"parallax":false}
);
const record = try itb.lookup(allocator, "my-nomac-plain"); // record with "name" filled in
const names = try itb.profiles(allocator);                  // ["blob-triple-mac-v1", ...]
```

Every cipher output is allocated from the `Allocator` handed to
`Pipeline.init` / `Pipeline.load` and owned by the caller — release
with `allocator.free`. `encryptStreamOneShot` /
`decryptStreamOneShot` put a whole in-memory payload through the
stream chain in a single call. For bounded-memory streaming,
`encryptStreamPump` / `decryptStreamPump` move a whole buffer through
an incremental session; the explicit `encryptStream` /
`decryptStream` sessions expose `write` / `end` / `read` /
`drainAll` for caller-driven loops. A session holds a `parent`
pointer to its Pipeline and must be deinited before it.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a Zig error (for example
`error.BadInput`) with the diagnostic available via
`itb.lastError()`.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive GC
the Go scratch heap grows unboundedly under allocation churn:

```zig
_ = itb.setMemoryLimit(4 << 30); // 4 GiB soft cap
_ = itb.setGcPercent(100);        // balanced GC
```

## Testing

```bash
./bindings/zig/run_tests.sh
```

The harness builds the prerequisites, compiles every `tests/*.zig` to
its own test binary, and runs them sequentially as separate
processes; per-process isolation gives every test file a fresh libitb3
global state, and `std.testing.allocator` leak-checks every
allocator-owned buffer. The suite covers Single Message round trips
per shipped profile (empty plaintext included), stream pumps,
incremental sessions with pathological batch sizes, tampered-wire
failure stickiness, mid-flight cancellation, rekey, profile
registration, opts-builder encoding, and error mapping — surface
parity checks; the deep suite lives in Go under the shipped tree.

## Benchmarking

```bash
./bindings/zig/run_bench.sh
```

Micro-benches (always ReleaseFast): `message` (encryptMessage) and
`stream_pump` (encrypt stream pump) throughput at 1 MiB / 16 MiB /
64 MiB, reported as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` defaults plus the canonical
bench-shape env vars (`ITB_NONCE_BITS` / `ITB_KEY_BITS` /
`ITB_WITH_PARALLAX` / `ITB_WITH_WRAPPER` / `ITB_INNER_HASH` /
`ITB_PROFILE` / `ITB_BENCH_MIN_SEC`), respecting caller overrides;
the bench binaries apply the same heap caps programmatically.

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Pipeline.loadF`. `itb3` also encrypts / decrypts
payloads directly on disk (`-i` / `-o`) or through stdin / stdout,
rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

A small CLI under `bindings/zig/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
cd bindings/zig && zig build
./zig-out/bin/eitb version
./zig-out/bin/eitb profiles
./zig-out/bin/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
./zig-out/bin/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

The blob-hex argument to `decrypt` is parsed tolerantly:
case-insensitive, optional `0x` prefix, embedded whitespace accepted.
`decrypt` reopens the session with `Pipeline.load` from the blob hex;
the profile argument only selects the Single Message or streaming
cipher pair.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb.lastError()` text is process-global last-write-wins on
  the Go side; fetch it immediately after the failing call. The
  error value is always attributable.
- The wrapper adds no synchronisation of its own: concurrent cipher
  calls on one Pipeline are safe (the Go side serialises what needs
  serialising), but `rekey` and `deinit` must not run concurrently
  with cipher calls or open stream sessions on the same Pipeline.
- Handles are released exactly once (`Pipeline.deinit` /
  session `deinit`); a stream session must not outlive its Pipeline.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
