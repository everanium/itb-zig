#!/usr/bin/env bash
#
# build.sh -- one-step build for the Zig binding: libitb3.so + the C
# binding static archive + the Zig library / eitb / bench binaries.
# Prerequisites (Go, a C11 compiler, GNU make, Zig 0.16+) must be
# installed separately; see README.md "Prerequisites".
#
# Every artefact this binding owns is removed first, so nothing the
# build produces can be a leftover from an earlier invocation.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels
#   ITB_SKIP_CLEAN=1 ./build.sh   # keep the compile cache

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# ---- Clean ----------------------------------------------------------
# Artefacts this binding owns. Two inputs are deliberately out of
# scope because this binding consumes rather than produces them: the
# Go shared library under dist/linux-amd64/, and the C binding's
# static archive at bindings/c/build/libitb3_c.a, which the make
# invocation below brings up to date through the C binding's own
# build rules.
CLEAN_TARGETS=(
    .zig-cache            # compile cache
    zig-cache             # compile cache under the pre-0.14 name
    zig-out               # eitb + bench binaries
)

clean_artefacts() {
    local rel abs tracked

    # A build artefact is never tracked, so a hit here means the list
    # above is wrong. Abort rather than delete a source file.
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        tracked="$(git ls-files -- "${CLEAN_TARGETS[@]}")"
        if [ -n "$tracked" ]; then
            echo "clean: tracked files inside the clean scope:" >&2
            printf '%s\n' "$tracked" | sed 's/^/    /' >&2
            exit 1
        fi
    fi

    for rel in "${CLEAN_TARGETS[@]}"; do
        abs="$(readlink -m -- "$SCRIPT_DIR/$rel")"
        case "$abs" in
            "$SCRIPT_DIR"/?*) ;;
            *) echo "clean: '$rel' escapes $SCRIPT_DIR ($abs)" >&2; exit 1;;
        esac
        [ -e "$abs" ] || continue
        echo "[clean] rm -rf $abs"
        rm -rf -- "$abs"
    done
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing artefacts"
else
    echo "==> cleaning previous artefacts"
    clean_artefacts
fi

cd "$REPO_ROOT"
echo "==> building libitb3.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared

echo "==> building C binding static archive (make, CC=${CC:-cc})"
make -C "$SCRIPT_DIR/../c" build/libitb3_c.a

cd "$SCRIPT_DIR"
echo "==> building Zig binding (zig build)"
zig build

echo "==> ready: ./run_tests.sh"
