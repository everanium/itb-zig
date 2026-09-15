#!/usr/bin/env bash
#
# run_tests.sh -- Build and run the Zig binding integration tests.
#
# Each tests/<name>.zig compiles to its own test binary and runs as a
# separate process, sequentially; per-process isolation gives every
# test file a fresh libitb3 global state. Binaries link libitb3.so via
# embedded RPATH, so LD_LIBRARY_PATH is unnecessary at runtime.
#
# Usage:
#   ./run_tests.sh

set -euo pipefail

cd "$(dirname "$0")"

./build.sh

zig build test --summary all
