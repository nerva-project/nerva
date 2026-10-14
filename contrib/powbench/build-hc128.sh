#!/bin/sh
# Build t_hc128: HC-128 throughput, CPU against GPU. The other half of the D5
# question, after build-gather.sh measured the random gather.
#
#   sh contrib/powbench/build-hc128.sh [output]
#   ./t_hc128 [seconds]
#
# The CPU arm links src/crypto/hc128.c, the daemon's own cipher, so the
# reference side is the shipped code rather than a re-derivation. The kernel is
# a transcription of that same file.
#
# OpenCL is loaded at runtime from OpenCL.dll via clmin.h: no SDK, no headers,
# no import library. Without a GPU the CPU half still runs.

set -e
OUT="${1:-t_hc128.exe}"
cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

g++ -O2 -march=x86-64 -fno-strict-aliasing \
    -I contrib/powbench -I src -I src/crypto \
    contrib/powbench/t_hc128.cpp contrib/powbench/hc128.c \
    $LINKFLAGS -pthread -o "$OUT" -lm
GCC_EXIT=$?

if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi
echo "built $OUT"
