#!/bin/sh
# Build t_aes: AES throughput, CPU AES-NI against three GPU table placements.
#
#   sh contrib/powbench/build-aes.sh [output]
#   ./t_aes [seconds] [-v]
#
# WHY IT EXISTS. F77 measured the hash core at 64.9x against a card and had to
# publish it as an upper bound, because the kernel reads its AES T-table out of
# __constant memory, where a warp's divergent lookups serialise. This separates
# the algorithm from the kernel.
#
# -maes is REQUIRED. Without it the CPU arm will not compile; with the wrong
# flags elsewhere in this tree it has silently measured software AES before
# (FINDINGS F16), which is why the CPU side here uses _mm_aesenc_si128 directly
# rather than going through any dispatcher.
#
# OpenCL is loaded at runtime from OpenCL.dll via clmin.h: no SDK, no headers,
# no import library. Without a GPU the CPU half still runs.

set -e
OUT="${1:-t_aes.exe}"
cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

g++ -O2 -std=c++14 -maes -msse4.1 -march=x86-64 -fno-strict-aliasing \
    -I contrib/powbench \
    contrib/powbench/t_aes.cpp \
    $LINKFLAGS -pthread -o "$OUT" -lm
GCC_EXIT=$?

if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi
echo "built $OUT"
