#!/bin/sh
# Build t_gather: random reads per second into the block cache, CPU against GPU.
# The number that decides PLAN-v8-PHASE8 D5, since every device needs 16,384 of
# them per nonce.
#
#   sh contrib/powbench/build-gather.sh [output]
#   ./t_gather [seconds]        machine quiet; a display-attached GPU is fine,
#                               launches are capped well under the TDR timeout
#
# OpenCL is loaded at runtime from OpenCL.dll via clmin.h, so no SDK, no
# headers and no import library are needed. If there is no GPU the CPU half
# still runs and reports.

set -e
OUT="${1:-t_gather.exe}"
cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

g++ -O2 -march=x86-64 -fno-strict-aliasing \
    -I contrib/powbench \
    contrib/powbench/t_gather.cpp \
    $LINKFLAGS -pthread -o "$OUT" -lm
GCC_EXIT=$?

if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi
echo "built $OUT"
