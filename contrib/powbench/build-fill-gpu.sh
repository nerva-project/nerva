#!/bin/sh
# Build t_fill_gpu: the whole v14 chain fill on a card against the CPU.
# DRAW-PREREG.md's C-3. No OpenCL SDK needed: clmin.h binds OpenCL.dll at run
# time. Windows only, as t_hc128.
#
#   sh contrib/powbench/build-fill-gpu.sh [output]
#   ./t_fill_gpu [seconds]

set -e

OUT="${1:-t_fill_gpu.exe}"

cd "$(dirname "$0")/../.." || exit 1

g++ -O2 -std=c++14 -march=x86-64 -fno-strict-aliasing \
    -I contrib/powbench -I src -I src/crypto \
    contrib/powbench/t_fill_gpu.cpp contrib/powbench/hc128.c \
    -static -pthread -o "$OUT" -lm
GCC_EXIT=$?

if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi

echo "built $OUT"
