#!/bin/sh
# Build t_v8_fill: is the chain fill bound by random-access memory, or by
# HC-128 throughput? F38's honest weak point, measured.
#
#   sh contrib/powbench/build-v8-fill.sh [output]
#   ./t_v8_fill [height] [seconds]      defaults 4500000 and 6
#
# The default height allocates about 240 MB. Pass a smaller one on a machine
# that cannot spare it; the arms stay comparable, the absolutes do not.
#
# No AES here and no src/crypto at all: the fill is HC-128 and memory, so the
# only dependency is contrib/powbench/hc128.c.

set -e

OUT="${1:-t_v8_fill.exe}"

cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

g++ -O2 -march=x86-64 -fno-strict-aliasing \
    -I src -I src/crypto -I contrib/powbench \
    contrib/powbench/t_v8_fill.cpp contrib/powbench/hc128.c \
    $LINKFLAGS -o "$OUT" -lm
GCC_EXIT=$?

# read the compiler's status, not a pipeline's. A `| tail` here once reported
# rc=0 for a build that had failed.
if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi

echo "built $OUT"
