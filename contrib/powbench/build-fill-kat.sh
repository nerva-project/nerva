#!/bin/sh
# Build t_fill_kat: independent known-answer vectors for get_cna_v6_data.
#
#   sh contrib/powbench/build-fill-kat.sh [output]
#
# Needs only HC-128 and cn_fast_hash (keccak), never db_lmdb.cpp: the point is
# that it shares no fill code with the daemon.

set -e

OUT="${1:-t_fill_kat.exe}"

cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

gcc -O2 -c -I src -I src/crypto -I contrib/epee/include src/crypto/hash.c -o /tmp/fk_hash.o
gcc -O2 -c -I src -I src/crypto -I contrib/epee/include src/crypto/keccak.c -o /tmp/fk_keccak.o
g++ -O2 -std=c++14 -fno-strict-aliasing -I contrib/powbench -I src -I src/crypto \
    contrib/powbench/t_fill_kat.cpp contrib/powbench/hc128.c /tmp/fk_hash.o /tmp/fk_keccak.o \
    $LINKFLAGS -o "$OUT"
GCC_EXIT=$?

if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, g++ exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi

echo "built $OUT"
