#!/bin/sh
# Build t_v8_grid: hardware AES against software AES for CNA v8 across the
# whole consensus draw range.
#
#   sh contrib/powbench/build-v8-grid.sh [output]
#   ./t_v8_grid        exit 0 only if every check passes
#
# -DSLOW_HASH_HW_AES_BUILT=1 and -maes are not optional. Without them the
# hardware translation units compile to the software body and the run compares
# software against software, which would pass and mean nothing. The binary
# refuses to run on a CPU without AES-NI for the same reason.
#
# -fno-strict-aliasing matches CMakeLists.txt for these translation units,
# so this builds the same code the daemon does.

set -e

OUT="${1:-t_v8_grid.exe}"

cd "$(dirname "$0")/../.." || exit 1

case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW* | MSYS* | CYGWIN*) LINKFLAGS=${LINKFLAGS--static} ;;
    *)                        LINKFLAGS=${LINKFLAGS-} ;;
esac

# Boost's headers are reached only for BOOST_PP_STRINGIZE, via epee's
# warnings.h, which hash-ops.h includes. Fall back to the stand-in rather than
# making a Boost install a prerequisite for measuring a hash function.
BOOSTINC=""
for d in /opt/homebrew/include /usr/local/include /mingw64/include /usr/include; do
    if [ -f "$d/boost/preprocessor/stringize.hpp" ]; then BOOSTINC="-I$d"; break; fi
done
[ -z "$BOOSTINC" ] && BOOSTINC="-I contrib/powbench/noboost"

gcc -O2 -maes -march=x86-64 -fno-strict-aliasing \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    $BOOSTINC -I src -I src/crypto -I contrib/epee/include \
    contrib/powbench/t_v8_grid.c \
    src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
    src/crypto/slow-hash-v8-hw.c src/crypto/slow-hash-v8-sw.c \
    src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
    src/crypto/aesb.c src/crypto/keccak.c src/crypto/hash.c \
    src/crypto/blake256.c src/crypto/groestl.c src/crypto/jh.c \
    src/crypto/skein.c \
    src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
    src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
    contrib/epee/src/memwipe.c \
    $LINKFLAGS -pthread -o "$OUT" -lm
GCC_EXIT=$?

# read the compiler's status, not a pipeline's. A `| tail` here once reported
# rc=0 for a build that had failed.
if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, gcc exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi

echo "built $OUT"
echo "run it with no arguments; exit 0 means every check passed"
