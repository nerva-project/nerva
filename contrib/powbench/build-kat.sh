#!/bin/sh
# Build t_kat: run the known-answer vectors and the HW/SW self test, so a change
# to src/crypto can be shown inert rather than asserted to be.
#
#   sh contrib/powbench/build-kat.sh [output]
#   ./t_kat        exit 0 only if both gates pass
#
# -DSLOW_HASH_HW_AES_BUILT=1 and -maes are not optional: without them the
# dispatcher reduces to the software body and the run proves nothing about the
# arm every miner uses. The binary says which arm it tested.
#
# -fno-strict-aliasing and -ffp-contract=off match CMakeLists.txt for these
# translation units, so this builds the same code the daemon does.

set -e

OUT="${1:-t_kat.exe}"

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

gcc -O2 -maes -march=x86-64 -fno-strict-aliasing -ffp-contract=off \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    $BOOSTINC -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/t_kat.c \
    src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
    src/crypto/slow-hash-v8-hw.c src/crypto/slow-hash-v8-sw.c \
    src/crypto/slow-hash-v8fp-hw.c src/crypto/slow-hash-v8fp-sw.c \
    src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
    src/crypto/aesb.c src/crypto/keccak.c src/crypto/hash.c \
    src/crypto/blake256.c src/crypto/groestl.c src/crypto/jh.c \
    src/crypto/skein.c \
    src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
    src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
    contrib/epee/src/memwipe.c \
    $LINKFLAGS -pthread -o "$OUT" -lm

echo "built $OUT"
echo "run it with no arguments; exit 0 means both gates passed"
