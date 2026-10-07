#!/bin/sh
# Build t_v8_sweep: cost v8 with and without salt_pad_v8 in one process.
# PLAN-v8-PHASE8 candidate D1.
#
#   sh contrib/powbench/build-v8-sweep.sh [output]
#   ./t_v8_sweep [threads] [seconds]
#
# Two compilations of the v8 bodies are linked side by side: v5pad1.c at 1 MB,
# which is the shipped algorithm, and v8nosweep.c, which is the same at the same
# pad with CN_V8_NO_SWEEP set. Comparing them inside one process on one machine
# is the only honest way to do it (measurement rule 6).
#
# -DSLOW_HASH_HW_AES_BUILT=1 and -maes are not optional: without them the
# dispatcher reduces to the software body, every number is about 5x slow, and
# the comparison means nothing.

set -e

OUT="${1:-t_v8_sweep.exe}"

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
    $BOOSTINC -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/t_v8_sweep.c \
    contrib/hf14checks/v8nosweep.c contrib/hf14checks/v8nopadxor.c \
    contrib/hf14checks/v5pad1.c \
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

echo "built $OUT"
echo
echo "  t_v8_sweep [threads] [seconds]   machine quiet"
