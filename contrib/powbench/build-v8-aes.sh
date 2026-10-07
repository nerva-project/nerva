#!/bin/sh
# Build t_v8_aes: how big the AES-NI against T-tables asymmetry is on v8,
# measured as the same hash run both ways. The number under PLAN-v8-PHASE8 P3,
# which has never had one.
#
#   sh contrib/powbench/build-v8-aes.sh [output]
#   ./t_v8_aes [threads] [seconds]   one thread on a quiet machine
#
# -DSLOW_HASH_HW_AES_BUILT=1 and -maes are not optional. Without them the
# hardware translation units compile to the software body and the run compares
# software against software, which would pass and mean nothing. The binary
# refuses to run on a CPU without AES-NI for the same reason.
#
# The "no-sweep" rows were the D1 candidate, built from v8ns-{hw,sw}.c. D1
# shipped on 2026-10-07 and those files were deleted, because the shipped v8 IS
# the no-sweep core now (F72). The build pointed at them anyway and failed, so
# the v14ns symbols are aliased to the shipped arms below: the two row pairs
# now time the same function, which makes the second pair a within-run control
# rather than a candidate. F59's pre-D1 "v8" rows cannot be reproduced from this
# tree any more.
#
# -fno-strict-aliasing and -ffp-contract=off match CMakeLists.txt for these
# translation units, so this builds the same code the daemon does.

set -e

OUT="${1:-t_v8_aes.exe}"

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
    -Dcn_slow_hash_v14ns_hw=cn_slow_hash_v14_hw \
    -Dcn_slow_hash_v14ns_sw=cn_slow_hash_v14_sw \
    $BOOSTINC -I src -I src/crypto -I contrib/epee/include \
    contrib/powbench/t_v8_aes.c \
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
GCC_EXIT=$?

# read the compiler's status, not a pipeline's. A `| tail` here once reported
# rc=0 for a build that had failed.
if [ "$GCC_EXIT" -ne 0 ]; then
    echo "BUILD FAILED, gcc exit $GCC_EXIT"
    exit "$GCC_EXIT"
fi

echo "built $OUT"
echo "run it with no arguments; exit 0 means every check passed"
