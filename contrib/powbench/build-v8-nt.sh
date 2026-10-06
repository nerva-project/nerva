#!/bin/sh
# Build t_v8_nt, the pad-size sweep of the streaming-store attack. PLAN-v8-PHASE7 B2.
#
#   sh contrib/powbench/build-v8-nt.sh [output]
#
# Every source path is relative to the repo root, so the script puts itself
# there rather than requiring you to be there.
#
# Three flags are not optional and the binary is wrong without them:
#
#   -DSLOW_HASH_HW_AES_BUILT=1  otherwise slow-hash.c reduces its dispatcher to
#                               the software-AES body, every number is about 5x
#                               too slow, and the comparison means nothing.
#   -maes                       the v5pad units refuse to build without it, on
#                               purpose: the software path has its own pad-size
#                               assumption in e2i.
#   -fno-strict-aliasing        slow-hash type-puns the scratchpad.
#
# -ffp-contract=off matches CMakeLists.txt's setting for these translation
# units, so the harness builds the same code the daemon does.
#
# The v5pad*.c units are what make this a sweep rather than a single point:
# each is a recompilation of the v8 bodies at one pad size, with renamed
# symbols. They are shared with v8bench; see contrib/hf14checks/v5pad.inc for
# the three pad-size assumptions they lift and why.
#
# -static on MinGW so the binary can be carried to another box. On Linux drop it
# if glibc-static is missing; the failure is an obscure link error.
set -e

OUT="${1:-t_v8_nt.exe}"

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
    contrib/powbench/t_v8_nt.c \
    contrib/hf14checks/v5pad025.c contrib/hf14checks/v5pad05.c \
    contrib/hf14checks/v5pad1.c contrib/hf14checks/v5pad2.c \
    contrib/hf14checks/v5pad4.c contrib/hf14checks/v5pad8.c \
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
echo
echo "  t_v8_nt [threads] [seconds_per_point] [L3_MB]"
echo "  e.g. t_v8_nt 30 4 64     on a 7950X"
echo "       t_v8_nt 8 4 6       on an i7-7700HQ"
echo
echo "Machine quiet. A point marked UNSTABLE wants repeats, not a longer window."
