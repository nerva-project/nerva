#!/bin/sh
# Build v8bench as a single executable that runs on a machine with no toolchain
# and no nerva build tree. Run from the repo root:
#
#   sh contrib/powbench/build-v8bench.sh
#
# Two flags are not optional and the binary is wrong without them:
#
#   -DSLOW_HASH_HW_AES_BUILT=1  otherwise slow-hash.c reduces its dispatcher to
#                               the software-AES body and every number is about
#                               5x too slow. The banner reports which path ran.
#   -fno-strict-aliasing        slow-hash type-puns the scratchpad.
#
# -O2 plus the per-architecture flags below match what the main build uses for
# the crypto sources, so the recompiled rows are comparable to the shipped ones.
#
# aarch64 (Termux on a phone, or any ARM64 Linux) differs in three ways, all of
# them required:
#
#   -march=armv8-a+crypto  enables the ARMv8 Crypto Extensions, which is what
#                          slow-hash.h's vaeseq_u8 path compiles against. The
#                          x86 -maes/-march pair is meaningless there.
#   no -static             bionic ships no static libc, so the link fails.
#                          Static was only there so the binary could be carried
#                          to a machine with no toolchain, which does not apply
#                          when you build on the device you are measuring.
#   cc, not gcc            Termux's compiler is clang; gcc is not installed.
#
# Everything else is deliberately identical, because the point of this harness
# is that both architectures run the same measured function.
set -e

case "${ARCH:-$(uname -m)}" in
    aarch64 | arm64)
        CC=${CC:-cc}
        OUT=${OUT:-v8bench}
        ARCHFLAGS="-march=armv8-a+crypto"
        LINKFLAGS=""
        ;;
    *)
        CC=${CC:-gcc}
        OUT=${OUT:-v8bench.exe}
        ARCHFLAGS="-maes -march=x86-64"
        LINKFLAGS="-static"
        ;;
esac

$CC -O2 $ARCHFLAGS -fno-strict-aliasing \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/v8bench.c \
    contrib/hf14checks/v5pad1.c contrib/hf14checks/v5pad2.c \
    contrib/hf14checks/v5pad4.c contrib/hf14checks/v5pad8.c \
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
echo "Check the banner's AES line before trusting any number: a run that reports"
echo "SOFTWARE is about five times slow and is comparable to nothing."
echo
echo "It needs no install and writes nothing. On a phone, run it repeatedly:"
echo "thermal throttling makes a single run drift downward."
