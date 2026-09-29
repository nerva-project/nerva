#!/bin/sh
# Build v8bench as a single static executable that runs on a machine with no
# toolchain, no MSYS2 and no nerva build tree. Run from the repo root:
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
# -O2 -maes -march=x86-64 match what the main build uses for the crypto sources,
# so the recompiled rows are comparable to the shipped ones.
set -e

OUT=${OUT:-v8bench.exe}

gcc -O2 -maes -march=x86-64 -fno-strict-aliasing \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/v8bench.c \
    contrib/hf14checks/v5pad1.c contrib/hf14checks/v5pad4.c \
    src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
    src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
    src/crypto/aesb.c src/crypto/keccak.c src/crypto/hash.c \
    src/crypto/blake256.c src/crypto/groestl.c src/crypto/jh.c \
    src/crypto/skein.c \
    src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
    src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
    contrib/epee/src/memwipe.c \
    -static -o "$OUT" -lm

echo "built $OUT"
echo
echo "Copy it to the other machines and run it with nothing else going on."
echo "It needs no install and writes nothing."
