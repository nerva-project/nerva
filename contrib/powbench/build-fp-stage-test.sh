#!/bin/sh
# Build the Phase 2 FP stage test. Generated from build-v8bench.sh: same source
# list, same flags, same platform handling, plus the two v8fp translation units,
# because this links v14 and v15 into one binary to compare them.
#
#   sh contrib/powbench/build-fp-stage-test.sh
#   ./t_fp_stage
#
# Exit 0 means the FP determinism vector matched, the stage changed the hash on
# every input including iters=0, and the two AES arms agreed.
#
# (the rest of this header is build-v8bench.sh's and applies unchanged)
# Build v8bench as a single executable that runs on a machine with no toolchain
# and no nerva build tree. Run it from anywhere:
#
#   sh contrib/powbench/build-v8bench.sh
#
# Every source path below is relative to the repo root, so the script puts
# itself there rather than requiring you to be there. Running it from its own
# directory used to fail with two dozen "no such file or directory" lines, which
# is a poor greeting on a machine where someone has just cloned the tree.
#
# Prerequisites: a C compiler and Boost's headers. Boost is not optional even
# though nothing here uses Boost: hash-ops.h includes epee's warnings.h, which
# includes boost/preprocessor/stringize.hpp, and every source below includes
# hash-ops.h. On Termux that is:
#
#   pkg install clang boost-headers
#
# Distributions usually call it libboost-dev or boost-devel. Headers only;
# nothing is linked against Boost.
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
# Platforms, and what differs on each:
#
#   Windows (MinGW)  -static, so the binary can be carried to the other boxes.
#   Linux            not static by default; glibc-static is often absent and the
#                    failure is an obscure link error. LINKFLAGS=-static if you
#                    want to carry it.
#   macOS            never static; there is no static libc and the link fails.
#                    Boost comes from Homebrew, so its include path is searched.
#   aarch64          -march=armv8-a+crypto or whatever this compiler wants for
#                    __ARM_FEATURE_CRYPTO, probed rather than assumed; cc rather
#                    than gcc; not static.
#
# The include path also covers the repo's own headers, so nothing else is
# needed beyond a compiler and Boost's headers.
set -e

cd "$(dirname "$0")/../.." || exit 1

TMP=${TMPDIR:-/tmp}/v8bench-probe.$$
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

OS=$(uname -s 2>/dev/null || echo unknown)
MACH=${ARCH:-$(uname -m 2>/dev/null || echo x86_64)}

case "$OS" in
    MINGW* | MSYS* | CYGWIN*)
        SUF=".exe"
        # Windows is where a carried binary is actually wanted, and where
        # -static is known to work with the MinGW toolchain.
        LINKFLAGS=${LINKFLAGS--static}
        ;;
    Darwin)
        SUF=""
        # macOS ships no static libc and the link fails outright with -static.
        LINKFLAGS=${LINKFLAGS-}
        ;;
    *)
        SUF=""
        # Linux can do -static when glibc-static is installed and cannot when it
        # is not, and the failure is an obscure link error. Off by default; set
        # LINKFLAGS=-static if you want a binary to carry to another box.
        LINKFLAGS=${LINKFLAGS-}
        ;;
esac

OUT=${OUT:-t_fp_stage$SUF}

# Homebrew keeps Boost outside the default search path. Only the preprocessor
# headers are used and nothing links against Boost, but the build stops without
# them: hash-ops.h includes epee's warnings.h, which includes
# boost/preprocessor/stringize.hpp.
BOOSTINC=""
for d in /opt/homebrew/include /usr/local/include /mingw64/include /usr/include; do
    if [ -f "$d/boost/preprocessor/stringize.hpp" ]; then BOOSTINC="-I$d"; break; fi
done
if [ -z "$BOOSTINC" ]; then
    # No Boost. The only thing this build wants from it is BOOST_PP_STRINGIZE,
    # via epee's warnings.h, so fall back to the stand-in rather than making a
    # Boost install a prerequisite for measuring a hash function. Searched
    # after the real headers, so a real installation always wins.
    BOOSTINC="-I contrib/powbench/noboost"
    echo "Boost headers not found; using contrib/powbench/noboost for BOOST_PP_STRINGIZE"
fi

case "$MACH" in
    aarch64 | arm64)
        CC=${CC:-cc}

        # This probe is not optional and it guards the worst failure mode
        # available here.
        #
        # slow-hash.h enables the ARM hardware-AES path on
        # __aarch64__ && __ARM_FEATURE_CRYPTO. Compilers disagree about when
        # they define that: some want -march=armv8-a+crypto, Apple clang has
        # its own spelling, and newer clang has moved toward __ARM_FEATURE_AES.
        #
        # If it ends up undefined the hardware translation unit quietly compiles
        # the SOFTWARE body under the hardware symbol, while
        # detect_hardware_aes() still returns 1 on Apple silicon because Apple
        # silicon always has the extensions. The banner would then report
        # hardware AES over numbers about five times too slow. That is F16
        # inverted, and worse, because F16 at least made the numbers look wrong.
        #
        # So ask the compiler directly rather than guessing from the platform.
        cat > "$TMP/probe.c" <<'PROBE'
#if !defined(__ARM_FEATURE_CRYPTO)
#error __ARM_FEATURE_CRYPTO is not defined
#endif
int main(void) { return 0; }
PROBE
        ARCHFLAGS=""
        found=0
        for f in "" "-march=armv8-a+crypto" "-mcpu=native" "-mcpu=apple-m1"; do
            if $CC $f -c "$TMP/probe.c" -o "$TMP/probe.o" 2>/dev/null; then
                ARCHFLAGS="$f"
                found=1
                break
            fi
        done
        if [ "$found" != "1" ]; then
            echo "error: this compiler will not define __ARM_FEATURE_CRYPTO." >&2
            echo "Without it the hardware path compiles the software body and" >&2
            echo "the banner still claims hardware AES. Refusing to build a" >&2
            echo "binary whose numbers would be wrong and look right." >&2
            echo "Try a newer clang or gcc, or pass ARCHFLAGS explicitly." >&2
            exit 1
        fi
        [ -n "$ARCHFLAGS" ] && echo "arm crypto via: $ARCHFLAGS"
        ;;
    *)
        CC=${CC:-gcc}
        ARCHFLAGS=${ARCHFLAGS:--maes -march=x86-64}
        ;;
esac

$CC -O2 $ARCHFLAGS -fno-strict-aliasing \
    -DSLOW_HASH_HW_AES_BUILT=1 \
    $BOOSTINC -I src -I src/crypto -I contrib/epee/include -I contrib/hf14checks \
    contrib/powbench/t_fp_stage.c \
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
echo "Check the banner's AES line before trusting any number: a run that reports"
echo "SOFTWARE is about five times slow and is comparable to nothing."
echo
echo "It needs no install and writes nothing. On a phone, run it repeatedly:"
echo "thermal throttling makes a single run drift downward."
