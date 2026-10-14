#!/bin/sh
# Build the two standalone FP probes. Run it from anywhere:
#
#   sh contrib/powbench/build-probes.sh
#
# Unlike v8bench these need no nerva sources and no Boost, so they build in a
# second and can be copied to a machine with no toolchain and no build tree.
#
#   t_fp_determinism  do x86-64 and ARM64 agree bit for bit? (FINDINGS F29/F30)
#   t_fp_cost         what does each FP operation cost? (PLAN-v8 Phase 2)
#
# One flag is not optional and both binaries are wrong without it:
#
#   -ffp-contract=off  the compiler otherwise fuses a*b+c into an FMA, which
#                      changes the rounding. t_fp_determinism detects this and
#                      refuses; t_fp_cost cannot, and would quietly time a
#                      different set of operations from the one it names.
#
# On x86 -mfpmath=sse -msse2 keeps the arithmetic off the x87 stack, whose
# 80-bit intermediates would make the checksums disagree with every other
# machine for reasons that have nothing to do with the question being asked.
set -e

cd "$(dirname "$0")/../.." || exit 1

case "${ARCH:-$(uname -m)}" in
    aarch64 | arm64)
        CC=${CC:-cc}
        SUF=""
        ARCHFLAGS=""
        # bionic ships no static libc, and you build on the device you measure
        LINKFLAGS=""
        ;;
    *)
        CC=${CC:-gcc}
        case "$(uname -s 2>/dev/null)" in
            MINGW* | MSYS* | CYGWIN*) SUF=".exe" ;;
            *) SUF="" ;;
        esac
        ARCHFLAGS="-mfpmath=sse -msse2"
        # static so the result can be carried to the other machines, which is
        # the whole point of a probe that has to run on every box in the set
        LINKFLAGS="-static"
        ;;
esac

for p in t_fp_determinism t_fp_cost; do
    $CC -O2 -ffp-contract=off $ARCHFLAGS \
        contrib/powbench/$p.c $LINKFLAGS -o "$p$SUF" -lm
    echo "built $p$SUF"
done

echo
echo "Both write nothing and need no install."
echo "t_fp_cost: run it with nothing else going on. On a phone, pin it:"
echo "  BENCH=./t_fp_cost sh contrib/powbench/pin-runs.sh"
