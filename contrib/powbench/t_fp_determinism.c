// Copyright (c) 2026, The Nerva Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/* Does IEEE-754 double precision give bit-identical results on x86-64 and
 * ARM64, under the constraints a PoW would have to impose?
 *
 * This is the gate for Phase 2. Floating point is the one lever that adds work
 * without adding memory, so it does not punish small-cache machines, and
 * consumer GPUs rate-limit FP64 to a fraction of FP32 while a CPU runs it at
 * integer speed. But a single ULP of disagreement between two platforms forks
 * the chain, and Nerva builds for ARM, so this is a live risk rather than a
 * theoretical one.
 *
 * So: test the primitives before building anything on them. This performs the
 * exact operation mix an FP stage would use, under the exact constraints, and
 * prints a checksum of the raw bit patterns. Build and run it on both
 * architectures; the checksums must match exactly.
 *
 * The constraints being tested, all of which are load-bearing:
 *
 *   1. Only add, sub, mul, div, sqrt. All five are correctly rounded and exact
 *      under IEEE-754, so conforming implementations must agree bit for bit.
 *      No transcendentals, which are not specified to the last bit.
 *   2. No FMA. A compiler that contracts a*b+c into one fused op changes the
 *      result, and whether it does is a compiler and target decision. Built
 *      with -ffp-contract=off, and checkpoint 3 below is designed to expose it
 *      if the flag is missed.
 *   3. Operands constrained so denormals, infinities and NaN are unreachable:
 *      sign bit cleared, exponent pinned into a bounded range. Denormal
 *      handling is where FTZ/DAZ and hardware differences actually bite.
 *   4. Rounding mode changed from data. This is what defeats a fixed-function
 *      FP pipeline, and it is also the most likely place for a platform to
 *      diverge, since x86 uses MXCSR and ARM uses FPCR. fesetround() is used
 *      here for portability; a shipping version would write the register
 *      directly, and would need re-testing at that point.
 *
 * Build (no dependencies, any C99 compiler):
 *   cc -O2 -ffp-contract=off t_fp_determinism.c -o t_fp -lm
 * On x86 add: -mfpmath=sse -msse2
 *
 * Run on x86-64 and on ARM64 and compare the four checksums.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fenv.h>
#include <math.h>

#if defined(__GNUC__)
#pragma STDC FENV_ACCESS ON
#endif

static uint64_t sm;
static uint64_t rnd64(void)
{
    uint64_t z = (sm += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* RandomX's group-E constraint, which is the mechanism that makes this whole
 * approach viable, and is worth copying rather than inventing.
 *
 * Sign forced to 0, and the top three exponent bits forced to 011 via
 * constExponentBits = 0x300. That pins the 11-bit exponent field into
 * [0x300, 0x3FF], which is structurally unreachable from 0 (denormal) and 2047
 * (infinity and NaN). Every value is therefore a positive normal, so sqrt
 * cannot produce NaN, division cannot produce a signed zero, and no operation
 * can reach a denormal.
 *
 * That is why RandomX can set FTZ and DAZ on x86 (mxcsr 0x9FC0) while ARM uses
 * the default environment: the settings differ, and it does not matter, because
 * the cases they govern never occur. Constraining values is stronger than
 * normalising platform behaviour, because it does not require every platform to
 * agree about anything except correctly-rounded arithmetic. */
#define CONST_EXPONENT_BITS 0x300ull

static double constrain_e(uint64_t bits)
{
    const uint64_t exp = CONST_EXPONENT_BITS | ((bits >> 52) & 0xFFull);
    const uint64_t out = (exp << 52) | (bits & 0x000FFFFFFFFFFFFFull);
    double d;
    memcpy(&d, &out, sizeof(d));
    return d;
}

static uint64_t bits_of(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof(u));
    return u;
}

/* FNV over the raw bit patterns, so the comparison is exact rather than
 * "close enough": any single-ULP difference changes this. */
static uint64_t mix(uint64_t h, uint64_t v)
{
    int i;
    for (i = 0; i < 8; i++) { h ^= (v >> (i * 8)) & 0xff; h *= 1099511628211ull; }
    return h;
}

int main(void)
{
    const int N = 200000;
    uint64_t h_basic = 1469598103934665603ull;
    uint64_t h_round = 1469598103934665603ull;
    uint64_t h_sqrtdiv = 1469598103934665603ull;
    uint64_t h_contract = 1469598103934665603ull;
    int i;

    printf("FP determinism probe\n");
    printf("  %zu-bit long double, FLT_EVAL_METHOD=%d\n",
           sizeof(long double) * 8,
#ifdef __FLT_EVAL_METHOD__
           __FLT_EVAL_METHOD__
#else
           -2
#endif
          );
#if defined(__x86_64__) || defined(_M_X64)
    printf("  arch: x86-64\n");
#elif defined(__aarch64__)
    printf("  arch: aarch64\n");
#else
    printf("  arch: other\n");
#endif
    printf("\n");

    /* 1. the four basic arithmetic ops, round-to-nearest throughout */
    fesetround(FE_TONEAREST);
    sm = 0xC0FFEE123456789ull;
    {
        double a = constrain_e(rnd64()), b = constrain_e(rnd64());
        double c = constrain_e(rnd64()), d = constrain_e(rnd64());
        for (i = 0; i < N; i++) {
            a = a + b;
            b = b - c;
            c = c * d;
            d = d / a;
            /* keep them in range without using any further FP semantics */
            a = constrain_e(bits_of(a) ^ rnd64());
            b = constrain_e(bits_of(b) ^ rnd64());
            c = constrain_e(bits_of(c) ^ rnd64());
            d = constrain_e(bits_of(d) ^ rnd64());
            h_basic = mix(h_basic, bits_of(a) ^ bits_of(b) ^ bits_of(c) ^ bits_of(d));
        }
    }

    /* 2. sqrt and div, the two correctly-rounded ops most often implemented by
     *    approximation-plus-refinement, which is where a platform would differ
     *    if it were going to */
    sm = 0x5EED5EED5EED5EEDull;
    {
        double a = constrain_e(rnd64());
        for (i = 0; i < N; i++) {
            const double b = constrain_e(rnd64());
            a = sqrt(a) + b / (a + 1.0);
            a = constrain_e(bits_of(a) ^ rnd64());
            h_sqrtdiv = mix(h_sqrtdiv, bits_of(a));
        }
    }

    /* 3. FMA contraction canary. If the compiler fuses a*b+c the rounding
     *    differs from doing them separately, so these two hashes diverge from
     *    each other on a build where -ffp-contract=off was missed. This does
     *    not need a second machine to catch. */
    sm = 0xFEEDFACEFEEDFACEull;
    {
        double worst = 0.0;
        for (i = 0; i < N; i++) {
            const double a = constrain_e(rnd64());
            const double b = constrain_e(rnd64());
            const double c = constrain_e(rnd64());
            const double fused_maybe = a * b + c;         /* may become an FMA */
            volatile double t = a * b;                    /* volatile forbids it */
            const double separate = t + c;
            if (bits_of(fused_maybe) != bits_of(separate)) worst += 1.0;
            h_contract = mix(h_contract, bits_of(fused_maybe));
        }
        if (worst != 0.0) {
            printf("  *** FMA CONTRACTION DETECTED on %d of %d cases ***\n", (int)worst, N);
            printf("  *** rebuild with -ffp-contract=off; this build is not usable ***\n\n");
        }
    }

    /* 4. rounding mode driven from data, which is the property that defeats a
     *    fixed-function pipeline, and the most likely place for x86 (MXCSR) and
     *    ARM (FPCR) to disagree */
    sm = 0xA5A5A5A5A5A5A5A5ull;
    {
        static const int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
        double a = constrain_e(rnd64()), b = constrain_e(rnd64());
        for (i = 0; i < N; i++) {
            const uint64_t r = rnd64();
            fesetround(modes[r & 3]);
            a = a / (b + 1.0);
            b = sqrt(b) * 1.0000000001;
            a = constrain_e(bits_of(a) ^ r);
            b = constrain_e(bits_of(b) ^ (r >> 7));
            h_round = mix(h_round, bits_of(a) ^ bits_of(b));
        }
        fesetround(FE_TONEAREST);
    }

    printf("  basic add/sub/mul/div : %016llx\n", (unsigned long long)h_basic);
    printf("  sqrt and div          : %016llx\n", (unsigned long long)h_sqrtdiv);
    printf("  fma contraction canary: %016llx\n", (unsigned long long)h_contract);
    printf("  data-driven rounding  : %016llx\n", (unsigned long long)h_round);
    printf("\n  All four must match exactly between x86-64 and aarch64.\n");
    return 0;
}
