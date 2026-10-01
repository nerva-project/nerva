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

/* Floating-point stage for CNA v8. PROTOTYPE, not in consensus.
 *
 * Included only by slow-hash-v8fp-{hw,sw}.c. Adds no macro to slow-hash.h and
 * edits no live function, so v10, v11 and v14 are untouched by construction.
 *
 * DETERMINISM. Only add, sub, mul, div and sqrt, the five operations IEEE-754
 * requires to be correctly rounded, so conforming implementations agree bit for
 * bit. No transcendentals. Every value carries RandomX's group-E constraint
 * (sign cleared, top three exponent bits forced to 011), which pins the
 * exponent into [0x300, 0x3FF] and makes zero, denormal, infinity and NaN
 * structurally unreachable.
 *
 * The constraint is applied to EVERY result, so no multiply ever feeds an add
 * and FMA contraction is impossible whatever the compiler flags say. Do not
 * thin or hoist it.
 *
 * Rationale and measurements: contrib/powbench/PLAN-v8.md and FINDINGS.md.
 */

#pragma once

#include <fenv.h>
#include <math.h>
#include <string.h>
#include <stdint.h>

/* Rounds per nonce. Cost is linear in this count. Changing it changes the
 * algorithm, and CN_V8_FP_SELFTEST_VECTOR must be regenerated with it. */
#define CN_V8_FP_ROUNDS   9600
#define CN_V8_FP_ROUND_MASK 15
#define CN_V8_FP_SELFTEST_VECTOR 0xde6e9e50908eab15ull

STATIC INLINE double cn_fp_bits_to_e(uint64_t bits)
{
    /* Sign cleared, top three exponent bits forced to 011. Eight further
     * exponent bits and the 52 fraction bits come from the input. */
    const uint64_t exp = 0x300ull | ((bits >> 52) & 0xFFull);
    const uint64_t out = (exp << 52) | (bits & 0x000FFFFFFFFFFFFFull);
    double d;
    memcpy(&d, &out, sizeof(d));
    return d;
}

STATIC INLINE uint64_t cn_fp_e_to_bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof(u));
    return u;
}

/* fesetround must not be inlined. GCC and Clang both ignore #pragma STDC
 * FENV_ACCESS, so without an opaque call plus memory clobbers they may assume
 * round-to-nearest throughout and fold arithmetic across the mode change.
 * RandomX relies on the same construction. */
#if defined(__GNUC__) || defined(__clang__)
#  define CN_FP_NOINLINE __attribute__((noinline))
#  define CN_FP_BARRIER() __asm__ __volatile__("" ::: "memory")
#elif defined(_MSC_VER)
#  define CN_FP_NOINLINE __declspec(noinline)
#  define CN_FP_BARRIER() _ReadWriteBarrier()
#else
#  define CN_FP_NOINLINE
#  define CN_FP_BARRIER() ((void)0)
#endif

static CN_FP_NOINLINE void cn_fp_set_round(int mode)
{
    CN_FP_BARRIER();
    fesetround(mode);
    CN_FP_BARRIER();
}

/* File scope so the stage and the self-test cannot select different modes. */
static const int cn_fp_modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };

/* One round: add, sub, mul, div, sqrt, each result constrained before anything
 * reads it. A macro so cn_fp_round and cn_fp_value_scan cannot diverge; OP sees
 * each raw result and expands to nothing on the shipping path. */
#define CN_FP_ROUND_BODY(e, OP)                                                     \
    e[0] = e[0] + e[1]; OP(0, e[0]); e[0] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[0])); \
    e[1] = e[1] - e[2]; OP(1, e[1]); e[1] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[1])); \
    e[2] = e[2] * e[3]; OP(2, e[2]); e[2] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[2])); \
    e[3] = e[3] / e[0]; OP(3, e[3]); e[3] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[3])); \
    e[0] = sqrt(e[0]);  OP(4, e[0]); e[0] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[0]));

#define CN_FP_NO_HOOK(i, x) ((void)0)

STATIC INLINE void cn_fp_round(double *e)
{
    CN_FP_ROUND_BODY(e, CN_FP_NO_HOOK)
}

/* Startup check: run the real round over a fixed vector and compare. Catches a
 * toolchain that computes something different, which would fork rather than
 * fail to compile. The expected value is the same on every architecture, which
 * is the point. Returns 0 on success. */
#define CN_V8_FP_SELFTEST_ROUNDS 256

STATIC INLINE uint64_t cn_fp_selftest_value(void)
{
    double e[4];
    uint64_t h = 1469598103934665603ull;
    uint32_t r;
    int i;

    e[0] = cn_fp_bits_to_e(0x0123456789ABCDEFull);
    e[1] = cn_fp_bits_to_e(0xFEDCBA9876543210ull);
    e[2] = cn_fp_bits_to_e(0xC0FFEE0BADF00D11ull);
    e[3] = cn_fp_bits_to_e(0x5EED5EED5EED5EEDull);

    for (r = 0; r < CN_V8_FP_SELFTEST_ROUNDS; r++)
    {
        if ((r & CN_V8_FP_ROUND_MASK) == 0)
            cn_fp_set_round(cn_fp_modes[(cn_fp_e_to_bits(e[0]) >> 3) & 3]);
        cn_fp_round(e);
    }
    cn_fp_set_round(FE_TONEAREST);

    for (i = 0; i < 4; i++)
    {
        h ^= cn_fp_e_to_bits(e[i]);
        h *= 1099511628211ull;
    }
    return h;
}

STATIC INLINE int cn_fp_selftest(void)
{
    return cn_fp_selftest_value() == CN_V8_FP_SELFTEST_VECTOR ? 0 : 1;
}

/* Value safety, checked on the real round body rather than inherited from
 * RandomX, whose round has a different shape. Classifies every raw result
 * before it is constrained and returns a bitmask per operation.
 *
 * Expected: no zero, denormal, infinity or NaN anywhere, and a negative only
 * from the subtraction. No negative at index 4 proves sqrt is never handed one;
 * no infinity or NaN at index 3 proves the divisor is never zero. */
#define CN_FP_SAW_ZERO      1u
#define CN_FP_SAW_DENORMAL  2u
#define CN_FP_SAW_INF       4u
#define CN_FP_SAW_NAN       8u
#define CN_FP_SAW_NEGATIVE 16u

STATIC INLINE void cn_fp_classify(unsigned *flags, double v)
{
    switch (fpclassify(v)) {
    case FP_ZERO:      *flags |= CN_FP_SAW_ZERO;     break;
    case FP_SUBNORMAL: *flags |= CN_FP_SAW_DENORMAL; break;
    case FP_INFINITE:  *flags |= CN_FP_SAW_INF;      break;
    case FP_NAN:       *flags |= CN_FP_SAW_NAN;      break;
    default: break;
    }
    if (signbit(v)) *flags |= CN_FP_SAW_NEGATIVE;
}

#define CN_FP_SCAN_HOOK(i, x) cn_fp_classify(&scan[i], (x))

/* out[] receives five masks, in the order add, sub, mul, div, sqrt. */
STATIC INLINE void cn_fp_value_scan(unsigned seeds, unsigned rounds, unsigned out[5])
{
    unsigned scan[5] = { 0, 0, 0, 0, 0 };
    uint64_t st = 0x243F6A8885A308D3ull;   /* pi, arbitrary and fixed */
    unsigned s, r, i;

    for (s = 0; s < seeds; s++) {
        double e[4];
        for (i = 0; i < 4; i++) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            e[i] = cn_fp_bits_to_e(st);
        }
        for (r = 0; r < rounds; r++) {
            if ((r & CN_V8_FP_ROUND_MASK) == 0)
                cn_fp_set_round(cn_fp_modes[(cn_fp_e_to_bits(e[0]) >> 3) & 3]);
            CN_FP_ROUND_BODY(e, CN_FP_SCAN_HOOK)
        }
        cn_fp_set_round(FE_TONEAREST);
    }
    for (i = 0; i < 5; i++) out[i] = scan[i];
}

/* Runs once per nonce, between the xx/yy loop and the iters loop.
 *
 * SEEDED FROM a AND THE PAD, NEVER FROM b. The two arms hold different values
 * in b by construction, and seeding from it made every input disagree across
 * them. a is void * because the arms declare it differently.
 *
 * Folds into both pad lines and into a, so the stage reaches the digest even
 * when iters is zero and the main AES loop does not run. */
STATIC INLINE void cn_fp_stage(uint8_t *hp_state, void *a)
{
    const uint32_t mask = (CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) - 1;
    double e[4];
    uint64_t *p0, *p1, *ua;
    uint32_t j0, j1;
    uint32_t r;

    /* Spelled out rather than calling state_index, which the software arm does
     * not have. This value must be bit-identical between the arms. */
    ua = (uint64_t *)a;

    j0 = (uint32_t)(((ua[0] >> 4) & mask) << 4);
    j1 = (uint32_t)(((ua[1] >> 4) & mask) << 4);

    p0 = U64(&hp_state[j0]);
    p1 = U64(&hp_state[j1]);

    e[0] = cn_fp_bits_to_e(p0[0]);
    e[1] = cn_fp_bits_to_e(p0[1]);
    e[2] = cn_fp_bits_to_e(p1[0] ^ ua[0]);
    e[3] = cn_fp_bits_to_e(p1[1] ^ ua[1]);

    for (r = 0; r < CN_V8_FP_ROUNDS; r++)
    {
        /* Fixed cadence, data-chosen mode: constant work per nonce. */
        if ((r & CN_V8_FP_ROUND_MASK) == 0)
            cn_fp_set_round(cn_fp_modes[(cn_fp_e_to_bits(e[0]) >> 3) & 3]);

        cn_fp_round(e);
    }

    /* Restore, or every later FP operation in the process is affected. */
    cn_fp_set_round(FE_TONEAREST);

    /* p1 before p0 in case j0 == j1, so the p0 write lands last. Deterministic
     * either way, but must not depend on statement order drifting. */
    p1[0] ^= cn_fp_e_to_bits(e[2]);
    p1[1] ^= cn_fp_e_to_bits(e[1]);
    p0[0] ^= cn_fp_e_to_bits(e[0]);
    p0[1] ^= cn_fp_e_to_bits(e[3]);

    ua[0] ^= cn_fp_e_to_bits(e[0]) ^ cn_fp_e_to_bits(e[2]);
    ua[1] ^= cn_fp_e_to_bits(e[1]) ^ cn_fp_e_to_bits(e[3]);
}
