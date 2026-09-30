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

/* PLAN-v8 Phase 2: the floating-point stage.
 *
 * Why FP at all, measured rather than assumed (FINDINGS.md F33): the mixed FP
 * operation set spreads 1.22x across the machine set where the hash itself
 * spreads 2.44x, so adding FP dilutes an unequal workload with a more equal
 * one. It is the first lever measured that reaches the 2.2x fairness target;
 * F showed pad tuning cannot. Consumer GPUs also rate-limit FP64 to a fraction
 * of FP32 while a CPU runs it at integer speed, which is the largest hardware
 * asymmetry available that costs no memory.
 *
 * This header is included only by the v8fp translation units. It adds no macro
 * to slow-hash.h and edits no live function, so cn_slow_hash_v10, v11 and v14
 * are untouched by construction rather than by inspection. PLAN-v8, "the rule
 * that governs every phase".
 *
 *
 * DETERMINISM, which is the part that can fork the chain
 *
 * Only add, sub, mul, div and sqrt are used. All five are correctly rounded
 * under IEEE-754, so conforming implementations must agree bit for bit. No
 * transcendentals, which are not specified to the last bit.
 *
 * Operands carry RandomX's group-E constraint: sign cleared and the top three
 * exponent bits forced to 011, pinning the 11-bit exponent field into
 * [0x300, 0x3FF]. That is structurally unreachable from 0 (denormal) and 2047
 * (infinity, NaN), so every value is a positive normal. sqrt cannot produce a
 * NaN, division cannot reach a signed zero or divide by zero, and no operation
 * can reach a denormal.
 *
 * This is the lesson from reviewing RandomX and it is worth restating, because
 * an earlier version of this plan had it backwards: RandomX does not normalise
 * platform FP behaviour, it constrains values so the divergent cases are
 * unreachable. x86 sets FTZ and DAZ via mxcsr 0x9FC0 while ARM64 uses the
 * default environment; those are different settings and it does not matter,
 * because the cases they govern never occur. Constraint requires the two
 * platforms to agree only about correctly-rounded arithmetic, which IEEE-754
 * already mandates. Verified on four x86 machines and three ARM core types,
 * FINDINGS.md F29.
 *
 *
 * FMA CONTRACTION, and why this is structurally safe rather than flag-safe
 *
 * A compiler that fuses a*b+c into one rounding step changes the result, and
 * whether it does so is a compiler and target decision. -ffp-contract=off is
 * necessary but it is not a guarantee anyone can enforce downstream: a
 * distribution rebuilding this daemon without the flag would produce a binary
 * that disagrees with the network by forking rather than by failing to compile.
 * That happened in miniature during testing (FINDINGS.md F30) and it is the
 * failure mode this stage most needs to be immune to.
 *
 * So no multiply result is ever consumed directly by an add or a subtract.
 * Every FP write passes through cn_fp_constrain first, which is integer bit
 * manipulation through memcpy. There is therefore no a*b+c pattern anywhere in
 * the generated code for a compiler to fuse, whatever its flags say. The
 * constraint the plan already required for value safety buys contraction
 * immunity for free.
 *
 * cn_fp_selftest() below is the belt to that braces: it checks a known vector
 * at startup, so a build that somehow still diverges says so instead of mining
 * an incompatible chain.
 *
 *
 * COST, which must not vary per nonce
 *
 * PLAN-v8's rule 4 prefers constant work per nonce. This stage runs exactly
 * CN_V8_FP_ROUNDS rounds every time, with no data-dependent iteration count and
 * no data-dependent branch. Rules 1 and 2, about control flow depending on pad
 * loads, do not bite here precisely because nothing in this stage branches on
 * data at all.
 *
 * That includes the rounding mode, and this is a deliberate departure from
 * RandomX. RandomX's CFROUND applies when bits 2-5 of an operand are zero,
 * about one time in sixteen, which makes the number of mode changes per program
 * a function of the data. Here the cadence is fixed at every sixteenth round,
 * so every nonce performs exactly CN_V8_FP_ROUNDS/16 mode changes, while which
 * of the four modes is selected still comes from the data. That keeps the
 * property the mode change exists for, which is defeating a fixed-function FP
 * pipeline, and drops the cost variation that rule 4 objects to.
 *
 * Measured, changing the mode costs 4 to 5 times more on x86 than on ARM
 * (F33), because an MXCSR write serialises the pipeline while the ARM FPCR
 * write is cheap. It is the most ARM-favourable component in the stage. An
 * earlier draft of the plan recorded this the other way around.
 */

#pragma once

#include <fenv.h>
#include <math.h>
#include <string.h>
#include <stdint.h>

/* Rounds per nonce. Derived in F33: about 7,640 rounds of the measured mixed
 * operation set brings the cross-CPU spread from 2.44x to the 2.2x target, at
 * +19.7% verify cost on the fastest machine in the set and +7.8% on the
 * slowest. Rounded to a multiple of 16 so the mode-change cadence divides it
 * exactly and every nonce performs exactly 480 of them.
 *
 * This figure came from a probe whose round differs from the one below: the
 * probe carried a PRNG draw per iteration and this does not. It is a starting
 * point to measure against, not a settled constant, and the number that decides
 * it is the spread after this stage exists. */
#define CN_V8_FP_ROUNDS   7680
#define CN_V8_FP_ROUND_MASK 15
#define CN_V8_FP_SELFTEST_VECTOR 0xde6e9e50908eab15ull

STATIC INLINE double cn_fp_bits_to_e(uint64_t bits)
{
    /* RandomX constExponentBits = 0x300: sign cleared, top three exponent bits
     * forced to 011. Eight further exponent bits and the 52 fraction bits come
     * from the input, so magnitude varies without leaving the safe band. */
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

/* One round: the five permitted operations, each result passed through the
 * group-E constraint before anything reads it. The constraint is what makes
 * contraction impossible and what keeps every value a positive normal, so it is
 * not optional decoration and must not be hoisted or thinned as an
 * optimisation. */
/* File scope so the stage and the self-test cannot drift apart in which modes
 * they select or in what order. */
static const int cn_fp_modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };

STATIC INLINE void cn_fp_round(double *e)
{
    e[0] = e[0] + e[1];  e[0] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[0]));
    e[1] = e[1] - e[2];  e[1] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[1]));
    e[2] = e[2] * e[3];  e[2] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[2]));
    e[3] = e[3] / e[0];  e[3] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[3]));
    e[0] = sqrt(e[0]);   e[0] = cn_fp_bits_to_e(cn_fp_e_to_bits(e[0]));
}

/* The stage. Seeded from the pad at a state-derived offset, so it cannot be
 * computed before the pad exists and cannot be hoisted out of the hash; folded
 * back into both the integer state and the pad, so it is load-bearing.
 *
 * Folding into the pad matters more than it looks. iters is
 * (height + 1) % iters_divisor and can be zero, in which case the main AES loop
 * does not run at all and a fold into the registers alone would reach the
 * digest only sometimes. finalize_hash XORs the whole pad into the state, so a
 * pad fold always reaches it. */
/* Startup check for the one failure this stage cannot detect at runtime.
 *
 * The constraint between every operation already makes FMA contraction
 * structurally impossible, and -ffp-contract=off says so again. Neither
 * protects against a toolchain that does something unexpected anyway, and the
 * consequence of that is not a crash or a wrong answer anyone would notice: it
 * is a node that computes a different hash from the network and forks. F30
 * recorded exactly this happening on a first ARM build.
 *
 * So run the real round over a fixed vector and compare. 256 rounds is enough
 * for a single-ULP difference to reach every register and is fast enough to sit
 * in daemon startup. Returns 0 on success.
 *
 * The expected value is architecture-independent by design: it is the same on
 * x86-64 and aarch64, which is the whole claim of F29 and is what makes this a
 * useful check rather than a per-platform constant that hides the problem. */
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
            fesetround(cn_fp_modes[(cn_fp_e_to_bits(e[0]) >> 3) & 3]);
        cn_fp_round(e);
    }
    fesetround(FE_TONEAREST);

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

/* Seeded from a and the pad, and deliberately NOT from b.
 *
 * The two arms do not hold the same value in b and cannot be made to. In the
 * hardware arm b is scratch for the multiply, left holding the last pad load,
 * while the live register is the SSE value _b; in the software arm
 * copy_block(b, a) makes b the real register. Only a is guaranteed to match,
 * because a drives the next iteration's pad index and the arms agree on the
 * final hash. Seeding from b produced a stage whose hardware and software
 * outputs differed on every input: the F3 failure mode exactly, invisible to
 * review, and it would split the chain along the AES-NI line.
 *
 * a is void * because the arms declare it differently, uint64_t[2] against
 * uint8_t[AES_BLOCK_SIZE]. The same sixteen bytes either way, and one body
 * serves both rather than two that have to be kept in step by hand.
 *
 * Two pad reads at independently derived offsets rather than one, so the stage
 * depends on more of the pad than a single line. */
STATIC INLINE void cn_fp_stage(uint8_t *hp_state, void *a)
{
    const uint32_t mask = (CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) - 1;
    double e[4];
    uint64_t *p0, *p1, *ua;
    uint32_t j0, j1;
    uint32_t r;

    /* Written out rather than calling state_index, which the software arm does
     * not have: it is defined only inside slow-hash.h's hardware-AES block, and
     * the software arm reaches the same value through
     * e2i(a, n) * AES_BLOCK_SIZE. The two are the same expression, but this
     * value must be bit-identical between the arms or the pair disagrees, so it
     * is spelled out once here instead of depending on which macro happens to
     * be in scope. */
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
        /* Fixed cadence, data-chosen mode. The count of mode changes is a
         * constant of the algorithm; which mode is selected is not. */
        if ((r & CN_V8_FP_ROUND_MASK) == 0)
            fesetround(cn_fp_modes[(cn_fp_e_to_bits(e[0]) >> 3) & 3]);

        cn_fp_round(e);
    }

    /* Leave the environment as it was found. A stage that returned with the
     * mode still changed would silently alter every later FP operation in the
     * process, including any in the caller's own code. */
    fesetround(FE_TONEAREST);

    /* Fold into both pad lines and into a, so the stage is load-bearing by
     * every route out of the hash rather than by one. p1 is written before p0
     * in case j0 == j1, which is reachable when a[0] and a[1] index the same
     * line: the p0 write then lands last and is the one the digest sees, which
     * is deterministic either way but must not depend on statement order
     * drifting later. */
    p1[0] ^= cn_fp_e_to_bits(e[2]);
    p1[1] ^= cn_fp_e_to_bits(e[1]);
    p0[0] ^= cn_fp_e_to_bits(e[0]);
    p0[1] ^= cn_fp_e_to_bits(e[3]);

    ua[0] ^= cn_fp_e_to_bits(e[0]) ^ cn_fp_e_to_bits(e[2]);
    ua[1] ^= cn_fp_e_to_bits(e[1]) ^ cn_fp_e_to_bits(e[3]);
}
