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

/* Is floating point more uniform across CPUs than memory latency is?
 *
 * Phase 2 of PLAN-v8 rests on two arguments. One is GPU resistance, which FP64
 * rate limits support on their own. The other is cross-CPU fairness, and it
 * rests on this sentence: "FP adds work without adding memory, so unlike a
 * larger pad it does not punish small-cache machines."
 *
 * That sentence is about memory. It says nothing about whether FP throughput is
 * more or less uniform across CPUs than memory latency is, and only the second
 * thing decides whether adding FP moves the spread toward the 2.2x target or
 * away from it. F31 puts the current spread at 2.44x at 1 MB with an ARM device
 * in the set. If FP alone spreads wider than that, then adding FP makes the
 * fairness axis worse and Phase 2's second argument is not merely unproven, it
 * is backwards.
 *
 * The prediction, stated before measuring, per PLAN-v8 section 1e: FP will
 * spread wider than 2.44x. Divide and square root are the least uniform
 * operations a CPU has, because divider width and refinement-step count vary
 * far more across microarchitectures than cache latency does, and an in-order
 * Cortex-A55 is weak at FP64 even by its own standards. If that is right, the
 * fairness argument dies and Phase 2 has to be justified on GPU resistance
 * alone, which is a different decision than the plan currently describes.
 *
 * What is measured, and why each one separately:
 *
 *   add/sub   pipelined, short latency, the most uniform thing here
 *   mul       likewise, with a wider spread historically
 *   div       long latency, poorly pipelined, varies most between designs
 *   sqrt      same family, often sharing the divider
 *   round     fesetround() from data, at the 1-in-16 rate the design calls for.
 *             A register write on x86 and a libc call on ARM, which puts a
 *             device-dependent cost directly on the axis being equalised.
 *   mixed     all five plus rounding, constrained per write: what a real stage
 *             would cost, including the dilution from its own scaffolding
 *
 * Every block runs the identical scaffolding, so the control measures exactly
 * what the others carry and the difference is the operation. That is the same
 * discipline as the v8 comparison, which reported a wrong verdict for a week by
 * measuring its control differently from its subject.
 *
 * Chains are serial: each result feeds the next. A PoW stage has to be
 * dependency-chained or a miner reorders it, so latency is the honest cost, not
 * throughput. An independent-operand version of this would flatter every wide
 * machine and tell us nothing about the fairness question.
 *
 * Build (no dependencies, any C99 compiler):
 *   cc -O2 -ffp-contract=off t_fp_cost.c -o t_fp_cost -lm
 * On x86 add: -mfpmath=sse -msse2
 *
 * Run on every machine in the set and compare the FPCOST lines. On a phone,
 * pin it: sh contrib/powbench/pin-runs.sh measures one core of each type, and
 * an unpinned phone number is a blend of two or three different CPUs.
 */

/* before any system header, for sched_getcpu() */
#if !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fenv.h>
#include <math.h>
#include <time.h>
#if !defined(_WIN32)
#  include <sched.h>
#endif

#if defined(__GNUC__)
#pragma STDC FENV_ACCESS ON
#endif

/* Same trap as v8bench, same guard. Android rewrites a backgrounded app's
 * cpuset, which moves a pinned run onto a different core class mid-measurement
 * and produces numbers that look like core-type measurements and are not. This
 * run is short enough that it is unlikely, which is exactly why it would go
 * unnoticed. See FINDINGS F32. */
static void placement(char *out, size_t n, int *cpu)
{
    out[0] = '\0';
    *cpu = -1;
#if defined(__linux__) || defined(__ANDROID__)
    {
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        if (f != NULL) {
            while (fgets(line, sizeof(line), f) != NULL) {
                if (strncmp(line, "Cpus_allowed_list:", 18) == 0) {
                    char *v = line + 18;
                    while (*v == ' ' || *v == '\t') v++;
                    v[strcspn(v, "\r\n")] = '\0';
                    snprintf(out, n, "%s", v);
                    break;
                }
            }
            fclose(f);
        }
    }
    *cpu = sched_getcpu();
#else
    (void)n;
#endif
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static uint64_t sm;
static uint64_t rnd64(void)
{
    uint64_t z = (sm += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/* RandomX's group-E constraint, identical to t_fp_determinism.c: sign cleared,
 * top three exponent bits forced to 011, pinning the exponent field into
 * [0x300, 0x3FF]. Every value is a positive normal, so sqrt cannot produce NaN,
 * division cannot reach a signed zero, and no operation can reach a denormal.
 * Without it a serial div or sqrt chain walks out of range within a few
 * thousand iterations and starts timing denormal handling instead of
 * arithmetic, which is a different measurement wearing the same name. */
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

/* Consumed by every block so nothing can be optimised away. volatile, because
 * a compiler that proves the result unused is free to delete the chain that
 * produced it, and an -O2 build that silently measures an empty loop is the
 * single easiest way to get a confident wrong answer here. */
static volatile uint64_t sink;

enum { OP_CONTROL, OP_ADD, OP_MUL, OP_DIV, OP_SQRT, OP_ROUND, OP_MIXED, OP_COUNT };

static const char *const op_name[OP_COUNT] = {
    "control", "add/sub", "mul", "div", "sqrt", "round", "mixed"
};

/* One block. Identical scaffolding in every case: the same PRNG draw, the same
 * constrain_e, the same accumulate. Only the inserted operation differs. */
static double run_block(int op, long n)
{
    static const int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    double a, b, t0, t1;
    uint64_t acc = 0;
    long i;

    sm = 0xC0FFEE123456789ull;
    a = constrain_e(rnd64());
    b = constrain_e(rnd64());

    t0 = now_sec();
    for (i = 0; i < n; i++) {
        const uint64_t r = rnd64();

        switch (op) {
        case OP_CONTROL:
            /* no FP operation, everything else identical */
            break;
        case OP_ADD:
            a = a + b;
            b = b - a;
            break;
        case OP_MUL:
            a = a * b;
            break;
        case OP_DIV:
            a = b / a;
            break;
        case OP_SQRT:
            a = sqrt(a);
            break;
        case OP_ROUND:
            /* the design's 1-in-16 rate, driven from data exactly as CFROUND
             * does it, with one multiply so the mode change has something to
             * apply to */
            if ((r & 0x3Cull) == 0) fesetround(modes[r & 3]);
            a = a * b;
            break;
        case OP_MIXED:
            /* what a real stage would do per round: all five operations, each
             * stored before the next reads it so contraction is structurally
             * impossible, every write constrained */
            a = a + b;
            a = constrain_e(bits_of(a));
            b = b - a;
            b = constrain_e(bits_of(b));
            a = a * b;
            a = constrain_e(bits_of(a));
            b = b / a;
            b = constrain_e(bits_of(b));
            a = sqrt(a);
            if ((r & 0x3Cull) == 0) fesetround(modes[r & 3]);
            break;
        default:
            break;
        }

        a = constrain_e(bits_of(a) ^ r);
        b = constrain_e(bits_of(b) ^ (r >> 7));
        acc ^= bits_of(a) ^ bits_of(b);
    }
    t1 = now_sec();

    fesetround(FE_TONEAREST);
    sink = acc;
    return t1 - t0;
}

/* Scale until the block runs long enough to time. A fixed count is either
 * unmeasurable on a fast core or a minute long on an A55, and both machines
 * have to produce a number that can be compared with the other. */
static double measure(int op, long *used_n)
{
    long n = 100000;
    double secs = 0.0;

    for (;;) {
        secs = run_block(op, n);
        if (secs >= 0.25 || n >= 400000000L) break;
        n *= 4;
    }
    *used_n = n;
    return secs / (double)n * 1e9;   /* ns per iteration */
}

int main(int argc, char **argv)
{
    double ns[OP_COUNT];
    long n[OP_COUNT];
    char aff0[64], aff1[64];
    int cpu0, cpu1, pinned, tainted = 0;
    int i;

    (void)argc; (void)argv;

    placement(aff0, sizeof(aff0), &cpu0);
    /* "6" is pinned; "0-7" and "0,4" are not. Only a single-CPU mask makes a
     * core change meaningful, since an unpinned thread moving is ordinary. */
    pinned = (aff0[0] != '\0' && strchr(aff0, '-') == NULL &&
              strchr(aff0, ',') == NULL);

    printf("FP cost probe\n");
    if (aff0[0] != '\0') printf("  cpus allowed: %s\n", aff0);
#if defined(__x86_64__) || defined(_M_X64)
    printf("  arch: x86-64\n");
#elif defined(__aarch64__)
    printf("  arch: aarch64\n");
#else
    printf("  arch: other\n");
#endif
    printf("  serial chains; ns per iteration\n");
    printf("  net = block minus control\n\n");

    printf("  %-8s %9s %9s\n", "op", "ns", "net");
    for (i = 0; i < OP_COUNT; i++) {
        ns[i] = measure(i, &n[i]);
        if (i == OP_CONTROL)
            printf("  %-8s %9.3f %9s\n", op_name[i], ns[i], "-");
        else
            printf("  %-8s %9.3f %9.3f\n", op_name[i], ns[i],
                   ns[i] - ns[OP_CONTROL]);
    }

    /* One transcribable line, same convention as v8bench's SWEEP. Net costs,
     * because the scaffolding is an artifact of the harness and only the
     * operation is the subject. */
    printf("\n  FPCOST");
    for (i = 1; i < OP_COUNT; i++)
        printf(" %s=%.3f", op_name[i], ns[i] - ns[OP_CONTROL]);
    printf("\n");

    placement(aff1, sizeof(aff1), &cpu1);
    if (aff0[0] != '\0' && aff1[0] != '\0' && strcmp(aff0, aff1) != 0) {
        printf("\n  *** TAINTED: cpus allowed changed from %s to %s\n", aff0, aff1);
        tainted = 1;
    } else if (pinned && cpu0 >= 0 && cpu1 >= 0 && cpu0 != cpu1) {
        printf("\n  *** TAINTED: pinned to cpu%d, ended on cpu%d\n", cpu0, cpu1);
        tainted = 1;
    }
    if (tainted) {
        printf("  *** These numbers mix more than one core. Discard them.\n");
        printf("  *** On Android, run termux-wake-lock and keep Termux\n");
        printf("  *** in the foreground, then measure again.\n");
    }

    printf("\n  The question this answers: is the spread of the\n");
    printf("  mixed column across machines wider or narrower\n");
    printf("  than 2.44x? Wider means adding FP makes\n");
    printf("  cross-CPU fairness worse, not better.\n");
    return tainted ? 2 : 0;
}
