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

/* Does the Phase 2 FP stage actually change the hash, and do the two AES arms
 * agree about it?
 *
 * Two questions, both of which a stage can fail silently.
 *
 * ABLATION. PLAN-v8 design constraint 6: the FP result must be folded back into
 * the integer state so it is load-bearing and cannot be skipped. A construction
 * can look strong while almost none of its randomness reaches the digest. This
 * compares v15 against v14 on the same inputs and requires them to differ on
 * every pair, which is the cheapest form of that check.
 *
 * iters is one of the values swept, and 0 is included deliberately. In
 * consensus iters is (height + 1) % iters_divisor and can be zero, in which
 * case the main AES loop never runs. A stage that folded only into the
 * registers would reach the digest on most nonces and not on those, which is
 * the kind of bug that surfaces as an occasional rejected block long after
 * launch. finalize_hash XORs the whole pad, so the stage folds into the pad too.
 *
 * CROSS-ARM. The hardware and software bodies are separate copies and the
 * software path shipped disagreeing with the hardware one until April 2019
 * (FINDINGS.md F3). This test earned its place immediately: the first version
 * of the stage seeded from register b, which the hardware arm leaves holding
 * the last pad load while the software arm keeps as the real register. Every
 * input disagreed between the arms, and nothing else in the build noticed.
 *
 * Build (from the repo root):
 *   sh contrib/powbench/build-fp-stage-test.sh
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "hash-ops.h"

void cn_slow_hash_v14_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v15_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v15_sw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
int  cn_slow_hash_v15_selftest(void);

/* kept in step with CN_V8_FP_ROUNDS in slow-hash-fp.h, which this file
 * cannot include: that header needs the pad-size machinery set up first. */
#define CN_V8_FP_ROUNDS_REPORTED 7680

/* slow-hash.c asks crypto.cpp this on x86; supply it rather than linking the
 * C++ crypto library for one CPUID. See v8bench.c, which does the same. */
#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}
#endif

typedef void (*fn)(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

/* salt_pad writes back into salt, and random_values indexes the pad, so both
 * are reset before every call exactly as cn_slow_hash_self_test does. Skipping
 * this reads uninitialised indices and segfaults rather than failing cleanly. */
static void call(cn_hash_context_t *ctx, fn f, const char *in, char *out, size_t iters)
{
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    f(ctx, in, strlen(in), out, iters, 8, 3, 3);
}

static void hex(const char *h, char *o)
{
    int i;
    for (i = 0; i < 32; i++) sprintf(o + i * 2, "%02x", (unsigned char)h[i]);
    o[64] = 0;
}


/* A second, independent measurement of what the stage costs.
 *
 * v8bench already reports this, but on an Apple M1 it read -0.59%, meaning the
 * stage appeared to cost nothing, while t_fp_cost on the same machine put a
 * mixed FP round at 19 ns, which over CN_V8_FP_ROUNDS should be plainly
 * visible. One of those is wrong and they share no code, so a third measurement
 * that shares code with neither is the way to tell which.
 *
 * Alternates the two so drift cannot land on one and not the other, which is
 * the same reason v8bench interleaves its group. */
static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

static void time_stage(cn_hash_context_t *ctx)
{
    const int reps = 120;
    char h[32];
    double t14 = 0.0, t15 = 0.0, t0;
    int i;

    for (i = 0; i < reps; i++) {
        t0 = now_ms();
        call(ctx, cn_slow_hash_v14_hw, "timing", h, 8);
        t14 += now_ms() - t0;

        t0 = now_ms();
        call(ctx, cn_slow_hash_v15_hw, "timing", h, 8);
        t15 += now_ms() - t0;
    }
    t14 /= reps;
    t15 /= reps;

    printf("\n  v14 %.4f ms   v15 %.4f ms   stage %+.2f%%\n",
           t14, t15, (t15 - t14) / t14 * 100.0);
    printf("  %.1f us over %d rounds = %.2f ns/round\n",
           (t15 - t14) * 1000.0, CN_V8_FP_ROUNDS_REPORTED,
           (t15 - t14) * 1e6 / (double)CN_V8_FP_ROUNDS_REPORTED);
}

int main(void)
{
    static const char *inputs[6] = { "", "a", "abc", "nerva", "The quick brown fox", "0123456789abcdef" };
    static const size_t itervals[3] = { 0, 1, 64 };
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h14[32], h15[32], h15sw[32], s14[65], s15[65];
    int i, t, differ = 0, hwsw = 1, total = 0, fp_ok;

    if (ctx == NULL) { printf("context alloc failed\n"); return 1; }

    /* The _hw and _sw entry points skip the dispatcher's lazy pad allocation,
     * so go through the public dispatcher once to get the pads mapped. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v14(ctx, "warmup", 6, h14, 1, 8, 3, 3);

    fp_ok = (cn_slow_hash_v15_selftest() == 0);

    for (t = 0; t < 3; t++)
        for (i = 0; i < 6; i++) {
            call(ctx, cn_slow_hash_v14_hw, inputs[i], h14,   itervals[t]);
            call(ctx, cn_slow_hash_v15_hw, inputs[i], h15,   itervals[t]);
            call(ctx, cn_slow_hash_v15_sw, inputs[i], h15sw, itervals[t]);
            total++;
            if (memcmp(h14, h15, 32) != 0) differ++;
            if (memcmp(h15, h15sw, 32) != 0) hwsw = 0;
            if (t == 0 && i < 2) {
                hex(h14, s14); hex(h15, s15);
                printf("  iters=0  \"%s\"\n    v14 %s\n    v15 %s\n", inputs[i], s14, s15);
            }
        }

    printf("\n  FP determinism vector ............ %s\n", fp_ok ? "PASS" : "FAIL");
    printf("  ablation, v15 != v14 ............. %d of %d\n", differ, total);
    printf("  cross-arm, v15 hw == v15 sw ...... %s\n", hwsw ? "PASS" : "FAIL");

    time_stage(ctx);

    cn_hash_context_free(ctx);
    return (fp_ok && differ == total && hwsw) ? 0 : 1;
}
