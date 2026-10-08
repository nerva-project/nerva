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

/* What raising v8's `iters` would cost a verifier: single-thread time of the
 * v8 hash against iters, from the shipped range (at most 63) up to 262144,
 * and the marginal cost per CN step.
 *
 * Each CN step is two dependent pad accesses: pre_aes loads at state_index(a)
 * and post_aes_variant loads and stores at state_index(c), with the second
 * address depending on the first result. So the slope is the latency of a
 * dependent pair, not a throughput figure.
 *
 * Build: as screen_time.c's header, with contrib/powbench/t_iters.c in place
 * of screen_time.c.
 *
 *   t_iters [rounds]       default 15; the median of the rounds is reported */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cpuid.h>
#include "hash-ops.h"

void cn_slow_hash_v14(cn_hash_context_t *, const void *, size_t, char *,
                      size_t, uint8_t, uint16_t, uint16_t);

/* Same stand-in v8bench.c uses: leaf 1, ECX bit 25, so crypto.cpp and the whole
 * C++ crypto library stay out of the link for one CPUID. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int cmpd(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static const size_t itervals[] = { 0, 63, 256, 1024, 4096, 16384, 65536, 262144 };
#define NIT (sizeof(itervals) / sizeof(itervals[0]))

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 15;
    char blob[76], out[32];
    double med[NIT];

    if (rounds < 1) rounds = 1;
    cn_hash_context_t *ctx = cn_hash_context_create();
    if (!ctx) return 1;
    memset(blob, 0xA5, sizeof blob);
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof blob, out, 32, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (!ctx->salt) return 1;

    double *samp = malloc(NIT * (size_t)rounds * sizeof(double));
    if (!samp) return 1;

    /* Interleaved, with the order reversed on alternate rounds, so a thermal
     * drift cancels instead of loading onto whichever row runs late. */
    for (int r = 0; r < rounds; r++)
        for (size_t q = 0; q < NIT; q++) {
            size_t k = (r & 1) ? NIT - 1 - q : q;
            double t0 = now_ms();
            cn_slow_hash_v14(ctx, blob, sizeof blob, out, itervals[k], CN_V8_INIT_SIZE_BLK, 6, 6);
            samp[k * rounds + r] = now_ms() - t0;
        }

    for (size_t k = 0; k < NIT; k++) {
        qsort(samp + k * rounds, rounds, sizeof(double), cmpd);
        med[k] = samp[k * rounds + rounds / 2];
    }

    printf("v8 verify cost against iters, one thread\n");
    printf("xx=yy=6 (30 xx/yy steps, the mean draw), blk=%d\n\n", CN_V8_INIT_SIZE_BLK);
    printf("     iters      ms     vs shipped    ns per CN step\n");
    for (size_t k = 0; k < NIT; k++) {
        double extra = med[k] - med[1];                     /* against iters=63 */
        double per = itervals[k] > 63
                   ? extra * 1e6 / (double)(itervals[k] - 63)
                   : 0.0;
        printf("  %8zu  %7.3f      %5.2fx      %s",
               itervals[k], med[k], med[k] / med[1],
               itervals[k] > 63 ? "" : "(baseline)");
        if (itervals[k] > 63) printf("%6.1f", per);
        printf("\n");
    }

    /* least squares slope over the rows above the shipped range */
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    int n = 0;
    for (size_t k = 0; k < NIT; k++) {
        if (itervals[k] < 256) continue;
        double x = (double)itervals[k], y = med[k];
        sx += x; sy += y; sxx += x * x; sxy += x * y; n++;
    }
    double slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);

    printf("\nmarginal cost %.2f ns per CN step (two dependent pad accesses)\n", slope * 1e6);
    printf("shipped v8 verify at iters<=63: %.3f ms\n", med[1]);
    printf("\nwhat a real chase would cost a verifier:\n");
    for (size_t it = 16384; it <= 262144; it *= 2)
        printf("  iters=%6zu  %6.3f ms  %5.2fx the shipped hash\n",
               it, med[1] + slope * (double)it, (med[1] + slope * (double)it) / med[1]);

    cn_hash_context_free(ctx);
    free(samp);
    return 0;
}
