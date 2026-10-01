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

/* Does the v8 screening analysis cover the whole screenable surface?
 *
 * The expanded review regressed nonce cost on N = (xx-1)*yy alone and treated
 * everything else as a constant floor P. But get_cna_v6_data draws THREE
 * parameters after the fill, not two: xx, yy and init_size_blk. init_size_blk
 * does not change the AES operation count (pad/init_size_byte iterations of
 * init_size_blk blocks is pad/16 blocks at any width) but it does change the
 * width of the dependency chain, so it can change the TIME of the two pad
 * passes that the model calls fixed.
 *
 * Grid is all 75 reachable cells, timed interleaved and reported by median, so
 * thermal drift cannot masquerade as a cell effect. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cpuid.h>
#include "hash-ops.h"

/* Same stand-in v8bench.c uses: leaf 1, ECX bit 25, so crypto.cpp and the whole
 * C++ crypto library stay out of the link for one CPUID. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

void cn_slow_hash_v14(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}
static int cmpd(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

#define NXX 5
#define NYY 5
#define NBLK 3
#define NCELL (NXX*NYY*NBLK)

static const uint8_t blks[NBLK] = {2, 4, 8};

struct cell { uint16_t xx, yy; uint8_t blk; double med; };

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 41;
    double F = argc > 2 ? atof(argv[2]) : 0.721;   /* chain fill cost, ms */
    char blob[76], out[32];
    cn_hash_context_t *ctx = cn_hash_context_create();
    if (!ctx) return 1;
    memset(blob, 0xA5, sizeof blob);
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof blob, out, 32, 8, 4, 4);   /* warm: allocates pads */
    if (!ctx->salt) return 1;

    struct cell *c = malloc(NCELL * sizeof *c);
    double *samp = malloc((size_t)NCELL * rounds * sizeof(double));
    int n = 0;
    for (int i = 0; i < NXX; i++)
        for (int j = 0; j < NYY; j++)
            for (int b = 0; b < NBLK; b++) {
                c[n].xx = 4 + i; c[n].yy = 4 + j; c[n].blk = blks[b]; n++;
            }

    /* Interleaved: every cell is touched once per round, and alternate rounds
     * walk the grid backwards, so a monotone drift cancels instead of loading
     * onto whichever cell happens to run late. */
    for (int r = 0; r < rounds; r++) {
        for (int q = 0; q < NCELL; q++) {
            int k = (r & 1) ? NCELL - 1 - q : q;
            double t0 = now_ms();
            cn_slow_hash_v14(ctx, blob, sizeof blob, out, 32, c[k].blk, c[k].xx, c[k].yy);
            samp[(size_t)k * rounds + r] = now_ms() - t0;
        }
    }
    for (int k = 0; k < NCELL; k++) {
        qsort(samp + (size_t)k * rounds, rounds, sizeof(double), cmpd);
        c[k].med = samp[(size_t)k * rounds + rounds / 2];
    }

    /* --- what the review's model sees: cost against N, at each blk --- */
    printf("cost by init_size_blk, at fixed (xx,yy) = the model's \"constant\" floor\n\n");
    printf("  N=(xx-1)*yy    blk=2     blk=4     blk=8    blk2/blk8\n");
    for (int i = 0; i < NXX; i += 2)
        for (int j = 0; j < NYY; j += 2) {
            double v[NBLK];
            for (int b = 0; b < NBLK; b++)
                for (int k = 0; k < NCELL; k++)
                    if (c[k].xx == 4+i && c[k].yy == 4+j && c[k].blk == blks[b]) v[b] = c[k].med;
            printf("  %2d (%d,%d)      %6.3f    %6.3f    %6.3f     %5.2fx\n",
                   (4+i-1)*(4+j), 4+i, 4+j, v[0], v[1], v[2], v[0]/v[2]);
        }

    double mn = 1e9, mx = 0, sum = 0;
    int kmin = 0;
    for (int k = 0; k < NCELL; k++) {
        if (c[k].med < mn) { mn = c[k].med; kmin = k; }
        if (c[k].med > mx) mx = c[k].med;
        sum += c[k].med;
    }
    double mean = sum / NCELL;
    printf("\nfull grid (75 equiprobable cells)\n");
    printf("  min  %6.3f ms  (xx=%d yy=%d blk=%d)\n", mn, c[kmin].xx, c[kmin].yy, c[kmin].blk);
    printf("  mean %6.3f ms\n", mean);
    printf("  max  %6.3f ms\n", mx);
    printf("  spread %.2fx\n", mx / mn);

    /* --- best achievable screen, over the real joint distribution --- */
    for (int a = 0; a < NCELL; a++)       /* sort cells by cost, cheapest first */
        for (int b = a + 1; b < NCELL; b++)
            if (c[b].med < c[a].med) { struct cell t = c[a]; c[a] = c[b]; c[b] = t; }

    printf("\nbest screen, accepting the cheapest m of 75 cells\n");
    printf("  fill cost F = %.3f ms\n\n", F);
    printf("   m   p      E[H|acc]   honest   screener   gain\n");
    double best = 0; int bestm = NCELL;
    for (int m = 1; m <= NCELL; m++) {
        double s = 0;
        for (int k = 0; k < m; k++) s += c[k].med;
        double EH = s / m, p = (double)m / NCELL;
        double honest = F + mean, scr = F / p + EH;
        double gain = honest / scr;
        if (gain > best) { best = gain; bestm = m; }
        if (m == 1 || m == 5 || m == 15 || m == 25 || m == 38 || m == 56 || m == NCELL)
            printf("  %2d  %.2f    %6.3f     %6.3f    %6.3f    %.3fx\n", m, p, EH, honest, scr, gain);
    }
    printf("\n  best: m=%d, gain %.3fx\n", bestm, best);

    /* free-oracle ceiling and break-even fill */
    printf("  ceiling with a free fill (F=0): %.3fx\n", mean / c[0].med);
    double lo = 0, hi = 10.0;
    for (int it = 0; it < 60; it++) {
        double mid = (lo + hi) / 2, bg = 0;
        for (int m = 1; m < NCELL; m++) {
            double s = 0; for (int k = 0; k < m; k++) s += c[k].med;
            double g = (mid + mean) / (mid / ((double)m / NCELL) + s / m);
            if (g > bg) bg = g;
        }
        if (bg > 1.0) lo = mid; else hi = mid;
    }
    printf("  break-even fill cost: %.4f ms (screening pays below this)\n", lo);
    cn_hash_context_free(ctx);
    return 0;
}
