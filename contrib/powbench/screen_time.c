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

/* How much of a v6 hash's time is the VM, and what does the cost spread in
 * FINDINGS.md F6 amount to in throughput rather than in operation counts?
 *
 * F6 measures memory operations. A hash also pays an 8 MB AES fill, an 8 MB
 * salt XOR and an 8 MB finalize pass, and those do not vary with the program,
 * so the VM's share of total hash time bounds what the spread is worth. This
 * measures that share directly, two ways:
 *
 *   A. decomposition. Time a full cn_slow_hash_v13 against the time of its
 *      2048 cn_vm_execute passes alone, on the same pad.
 *   B. end to end. Generate N nonces, estimate each one's cost from its
 *      program alone (the screen from screen.c), then time the real hash for
 *      each and compare the cheap tail against the mean.
 *
 * B is the number that matters, because it needs no assumption about which
 * parts of the hash the estimate is correlated with. A explains B.
 *
 * Wants an idle machine. Stop the daemon and close the browser first, or the
 * numbers are noise.
 *
 * Build:
 *   gcc -O2 -maes -march=x86-64 -fno-strict-aliasing \
 *       -I src -I src/crypto -I contrib/epee/include \
 *       contrib/powbench/screen_time.c \
 *       src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
 *       src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
 *       src/crypto/aesb.c src/crypto/keccak.c src/crypto/blake256.c \
 *       src/crypto/groestl.c src/crypto/jh.c src/crypto/skein.c \
 *       src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
 *       src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
 *       -o screen_time -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include <cpuid.h>

#include "cna-vm.h"
#include "hash-ops.h"

/* slow-hash.c asks crypto.cpp whether AES-NI is present, and picks the HW or
 * SW body on the answer. Linking crypto.cpp here would drag in the whole C++
 * crypto library for one CPUID, so this supplies the symbol instead, with the
 * same check crypto::has_aesni() does: leaf 1, ECX bit 25.
 *
 * Getting this wrong is not a small error. Built without
 * SLOW_HASH_HW_AES_BUILT, or with this returning 0, the harness silently times
 * the software-AES path and reports a v6 hash about five times slower than it
 * is. The build line and the banner both have to say HW for a number to count. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0)
        return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d))
        return 0;
    return (c & (1u << 25)) != 0;
}

/* ------------------------------------------------------------------ */

static uint64_t sm_state;

static uint64_t splitmix64(void)
{
    uint64_t z = (sm_state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static void fill_random(void *dst, size_t bytes)
{
    uint8_t *p = (uint8_t *)dst;
    size_t i = 0;
    while (i < bytes)
    {
        uint64_t v = splitmix64();
        size_t n = bytes - i < 8 ? bytes - i : 8;
        memcpy(p + i, &v, n);
        i += n;
    }
}

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* the same estimate screen.c uses: all branches taken, no regs, no memory */
static int estimate_memops(const cn_vm_program_t *prog)
{
    const int pc_mask = CN_PROGRAM_SIZE - 1;
    int pc = 0, step, memops = 0;

    for (step = 0; step < CN_PROGRAM_SIZE; step++)
    {
        const cn_vm_instruction_t *ins = &prog->instructions[pc & pc_mask];
        int next_pc = pc + 1;

        if (ins->op == CN_OP_SP_READ || ins->op == CN_OP_SP_WRITE)
            memops++;
        if (ins->op == CN_OP_CBRANCH)
            next_pc = (pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & pc_mask;

        pc = next_pc;
    }
    return memops;
}

typedef struct { int est; double sec; } sample_t;

static int cmp_est(const void *a, const void *b)
{
    int x = ((const sample_t *)a)->est, y = ((const sample_t *)b)->est;
    return (x > y) - (x < y);
}

static double mean_sec(const sample_t *s, int lo, int hi)
{
    double t = 0; int i;
    for (i = lo; i < hi; i++) t += s[i].sec;
    return hi > lo ? t / (hi - lo) : 0.0;
}

int main(int argc, char **argv)
{
    const int n = argc > 1 ? atoi(argv[1]) : 2000;
    const int warmup = 20;

    cn_hash_context_t *ctx;
    sample_t *s;
    char blob[76];
    char out[32];
    uint8_t seed[32];
    int i;
    volatile uint64_t sink = 0;

    sm_state = 0xA5A5C0FFEE123456ull;

    ctx = cn_hash_context_create();
    if (!ctx) { fprintf(stderr, "cn_hash_context_create failed\n"); return 1; }
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));

    printf("v6 hash timing, %d nonces\n", n);
    printf("(stop nervad and close the browser before trusting these)\n\n");

    /* the salt is normally chain-derived; its content does not change the
     * cost, only the values, so a fixed pseudorandom fill is fine for timing */
    fill_random(blob, sizeof(blob));
    fill_random(seed, sizeof(seed));
    for (i = 0; i < warmup; i++)
        cn_slow_hash_v13(ctx, blob, sizeof(blob), out, seed);
    if (ctx->salt) fill_random(ctx->salt, CN_SALT_MEMORY);

    /* The 8 MB pad's backing pages dominate the fixed cost: on base pages it
     * thrashes the TLB and the fill/finalize passes cost several times what
     * they should. The daemon asks for large pages and usually gets them; a
     * harness run without the privilege does not, and would understate the
     * VM's share of the hash. Print it rather than assume it. */
    printf("AES path              : %s\n",
#if defined(SLOW_HASH_HW_AES_BUILT)
           crypto_has_aesni() ? "hardware (AES-NI)" : "SOFTWARE - numbers not comparable"
#else
           "SOFTWARE - built without SLOW_HASH_HW_AES_BUILT, numbers not comparable"
#endif
          );
    printf("v13 pad backing pages : %s\n\n",
           cn_page_tier_name(cn_page_tier_for_version(ctx, 13)));

    /* ---------- A. decomposition ---------- */
    {
        const int reps = 30;
        double t_full = 0, t_vm = 0;
        uint64_t regs[CN_REG_COUNT];
        cn_vm_program_t prog;
        double t0;
        int r;

        for (r = 0; r < reps; r++)
        {
            fill_random(seed, sizeof(seed));
            fill_random(blob, sizeof(blob));

            t0 = now_sec();
            cn_slow_hash_v13(ctx, blob, sizeof(blob), out, seed);
            t_full += now_sec() - t0;
            sink ^= (uint64_t)out[0];

            cn_vm_generate_program(&prog, seed);
            fill_random(regs, sizeof(regs));
            t0 = now_sec();
            {
                int it;
                for (it = 0; it < CN_VM_ITERATIONS; it++)
                    cn_vm_execute(&prog, ctx->cna_scratchpad, regs);
            }
            t_vm += now_sec() - t0;
            sink ^= regs[0];
        }

        t_full /= reps;
        t_vm   /= reps;

        printf("A. where the time goes, mean of %d\n", reps);
        printf("   full cn_slow_hash_v13 : %8.3f ms\n", t_full * 1e3);
        printf("   its %d VM passes     : %8.3f ms  (%.1f%% of the hash)\n",
               CN_VM_ITERATIONS, t_vm * 1e3, 100.0 * t_vm / t_full);
        printf("   everything else       : %8.3f ms  (%.1f%%, fixed cost)\n\n",
               (t_full - t_vm) * 1e3, 100.0 * (t_full - t_vm) / t_full);
    }

    /* ---------- B. end to end ---------- */
    s = (sample_t *)malloc((size_t)n * sizeof(sample_t));
    if (!s) { fprintf(stderr, "out of memory\n"); return 1; }

    for (i = 0; i < n; i++)
    {
        cn_vm_program_t prog;
        double t0;

        fill_random(seed, sizeof(seed));
        fill_random(blob, sizeof(blob));
        cn_vm_generate_program(&prog, seed);
        s[i].est = estimate_memops(&prog);

        t0 = now_sec();
        cn_slow_hash_v13(ctx, blob, sizeof(blob), out, seed);
        s[i].sec = now_sec() - t0;
        sink ^= (uint64_t)out[0];
    }

    {
        double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0, r;
        double all;
        int k1, k5, k10;

        for (i = 0; i < n; i++)
        {
            double x = s[i].est, y = s[i].sec;
            sx += x; sy += y; sxx += x*x; syy += y*y; sxy += x*y;
        }
        {
            double nn = n;
            double num = nn*sxy - sx*sy;
            double den = sqrt((nn*sxx - sx*sx) * (nn*syy - sy*sy));
            r = den > 0 ? num / den : 0.0;
        }

        qsort(s, (size_t)n, sizeof(sample_t), cmp_est);
        all = mean_sec(s, 0, n);
        k1  = n / 100  > 0 ? n / 100  : 1;
        k5  = n / 20   > 0 ? n / 20   : 1;
        k10 = n / 10   > 0 ? n / 10   : 1;

        printf("B. real hash time against the cheap estimate, %d nonces\n", n);
        printf("   correlation(estimate, hash time) r = %.4f\n", r);
        printf("   mean hash time, all nonces          : %8.3f ms\n", all * 1e3);
        printf("   mean hash time, cheapest  1%% by est : %8.3f ms  (%.2fx faster)\n",
               mean_sec(s, 0, k1) * 1e3, all / mean_sec(s, 0, k1));
        printf("   mean hash time, cheapest  5%% by est : %8.3f ms  (%.2fx faster)\n",
               mean_sec(s, 0, k5) * 1e3, all / mean_sec(s, 0, k5));
        printf("   mean hash time, cheapest 10%% by est : %8.3f ms  (%.2fx faster)\n",
               mean_sec(s, 0, k10) * 1e3, all / mean_sec(s, 0, k10));
        printf("   mean hash time, dearest   1%% by est : %8.3f ms\n",
               mean_sec(s, n - k1, n) * 1e3);
        /* The column above is per accepted nonce and ignores what screening
         * costs. At acceptance q you pay for 1/q estimates to get one hash, so
         * the honest figure is
         *
         *     net = t_unscreened / ( (1/q) * t_estimate + t_accepted )
         *
         * which can be below 1.0: a cheap tail is worth nothing if reaching it
         * costs more than the hashes it avoids. t_estimate here is program
         * generation plus the walk. A real miner would also owe the part of
         * the chain fill that produces salt[0..32), which needs the block
         * cache and is not modelled; that makes the figures below optimistic,
         * which is the right direction for a bound. */
        {
            double t_est;
            const int reps = 200000;
            double t0;
            int j;
            volatile int acc = 0;

            t0 = now_sec();
            for (j = 0; j < reps; j++)
            {
                cn_vm_program_t p;
                uint8_t sd[32];
                fill_random(sd, sizeof(sd));
                cn_vm_generate_program(&p, sd);
                acc += estimate_memops(&p);
            }
            t_est = (now_sec() - t0) / reps;
            sink ^= (uint64_t)acc;

            printf("\nC. net throughput, screening cost included\n");
            printf("   one estimate (program gen + walk) : %8.1f us\n", t_est * 1e6);
            printf("   accept    est/accepted    net vs unscreened\n");
            {
                static const double q[] = {0.01, 0.05, 0.10, 0.25};
                const double tail[4] = { mean_sec(s, 0, k1), mean_sec(s, 0, k5),
                                         mean_sec(s, 0, k10), mean_sec(s, 0, n/4 ? n/4 : 1) };
                size_t qi;
                for (qi = 0; qi < 4; qi++)
                {
                    double per = (1.0 / q[qi]) * t_est + tail[qi];
                    printf("   %5.0f%%    %10.0f     %6.2fx%s\n",
                           q[qi] * 100.0, 1.0 / q[qi], all / per,
                           all / per < 1.0 ? "  (a loss)" : "");
                }
            }
        }
    }

    free(s);
    cn_hash_context_free(ctx);
    return (int)(sink & 0);
}
