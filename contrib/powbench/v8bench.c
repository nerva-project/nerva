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

/* CNA v8 against CNA v5: a standalone, statically linkable benchmark.
 *
 * Phase 1 of the v8 plan widens salt_pad's extra-hash selector from three of
 * the four available hashes to all four, so Skein stops being dead weight in
 * the table and becomes a fourth structurally distinct datapath that an ASIC
 * cannot trim. The question this answers is what that costs to verify, which
 * has to hold on the weakest machine in the set, not the fastest.
 *
 * Two things make this harder to measure than it looks, and both are handled
 * here rather than left to the reader:
 *
 *   Work per nonce varies about 4.7x. v5 draws xx, yy, init_size_blk and iters
 *   per nonce, so a small sample measures the draw and not the algorithm. At
 *   n=60 the standard error on the mean is near 4.5%, which cannot resolve a
 *   2% question. Worse, with a fixed RNG seed a small sample repeats the same
 *   unrepresentative draw every run, so a sampling artifact looks stable and
 *   reads as a real result. That happened during development and inverted the
 *   sign of the answer. n is 2000 here at 1 MB.
 *
 *   The two variants are measured INTERLEAVED, one v5 nonce then one v8 nonce
 *   on identical parameters, rather than as consecutive blocks. Thermal drift,
 *   boost behaviour and background load then hit both equally instead of
 *   landing on whichever ran second.
 *
 * The control pair is what makes the result trustworthy: "ref" is the shipped
 * function out of the library, "ctl" is the same source recompiled here at the
 * same pad size. They should agree. Whatever they differ by is this machine's
 * noise floor, and the verdict is scaled to it rather than to a fixed
 * threshold that may be below what the machine can resolve.
 *
 * Build (static, no MSYS2 or MinGW DLLs needed at runtime):
 *   see build-v8bench.sh next to this file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <cpuid.h>

#include "hash-ops.h"

/* slow-hash.c asks crypto.cpp whether AES-NI is present and picks the HW or SW
 * body on the answer. Linking crypto.cpp would drag in the C++ crypto library
 * for one CPUID, so supply it here with the same check crypto::has_aesni()
 * does: leaf 1, ECX bit 25. Getting this wrong, or building without
 * SLOW_HASH_HW_AES_BUILT, silently measures software AES and reports a hash
 * about five times slower than it is. The banner prints which path ran. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

/* The CPU brand string, so a result pasted into a report says which box it came
 * from without anyone having to remember. CPUID leaves 0x80000002..4 hold it as
 * 48 bytes of ASCII; every x86-64 part supports them. */
static void cpu_brand(char out[49])
{
    unsigned int r[12];
    unsigned int a, b, c, d;
    int i;

    out[0] = '\0';
    if (!__get_cpuid(0x80000000u, &a, &b, &c, &d) || a < 0x80000004u) {
        snprintf(out, 49, "unknown x86-64");
        return;
    }
    for (i = 0; i < 3; i++)
        __get_cpuid(0x80000002u + (unsigned)i, &r[i*4], &r[i*4+1], &r[i*4+2], &r[i*4+3]);
    memcpy(out, r, 48);
    out[48] = '\0';

    /* parts pad the brand string with spaces, Intel at the front and AMD at
     * the back, so trim both ends */
    {
        char *p = out;
        size_t n;
        while (*p == ' ') p++;
        if (p != out) memmove(out, p, strlen(p) + 1);
        n = strlen(out);
        while (n > 0 && out[n - 1] == ' ') out[--n] = '\0';
    }
}

typedef void (*hashfn)(cn_hash_context_t *, const void *, size_t, char *,
                       size_t, uint8_t, uint16_t, uint16_t);

/* the resized recompilations, from contrib/hf14checks/v5pad{1,4}.c */
void cn_slow_hash_v11_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* xorshift, so the parameter stream is identical on every machine and both
 * variants of a pair see exactly the same work */
static uint32_t rng_state;
static uint32_t rnd(void)
{
    uint32_t x = rng_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return (rng_state = x);
}

struct params { size_t iters; uint8_t blk; uint16_t xx, yy; };

/* the ranges get_block_longhash_v11 draws from */
static struct params draw(void)
{
    struct params p;
    p.xx  = (uint16_t)(4 + rnd() % 5);
    p.yy  = (uint16_t)(4 + rnd() % 5);
    p.blk = (uint8_t)(2u << (rnd() % 3));
    p.iters = rnd() % (1 + rnd() % 64);
    return p;
}

struct result { double mean_ms, min_ms, max_ms; };

/* One interleaved pass: for each sample, the same parameters are handed to a
 * and then to b, and both times are recorded. */
static void bench_pair(hashfn fa, hashfn fb, size_t pad_bytes, unsigned n,
                       struct result *ra, struct result *rb, int *ok)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    uint8_t *own = NULL, *saved = NULL;
    char out[32];
    static const char blob[] = "nerva cna v8 phase 1 benchmark input, long enough for the v1 tweak at 35";
    unsigned i;

    *ok = 0;
    if (ctx == NULL) return;
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));

    /* One warm hash through the dispatcher first: the pads are allocated
     * lazily, and the resized functions below read context->scratchpad with no
     * allocation of their own. */
    { struct params w = draw(); cn_slow_hash_v11(ctx, blob, sizeof(blob) - 1, out, w.iters, w.blk, w.xx, w.yy); }
    if (ctx->salt == NULL) { cn_hash_context_free(ctx); return; }

    if (pad_bytes) {
        own = (uint8_t *)malloc(pad_bytes);
        if (own == NULL) { cn_hash_context_free(ctx); return; }
        memset(own, 0, pad_bytes);
        saved = ctx->scratchpad;
        ctx->scratchpad = own;
    }

    ra->mean_ms = rb->mean_ms = 0.0;
    ra->min_ms = rb->min_ms = 1e30;
    ra->max_ms = rb->max_ms = 0.0;

    for (i = 0; i < n; i++)
    {
        const struct params p = draw();
        double t0, ms;

        t0 = now_sec();
        fa(ctx, blob, sizeof(blob) - 1, out, p.iters, p.blk, p.xx, p.yy);
        ms = (now_sec() - t0) * 1e3;
        ra->mean_ms += ms;
        if (ms < ra->min_ms) ra->min_ms = ms;
        if (ms > ra->max_ms) ra->max_ms = ms;

        t0 = now_sec();
        fb(ctx, blob, sizeof(blob) - 1, out, p.iters, p.blk, p.xx, p.yy);
        ms = (now_sec() - t0) * 1e3;
        rb->mean_ms += ms;
        if (ms < rb->min_ms) rb->min_ms = ms;
        if (ms > rb->max_ms) rb->max_ms = ms;
    }

    ra->mean_ms /= n;
    rb->mean_ms /= n;

    if (pad_bytes) { ctx->scratchpad = saved; free(own); }
    cn_hash_context_free(ctx);
    *ok = 1;
}

static void row(const char *name, const struct result *r)
{
    printf("  %-14s %9.4f %9.4f %9.4f %10.1f\n",
           name, r->mean_ms, r->min_ms, r->max_ms, 1000.0 / r->mean_ms);
}

int main(int argc, char **argv)
{
    const unsigned n1 = argc > 1 ? (unsigned)atoi(argv[1]) : 2000;
    const unsigned n4 = argc > 2 ? (unsigned)atoi(argv[2]) : 600;
    struct result v5ref, v8ref, v5ctl, v8ctl, v5p4, v8p4;
    int ok1, ok2, ok3;
    double ctl_noise, d1, d4, gate;

    {
        char brand[49];
        cpu_brand(brand);
        printf("CNA v8 (Skein in salt_pad) against CNA v5, Phase 1\n");
        printf("CPU: %s\n", brand);
    }
    printf("AES path: %s\n",
#if defined(SLOW_HASH_HW_AES_BUILT)
           crypto_has_aesni() ? "hardware (AES-NI)"
                              : "SOFTWARE - this CPU has no AES-NI, numbers are not comparable to other machines"
#else
           "SOFTWARE - built without SLOW_HASH_HW_AES_BUILT, numbers are meaningless"
#endif
          );
    printf("samples: %u per variant at 1 MB, %u at 4 MB, interleaved\n\n", n1, n4);
    printf("Close other programs first. This measures single-thread verify cost.\n\n");

    rng_state = 0x9E3779B9u;
    bench_pair(cn_slow_hash_v11,    cn_slow_hash_v14,    0,            n1, &v5ref, &v8ref, &ok1);
    rng_state = 0x9E3779B9u;
    bench_pair(cn_slow_hash_v11_p1, cn_slow_hash_v14_p1, 1024ull*1024, n1, &v5ctl, &v8ctl, &ok2);
    rng_state = 0x9E3779B9u;
    bench_pair(cn_slow_hash_v11_p4, cn_slow_hash_v14_p4, 4096ull*1024, n4, &v5p4,  &v8p4,  &ok3);

    if (!ok1 || !ok2 || !ok3) { printf("setup failed (out of memory?)\n"); return 1; }

    printf("  %-14s %9s %9s %9s %10s\n", "VARIANT", "mean ms", "min ms", "max ms", "H/s (1T)");
    row("v5 1MB ref", &v5ref); row("v8 1MB ref", &v8ref);
    row("v5 1MB ctl", &v5ctl); row("v8 1MB ctl", &v8ctl);
    row("v5 4MB",     &v5p4);  row("v8 4MB",     &v8p4);

    /* ref against ctl is the same source built two ways, so their difference
     * is this machine's floor for the comparison below. */
    ctl_noise = fabs(v5ctl.mean_ms - v5ref.mean_ms) / v5ref.mean_ms * 100.0;
    d1 = (v8ctl.mean_ms - v5ctl.mean_ms) / v5ctl.mean_ms * 100.0;
    d4 = (v8p4.mean_ms  - v5p4.mean_ms)  / v5p4.mean_ms  * 100.0;
    gate = 2.0 * ctl_noise; if (gate < 2.0) gate = 2.0;

    printf("\n  control  |v5ctl - v5ref| = %.2f%%   (the noise floor on this machine)\n", ctl_noise);
    printf("  v8 vs v5 at 1 MB        = %+.2f%%   (negative is v8 cheaper)\n", d1);
    printf("  v8 vs v5 at 4 MB        = %+.2f%%\n", d4);
    printf("  gate = max(2%%, 2 x floor) = %.2f%%\n", gate);

    if (ctl_noise > 4.0)
        printf("\n  UNUSABLE: the control pair disagrees by more than 4%%. Something else is\n"
               "  running on this machine. Close it and run again; do not read the rows above.\n");
    else
        printf("\n  1 MB: %s      4 MB: %s\n",
               fabs(d1) <= gate ? "PASS" : "OVER GATE",
               fabs(d4) <= gate ? "PASS" : "OVER GATE");

    printf("\n  Please report all six rows plus the control line.\n");
    return 0;
}
