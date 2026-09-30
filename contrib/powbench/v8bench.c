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

/* before any system header: sched_getcpu() is a GNU extension, and glibc and
 * bionic both hide it without this */
#if !defined(_GNU_SOURCE)
#  define _GNU_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#  define V8B_X86 1
#  include <cpuid.h>
#endif
#include <pthread.h>
#include <unistd.h>
#if !defined(_WIN32)
#  include <sys/ioctl.h>
#  include <sched.h>
#endif
#if defined(__ANDROID__)
#  include <sys/system_properties.h>
#endif
#if defined(__APPLE__)
#  include <sys/sysctl.h>
#endif

#include "hash-ops.h"

/* CPU identification is the only architecture-specific code in this harness.
 * The hash bodies are not: slow-hash.h carries a full ARMv8 crypto path, so the
 * measured work is the same function on both. */
#if defined(V8B_X86)
/* slow-hash.c asks crypto.cpp whether AES-NI is present and picks the HW or SW
 * body on the answer. Linking crypto.cpp would drag in the C++ crypto library
 * for one CPUID, so supply it here with the same check crypto::has_aesni()
 * does: leaf 1, ECX bit 25. Getting this wrong, or building without
 * SLOW_HASH_HW_AES_BUILT, silently measures software AES and reports a hash
 * about five times slower than it is. The banner prints which path ran.
 *
 * aarch64 needs no counterpart: detect_hardware_aes() in slow-hash.c reads
 * getauxval(AT_HWCAP) & HWCAP_AES there and never calls this, so the symbol is
 * genuinely x86-only rather than merely unused. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}
#endif

/* parts pad the brand string with spaces, Intel at the front and AMD at the
 * back, so trim both ends */
static void brand_trim(char *out)
{
    char *p = out;
    size_t n;
    while (*p == ' ') p++;
    if (p != out) memmove(out, p, strlen(p) + 1);
    n = strlen(out);
    while (n > 0 && out[n - 1] == ' ') out[--n] = '\0';
}

/* The CPU brand string, so a result pasted into a report says which box it came
 * from without anyone having to remember. */
#if defined(V8B_X86)
/* CPUID leaves 0x80000002..4 hold it as 48 bytes of ASCII; every x86-64 part
 * supports them. */
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
    brand_trim(out);
}
#else
/* ARM has no brand-string instruction. The kernel exposes a name on some
 * platforms and not others, so try the places it appears and fall back to the
 * architecture rather than printing an empty field: this string only has to
 * identify a screenshot, and a vague name is better than a blank one. Android
 * in particular usually drops the "Hardware" line on arm64. */
static void cpu_brand(char out[49])
{
    static const char *const keys[] = { "Hardware", "model name", "Model" };
    FILE *f;
    char line[256];
    size_t k;

    out[0] = '\0';

#if defined(__APPLE__)
    /* macOS has no /proc at all, so both paths below come back empty and the
     * first Apple silicon run reported "unknown_aarch64". sysctl carries the
     * CPU name on Intel and Apple silicon alike, under the same key, so this
     * is a macOS path rather than an Apple-silicon special case. */
    {
        size_t n = 49;
        if (sysctlbyname("machdep.cpu.brand_string", out, &n, NULL, 0) == 0) {
            out[48] = '\0';
            brand_trim(out);
            if (out[0] != '\0') return;
        }
        out[0] = '\0';
    }
#endif

#if defined(__ANDROID__)
    /* Android drops the Hardware line from /proc/cpuinfo on arm64 and SELinux
     * denies an unprivileged app most of /sys, so both of the paths below come
     * back empty on a phone and the first ARM run reported "unknown_aarch64".
     * The property system is the one place a device name is reliably readable.
     * ro.product.model is the marketing name ("Pixel 7a"); ro.board.platform is
     * the SoC, which is what actually matters for a hardware comparison, so
     * prefer both together when they fit. */
    {
        char model[PROP_VALUE_MAX], soc[PROP_VALUE_MAX];
        int nm = __system_property_get("ro.product.model", model);
        int ns = __system_property_get("ro.board.platform", soc);
        if (nm > 0 && ns > 0) snprintf(out, 49, "%s %s", model, soc);
        else if (nm > 0)      snprintf(out, 49, "%s", model);
        else if (ns > 0)      snprintf(out, 49, "%s", soc);
        brand_trim(out);
        if (out[0] != '\0') return;
    }
#endif

    f = fopen("/proc/device-tree/model", "rb");
    if (f != NULL) {
        size_t n = fread(out, 1, 48, f);
        fclose(f);
        out[n] = '\0';
        brand_trim(out);
        if (out[0] != '\0') return;
    }

    f = fopen("/proc/cpuinfo", "r");
    if (f != NULL) {
        while (fgets(line, sizeof(line), f) != NULL) {
            for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
                if (strncmp(line, keys[k], strlen(keys[k])) == 0) {
                    char *v = strchr(line, ':');
                    if (v != NULL) {
                        snprintf(out, 49, "%s", v + 1);
                        out[strcspn(out, "\r\n")] = '\0';
                        brand_trim(out);
                    }
                    break;
                }
            }
            if (out[0] != '\0') break;
        }
        fclose(f);
    }

    if (out[0] == '\0')
        snprintf(out, 49, "unknown aarch64");
}
#endif

typedef void (*hashfn)(cn_hash_context_t *, const void *, size_t, char *,
                       size_t, uint8_t, uint16_t, uint16_t);

/* the resized recompilations, from contrib/hf14checks/v5pad{1,4}.c */
void cn_slow_hash_v11_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p2(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p8(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p2(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p8(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

/* PLAN-v8 Phase 2 prototype: v8 with the floating-point stage. Declared here
 * rather than taken from hash-ops.h alongside the others only because it may
 * not exist in an older tree someone builds this against. */
void cn_slow_hash_v15(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

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

/* One interleaved pass over k variants: each sample draws its parameters once
 * and hands the same ones to every variant in turn, recording each.
 *
 * Everything compared here has to go through this together. An earlier version
 * interleaved v5 against v8 but measured ref against ctl in separate passes,
 * so drift cancelled in the first comparison and not in the second. The
 * control then read as noise the paired figures did not have, and on one
 * machine tripped a "too noisy to use" guard while its paired numbers were
 * in line with every other box. The control has to be measured the same way
 * as the thing it is the control for.
 *
 * The starting variant rotates each sample, so no variant always runs first
 * against a cold pad or last against a warm one. */
static void bench_group(hashfn *fns, struct result *res, unsigned k,
                        size_t pad_bytes, unsigned n, int *ok)
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

    for (i = 0; i < k; i++) {
        res[i].mean_ms = 0.0;
        res[i].min_ms  = 1e30;
        res[i].max_ms  = 0.0;
    }

    for (i = 0; i < n; i++)
    {
        const struct params p = draw();
        unsigned j;

        for (j = 0; j < k; j++)
        {
            const unsigned v = (i + j) % k;   /* rotate the running order */
            double t0 = now_sec(), ms;
            fns[v](ctx, blob, sizeof(blob) - 1, out, p.iters, p.blk, p.xx, p.yy);
            ms = (now_sec() - t0) * 1e3;
            res[v].mean_ms += ms;
            if (ms < res[v].min_ms) res[v].min_ms = ms;
            if (ms > res[v].max_ms) res[v].max_ms = ms;
        }
    }

    for (i = 0; i < k; i++) res[i].mean_ms /= n;

    if (pad_bytes) { ctx->scratchpad = saved; free(own); }
    cn_hash_context_free(ctx);
    *ok = 1;
}

/* Do the shipped and recompiled v8 builds compute the same function?
 *
 * The timing control can only say their costs are close, and a cost ratio has
 * no way to separate an algorithm difference from a memory artifact. This
 * compares the hashes themselves, which settles it outright: same inputs, same
 * pad size, so the outputs must be identical byte for byte.
 *
 * It is the check that would have caught v5pad.inc keeping a salt_pad_v8
 * override after the shipped macro became pad-aware, where the benchmark and
 * the daemon quietly ran different algorithms while every timing looked
 * plausible. */
static int shipped_matches_recompiled(void)
{
    static const char blob[] = "nerva cna v8 shipped against recompiled, identical inputs";
    cn_hash_context_t *ctx = cn_hash_context_create();
    uint8_t *own = NULL, *saved = NULL;
    char a[32], b[32];
    int i, bad = 0;

    if (ctx == NULL) return -1;

    /* one dispatcher call to fault in the pads the shipped build needs */
    cn_slow_hash_v14(ctx, blob, sizeof(blob) - 1, a, 8, 8, 4, 4);
    if (ctx->salt == NULL) { cn_hash_context_free(ctx); return -1; }

    own = (uint8_t *)malloc(1024ull*1024);
    if (own == NULL) { cn_hash_context_free(ctx); return -1; }

    rng_state = 0x5EED1234u;
    for (i = 0; i < 24; i++)
    {
        const struct params p = draw();

        /* salt_pad writes back into salt, so both builds must start from the
         * same salt, and random_values must match too */
        memset(&ctx->random_values, 0, sizeof(ctx->random_values));
        memset(ctx->salt, 0, CN_SALT_MEMORY);
        cn_slow_hash_v14(ctx, blob, sizeof(blob) - 1, a, p.iters, p.blk, p.xx, p.yy);

        memset(&ctx->random_values, 0, sizeof(ctx->random_values));
        memset(ctx->salt, 0, CN_SALT_MEMORY);
        memset(own, 0, 1024ull*1024);
        saved = ctx->scratchpad; ctx->scratchpad = own;
        cn_slow_hash_v14_p1(ctx, blob, sizeof(blob) - 1, b, p.iters, p.blk, p.xx, p.yy);
        ctx->scratchpad = saved;

        if (memcmp(a, b, 32) != 0) bad++;
    }

    free(own);
    cn_hash_context_free(ctx);
    return bad;
}

/* ------------------------------------------------------------------ */
/* thread scaling                                                       */
/*
 * Everything above is single-threaded, which is the right measure for
 * verification cost but the wrong one for "1 CPU = 1 vote". Mining runs every
 * core at once and the pads compete for a shared L3, so a pad that fits
 * comfortably on one thread may not fit eight times over.
 *
 * That distinction is the whole disagreement about pad size. Single-threaded, a
 * large pad splits machines by L3 capacity. Multi-threaded, a large pad
 * overflows every machine's L3 and pushes them all onto DRAM latency, which is
 * the one hardware property a small box shares with a big one. HF13 argued the
 * second; the sweep measures the first; neither settles the other.
 *
 * What this measures is total throughput at T threads. For fairness the number
 * that matters is how that compares across machines against their core counts:
 * if a 16-core earns 4x a 4-core, core count is what votes. If the ratio is
 * much flatter than the core ratio, the memory system is what votes, which is
 * closer to one box one vote.
 */

/* Start gate: hold every worker until all of them are built, so the clock
 * measures hashing rather than thread creation and page faults.
 *
 * This used a POSIX barrier and does not any more, for two independent reasons.
 *
 * macOS does not implement them. Barriers are optional in the standard and
 * Apple's libpthread omits them, so the type and its three functions are simply
 * undeclared there and the harness would not compile at all.
 *
 * The fixed participant count was also wrong. The barrier was sized t + 1, and
 * when pthread_create failed partway the controller tried to absorb the missing
 * slots by waiting once per missing thread. Its first such wait blocks, because
 * the barrier has not been reached, so it could never make the remaining calls:
 * the loop whose comment read "or everyone waits forever" was itself the thing
 * that waited forever. Only reachable when thread creation fails, which is why
 * it survived this long.
 *
 * A gate needs no fixed count. Workers announce arrival and block; the
 * controller waits for however many workers actually exist, then releases them.
 * Nothing has to be known in advance and nothing has to be absorbed. */
struct start_gate {
    pthread_mutex_t m;
    pthread_cond_t  c;
    unsigned        ready;   /* workers that have announced themselves */
    int             go;      /* set once the controller has seen them all */
};

static int gate_init(struct start_gate *g)
{
    if (pthread_mutex_init(&g->m, NULL) != 0) return -1;
    if (pthread_cond_init(&g->c, NULL) != 0) { pthread_mutex_destroy(&g->m); return -1; }
    g->ready = 0;
    g->go = 0;
    return 0;
}

static void gate_destroy(struct start_gate *g)
{
    pthread_cond_destroy(&g->c);
    pthread_mutex_destroy(&g->m);
}

/* worker side: announce, then block until told to go */
static void gate_arrive(struct start_gate *g)
{
    pthread_mutex_lock(&g->m);
    g->ready++;
    pthread_cond_broadcast(&g->c);
    while (!g->go)
        pthread_cond_wait(&g->c, &g->m);
    pthread_mutex_unlock(&g->m);
}

/* controller side: wait for exactly the workers that exist, then release */
static void gate_release(struct start_gate *g, unsigned n)
{
    pthread_mutex_lock(&g->m);
    while (g->ready < n)
        pthread_cond_wait(&g->c, &g->m);
    g->go = 1;
    pthread_cond_broadcast(&g->c);
    pthread_mutex_unlock(&g->m);
}

struct worker {
    hashfn   fn;
    size_t   pad_bytes;
    unsigned n;
    struct start_gate *start;
    double   hs;        /* out: hashes per second achieved by this thread */
};

static void *worker_main(void *arg)
{
    struct worker *w = (struct worker *)arg;
    static const char blob[] = "nerva cna v8 thread scaling input, past the tweak at 35";
    cn_hash_context_t *ctx = cn_hash_context_create();
    uint8_t *own = NULL, *saved = NULL;
    char out[32];
    uint32_t seed;
    unsigned i;
    double t0;

    w->hs = 0.0;
    if (ctx == NULL) { gate_arrive(w->start); return NULL; }
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));

    /* Set up, allocate and fault the pad in BEFORE the barrier. Timing the
     * allocation alongside the hashing is what made an earlier harness read a
     * thread-count collapse that was really the allocator: every thread
     * memsets its pad, and at 32 threads that is hundreds of MB. */
    { struct params wp; rng_state = 1; wp = draw();
      cn_slow_hash_v11(ctx, blob, sizeof(blob) - 1, out, wp.iters, wp.blk, wp.xx, wp.yy); }
    if (ctx->salt == NULL) { cn_hash_context_free(ctx); gate_arrive(w->start); return NULL; }

    own = (uint8_t *)malloc(w->pad_bytes);
    if (own == NULL) { cn_hash_context_free(ctx); gate_arrive(w->start); return NULL; }
    memset(own, 0, w->pad_bytes);
    saved = ctx->scratchpad;
    ctx->scratchpad = own;

    /* Each thread draws its own parameter stream, seeded from its own address,
     * so the threads do not run in lockstep on identical work. */
    seed = (uint32_t)(uintptr_t)w ^ 0x9E3779B9u;
    if (seed == 0) seed = 1;

    gate_arrive(w->start);

    t0 = now_sec();
    for (i = 0; i < w->n; i++)
    {
        struct params p;
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        p.xx  = (uint16_t)(4 + seed % 5);
        p.yy  = (uint16_t)(4 + (seed >> 8) % 5);
        p.blk = (uint8_t)(2u << ((seed >> 16) % 3));
        p.iters = (seed >> 20) % 64;
        w->fn(ctx, blob, sizeof(blob) - 1, out, p.iters, p.blk, p.xx, p.yy);
    }
    w->hs = (double)w->n / (now_sec() - t0);

    ctx->scratchpad = saved;
    free(own);
    cn_hash_context_free(ctx);
    return NULL;
}

/* Total H/s across t threads, measured as all the work divided by the wall
 * time of the whole group.
 *
 * Not the sum of each thread's own rate, which was the first version and is
 * biased upward: v8's work per nonce varies about 4.7x, so threads finish at
 * different times, and the ones still running after others have exited get a
 * quieter machine and report a rate no miner would ever see. The bias grows
 * with thread count, which is exactly where the interesting behaviour is.
 *
 * The parent joins the barrier so timing starts when the last worker is set
 * up, keeping allocation and page-faulting out of the measurement. */
static double bench_threads(hashfn fn, size_t pad_bytes, unsigned n, unsigned t)
{
    struct start_gate start;
    pthread_t *th = (pthread_t *)malloc(t * sizeof(pthread_t));
    struct worker *w = (struct worker *)malloc(t * sizeof(struct worker));
    unsigned i, made = 0;
    double t0, wall;

    if (th == NULL || w == NULL) { free(th); free(w); return 0.0; }
    if (gate_init(&start) != 0) { free(th); free(w); return 0.0; }

    for (i = 0; i < t; i++) {
        w[i].fn = fn; w[i].pad_bytes = pad_bytes; w[i].n = n;
        w[i].start = &start; w[i].hs = 0.0;
        if (pthread_create(&th[i], NULL, worker_main, &w[i]) != 0) break;
        made++;
    }
    /* Release exactly the threads that were created. Nothing to absorb: if
     * some could not be started, the gate waits for fewer. */
    gate_release(&start, made);         /* all set up; start the clock */
    t0 = now_sec();
    for (i = 0; i < made; i++) pthread_join(th[i], NULL);
    wall = now_sec() - t0;

    gate_destroy(&start);
    free(th); free(w);
    return wall > 0.0 ? (double)made * (double)n / wall : 0.0;
}

/* Results come back as phone screenshots now, not just desktop terminals, and a
 * table that wraps at 40 columns is unreadable in a way that costs a rerun. So
 * every wide block below has a narrow form. Nothing is dropped that a reader
 * needs: the narrow form stacks instead of truncating, except for the sample
 * count and the max column, which are fixed and recoverable respectively.
 *
 * Detected rather than flagged, because the person running it on a phone is the
 * least likely to know a flag exists. V8BENCH_NARROW=1 or =0 overrides. */
static int g_narrow;

static void detect_narrow(void)
{
    const char *e = getenv("V8BENCH_NARROW");
    unsigned cols = 0;

    if (e != NULL && e[0] != '\0') { g_narrow = (e[0] != '0'); return; }

#if defined(TIOCGWINSZ)
    {
        /* Try stderr and stdin as well as stdout. The first version asked only
         * about stdout, so piping into grep, which is exactly what the pinned
         * run script does, made the width unknown and silently produced the
         * wide layout on a phone. stderr is still the terminal in that case. */
        static const int fds[3] = { 1, 2, 0 };
        struct winsize ws;
        int i;
        for (i = 0; i < 3 && cols == 0; i++)
            if (ioctl(fds[i], TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
                cols = (unsigned)ws.ws_col;
    }
#endif
    if (cols == 0) {
        const char *c = getenv("COLUMNS");
        if (c != NULL) cols = (unsigned)atoi(c);
    }
    /* An unknown width is assumed wide: a desktop redirecting to a file is far
     * more common than a phone that reports nothing. */
    g_narrow = (cols > 0 && cols < 60);
}

/* Placement tracking.
 *
 * A pinned run that was not really pinned is worse than no pinned run: it
 * produces numbers that look like core-type measurements and are not. Verifying
 * the affinity before starting is not enough, because Android can change a
 * task's cpuset mid-run. A Pixel 7a pinned to cpu0 produced a pad sweep reading
 * 1MB=7.2695 2MB=13.2546 4MB=6.9353, cost falling as the pad quadrupled,
 * because it started on an A55 and finished on a big core. Nothing in the
 * output said so; it had to be caught by eye. This catches it instead. */
static char g_aff_start[64];
static int  g_cpu_start = -1;
static int  g_pinned;
static int  g_tainted;
static char g_taint[192];

static void read_affinity(char *out, size_t n)
{
    out[0] = '\0';
#if defined(__linux__) || defined(__ANDROID__)
    {
        FILE *f = fopen("/proc/self/status", "r");
        char line[256];
        if (f == NULL) return;
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
#else
    (void)n;
#endif
}

static int current_cpu(void)
{
#if (defined(__linux__) || defined(__ANDROID__)) && defined(_GNU_SOURCE)
    return sched_getcpu();
#else
    return -1;
#endif
}

static void placement_baseline(void)
{
    read_affinity(g_aff_start, sizeof(g_aff_start));
    /* "6" is pinned; "0-7" and "0,4" are not. An unpinned thread moving between
     * cores is normal scheduling and must not be reported as a fault, so the
     * core-moved test below applies only when the mask names one core. */
    g_pinned = (g_aff_start[0] != '\0' &&
                strchr(g_aff_start, '-') == NULL &&
                strchr(g_aff_start, ',') == NULL);
    g_cpu_start = current_cpu();

    if (g_aff_start[0] != '\0') printf("cpus allowed: %s\n", g_aff_start);
}

static void placement_check(const char *where)
{
    char now[64];
    const int cpu = current_cpu();

    read_affinity(now, sizeof(now));

    /* The mask changing under a running process is always wrong, pinned or not:
     * nothing in this program asks for it. */
    if (g_aff_start[0] != '\0' && now[0] != '\0' &&
        strcmp(now, g_aff_start) != 0 && !g_tainted) {
        snprintf(g_taint, sizeof(g_taint),
                 "cpus allowed changed from %s to %s during %s",
                 g_aff_start, now, where);
        g_tainted = 1;
    }
    if (g_pinned && g_cpu_start >= 0 && cpu >= 0 && cpu != g_cpu_start &&
        !g_tainted) {
        snprintf(g_taint, sizeof(g_taint),
                 "pinned to cpu%d but running on cpu%d by %s",
                 g_cpu_start, cpu, where);
        g_tainted = 1;
    }
}

/* Cost must rise with the pad. A sweep that falls has measured more than one
 * kind of core, whatever the affinity says, so it is checked on its own rather
 * than trusting the placement probes to have noticed. */
static void check_monotonic(const double ms[4])
{
    static const char *const names[4] = { "1 MB", "2 MB", "4 MB", "8 MB" };
    int i;
    for (i = 1; i < 4; i++) {
        if (ms[i] > 0.0 && ms[i-1] > 0.0 && ms[i] < ms[i-1] && !g_tainted) {
            snprintf(g_taint, sizeof(g_taint),
                     "%s (%.4f ms) came out cheaper than %s (%.4f ms)",
                     names[i], ms[i], names[i-1], ms[i-1]);
            g_tainted = 1;
        }
    }
}

static int g_taint_printed;

static void print_taint(void)
{
    if (!g_tainted || g_taint_printed) return;
    g_taint_printed = 1;
    printf("\n  *** TAINTED: %s\n", g_taint);
    printf("  *** These numbers mix more than one core. Discard them.\n");
    printf("  *** On Android, run termux-wake-lock and keep Termux\n");
    printf("  *** in the foreground, then measure again.\n");
}

/* The SWEEP and SCALE lines are meant to be transcribed, so the narrow form
 * keeps every token identical and only breaks where a phone would break it
 * anyway. Splitting on our terms beats letting the terminal split mid-number. */
static void tag_line(const char *tag, const char *brand, const char *extra,
                     const char *unit, const double v[4], int decimals)
{
    static const char *const pads[4] = { "1MB", "2MB", "4MB", "8MB" };
    int i;

    if (!g_narrow) {
        printf("\n  %s %s%s", tag, brand, extra);
        for (i = 0; i < 4; i++)
            printf(" %s=%.*f", pads[i], decimals, v[i]);
        printf("\n");
        return;
    }

    printf("\n  %s %s%s\n", tag, brand, extra);
    for (i = 0; i < 4; i++)
        printf("%s%s=%.*f%s", (i % 2) == 0 ? "    " : " ",
               pads[i], decimals, v[i], (i % 2) == 1 ? "\n" : "");
    (void)unit;
}

static void row(const char *name, const struct result *r)
{
    if (g_narrow) {
        printf("  %-14s %8.1f H/s\n", name, 1000.0 / r->mean_ms);
        printf("    mean %.4f min %.4f max %.4f\n",
               r->mean_ms, r->min_ms, r->max_ms);
        return;
    }
    printf("  %-14s %8.4f %8.4f %8.4f %8.1f\n",
           name, r->mean_ms, r->min_ms, r->max_ms, 1000.0 / r->mean_ms);
}

int main(int argc, char **argv)
{
    const unsigned n1 = argc > 1 ? (unsigned)atoi(argv[1]) : 2000;
    const unsigned n4 = argc > 2 ? (unsigned)atoi(argv[2]) : 600;
    struct result v5ref, v8ref, v5ctl, v8ctl, v5p4, v8p4, v15r;
    double v15peak = 0.0;
    int ok1, ok2;
    double ctl_noise, d1, d4, gate;

    detect_narrow();

    {
        char brand[49];
        char when[64];
        time_t t = time(NULL);
        struct tm *lt = localtime(&t);

        cpu_brand(brand);
        printf(g_narrow ? "CNA v8 vs CNA v5\n"
                        : "CNA v8 (Skein in salt_pad) against CNA v5\n");
        printf("CPU: %s\n", brand);
        placement_baseline();

        /* Both stamps, because results come back as screenshots from several
         * machines over several days. The run time says when a number was
         * taken; the build stamp says which binary produced it, which is the
         * one that catches an old copy still sitting on a box after a rebuild. */
        if (lt == NULL || strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", lt) <= 0)
            when[0] = 0;
        if (g_narrow) {
            if (when[0]) printf("run: %s (local)\n", when);
            printf("built: %s %s\n", __DATE__, __TIME__);
        } else {
            /* One line: the run stamp says when a number was taken and the
             * build stamp which binary produced it, and the second is what
             * catches a stale copy left on a box after a rebuild. Both still
             * here, just not on two lines each. */
            printf("run %s | built %s %s\n",
                   when[0] ? when : "?", __DATE__, __TIME__);
        }
    }
    printf("AES path: %s\n",
#if defined(SLOW_HASH_HW_AES_BUILT)
           /* ask the dispatcher, not the CPUID helper: on aarch64
            * detect_hardware_aes() reads getauxval(AT_HWCAP) & HWCAP_AES and
            * never consults crypto_has_aesni(), so asking the helper would
            * report software AES while the hardware path ran. This must report
            * what actually executed or the banner is worse than no banner. */
           cn_hardware_aes_supported()
               ? "hardware (AES)"
               : (g_narrow ? "SOFTWARE - not comparable"
                           : "SOFTWARE - no hardware AES on this CPU, numbers are not comparable to other machines")
#else
           "SOFTWARE - built without SLOW_HASH_HW_AES_BUILT, numbers are meaningless"
#endif
          );
    if (g_narrow)
        printf("samples: %u @1MB, %u @4MB\n\n", n1, n4);
    else
        printf("samples %u@1MB %u@4MB interleaved | close other programs\n",
               n1, n4);

    /* Establish that the two v8 builds are the same function before spending a
     * minute timing them. If they are not, no number below means anything. */
    {
        const int bad = shipped_matches_recompiled();
        if (bad < 0) {
            printf("  could not run the shipped-vs-recompiled check (allocation failed)\n\n");
        } else if (bad > 0) {
            printf("  STOP: shipped v8 and recompiled v8 gave different hashes on %d of 24\n"
                   "  inputs. They are not the same algorithm, so the timings below would be\n"
                   "  meaningless. Check whether v5pad.inc still overrides something the\n"
                   "  shipped macros now handle themselves.\n", bad);
            return 1;
        } else if (g_narrow) {
            printf("  shipped v8 == recomp v8 (24 inputs)\n\n");
        } else {
            printf("  shipped v8 == recompiled v8 on 24 inputs\n");
        }
    }

    /* Two interleaved groups, one per pad size, because the shipped builds no
     * longer share a pad: v5 ships at 1 MB and v8 now ships at 4 MB. An earlier
     * version put cn_slow_hash_v11 and cn_slow_hash_v14 in the same "1 MB" row
     * and kept doing so after v8 moved, which silently turned the headline
     * comparison into v5 at 1 MB against v8 at 4 MB. Every variant compared to
     * another must be at the same pad, and that is what these groups enforce.
     *
     * Each group also carries one shipped build, so the control answers the
     * question that actually matters: does the benchmarked build behave like
     * the one that ships? At 1 MB that is v5, at 4 MB it is v8. One confound
     * worth knowing: the shipped builds read the context's own pad, which is
     * hugepage-backed, while the recompiled ones read a plain malloc buffer,
     * so a small difference is expected and is not a fault in either. */
    {
        /* v15 joins the 1 MB group rather than getting its own pass, because
         * the whole point of interleaving is that drift cannot land on one
         * variant and not another. The Phase 2 decision is a difference of a
         * few percent between v8 and v15 on the same machine, which a separate
         * pass could manufacture or hide on its own. */
        hashfn one_mb[5]  = { cn_slow_hash_v11,       /* shipped v5, 1 MB */
                              cn_slow_hash_v11_p1,    /* recompiled v5, 1 MB */
                              cn_slow_hash_v14_p1,    /* recompiled v8, 1 MB */
                              cn_slow_hash_v14,       /* shipped v8, 1 MB */
                              cn_slow_hash_v15 };     /* v8 + FP stage, 1 MB */
        hashfn four_mb[2] = { cn_slow_hash_v11_p4,    /* recompiled v5, 4 MB */
                              cn_slow_hash_v14_p4 };  /* recompiled v8, 4 MB */
        struct result r1[5], r4[2];

        rng_state = 0x9E3779B9u;
        bench_group(one_mb, r1, 5, 1024ull*1024, n1, &ok1);
        rng_state = 0x9E3779B9u;
        bench_group(four_mb, r4, 2, 4096ull*1024, n4, &ok2);

        if (!ok1 || !ok2) { printf("setup failed (out of memory?)\n"); return 1; }

        v5ref = r1[0]; v5ctl = r1[1]; v8ctl = r1[2]; v8ref = r1[3]; v15r = r1[4];
        v5p4  = r4[0]; v8p4  = r4[1];
    }

    /* Phase 3's question is which pad to ship, so sweep it. Each size is a
     * separate compilation of the same source at a different
     * CN_SCRATCHPAD_MEMORY, which is also what makes v8's derived salt stride
     * worth having: each build picks up the stride its pad requires with no
     * per-size constant to get wrong.
     *
     * Two numbers matter per size and they pull against each other. Verify
     * cost sets sync speed, and it rises with the pad. Cross-CPU spread sets
     * how close this gets to one box one vote, and the whole premise of moving
     * off v6's 8 MB is that a smaller pad narrows it. Collect both here; the
     * spread needs every machine, so it is computed from the reported rows
     * rather than printed by any single run. */
    {
        /* Sample counts are per pad, and chosen so every row gets a comparable
         * amount of wall time rather than a comparable sample count. The
         * previous version used 600 at 4 and 8 MB, which made the large pads
         * the noisiest rows precisely where the pad decision needs precision:
         * two runs minutes apart disagreed by 5.7% at 4 MB. These give roughly
         * 7 s a row, about 30 s for the sweep, and cut that scatter by half. */
        static const struct { const char *name; hashfn v5, v8; size_t pad; unsigned n; } sweep[] = {
            { "1 MB", cn_slow_hash_v11_p1, cn_slow_hash_v14_p1, 1024ull*1024, 4000 },
            { "2 MB", cn_slow_hash_v11_p2, cn_slow_hash_v14_p2, 2048ull*1024, 2500 },
            { "4 MB", cn_slow_hash_v11_p4, cn_slow_hash_v14_p4, 4096ull*1024, 1500 },
            { "8 MB", cn_slow_hash_v11_p8, cn_slow_hash_v14_p8, 8192ull*1024,  800 },
        };
        size_t si;
        double v8ms[4];

        if (g_narrow) {
            printf("\n  pad sweep (~30 s)\n");
            printf("  %-4s %7s %7s %6s %7s\n",
                   "pad", "v5 ms", "v8 ms", "H/s", "v8:v5");
        } else {
            printf("\n  pad sweep (v8 against v5; ~30 s)\n");
            printf("  %-5s %9s %9s %8s %8s %6s\n",
                   "pad", "v5 ms", "v8 ms", "v8 H/s", "v8:v5", "n");
        }

        for (si = 0; si < 4; si++) v8ms[si] = 0.0;

        for (si = 0; si < sizeof(sweep)/sizeof(sweep[0]); si++)
        {
            hashfn pair[2] = { sweep[si].v5, sweep[si].v8 };
            struct result r[2];
            int ok;

            rng_state = 0x9E3779B9u;
            bench_group(pair, r, 2, sweep[si].pad, sweep[si].n, &ok);
            if (!ok) { printf("  %-6s  (allocation failed)\n", sweep[si].name); continue; }

            v8ms[si] = r[1].mean_ms;
            if (g_narrow)
                printf("  %-4s %7.4f %7.4f %6.1f %+6.2f%%\n",
                       sweep[si].name, r[0].mean_ms, r[1].mean_ms,
                       1000.0 / r[1].mean_ms,
                       (r[1].mean_ms - r[0].mean_ms) / r[0].mean_ms * 100.0);
            else
                printf("  %-5s %9.4f %9.4f %8.1f %+7.2f%% %6u\n",
                       sweep[si].name, r[0].mean_ms, r[1].mean_ms,
                       1000.0 / r[1].mean_ms,
                       (r[1].mean_ms - r[0].mean_ms) / r[0].mean_ms * 100.0,
                       sweep[si].n);

            /* per row, not once at the end: this is what says which rows are
             * still good when a run is moved partway through */
            placement_check(sweep[si].name);
        }

        check_monotonic(v8ms);

        /* Cross-CPU spread is slowest divided by fastest at each pad, so it
         * cannot be computed by any single run. Results come back from four
         * machines as screenshots, so print one line that is easy to read off
         * and hard to transcribe wrongly. */
        {
            char brand[49];
            char *p;
            cpu_brand(brand);
            for (p = brand; *p; p++) if (*p == ' ') *p = '_';
            tag_line("SWEEP", brand, "", "ms", v8ms, 4);
            {
                const int c = current_cpu();
                if (c >= 0) printf("  ran on cpu%d\n", c);
            }
            print_taint();
        }

        /* Thread scaling. Sized from the single-thread times just measured, so
         * each configuration takes about the same wall time on any machine
         * rather than a fixed sample count that is too small on a slow box and
         * wasteful on a fast one. */
        {
            unsigned hw = 0, tcounts[6], ntc = 0, ti;
            double base[4];
            long procs;

#if defined(_SC_NPROCESSORS_ONLN)
            procs = sysconf(_SC_NPROCESSORS_ONLN);
            hw = procs > 0 ? (unsigned)procs : 0;
#endif
            if (hw == 0) {
                const char *e = getenv("NUMBER_OF_PROCESSORS");
                hw = e ? (unsigned)atoi(e) : 0;
            }
            if (hw == 0) hw = 4;

            /* A power-of-two ladder walks past the peak. Real miners settle at
             * some count between physical cores and logical, and both cliffs
             * seen so far (4 MB past 16T, 8 MB past 4T) sit between rungs.
             * Sample around the physical core count instead, assuming 2-way
             * SMT, which holds for all four machines in the set.
             *
             * Override with a third argument, e.g. v8bench 2000 600 1,6,12,14,16 */
            /* A thread count of 0 means skip this section. When the run is
             * pinned to one core there is nothing to scale, and skipping it
             * keeps the output short enough to read on a phone without a grep
             * filter deciding which numbers survive. */
            if (argc > 3 && argv[3][0] == '0' && argv[3][1] == '\0') {
                ntc = 0;
            } else if (argc > 3) {
                const char *q = argv[3];
                while (*q && ntc < 12) {
                    unsigned v = (unsigned)atoi(q);
                    if (v > 0) tcounts[ntc++] = v;
                    while (*q && *q != ',') q++;
                    if (*q == ',') q++;
                }
            } else {
                const unsigned phys = hw >= 2 ? hw / 2 : 1;
                unsigned cand[12]; unsigned nc = 0, a, b;
                cand[nc++] = 1;
                if (hw >= 2) cand[nc++] = 2;
                if (hw >= 4) cand[nc++] = 4;
                if (phys > 4) cand[nc++] = phys / 2;
                if (phys > 2) cand[nc++] = phys - 2;
                cand[nc++] = phys;                 /* physical cores */
                if (hw > phys) cand[nc++] = phys + phys / 2;
                if (hw > phys) cand[nc++] = hw;    /* full SMT */
                /* sort and dedupe */
                for (a = 0; a < nc; a++)
                    for (b = a + 1; b < nc; b++)
                        if (cand[b] < cand[a]) { unsigned t = cand[a]; cand[a] = cand[b]; cand[b] = t; }
                for (a = 0; a < nc && ntc < 12; a++)
                    if (cand[a] >= 1 && cand[a] <= hw && (ntc == 0 || cand[a] != tcounts[ntc-1]))
                        tcounts[ntc++] = cand[a];
            }

            /* Kept to one line on purpose. The reasoning behind this pass, why
             * the peak matters more than the tail, why the tail is sensitive to
             * background load, and why OS thread placement muddies a multi-CCD
             * part, is in the comment above bench_threads rather than reprinted
             * on every run. */
            if (ntc == 0) {
                /* nothing to scale; v8ms still holds single-thread ms, which
                 * would make the SCALE line lie, so it is not printed either */
            } else if (g_narrow) {
                printf("\n  thread scaling, total H/s, %u CPUs\n", hw);
                printf("  (peak matters; tail is noisy)\n");
            } else {
                printf("\n  thread scaling, total H/s, %u CPUs (tail is load-sensitive)\n", hw);
                printf("  %-5s", "pad");
                for (ti = 0; ti < ntc; ti++) printf(" %8uT", tcounts[ti]);
                printf("  %s\n", "peak");
            }

            for (si = 0; si < 4 && ntc > 0; si++)
            {
                double best = 0.0, one = 0.0;
                unsigned n, best_t = 0;

                if (v8ms[si] <= 0.0) continue;
                /* ~1.2 s of work per thread per configuration */
                n = (unsigned)(1200.0 / v8ms[si]);
                if (n < 8) n = 8;

                /* The narrow form stacks the thread counts three to a line under
                 * the pad name rather than buffering them to put the peak
                 * first, so a slow machine still shows progress as it measures. */
                if (g_narrow) printf("  %s\n", sweep[si].name);
                else          printf("  %-5s", sweep[si].name);
                for (ti = 0; ti < ntc; ti++) {
                    const double hs = bench_threads(sweep[si].v8, sweep[si].pad, n, tcounts[ti]);
                    if (ti == 0) one = hs;
                    if (hs > best) { best = hs; best_t = tcounts[ti]; }
                    if (g_narrow) {
                        printf("%s%uT=%.1f", (ti % 3) == 0 ? "    " : " ",
                               tcounts[ti], hs);
                        if ((ti % 3) == 2 || ti + 1 == ntc) printf("\n");
                    } else {
                        printf(" %9.1f", hs);
                    }
                }
                /* where the peak is matters as much as how high: a pad whose
                 * peak sits well below the core count is one the memory system
                 * is already limiting, which is the regime fairness wants. */
                if (g_narrow)
                    printf("    peak %.2fx @%uT\n", one > 0.0 ? best / one : 0.0, best_t);
                else
                    printf("  %5.2fx @%uT\n", one > 0.0 ? best / one : 0.0, best_t);
                v8ms[si] = best;   /* reuse the slot to carry peak H/s to the SCALE line */
            }

            /* The one thing single-thread latency cannot answer: SMT siblings
             * share FP units, so a stage that is fair thread-for-thread need
             * not be fair machine-for-machine once every core is loaded. This
             * row is v15 at 1 MB across the same thread counts, so the peak
             * total throughput with and without the stage can be compared on
             * each machine and then across machines.
             *
             * Sized from v15's own single-thread time rather than v8's, so it
             * gets the same wall time per configuration and not a shorter one. */
            if (ntc > 0 && v15r.mean_ms > 0.0) {
                double best = 0.0, one = 0.0;
                unsigned n, best_t = 0;

                n = (unsigned)(1200.0 / v15r.mean_ms);
                if (n < 8) n = 8;

                if (g_narrow) printf("  1 MB FP\n");
                else          printf("  %-5s", "1MBFP");
                for (ti = 0; ti < ntc; ti++) {
                    const double hs = bench_threads(cn_slow_hash_v15, 1024ull*1024, n, tcounts[ti]);
                    if (ti == 0) one = hs;
                    if (hs > best) { best = hs; best_t = tcounts[ti]; }
                    if (g_narrow) {
                        printf("%s%uT=%.1f", (ti % 3) == 0 ? "    " : " ",
                               tcounts[ti], hs);
                        if ((ti % 3) == 2 || ti + 1 == ntc) printf("\n");
                    } else {
                        printf(" %9.1f", hs);
                    }
                }
                if (g_narrow)
                    printf("    peak %.2fx @%uT\n", one > 0.0 ? best / one : 0.0, best_t);
                else
                    printf("  %5.2fx @%uT\n", one > 0.0 ? best / one : 0.0, best_t);
                v15peak = best;
            }

            if (ntc > 0) {
                char brand[49]; char *p; char extra[24];
                cpu_brand(brand);
                for (p = brand; *p; p++) if (*p == ' ') *p = '_';
                snprintf(extra, sizeof(extra), " cpus=%u", hw);
                tag_line("SCALE", brand, extra, "H/s", v8ms, 1);
                if (v15peak > 0.0 && v8ms[0] > 0.0)
                    printf("  FPSCALE %s v8=%.1f v15=%.1f (%+.2f%%)\n",
                           brand, v8ms[0], v15peak,
                           (v15peak - v8ms[0]) / v8ms[0] * 100.0);
                if (g_narrow) {
                    printf("  ^ peak total H/s per pad.\n");
                    printf("  Send this and the SWEEP line.\n");
                } else {
                    /* wide mode says this once at the end instead */
                }
            }
        }
    }

    if (g_narrow)
        printf("\n  VARIANT (ms, and H/s at 1T)\n");
    else
        printf("  %-14s %8s %8s %8s %8s\n", "VARIANT", "mean", "min", "max", "H/s");
    row("v5 1MB shipped", &v5ref);
    row("v5 1MB recomp",  &v5ctl);
    row("v8 1MB recomp",  &v8ctl);
    row("v8 1MB SHIPPED", &v8ref);
    row("v5 4MB recomp",  &v5p4);
    row("v8 4MB recomp",  &v8p4);
    row("v15 1MB FP",     &v15r);

    /* The verdict below was wrong three separate ways and all three are fixed
     * here, because each of them produced a confident and false statement.
     *
     * 1. It failed on improvements. The test was |delta| <= gate, so v8 being
     *    24% CHEAPER at 4 MB reported "OVER GATE" exactly as a 24% regression
     *    would. Phase 1 asks whether v8 costs more to verify, so only a
     *    regression can fail.
     *
     * 2. It scaled the gate by the control. That made sense while ref and ctl
     *    were measured in separate passes and their difference was drift. They
     *    are interleaved now, so the control is no longer noise.
     *
     * 3. It called the control a noise floor and failed above 4%. Post
     *    interleaving that number is a real, understood difference: ctl comes
     *    from v5pad.inc, which wraps the salt index, and at 1 MB that wrap is a
     *    logical no-op that still costs an AND in the innermost loop. Narrower
     *    cores pay more for it. Failing on it condemned a machine whose actual
     *    results were in line with every other box.
     *
     * What can still invalidate a conclusion is the two like-for-like
     * comparisons disagreeing with each other, so that is what is checked. */
    /* Each comparison is between two builds at the SAME pad, and each control
     * asks whether the recompiled build matches the one that ships, at the size
     * that build actually runs. */
    ctl_noise = fabs(v5ctl.mean_ms - v5ref.mean_ms) / v5ref.mean_ms * 100.0;
    d1 = (v8ctl.mean_ms - v5ctl.mean_ms) / v5ctl.mean_ms * 100.0;
    d4 = (v8p4.mean_ms  - v5p4.mean_ms)  / v5p4.mean_ms  * 100.0;
    gate = 2.0;   /* fixed: interleaving handles drift, so this need not flex */

    {
        const double v8_ship_vs_recomp =
            fabs(v8ref.mean_ms - v8ctl.mean_ms) / v8ctl.mean_ms * 100.0;

        if (g_narrow) {
            printf("\n  v8 vs v5 1MB = %+.2f%%\n", d1);
            printf("  v8 vs v5 4MB = %+.2f%%\n", d4);
            printf("  (negative = v8 cheaper)\n");
            printf("\n  ctl v5 1MB ship/recomp = %.2f%%\n", ctl_noise);
            printf("  ctl v8 1MB ship/recomp = %.2f%%\n", v8_ship_vs_recomp);
            printf("  gate: v8 max %.2f%% slower\n", gate);
        } else {
            printf("\n  v8 vs v5:  1MB %+.2f%%   4MB %+.2f%%   (negative = v8 cheaper)\n",
                   d1, d4);
            printf("  controls:  v5 %.2f%%   v8 %.2f%%   gate: v8 max %.2f%% slower\n",
                   ctl_noise, v8_ship_vs_recomp, gate);
        }

        printf("%s  1 MB: %s   4 MB: %s%s", g_narrow ? "\n" : "",
               d1 <= gate ? "PASS" : "SLOWER THAN GATE",
               d4 <= gate ? "PASS" : "SLOWER THAN GATE",
               g_narrow ? "\n" : "");   /* wide continues on this line */

        /* Phase 2's number. The gate above asks whether v8 costs more than v5;
         * this asks what the FP stage costs on top of v8, which is the figure
         * that goes into the spread arithmetic. It is not a pass or fail: the
         * stage is meant to cost something, and whether that cost is worth it
         * is decided across machines, not on one. */
        {
            const double dfp = (v15r.mean_ms - v8ref.mean_ms) / v8ref.mean_ms * 100.0;
            char brand[49];
            char *q;
            cpu_brand(brand);
            for (q = brand; *q; q++) if (*q == ' ') *q = '_';

            printf("%s  FP stage: %+.2f%% over v8\n",
                   g_narrow ? "\n" : "   ", dfp);
            if (g_narrow) {
                printf("\n  FPSTAGE %s\n", brand);
                printf("    v8=%.4f v15=%.4f\n",
                       v8ref.mean_ms, v15r.mean_ms);
            } else {
                printf("  FPSTAGE %s v8=%.4f v15=%.4f\n",
                       brand, v8ref.mean_ms, v15r.mean_ms);
            }
            if (g_narrow) printf("  ^ spread is across machines.\n");
        }


        /* The two builds are already proven identical by output at startup, so
         * this figure is memory behaviour only. Some is expected: the shipped
         * build reads v13's buffer while the recompiled one reads the
         * benchmark's, so within the interleaved group the shipped build's pad
         * is the one that has been sitting untouched while 4 MB of other pad
         * streamed past it. Reported for information, never fatal. */
        if (v8_ship_vs_recomp > 10.0)
            printf("\n  note: the two v8 builds differ by %.2f%% in cost while computing the\n"
                   "  same hashes. That is larger than buffer separation usually accounts\n"
                   "  for; worth a look if it persists across machines.\n",
                   v8_ship_vs_recomp);
    }

    /* Checked again here, because the variant groups run after the sweep and a
     * move during them would otherwise go unreported. */
    placement_check("the variant groups");
    print_taint();

    if (g_narrow)
        printf("\n  Report the SWEEP line plus these\n  verdict lines.\n");
    else
        printf("  Send the SWEEP, SCALE and FPSTAGE lines.\n");
    return g_tainted ? 2 : 0;
}
