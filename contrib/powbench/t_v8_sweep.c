/* What does removing salt_pad_v8 actually save? PLAN-v8-PHASE8 candidate D1.
 *
 * D1 proposes deleting the sweeps because they are 21.1% of a nonce by the eager
 * instrumented profile and are provably not hard: A1b reorders 30 of them into
 * two passes and the digest does not move (F51). Work that survives being
 * reordered into a different number of passes is not work in the shape we pay
 * for it.
 *
 * **The 21.1% is not the saving, and that is the reason this measures rather
 * than sums.** Under the deferral the cost sits in three places:
 *
 *   salt_pad_v8_defer      records the sweep and does the 32-byte salt patch
 *   CN_V8_FLUSH_SWEEPS     applies all of them to the pad in one pass
 *   post_aes_variant_v8    reconstructs deferred sweeps whenever it reads the
 *                          pad, F51's O(sweeps * patches) per read
 *
 * Removing the sweeps removes all three, so the saving is larger than any one
 * of them and cannot be read off a phase breakdown. It is also not the eager
 * figure, which was measured before the deferral existed.
 *
 * Method:
 *
 *   A-B-B-A per group of four nonces so drift and boost hit both arms equally,
 *   rdtsc per arm rather than wall clock, and one parameter draw feeding all
 *   four nonces so the two arms do the same amount of everything else. Work per
 *   nonce varies several-fold in v8, so unmatched parameters would measure the
 *   draw instead of the change.
 *
 *   The salt is snapshotted and restored before every nonce. salt_pad_v8 writes
 *   into the salt, so the no-sweep arm leaves it untouched where the real arm
 *   mutates it; without the restore the two arms would drift into hashing
 *   different work and the comparison would silently rot.
 *
 * THE DIGESTS DIFFER ON PURPOSE. This is not an optimisation A/B, it is two
 * algorithms being costed, so there is no digest check to make. What is checked
 * is that the no-sweep arm is not accidentally degenerate: it prints the digest
 * entropy of both arms, because a variant that quietly stopped depending on the
 * salt would look fast and be worthless.
 *
 * The core is about 40% of a real nonce (F52: 0.535 ms against 1.323 ms), the
 * chain fill being the rest and unaffected by this change. So a saving here is
 * worth 0.405 times as much on a nonce, and the harness prints both.
 *
 *   t_v8_sweep [threads] [seconds]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <x86intrin.h>
#include <cpuid.h>

#include "hash-ops.h"

/* F52's decomposition on a 7950X: the hash core against a real daemon nonce.
 * Used only to convert a core saving into a nonce saving, and printed as such
 * so the conversion is visible rather than buried. */
#define CORE_SHARE_OF_NONCE 0.405

#define NARMS 3
static const char *const g_arm_name[NARMS] = {
    "v8 as it stands      ",
    "pad sweep removed    ",
    "whole salt_pad gone  "
};

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

typedef void (*hashfn)(cn_hash_context_t *, const void *, size_t, char *,
                       size_t, uint8_t, uint16_t, uint16_t);

/* the shipped v8 at 1 MB, and the same thing without salt_pad_v8 */
void cn_slow_hash_v14_p1 (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_ns1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_np1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double g_seconds = 6.0;

typedef struct {
    int      id;
    uint64_t n[NARMS];
    uint64_t cyc[NARMS];
    /* FNV-1a over every digest each arm produced, NOT a XOR: A-B-B-A hashes
     * each arm twice per group from a restored salt, so the pair is identical
     * and a XOR accumulator cancels itself to zero and proves nothing. That is
     * exactly what the first version of this harness did. */
    uint64_t fnv[NARMS];
    int      failed;
} worker_t;

static void *worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char *salt0 = (char *)malloc(CN_SALT_MEMORY);
    static const hashfn fn[NARMS] = { cn_slow_hash_v14_p1,
                                      cn_slow_hash_v14_np1,
                                      cn_slow_hash_v14_ns1 };
    char blob[76];
    char h[NARMS][HASH_SIZE];
    uint64_t rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)w->id * 0xD1B54A32D192ED03ull);
    double deadline;
    int i, k;

    for (i = 0; i < NARMS; i++) w->fnv[i] = 0xCBF29CE484222325ull;
    if (ctx == NULL || salt0 == NULL) { w->failed = 1; return NULL; }
    memset(blob, (int)(w->id + 1), sizeof(blob));

    /* Warm through the real dispatcher: the resized entry points are hash
     * bodies alone and never call cn_pads_require, so without this there is no
     * pad and no salt. Outside the timed window. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof(blob), h[0], 8, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL) { w->failed = 1; return NULL; }
    memcpy(salt0, ctx->salt, CN_SALT_MEMORY);

    deadline = now_s() + g_seconds;

    while (now_s() < deadline)
    {
        /* A-B-C-C-B-A: every arm is equidistant from the group's midpoint,
         * so a linear drift in clock or temperature cancels for all three
         * rather than landing on whichever ran last. */
        static const int arm[2 * NARMS] = {0, 1, 2, 2, 1, 0};
        size_t   iters;
        uint16_t xx, yy;

        rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27;
        xx = (uint16_t)(4 + (rs >> 3) % 5);
        yy = (uint16_t)(4 + (rs >> 11) % 5);
        iters = (size_t)((rs >> 19) % (1 + (rs >> 27) % 64));

        for (i = 0; i < 2 * NARMS; i++)
        {
            const int a = arm[i];
            uint64_t t0, t1;
            memcpy(ctx->salt, salt0, CN_SALT_MEMORY);
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            t0 = __rdtsc();
            fn[a](ctx, blob, sizeof(blob), h[a], iters, CN_V8_INIT_SIZE_BLK, xx, yy);
            t1 = __rdtsc();
            w->cyc[a] += t1 - t0;
            w->n[a]++;
            for (k = 0; k < HASH_SIZE; k++) {
                w->fnv[a] ^= (unsigned char)h[a][k];
                w->fnv[a] *= 0x100000001B3ull;
            }
        }
    }

    free(salt0);
    cn_hash_context_free(ctx);
    return NULL;
}

/* Ticks per second for the invariant TSC, measured against the wall clock.
 *
 * The cycles/nonce column compares arms on ONE machine and needs no rate: the
 * TSC counts at a fixed nominal rate, so a ratio is already right. Comparing
 * one machine against another does need it, because the nominal rates differ
 * and 1000 ticks is not the same amount of time on two CPUs. That comparison is
 * the cross-machine spread, which is the gate D1 still owes.
 *
 * Spun rather than slept: a sleep on Windows rounds to the scheduler tick and
 * would calibrate against a quantised interval. 200 ms is enough for 0.1%.
 */
static double tsc_hz(void)
{
    double t0 = now_s(), t1;
    uint64_t c0 = __rdtsc(), c1;
    do { t1 = now_s(); } while (t1 - t0 < 0.2);
    c1 = __rdtsc();
    return (double)(c1 - c0) / (t1 - t0);
}

static int popcount64(uint64_t v)
{
    int c = 0;
    while (v) { c += (int)(v & 1u); v >>= 1; }
    return c;
}

int main(int argc, char **argv)
{
    int threads = (argc > 1) ? atoi(argv[1]) : 1;
    worker_t *w;
    pthread_t *th;
    uint64_t n[NARMS], cyc[NARMS], fnv[NARMS];
    int failed = 0, i, a;
    double hz;

    if (argc > 2) g_seconds = atof(argv[2]);
    if (threads < 1) threads = 1;

    for (i = 0; i < NARMS; i++) { n[i] = 0; cyc[i] = 0; fnv[i] = 0; }

    w  = (worker_t *)calloc((size_t)threads, sizeof(worker_t));
    th = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    if (w == NULL || th == NULL) { printf("out of memory\n"); return 1; }

    printf("v8 with salt_pad_v8 against v8 without it, 1 MB pad\n");
    printf("%d thread(s), %.1f s, A-B-C-C-B-A, one draw per group of six\n",
           threads, g_seconds);

    /* before the threads start, so the calibration runs on an idle machine */
    hz = tsc_hz();
    printf("invariant TSC %.3f GHz nominal, measured against the wall clock\n\n",
           hz / 1e9);
    fflush(stdout);

    for (i = 0; i < threads; i++) { w[i].id = i; pthread_create(&th[i], NULL, worker, &w[i]); }
    for (i = 0; i < threads; i++) pthread_join(th[i], NULL);

    for (i = 0; i < threads; i++) {
        for (a = 0; a < NARMS; a++) {
            n[a] += w[i].n[a]; cyc[a] += w[i].cyc[a];
            fnv[a] ^= w[i].fnv[a];
        }
        failed += w[i].failed;
    }
    if (failed) { printf("%d thread(s) failed to start\n", failed); return 1; }
    for (a = 0; a < NARMS; a++)
        if (n[a] == 0) { printf("no nonces completed on arm %d\n", a); return 1; }

    printf("  %-22s %12s %10s %10s %10s\n", "", "cycles/nonce", "ms/nonce", "core", "nonce");
    for (a = 0; a < NARMS; a++)
    {
        const double ca = (double)cyc[a] / (double)n[a];
        const double c0 = (double)cyc[0] / (double)n[0];
        printf("  %-22s %12.0f %10.4f", g_arm_name[a], ca, ca / hz * 1000.0);
        if (a == 0)
            printf("   baseline   baseline\n");
        else
            /* core: how much faster the core is. nonce: the same saving scaled
             * by the core's share of a real nonce, since the chain fill is the
             * rest and none of these variants touch it. */
            printf(" %+9.2f%% %+9.2f%%\n",
                   (c0 / ca - 1.0) * 100.0,
                   (1.0 - (ca / c0)) * CORE_SHARE_OF_NONCE * 100.0);
    }
    printf("\n  %llu nonces per arm. The chain fill is the other %.1f%% of a\n",
           (unsigned long long)n[0], (1.0 - CORE_SHARE_OF_NONCE) * 100.0);
    printf("  nonce (F52) and no variant here touches it.\n");

    /* A degenerate variant would be fast and useless. This is a smell test, not
     * a proof: roughly half the bits set, and the arms differing from each
     * other, is what working hashes look like. Two arms matching would mean the
     * thing between them never reaches the digest, which is itself a finding. */
    printf("\n  digest smell test, FNV-1a over every digest produced:\n");
    for (a = 0; a < NARMS; a++)
        printf("    %-22s %016llx  %2d / 64 bits set\n", g_arm_name[a],
               (unsigned long long)fnv[a], popcount64(fnv[a]));
    /* Compare EVERY pair, not just each arm against the baseline. The first
     * version of this check compared only against arm 0 and so missed that arms
     * 1 and 2 were identical to each other, which is the finding that mattered:
     * two variants agreeing means whatever differs between them is dead code. */
    {
        int b, quiet = 1;
        for (a = 0; a < NARMS; a++)
            for (b = a + 1; b < NARMS; b++)
                if (fnv[a] == fnv[b]) {
                    printf("    *** arms %d and %d agree: what differs between them\n", a, b);
                    printf("        never reaches the digest and is dead code\n");
                    quiet = 0;
                }
        if (quiet)
            printf("    (all distinct, as three different hashes should be)\n");
    }

    free(w); free(th);
    return 0;
}
