/* How big is the AES-NI against T-tables asymmetry on v8, in one number?
 *
 * WHY. Everything v8 claims about goal 1 rests on one sentence in RESULTS.md
 * 6.3: "its resistance comes from the AES-NI against T-tables asymmetry rather
 * than program divergence, and that asymmetry disappears the day a GPU gets
 * competitive AES." PLAN-v8-PHASE8 P3 is built on it, D2's whole value is
 * making a feeder pay more chained AES, and D1 is argued safe because it leaves
 * the absolute AES alone. The sentence has never had a number attached.
 *
 * This measures the half of that question a CPU can answer: the cost of running
 * v8 with T-table AES instead of the AES instructions, on one machine, with
 * everything else held identical. Both arms are already in the tree and already
 * proven to agree bit for bit over the whole consensus domain (F58), so this is
 * the same hash twice with one implementation choice changed, which is as clean
 * as a comparison gets.
 *
 * WHAT IT DOES NOT MEASURE, stated up front because the temptation to overclaim
 * here is strong:
 *
 *   It is NOT a GPU number. A card running T-tables pays differently: shared
 *   memory bank conflicts rather than L1 hits, and it has thousands of lanes to
 *   hide latency with. This is a CPU with good caches doing the slow thing, so
 *   it is the FLOOR of the structural penalty, not an estimate of the card's.
 *
 *   It is NOT the AES share of a nonce. The software arm replaces AES
 *   everywhere it appears, so the ratio mixes the fill, the main loop and the
 *   finalize. Separating those needs instrumentation, not this.
 *
 *   The chain fill is not here at all, and it is ~60% of a real nonce (F52).
 *   The harness prints the whole-nonce figure beside the core one so the
 *   conversion is visible rather than left to the reader.
 *
 * The no-sweep variant is measured too, because D1's safety argument is that it
 * leaves the absolute AES alone. If the asymmetry is materially weaker without
 * the sweeps then that argument is wrong, and this is where it would show.
 *
 * Method follows the rules the rest of this harness uses: arms interleaved
 * within one process in a palindrome so linear drift cancels, one parameter
 * draw feeding every arm in a group, the salt restored before each nonce, and
 * the TSC calibrated against the wall clock so the number is time and not
 * ticks.
 *
 *   t_v8_aes [threads] [seconds]
 *
 * Build: sh contrib/powbench/build-v8-aes.sh
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
 * Used only to convert a core figure into a nonce figure, and printed as such
 * so the conversion is visible rather than buried. */
#define CORE_SHARE_OF_NONCE 0.405

#define NARMS 4
static const char *const g_arm_name[NARMS] = {
    "v8          AES-NI  ",
    "v8          T-table ",
    "v8 no-sweep AES-NI  ",
    "v8 no-sweep T-table "
};

extern void cn_slow_hash_v14_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14_sw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14ns_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14ns_sw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

typedef void (*hashfn)(cn_hash_context_t *, const void *, size_t, char *,
                       size_t, uint8_t, uint16_t, uint16_t);

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double g_seconds = 10.0;

typedef struct {
    int      id;
    uint64_t n[NARMS];
    uint64_t cyc[NARMS];
    /* The two arms of a variant MUST produce the same digest: that is F58, and
     * if it stops holding here the timing is of two different hashes. Counted
     * rather than assumed. */
    uint64_t mismatch;
    int      failed;
} worker_t;

static void *worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char *salt0 = (char *)malloc(CN_SALT_MEMORY);
    static const hashfn fn[NARMS] = { cn_slow_hash_v14_hw,
                                      cn_slow_hash_v14_sw,
                                      cn_slow_hash_v14ns_hw,
                                      cn_slow_hash_v14ns_sw };
    char blob[76];
    char h[NARMS][HASH_SIZE];
    uint64_t rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)w->id * 0xD1B54A32D192ED03ull);
    double deadline;
    int i;

    if (ctx == NULL || salt0 == NULL) { w->failed = 1; return NULL; }
    memset(blob, (int)(w->id + 1), sizeof(blob));

    /* the dispatcher allocates the pad and the salt lazily; outside the timed
     * window. The salt's contents do not matter as long as every arm in a group
     * starts from the same bytes, which the restore below guarantees. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof(blob), h[0], 8, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL) { w->failed = 1; return NULL; }
    memcpy(salt0, ctx->salt, CN_SALT_MEMORY);

    deadline = now_s() + g_seconds;

    while (now_s() < deadline)
    {
        /* A-B-C-D-D-C-B-A: every arm is equidistant from the group's midpoint,
         * so a linear drift in clock or temperature cancels for all four rather
         * than landing on whichever ran last. The software arms are several
         * times slower than the hardware ones, so an unpaired layout would let
         * thermal droop accumulate against them specifically, which is exactly
         * the direction that would inflate the result being looked for. */
        static const int arm[2 * NARMS] = {0, 1, 2, 3, 3, 2, 1, 0};
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
        }

        if (memcmp(h[0], h[1], HASH_SIZE) != 0) w->mismatch++;
        if (memcmp(h[2], h[3], HASH_SIZE) != 0) w->mismatch++;
    }

    free(salt0);
    cn_hash_context_free(ctx);
    return NULL;
}

/* Ticks per second for the invariant TSC, measured against the wall clock, so
 * the result is time rather than ticks and can be compared between machines.
 * Spun rather than slept: a sleep on Windows rounds to the scheduler tick. */
static double tsc_hz(void)
{
    double t0 = now_s(), t1;
    uint64_t c0 = __rdtsc(), c1;
    do { t1 = now_s(); } while (t1 - t0 < 0.2);
    c1 = __rdtsc();
    return (double)(c1 - c0) / (t1 - t0);
}

int main(int argc, char **argv)
{
    int threads = (argc > 1) ? atoi(argv[1]) : 1;
    worker_t *w;
    pthread_t *th;
    uint64_t n[NARMS], cyc[NARMS], mismatch = 0;
    double ms[NARMS], hz;
    int failed = 0, i, a;

    if (argc > 2) g_seconds = atof(argv[2]);
    if (threads < 1) threads = 1;

    for (i = 0; i < NARMS; i++) { n[i] = 0; cyc[i] = 0; }

    w  = (worker_t *)calloc((size_t)threads, sizeof(worker_t));
    th = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
    if (w == NULL || th == NULL) { printf("out of memory\n"); return 1; }

    printf("v8: AES instructions against T-tables, 1 MB pad\n");

    if (!cn_hardware_aes_supported())
    {
        printf("NO HARDWARE AES: both arms would be T-tables. Refusing.\n");
        return 1;
    }

    hz = tsc_hz();
    printf("%d thread, %.0f s, A-B-C-D-D-C-B-A, TSC %.3f GHz\n\n",
           threads, g_seconds, hz / 1e9);
    fflush(stdout);

    for (i = 0; i < threads; i++) { w[i].id = i; pthread_create(&th[i], NULL, worker, &w[i]); }
    for (i = 0; i < threads; i++) pthread_join(th[i], NULL);

    for (i = 0; i < threads; i++) {
        for (a = 0; a < NARMS; a++) { n[a] += w[i].n[a]; cyc[a] += w[i].cyc[a]; }
        mismatch += w[i].mismatch;
        failed += w[i].failed;
    }
    if (failed) { printf("%d thread(s) failed to start\n", failed); return 1; }
    for (a = 0; a < NARMS; a++)
        if (n[a] == 0) { printf("no nonces completed on arm %d\n", a); return 1; }

    for (a = 0; a < NARMS; a++)
        ms[a] = (double)cyc[a] / (double)n[a] / hz * 1000.0;

    for (a = 0; a < NARMS; a++)
        printf("  %-20s %9.4f ms\n", g_arm_name[a], ms[a]);

    /* nonce column: the chain fill is 59.5% of a nonce (F52), uses no AES and
     * so costs the same in both arms, which dilutes the ratio. Dividing the
     * core ratio by 0.405 would be the wrong arithmetic. */
    printf("\n  T-table over AES-NI     core    nonce\n");
    printf("    v8                  %6.2fx  %6.2fx\n", ms[1] / ms[0],
           (CORE_SHARE_OF_NONCE * ms[1] + (1.0 - CORE_SHARE_OF_NONCE) * ms[0]) / ms[0]);
    printf("    v8 no-sweep         %6.2fx  %6.2fx\n", ms[3] / ms[2],
           (CORE_SHARE_OF_NONCE * ms[3] + (1.0 - CORE_SHARE_OF_NONCE) * ms[2]) / ms[2]);

    /* Phase 2: split the AES into the part that is serial and the part that is
     * not, because D2's feeder argument is about CHAINED AES specifically. The
     * pad fill and the finalize run 8 AES blocks side by side and bitslice
     * well; the main loop feeds each round into the next and does not.
     *
     * F58 is what makes this measurable without instrumentation: without the
     * sweeps the hash depends on (xx-1)*yy+iters alone, so step count is a
     * single knob. Two points give a slope and an intercept.
     *
     *   slope      per-step cost of the serial main loop
     *   intercept  everything once per nonce: keccak, the AES pad fill,
     *              randomize_scratchpad_256k_v8, and the AES finalize
     */
    {
        /* Four step counts, two in domain and two far outside it.
         *
         * The in-domain pair shows what the main loop costs where consensus
         * actually runs. The first version of this stopped there and tried to
         * read a per-step slope off it, which was a mistake: 12 against 119
         * steps moved the core by 0.5% one run and -0.1% the next, so the
         * slope was noise, and a solve built on it returned an AES share of
         * 227% and then -127%. Numbers that absurd are a gift; a plausible
         * wrong one would have been believed.
         *
         * So the per-step cost is taken where it dominates instead, at 2,000
         * and 20,000 steps, and only then used as the pure-AES ratio. That
         * ratio is a property of one aesenc against one set of table lookups,
         * which is what the solve needs; it is not a claim that a nonce ever
         * runs that long. */
        static const uint16_t pt[4][3] = { {1, 1, 12}, {1, 1, 119},
                                           {1, 1, 2000}, {1, 1, 20000} };
        const hashfn nsfn[2] = { cn_slow_hash_v14ns_hw, cn_slow_hash_v14ns_sw };
        double t[2][4];     /* [aes arm][point], ms */
        cn_hash_context_t *c2 = cn_hash_context_create();
        char *salt0 = (char *)malloc(CN_SALT_MEMORY);
        char blob[76], hh[HASH_SIZE];
        int p, reps, r;

        if (c2 == NULL || salt0 == NULL) { printf("\nphase 2 allocation failed\n"); return 1; }
        memset(blob, 7, sizeof(blob));
        memset(&c2->random_values, 0, sizeof(c2->random_values));
        cn_slow_hash_v14(c2, blob, sizeof(blob), hh, 8, CN_V8_INIT_SIZE_BLK, 4, 4);
        if (c2->salt == NULL) { printf("\nphase 2 salt allocation failed\n"); return 1; }
        memcpy(salt0, c2->salt, CN_SALT_MEMORY);

        /* interleaved the same way, so the two points and the two arms all sit
         * symmetrically about each group's midpoint */
        for (a = 0; a < 2; a++) for (p = 0; p < 4; p++) t[a][p] = 0.0;
        reps = 40;
        for (r = 0; r < reps; r++)
        {
            /* palindrome over all eight (arm, point) cells, same reason as
             * the main phase: every cell equidistant from the midpoint */
            static const int ord[16][2] = {
                {0,0},{0,1},{0,2},{0,3},{1,0},{1,1},{1,2},{1,3},
                {1,3},{1,2},{1,1},{1,0},{0,3},{0,2},{0,1},{0,0} };
            int k;
            for (k = 0; k < 16; k++)
            {
                const int aa = ord[k][0], pp = ord[k][1];
                uint64_t c0, c1;
                memcpy(c2->salt, salt0, CN_SALT_MEMORY);
                memset(&c2->random_values, 0, sizeof(c2->random_values));
                c0 = __rdtsc();
                nsfn[aa](c2, blob, sizeof(blob), hh, pt[pp][2], CN_V8_INIT_SIZE_BLK,
                         pt[pp][0], pt[pp][1]);
                c1 = __rdtsc();
                t[aa][pp] += (double)(c1 - c0);
            }
        }
        for (a = 0; a < 2; a++) for (p = 0; p < 4; p++)
            t[a][p] = t[a][p] / (double)(reps * 2) / hz * 1000.0;

        printf("\n  steps    %9s %9s %9s %9s\n", "12", "119", "2,000", "20,000");
        for (a = 0; a < 2; a++)
            printf("  %-7s  %9.4f %9.4f %9.4f %9.4f\n", a ? "T-table" : "AES-NI",
                   t[a][0], t[a][1], t[a][2], t[a][3]);

        {
            /* Per-step cost taken at 2,000 against 20,000, where it dominates.
             * The in-domain pair cannot give it: 12 against 119 moves the core
             * by less than the noise, which is itself the finding, and an
             * earlier version that fitted a slope there returned an AES share
             * of 227% and then -127%. F59 section 5.
             *
             * The two ratios below differ nearly sevenfold because the pad fill
             * is back-to-back AES and nothing else, while a main-loop step is
             * one aesenc around a random read from a 1 MB pad and is memory
             * bound. The consequences are in F59, not here. */
            const double sl_hw = (t[0][3] - t[0][2]) / 18000.0;
            const double sl_sw = (t[1][3] - t[1][2]) / 18000.0;
            const double ic_hw = t[0][2] - 2000.0 * sl_hw;
            const double ic_sw = t[1][2] - 2000.0 * sl_sw;
            printf("\n  12 to 119, the drawn range: %+.2f%% hw, %+.2f%% sw (noise)\n",
                   (t[0][1] / t[0][0] - 1.0) * 100.0, (t[1][1] / t[1][0] - 1.0) * 100.0);
            printf("  pad fill + finalize  %7.4f  %7.4f ms  %6.2fx\n",
                   ic_hw, ic_sw, ic_sw / ic_hw);
            printf("  per main-loop step   %7.1f  %7.1f ns  %6.2fx\n",
                   sl_hw * 1e6, sl_sw * 1e6, sl_sw / sl_hw);
        }

        printf("\n  digests agree: %s    %llu nonces/arm\n",
               mismatch ? "NO" : "yes", (unsigned long long)n[0]);

        free(salt0);
        cn_hash_context_free(c2);
    }

    free(w); free(th);
    return mismatch ? 1 : 0;
}
