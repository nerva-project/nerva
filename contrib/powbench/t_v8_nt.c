/* Do non-temporal stores help v8's fill, and at which pad size does that change?
 *
 * This is B2 in PLAN-v8-PHASE7: the streaming-store attack is worth +22% on
 * v13's 8 MB pad and a 39% to 61% LOSS on v8's 1 MB one, and the sign flips
 * somewhere in between. Nobody knows where. The threshold is not at 1.0x
 * over-subscription: V6-MINER-LOG lesson 9 measures 1.3x as changing nothing
 * and 3.8x as wide open.
 *
 * So this sweeps the pad instead of fixing it, using the same resized
 * recompilations v8bench uses (contrib/hf14checks/v5pad*.c), and prints the
 * per-thread working set as a ratio to the cache the operator supplies. The
 * deliverable is one number: the over-subscription ratio at which a v8 attacker
 * starts winning. With it, "do not grow the pad" stops being a judgement.
 *
 * Remember the salt. The working set is the pad PLUS 256 KB of salt per thread,
 * so at a 1 MB pad it is 1.25 MB and not 1 MB. Every ratio in lesson 9 counts
 * pads only and is therefore 25% low.
 *
 * Method, following what this project learned the hard way:
 *
 *   A-B-B-A per group of four nonces, so drift and boost behaviour hit both
 *   arms equally instead of landing on whichever ran second. Cycles are counted
 *   per arm with rdtsc rather than wall clock, so a descheduled thread does not
 *   land entirely on one arm.
 *
 *   Parameters are drawn from the ranges get_block_longhash_v14 uses, and the
 *   same draw feeds all four nonces of a group, so the two arms always hash
 *   identical work. Work per nonce varies several-fold in v8, so unmatched
 *   parameters would measure the draw and not the change.
 *
 *   The two arms must also agree bit for bit, and that is checked rather than
 *   assumed: a correctness test riding along with the timing one.
 *
 * SIZING, which is the reason this is not simply the fork's version with more
 * rows. The fork ran a fixed 20 s per point and 1.3M nonces in total, a number
 * chosen by guess. Measured on 2026-10-06, this machine when quiet is stable to
 * under 1% where the working set is comfortably cache-resident and bistable to
 * 11% exactly at the cache cliff, which is the regime this harness is built to
 * find. A flat sample count is therefore both too slow everywhere and too
 * imprecise where it matters, and a longer run at the cliff just averages two
 * states together rather than resolving them.
 *
 * So each point prints a SPLIT-HALF CHECK: the same ratio computed from the
 * first and second halves of its own window. If the halves agree the window was
 * long enough and nothing is gained by lengthening it. If they disagree the
 * point is unstable, and the answer is more repeats rather than a longer run.
 * Default 4 s a point, which is about 25 s for the whole sweep; raise it only
 * when the split-half says to.
 *
 *   t_v8_nt [threads] [seconds_per_point] [L3_MB]
 *
 * L3_MB is optional and only labels the output with the over-subscription
 * ratio; it changes no measurement.
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

/* slow-hash.c calls this and the real one is in a C++ TU that is not linked
 * here. Same answer, so the dispatcher picks the same arm it would in the
 * daemon; without it the link fails rather than quietly running software AES. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

typedef void (*hashfn)(cn_hash_context_t *, const void *, size_t, char *,
                       size_t, uint8_t, uint16_t, uint16_t);

/* the resized recompilations, from contrib/hf14checks/v5pad*.c */
void cn_slow_hash_v14_p025(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p05 (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p1  (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p2  (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p4  (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p8  (cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

static const struct { const char *name; hashfn fn; size_t pad; } g_pads[] = {
    { "256KB", cn_slow_hash_v14_p025,  256ull*1024 },
    { "512KB", cn_slow_hash_v14_p05,   512ull*1024 },
    { "1MB",   cn_slow_hash_v14_p1,   1024ull*1024 },
    { "2MB",   cn_slow_hash_v14_p2,   2048ull*1024 },
    { "4MB",   cn_slow_hash_v14_p4,   4096ull*1024 },
    { "8MB",   cn_slow_hash_v14_p8,   8192ull*1024 },
};
#define NPADS ((int)(sizeof(g_pads)/sizeof(g_pads[0])))

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double g_seconds = 4.0;

typedef struct {
    int      id;
    hashfn   fn;
    size_t   pad;
    /* [half][arm], arm 0 = ordinary stores, arm 1 = streaming */
    uint64_t n[2][2];
    uint64_t cyc[2][2];
    int      mismatches;
    int      failed;
} worker_t;

/* _mm_stream_si128 needs 16-byte alignment and the daemon's pad is page
 * aligned, so align to a page here too rather than trusting malloc. */
static void *aligned_alloc_4k(size_t bytes, void **raw)
{
    const size_t a = 4096;
    char *p = (char *)malloc(bytes + a);
    if (p == NULL) { *raw = NULL; return NULL; }
    *raw = p;
    return p + (a - ((uintptr_t)p % a)) % a;
}

static void *worker(void *arg)
{
    worker_t *w = (worker_t *)arg;
    cn_hash_context_t *ctx = cn_hash_context_create();
    char *salt0 = (char *)malloc(CN_SALT_MEMORY);
    void *raw = NULL;
    uint8_t *own, *saved;
    char blob[76];
    char h[2][HASH_SIZE];
    uint64_t rs = 0x9E3779B97F4A7C15ull ^ ((uint64_t)w->id * 0xD1B54A32D192ED03ull);
    double t_start, t_mid, deadline;
    int i;

    if (ctx == NULL || salt0 == NULL) { w->failed = 1; return NULL; }
    memset(blob, (int)(w->id + 1), sizeof(blob));

    /* Warm through the real dispatcher: the resized entry points are the hash
     * bodies alone and never call cn_pads_require, so without this the context
     * has no pad and no salt. Outside the timed window on purpose. */
    cn_nt_fill_enable(0);
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, blob, sizeof(blob), h[0], 8, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL) { w->failed = 1; return NULL; }

    own = (uint8_t *)aligned_alloc_4k(w->pad, &raw);
    if (own == NULL) { w->failed = 1; return NULL; }
    memset(own, 0, w->pad);
    saved = ctx->scratchpad;
    ctx->scratchpad = own;

    /* v8's sweeps write into the salt through salt_pad_v8_defer, so the state a
     * nonce starts from is not the state the previous nonce started from. Both
     * arms have to start from the same salt or they are not hashing the same
     * work, and their digests cannot be compared at all. Snapshot once, restore
     * before every nonce; the restore costs both arms equally. */
    memcpy(salt0, ctx->salt, CN_SALT_MEMORY);

    t_start  = now_s();
    deadline = t_start + g_seconds;
    t_mid    = t_start + g_seconds / 2.0;

    while (now_s() < deadline)
    {
        /* one draw, four nonces: off, on, on, off */
        static const int arm[4] = {0, 1, 1, 0};
        const int half = (now_s() >= t_mid) ? 1 : 0;
        size_t   iters;
        uint16_t xx, yy;

        rs ^= rs >> 12; rs ^= rs << 25; rs ^= rs >> 27;
        xx = (uint16_t)(4 + (rs >> 3) % 5);
        yy = (uint16_t)(4 + (rs >> 11) % 5);
        iters = (size_t)((rs >> 19) % (1 + (rs >> 27) % 64));

        for (i = 0; i < 4; i++)
        {
            const int a = arm[i];
            uint64_t t0, t1;
            memcpy(ctx->salt, salt0, CN_SALT_MEMORY);
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            cn_nt_fill_enable(a);
            t0 = __rdtsc();
            w->fn(ctx, blob, sizeof(blob), h[a], iters, CN_V8_INIT_SIZE_BLK, xx, yy);
            t1 = __rdtsc();
            w->cyc[half][a] += t1 - t0;
            w->n[half][a]++;
        }
        /* the two arms hashed identical work, so they must agree */
        if (memcmp(h[0], h[1], HASH_SIZE) != 0)
            w->mismatches++;
    }

    cn_nt_fill_enable(0);
    ctx->scratchpad = saved;
    free(raw);
    free(salt0);
    cn_hash_context_free(ctx);
    return NULL;
}

/* streaming against ordinary, in percent, positive meaning streaming is faster */
static double ratio_pct(uint64_t c0, uint64_t n0, uint64_t c1, uint64_t n1)
{
    if (n0 == 0 || n1 == 0 || c1 == 0) return 0.0;
    return 100.0 * (((double)c0 / (double)n0) / ((double)c1 / (double)n1) - 1.0);
}

int main(int argc, char **argv)
{
    int threads = (argc > 1) ? atoi(argv[1]) : 16;
    double l3_mb = (argc > 3) ? atof(argv[3]) : 0.0;
    int p;

    if (argc > 2) g_seconds = atof(argv[2]);
    if (threads < 1) threads = 1;

    printf("v8 fill: ordinary stores against streaming, %d threads, %.1f s a point\n",
           threads, g_seconds);
    printf("working set per thread is the pad plus %d KB of salt.\n",
           CN_SALT_MEMORY / 1024);
    if (l3_mb > 0.0)
        printf("over-subscription is that total times %d threads, against %.0f MB of L3.\n",
               threads, l3_mb);
    else
        printf("pass L3 size in MB as a third argument to label the over-subscription ratio.\n");
    printf("\n  %-6s %9s %11s %11s %10s %9s %9s\n",
           "pad", "set/thr", "ordinary", "streaming", "streaming", "1st half", "2nd half");
    printf("  %-6s %9s %11s %11s %10s %9s %9s\n",
           "", l3_mb > 0.0 ? "ratio" : "MB", "cyc/nonce", "cyc/nonce", "is", "is", "is");
    fflush(stdout);

    for (p = 0; p < NPADS; p++)
    {
        worker_t *w  = (worker_t *)calloc((size_t)threads, sizeof(worker_t));
        pthread_t *th = (pthread_t *)calloc((size_t)threads, sizeof(pthread_t));
        uint64_t n[2][2] = {{0,0},{0,0}}, cyc[2][2] = {{0,0},{0,0}};
        int mismatches = 0, failed = 0, i, hh, aa;
        double set_mb = (double)(g_pads[p].pad + CN_SALT_MEMORY) / (1024.0 * 1024.0);
        double full, h1, h2;

        if (w == NULL || th == NULL) { printf("  out of memory\n"); return 1; }

        for (i = 0; i < threads; i++) {
            w[i].id = i; w[i].fn = g_pads[p].fn; w[i].pad = g_pads[p].pad;
            pthread_create(&th[i], NULL, worker, &w[i]);
        }
        for (i = 0; i < threads; i++) pthread_join(th[i], NULL);

        for (i = 0; i < threads; i++) {
            for (hh = 0; hh < 2; hh++)
                for (aa = 0; aa < 2; aa++) {
                    n[hh][aa]   += w[i].n[hh][aa];
                    cyc[hh][aa] += w[i].cyc[hh][aa];
                }
            mismatches += w[i].mismatches;
            failed     += w[i].failed;
        }

        if (failed) { printf("  %-6s  %d thread(s) failed to start\n", g_pads[p].name, failed); }
        else if (n[0][0] + n[1][0] == 0 || n[0][1] + n[1][1] == 0) {
            printf("  %-6s  no nonces completed; raise the seconds argument\n", g_pads[p].name);
        } else {
            full = ratio_pct(cyc[0][0] + cyc[1][0], n[0][0] + n[1][0],
                             cyc[0][1] + cyc[1][1], n[0][1] + n[1][1]);
            h1   = ratio_pct(cyc[0][0], n[0][0], cyc[0][1], n[0][1]);
            h2   = ratio_pct(cyc[1][0], n[1][0], cyc[1][1], n[1][1]);

            printf("  %-6s", g_pads[p].name);
            if (l3_mb > 0.0) printf(" %8.2fx", set_mb * threads / l3_mb);
            else             printf(" %9.2f", set_mb);
            printf(" %11.0f %11.0f %+9.2f%% %+8.2f%% %+8.2f%%",
                   (double)(cyc[0][0] + cyc[1][0]) / (double)(n[0][0] + n[1][0]),
                   (double)(cyc[0][1] + cyc[1][1]) / (double)(n[0][1] + n[1][1]),
                   full, h1, h2);

            /* The split-half check is the sizing diagnostic. A point whose two
             * halves disagree by more than the effect it is reporting has not
             * converged, and the fix is repeats rather than a longer window:
             * at the cache cliff the variance is bimodal, so a longer run
             * averages two states instead of resolving either. */
            if (full != 0.0 && (h1 - h2 > 2.0 || h2 - h1 > 2.0))
                printf("  UNSTABLE");
            if (mismatches)
                printf("  %d MISMATCHES", mismatches);
            printf("\n");
        }
        fflush(stdout);
        free(w); free(th);
    }

    printf("\n  Negative means streaming LOSES, which is the defended state:\n");
    printf("  the pad is cache resident, the fill's stores never reach DRAM,\n");
    printf("  and streaming only forces traffic that was not happening.\n");
    printf("  The sign flip is the attack switching on. PLAN-v8-PHASE7 B2.\n");
    printf("\n  A point marked UNSTABLE needs repeats, not a longer window.\n");
    return 0;
}
