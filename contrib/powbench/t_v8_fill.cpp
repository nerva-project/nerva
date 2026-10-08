/* Is the chain fill actually bound by random-access database bandwidth?
 *
 * WHY. F38 names this as the honest weak point of the whole design, and
 * PLAN-v8-PHASE8 repeats it under "what would make this whole direction wrong":
 *
 *     The pool resistance and the ASIC bound are the same argument, and both
 *     assume random-access database bandwidth is the binding constraint. A
 *     236 MB working set is not large.
 *
 * Everything v8 claims about goals 1 and 3 inherits that assumption. The fill
 * is 56 to 59% of a nonce (F57) and 74% after D1, and F38's rule says it is the
 * part a specialist cannot specialise. If instead the fill is bound by HC-128
 * throughput, the rule is wrong in the one place it matters, because a stream
 * cipher is the easiest thing in this entire algorithm to put in silicon.
 *
 * The assumption has never been tested. This tests it.
 *
 * METHOD. Four arms over the same loop body, differing only in which index the
 * pick returns. The selector draw happens whether or not its branch is taken,
 * and the hot arm computes a real index and then discards it.
 *
 * CORRECTION, 2026-10-07 (FINDINGS F82). This used to claim that the HC-128
 * work is therefore identical in every arm. It is identical only between arms
 * with the SAME odds. HC128_U32 rejection-samples: a full-history pick draws
 * over `height` and accepts height / 2^ceil(log2 height), 53.6% at 4.5M, while
 * a window pick draws over 100,000 and accepts 76.3%. So an arm with more
 * full-history picks consumes more keystream, takes more NextKeys and
 * mispredicts the redraw branch more often, before it touches any memory.
 * ARM_HOT is a true floor for ARM_SHIPPED, which shares its odds, and NOT for
 * ARM_ALL, ARM_WINDOW or the odds sweep: "all full history minus hot" is extra
 * memory PLUS extra cipher, and "window only" can legitimately come in under
 * the hot arm. F69 found the same mechanism from the height side. The measured
 * totals are unaffected; only their split into memory and cipher is.
 *
 *   shipped        13/256 full history, the rest in the 100,000-block window
 *   window only    odds forced to 0: everything in 5.6 MB
 *   one hot entry  every read goes to entry 0: memory cost removed entirely,
 *                  so this arm is the HC-128 floor
 *   all history    odds forced to 256: every read over the whole cache
 *
 * **shipped divided by one-hot is the number this is for.** It is how much of
 * the fill is memory at all, and therefore the most an attacker could win by
 * making the memory free. Near 1.0 refutes the premise.
 *
 * The loop is the run-ahead form the daemon runs, not the pre-rewrite one in
 * chain_fill.h, which is also missing the mid-point reseed. The run-ahead is
 * the right thing to measure here precisely because it already extracts the
 * memory-level parallelism, so what is left is the residual an attacker would
 * still have to beat rather than an artifact of a serial loop.
 *
 * The cache contents are synthetic. Timing depends on the size and the access
 * pattern, not on the bytes, and a synthetic cache keeps LMDB out of a
 * measurement that is not about LMDB. build_block_cache is a no-op once warm
 * and the real reads go to exactly this kind of resident array.
 *
 *   t_v8_fill [height] [seconds]
 *   t_v8_fill [height] [seconds] reseed    RESEED-PREREG.md step 1 only
 *   t_v8_fill [height] [seconds] draw      DRAW-PREREG.md step 1 only
 *
 * Build: sh contrib/powbench/build-v8-fill.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <vector>
#include <x86intrin.h>

#include "hc128.h"

#define CNA_V6_WINDOW_BLOCKS     100000u
#define CNA_V6_FULL_HISTORY_ODDS 13u
#define SALT_BYTES               262144

/* 56 bytes, matching struct block_cache_data in db_lmdb.h: a 32-byte hash and
 * three uint64. Packed, because the real one is 56 and a padded 64 would
 * change both the footprint and the cache-line behaviour. */
#pragma pack(push, 1)
struct blk_ent { uint8_t hash[32]; uint64_t timestamp, diff_lo, coins; };
#pragma pack(pop)

/* The first four are the original arms. The last three are D3-ODDS-PREREG's
 * intermediate candidates, added 2026-10-07 so the cost curve's shape is
 * visible and not just its endpoints.
 *
 * ARM_HOT draws with the shipped odds and then throws the index away, so it
 * remains the HC-128 floor while consuming exactly the keystream every other
 * arm does. Keeping ARM_SHIPPED at 0 means the 13/256 control is in every
 * table by construction, which the pre-registration requires. */
enum { ARM_SHIPPED = 0, ARM_WINDOW, ARM_HOT, ARM_ALL,
       ARM_O32, ARM_O64, ARM_O128, NARMS };
static const char *const g_arm[NARMS] = {
    "shipped, 13/256 ",
    "window only     ",
    "one hot entry   ",
    "all full history",
    "odds 32/256     ",
    "odds 64/256     ",
    "odds 128/256    "
};
static const uint32_t g_odds[NARMS] = {
    CNA_V6_FULL_HISTORY_ODDS, 0u, CNA_V6_FULL_HISTORY_ODDS, 256u, 32u, 64u, 128u
};

static std::vector<blk_ent> g_cache;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static double tsc_hz(void)
{
    double t0 = now_s(), t1;
    uint64_t c0 = __rdtsc(), c1;
    do { t1 = now_s(); } while (t1 - t0 < 0.2);
    c1 = __rdtsc();
    return (double)(c1 - c0) / (t1 - t0);
}

/* The fill as it was BEFORE A1, for the one comparison that needs it.
 *
 * The old loop interleaved HC-128 with each read: draw an index, read it,
 * draw the next, read it, encrypt, repeat. The reads therefore issued one at a
 * time and each paid full latency with nothing to hide it behind. That is the
 * form the April 2026 diag3 sync was measured on, where losing L3 residency
 * cost 3.7x per block.
 *
 * The current form prefetches 64 reads before touching any of them, so the
 * latency overlaps. Whether that changed what the 100,000-block window is worth
 * is the question, and it is answered by the ratio of full-history to windowed
 * WITHIN each scheduling, not across them: that way the differences in how the
 * keystream is applied cancel out and only the read scheduling is left.
 *
 * Faithful to chain_fill.h's pre-run-ahead port, including its use of
 * HC128_EncryptMessage rather than a copied keystream. */
static void fill_serial(unsigned char *out, HC128_State *rng, uint32_t height, int arm)
{
    const blk_ent *C = g_cache.data();
    const uint32_t wsz   = height > CNA_V6_WINDOW_BLOCKS ? CNA_V6_WINDOW_BLOCKS : height;
    const uint32_t wbase = height - wsz;
    const uint32_t odds  = g_odds[arm];
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;

    #define PICK_S() ({                                                      \
        uint64_t i_ = (HC128_U32(rng, &ki, 256) < odds)                      \
                    ? (uint64_t)HC128_U32(rng, &ki, height)                  \
                    : (uint64_t)(wbase + HC128_U32(rng, &ki, wsz));          \
        (arm == ARM_HOT) ? (uint64_t)0 : i_; })

    while (count < 4096)
    {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++)
        {
            memcpy(msg,      C[PICK_S()].hash, 32);
            memcpy(msg + 32, &C[PICK_S()].timestamp, 8);
            memcpy(msg + 40, &C[PICK_S()].diff_lo,   8);
            memcpy(msg + 48, &C[PICK_S()].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        {
            unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
            unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
            HC128_Init(rng, key, iv);
        }
        if (count == 2048)
        {
            for (int r = 0; r < 4; r++)
                memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072u - 16u), 16);
            HC128_EncryptMessage(rng, msg, optr, 64);
            HC128_Init(rng, optr, optr + 16);
        }
    }
    #undef PICK_S
}

/* One fill, 4096 messages of 64 bytes, 4 cache reads each: 16,384 random reads
 * for 256 KB of salt. Transcribed from BlockchainLMDB::get_cna_v6_data
 * including the run-ahead over a sixteen-count block and the mid-point reseed
 * at count 2048. */
/* One raw keystream word, the way HC128_U32 fetches one but with no mask and
 * no redraw. DRAW-PREREG.md's candidates A and B take the index from it. */
static inline uint32_t hc_word(HC128_State *rng, size_t *ki)
{
    if (*ki > 15) { HC128_NextKeys(rng); *ki = 0; }
    return rng->keystream[(*ki)++];
}

/* DRAW-PREREG.md: 0 = S, shipped; 1 = A, multiply-high index after the
 * selector; 2 = B, A with the selector dropped at odds 256. */
enum { DRAW_S = 0, DRAW_A = 1, DRAW_B = 2 };

static void fill(unsigned char *out, HC128_State *rng, uint32_t height, int arm,
                 int reseed_blocks, int draw = DRAW_S)
{
    const blk_ent *C = g_cache.data();
    const uint32_t wsz   = height > CNA_V6_WINDOW_BLOCKS ? CNA_V6_WINDOW_BLOCKS : height;
    const uint32_t wbase = height - wsz;
    /* the only thing that differs between arms */
    const uint32_t odds  = g_odds[arm];
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    uint64_t idx[16][4];
    uint32_t ks[16][16];

    /* The selector is drawn whatever the odds, but the two branches do NOT
     * consume keystream the same way: HC128_U32 redraws on overflow and the
     * full-history range accepts less often than the window's (see the header
     * correction). ARM_HOT computes the index and throws it away, so it costs
     * exactly what ARM_SHIPPED costs in compute and is a floor for that arm,
     * and only that arm. */
    #define PICK() ({                                                        \
        uint64_t i_;                                                         \
        if (draw == DRAW_S)                                                  \
            i_ = (HC128_U32(rng, &ki, 256) < odds)                           \
               ? (uint64_t)HC128_U32(rng, &ki, height)                       \
               : (uint64_t)(wbase + HC128_U32(rng, &ki, wsz));               \
        else if (draw == DRAW_B && odds >= 256)                              \
            i_ = ((uint64_t)hc_word(rng, &ki) * height) >> 32;               \
        else                                                                 \
            i_ = (HC128_U32(rng, &ki, 256) < odds)                           \
               ? ((uint64_t)hc_word(rng, &ki) * height) >> 32                \
               : wbase + (((uint64_t)hc_word(rng, &ki) * wsz) >> 32);        \
        (arm == ARM_HOT) ? (uint64_t)0 : i_; })

    while (count < 4096)
    {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++)
        {
            for (size_t j = 0; j < 4; j++)
            {
                idx[k][j] = PICK();
                __builtin_prefetch(&C[idx[k][j]]);
            }
            HC128_NextKeys(rng);
            memcpy(ks[k], rng->keystream, sizeof(ks[k]));
        }
        for (size_t k = 0; k < 16; k++)
        {
            memcpy(msg,      C[idx[k][0]].hash, 32);
            memcpy(msg + 32, &C[idx[k][1]].timestamp, 8);
            memcpy(msg + 40, &C[idx[k][2]].diff_lo,   8);
            memcpy(msg + 48, &C[idx[k][3]].coins,     8);
            memcpy(msg + 56, &count, 8);
            for (size_t j = 0; j < 16; j++)
            {
                uint32_t w;
                memcpy(&w, msg + j * 4, 4);
                w ^= ks[k][j];
                memcpy(optr + j * 4, &w, 4);
            }
            optr += 64;
            count++;
        }
        /* Shipped behaviour is reseed_blocks == 1, a reseed every 16 messages
         * and so 256 of them. Larger values are the sweep: they say what the
         * reseeds cost, not what they are worth. */
        if (((count / 16) % (uint64_t)reseed_blocks) == 0)
        {
            unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
            unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
            HC128_Init(rng, key, iv);
        }
        /* the mid-point reseed the daemon does at count 2048, which
         * chain_fill.h's port leaves out */
        if (count == 2048)
        {
            for (int r = 0; r < 4; r++)
                memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072u - 16u), 16);
            HC128_EncryptMessage(rng, msg, optr, 64);
            HC128_Init(rng, optr, optr + 16);
        }
    }
    #undef PICK
}

static void cache_init(uint32_t height)
{
    g_cache.resize(height);
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    for (uint32_t i = 0; i < height; i++) {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        memcpy(g_cache[i].hash, &x, 8);
        g_cache[i].timestamp = x ^ i;
        g_cache[i].diff_lo   = x + i;
        g_cache[i].coins     = x * 3u;
    }
}

int main(int argc, char **argv)
{
    uint32_t height = (argc > 1) ? (uint32_t)strtoul(argv[1], NULL, 10) : 4500000u;
    double seconds  = (argc > 2) ? atof(argv[2]) : 6.0;
    std::vector<unsigned char> salt(SALT_BYTES);
    uint64_t cyc[NARMS] = {0}, n[NARMS] = {0};
    double ms[NARMS], hz;
    uint64_t gid = 0;
    int a;

    if (height < CNA_V6_WINDOW_BLOCKS + 1) height = CNA_V6_WINDOW_BLOCKS + 1;
    printf("v8 chain fill: is it memory bound or HC-128 bound?\n");
    printf("height %u, cache %.0f MB, window %.1f MB, %.0f s total\n",
           height, (double)height * sizeof(blk_ent) / 1048576.0,
           (double)CNA_V6_WINDOW_BLOCKS * sizeof(blk_ent) / 1048576.0, seconds);
    fflush(stdout);

    cache_init(height);
    hz = tsc_hz();

    /* ---- RESEED-PREREG.md step 1 ----
     *
     * The reseed interval at the shipped odds, 256 of 256, which the sweep
     * further down predates (it runs at 13). Arms are interleaved the same way
     * as the main loop, k = 1 first and last, one seed per group, so drift
     * lands on every arm alike. The run-ahead stays at one sixteen-count block
     * whatever k is, which is the form the daemon change would take. */
    /* ---- DRAW-PREREG.md step 1 ----
     *
     * The three draw candidates at the shipped v14 settings, k = 16 and odds
     * 256, interleaved S A B B A S with one seed per group. */
    if (argc > 3 && strcmp(argv[3], "draw") == 0)
    {
        static const char *const nm[3] = {"S, shipped", "A, mulhi", "B, mulhi no selector"};
        uint64_t rc[3] = {0}, rn[3] = {0};
        const double deadline = now_s() + seconds;
        int i;

        printf("draw candidates at k = 16, odds 256, interleaved, %.0f s\n", seconds);
        while (now_s() < deadline)
        {
            unsigned char seed[32];
            uint64_t x = gid++ * 0x9e3779b97f4a7c15ULL + 0xD4A3ULL;
            for (i = 0; i < 4; i++) {
                x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
                memcpy(seed + i * 8, &x, 8);
            }
            for (i = 0; i < 6; i++)
            {
                const int d = (i < 3) ? i : (5 - i);
                HC128_State rng;
                uint64_t t0, t1;
                { unsigned char s2_[32]; memcpy(s2_, seed, 32); s2_[31] ^= (unsigned char)(i + 1); HC128_Init(&rng, s2_, s2_ + 16); }  /* unique per fill: a repeated seed rereads warm cache */
                HC128_NextKeys(&rng);
                t0 = __rdtsc();
                fill(salt.data(), &rng, height, ARM_ALL, 16, d);
                t1 = __rdtsc();
                rc[d] += t1 - t0;
                rn[d]++;
            }
        }
        {
            const double base = (double)rc[0] / (double)rn[0] / hz * 1000.0;
            printf("\n  %-22s %10s %10s\n", "", "ms/fill", "vs S");
            for (i = 0; i < 3; i++)
            {
                const double m = (double)rc[i] / (double)rn[i] / hz * 1000.0;
                printf("  %-22s %10.4f %9.3fx\n", nm[i], m, m / base);
            }
            printf("\n  DRAW height=%u S=%.4f A=%.4f B=%.4f\n", height,
                   (double)rc[0] / (double)rn[0] / hz * 1000.0,
                   (double)rc[1] / (double)rn[1] / hz * 1000.0,
                   (double)rc[2] / (double)rn[2] / hz * 1000.0);
            printf("  %llu fills per arm\n", (unsigned long long)rn[0]);
        }
        return 0;
    }

    if (argc > 3 && strcmp(argv[3], "reseed") == 0)
    {
        static const int ks_[] = {1, 4, 8, 16, 256};
        enum { NK = sizeof(ks_) / sizeof(ks_[0]) };
        uint64_t rc[NK] = {0}, rn[NK] = {0};
        const double deadline = now_s() + seconds;
        int i;

        printf("reseed interval at odds 256, interleaved, %.0f s\n", seconds);
        while (now_s() < deadline)
        {
            unsigned char seed[32];
            uint64_t x = gid++ * 0x9e3779b97f4a7c15ULL + 0xBEEFULL;
            for (i = 0; i < 4; i++) {
                x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
                memcpy(seed + i * 8, &x, 8);
            }
            for (i = 0; i < 2 * NK; i++)
            {
                const int r = (i < NK) ? i : (2 * NK - 1 - i);
                HC128_State rng;
                uint64_t t0, t1;
                { unsigned char s2_[32]; memcpy(s2_, seed, 32); s2_[31] ^= (unsigned char)(i + 1); HC128_Init(&rng, s2_, s2_ + 16); }  /* unique per fill: a repeated seed rereads warm cache */
                HC128_NextKeys(&rng);
                t0 = __rdtsc();
                fill(salt.data(), &rng, height, ARM_ALL, ks_[r]);
                t1 = __rdtsc();
                rc[r] += t1 - t0;
                rn[r]++;
            }
        }
        printf("\n  %-6s %8s %10s %12s\n", "k", "inits", "ms/fill", "vs k=1");
        {
            const double base = (double)rc[0] / (double)rn[0] / hz * 1000.0;
            for (i = 0; i < NK; i++)
            {
                const double m = (double)rc[i] / (double)rn[i] / hz * 1000.0;
                printf("  %-6d %8d %10.4f %11.3fx\n", ks_[i], 256 / ks_[i] + 1, m, m / base);
            }
            printf("\n  RESEED height=%u", height);
            for (i = 0; i < NK; i++)
                printf(" k%d=%.4f", ks_[i], (double)rc[i] / (double)rn[i] / hz * 1000.0);
            printf("\n  %llu fills per arm\n", (unsigned long long)rn[0]);
        }
        return 0;
    }

    /* A-B-C-D-D-C-B-A within one process, one seed per group of eight, so a
     * drift in clock or temperature cancels for every arm rather than landing
     * on whichever ran last. */
    {
        const double deadline = now_s() + seconds;
        while (now_s() < deadline)
        {
            static const int ord[2 * NARMS] =
                {0,1,2,3,4,5,6, 6,5,4,3,2,1,0};
            unsigned char seed[32];
            uint64_t x = gid++ * 0x9e3779b97f4a7c15ULL + 0xFEEDULL;
            int i;
            for (i = 0; i < 4; i++) {
                x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
                memcpy(seed + i * 8, &x, 8);
            }
            for (i = 0; i < 2 * NARMS; i++)
            {
                HC128_State rng;
                uint64_t t0, t1;
                { unsigned char s2_[32]; memcpy(s2_, seed, 32); s2_[31] ^= (unsigned char)(i + 1); HC128_Init(&rng, s2_, s2_ + 16); }  /* unique per fill: a repeated seed rereads warm cache */
                HC128_NextKeys(&rng);
                t0 = __rdtsc();
                fill(salt.data(), &rng, height, ord[i], 1);
                t1 = __rdtsc();
                cyc[ord[i]] += t1 - t0;
                n[ord[i]]++;
            }
        }
    }

    for (a = 0; a < NARMS; a++)
        ms[a] = (double)cyc[a] / (double)n[a] / hz * 1000.0;

    printf("\n  %-18s %10s %10s\n", "", "ms/fill", "vs floor");
    for (a = 0; a < NARMS; a++)
        printf("  %-18s %10.4f %9.2fx\n", g_arm[a], ms[a], ms[a] / ms[ARM_HOT]);

    printf("\n  HC-128 compute floor      %.4f ms   %5.1f%% of the shipped fill\n",
           ms[ARM_HOT], ms[ARM_HOT] / ms[ARM_SHIPPED] * 100.0);
    printf("  memory, shipped           %.4f ms   %5.1f%%\n",
           ms[ARM_SHIPPED] - ms[ARM_HOT],
           (ms[ARM_SHIPPED] - ms[ARM_HOT]) / ms[ARM_SHIPPED] * 100.0);
    printf("  of which the 5%% full-history draws: %.4f ms  %5.1f%%\n",
           ms[ARM_SHIPPED] - ms[ARM_WINDOW],
           (ms[ARM_SHIPPED] - ms[ARM_WINDOW]) / ms[ARM_SHIPPED] * 100.0);

    /* What inside HC-128 the floor actually is. A fill reseeds every 16
     * messages, so it runs 256 HC128_Init per nonce plus one more at the
     * midpoint, and HC128_Init is the expensive half of this cipher: it runs
     * the full P and Q expansion before producing a usable word. If the floor
     * is mostly key setup rather than keystream, that matters, because setup is
     * the more regular of the two and the easier to pipeline in hardware. */
    {
        unsigned char seed[32], buf[64];
        HC128_State rng;
        uint64_t t0, t1;
        double init_ms, keys_ms;
        const int NI = 2570;       /* 10 fills' worth of reseeds */
        const int NK = 100000;
        int i;

        memset(seed, 0x5a, sizeof(seed));
        memset(buf, 0x33, sizeof(buf));
        HC128_Init(&rng, seed, seed + 16);

        t0 = __rdtsc();
        for (i = 0; i < NI; i++) HC128_Init(&rng, seed, seed + 16);
        t1 = __rdtsc();
        init_ms = (double)(t1 - t0) / hz * 1000.0 / 10.0;   /* per fill */

        t0 = __rdtsc();
        for (i = 0; i < NK; i++) HC128_NextKeys(&rng);
        t1 = __rdtsc();
        keys_ms = (double)(t1 - t0) / (double)NK / hz * 1000.0;

        printf("\n  inside the floor, per fill:\n");
        printf("    257 HC128_Init (reseed every 16 msgs)  %.4f ms  %5.1f%%\n",
               init_ms, init_ms / ms[ARM_SHIPPED] * 100.0);
        printf("    HC128_NextKeys, %.1f ns each, ~10,500   %.4f ms  %5.1f%%\n",
               keys_ms * 1e6, keys_ms * 10500.0,
               keys_ms * 10500.0 / ms[ARM_SHIPPED] * 100.0);
    }

    /* ---- can it be improved, and what would it cost ----
     *
     * Two levers fall out of the breakdown above, and both are measurable
     * rather than arguable.
     *
     * LEVER 1, the reseed interval. 257 reseeds are 67% of the fill. Sweeping
     * the interval says what the fill would cost without them. What it cannot
     * say is what they are worth: each one keys HC-128 from blocks already
     * read, so it is a point where the index stream stops being predictable
     * from the nonce alone. That is a security property and this harness does
     * not price it.
     *
     * LEVER 2, dependent reads. Memory is 5.7% because A1's run-ahead issues 64
     * prefetches at once, so 16,384 reads cost 12.2 ns each against a DRAM
     * latency near 80. Chaining the reads, each index derived from the bytes
     * at the previous one, removes that parallelism by construction and leaves
     * latency that nobody can optimise away. The knob is how many chains run
     * side by side: one chain is fully serial, sixteen is close to today.
     *
     * This probe is memory only, no cipher, so it isolates the latency a
     * dependent fill would have to pay on top of whatever cipher work it kept.
     */
    /* ---- what did A1's run-ahead do to the value of the window? ----
     *
     * The 100,000-block window exists because losing L3 residency cost 3.7x per
     * block when it was measured (April 2026, diag3). That measurement predates
     * the run-ahead. If prefetching 64 reads ahead hides the latency, the window
     * is worth much less than it was, and drawing from full history, which D5
     * needs, costs much less than the 2026 data implies.
     *
     * The comparison that means something is full-history over window-only
     * WITHIN each scheduling. Across schedulings the two forms also differ in
     * how they apply the keystream, and that cancels in a within-scheduling
     * ratio. */
    {
        const int order[8] = {0, 1, 2, 3, 3, 2, 1, 0};  /* (sched, arm) pairs below */
        const int sarm[4]  = {ARM_WINDOW, ARM_SHIPPED, ARM_ALL, ARM_HOT};
        double t_ser[4] = {0,0,0,0}, t_run[4] = {0,0,0,0};
        unsigned char seed[32];
        int r, i, reps = 12;

        memset(seed, 0x27, sizeof(seed));
        for (r = 0; r < reps; r++)
            for (i = 0; i < 8; i++)
            {
                const int a = sarm[order[i]];
                HC128_State rng;
                uint64_t c0, c1;

                HC128_Init(&rng, seed, seed + 16); HC128_NextKeys(&rng);
                c0 = __rdtsc(); fill_serial(salt.data(), &rng, height, a); c1 = __rdtsc();
                t_ser[order[i]] += (double)(c1 - c0);

                HC128_Init(&rng, seed, seed + 16); HC128_NextKeys(&rng);
                c0 = __rdtsc(); fill(salt.data(), &rng, height, a, 1); c1 = __rdtsc();
                t_run[order[i]] += (double)(c1 - c0);
            }
        for (i = 0; i < 4; i++) {
            t_ser[i] = t_ser[i] / (reps * 2) / hz * 1000.0;
            t_run[i] = t_run[i] / (reps * 2) / hz * 1000.0;
        }

        printf("\n  what A1's run-ahead did to the window's value:\n");
        printf("    %-16s %12s %12s\n", "", "pre-A1", "with run-ahead");
        {
            static const char *nm[4] = {"window only", "shipped 13/256", "all full history", "one hot entry"};
            for (i = 0; i < 4; i++)
                printf("    %-16s %12.4f %12.4f\n", nm[i], t_ser[i], t_run[i]);
            printf("    %-16s %11.2fx %11.2fx   <- what the window is worth\n",
                   "full / window", t_ser[2] / t_ser[0], t_run[2] / t_run[0]);
            printf("    %-16s %11.2fx %11.2fx\n",
                   "shipped / window", t_ser[1] / t_ser[0], t_run[1] / t_run[0]);
        }
    }

    {
        const int rs[] = {1, 2, 4, 16, 256};
        size_t ri;
        printf("\n  reseed interval, shipped is every 16 messages (256 of them):\n");
        printf("    %-10s %8s %10s %10s\n", "every", "reseeds", "ms/fill", "vs shipped");
        for (ri = 0; ri < sizeof(rs) / sizeof(rs[0]); ri++)
        {
            unsigned char seed[32];
            uint64_t t0, t1, acc = 0;
            int r;
            memset(seed, 0x11, sizeof(seed));
            for (r = 0; r < 24; r++)
            {
                HC128_State rng;
                HC128_Init(&rng, seed, seed + 16);
                HC128_NextKeys(&rng);
                t0 = __rdtsc();
                fill(salt.data(), &rng, height, ARM_SHIPPED, rs[ri]);
                t1 = __rdtsc();
                acc += t1 - t0;
            }
            {
                const double m = (double)acc / 24.0 / hz * 1000.0;
                printf("    %-10d %8d %10.4f %9.2fx\n", rs[ri] * 16, 256 / rs[ri],
                       m, m / ms[ARM_SHIPPED]);
            }
        }
    }

    {
        const int chains[] = {1, 2, 4, 8, 16, 64};
        size_t ci;
        printf("\n  what a dependent read chain would cost, 16,384 reads,\n");
        printf("  memory only, no cipher:\n");
        printf("    %-8s %10s %10s\n", "chains", "ms", "ns/read");
        for (ci = 0; ci < sizeof(chains) / sizeof(chains[0]); ci++)
        {
            const int nc = chains[ci];
            const int per = 16384 / nc;
            uint64_t t0, t1, acc = 0;
            double best = 1e9;
            int rep, c, s;
            std::vector<uint64_t> cur(nc);
            for (rep = 0; rep < 20; rep++)
            {
                for (c = 0; c < nc; c++)
                    cur[c] = ((uint64_t)c * 2654435761u + rep) % height;
                t0 = __rdtsc();
                for (s = 0; s < per; s++)
                    for (c = 0; c < nc; c++)
                    {
                        uint64_t h;
                        memcpy(&h, g_cache[cur[c]].hash, 8);
                        acc ^= h;
                        cur[c] = (h ^ (uint64_t)s) % height;
                    }
                t1 = __rdtsc();
                {
                    const double ms_ = (double)(t1 - t0) / hz * 1000.0;
                    if (ms_ < best) best = ms_;
                }
            }
            printf("    %-8d %10.4f %10.1f%s\n", nc, best, best * 1e6 / 16384.0,
                   acc == 0 ? " " : "");
        }
        printf("  (best of 20, so a scheduler interruption cannot inflate it)\n");
    }

    printf("\n  %llu fills per arm, 16,384 reads each.\n",
           (unsigned long long)n[0]);
    return 0;
}
