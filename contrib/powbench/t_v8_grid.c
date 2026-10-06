/* Hardware AES against software AES for CNA v8, over the whole consensus
 * domain, for the shipped hash and for the D1 candidate beside it.
 *
 * WHY THIS EXISTS. cn_slow_hash_self_test compares the two v8 arms at exactly
 * one point, (xx, yy, iters) = (3, 3, 64), which is not even in the range the
 * chain draws from: cryptonote_tx_utils.cpp draws xx and yy from [4, 8] and
 * iters from [0, 63]. So the arm every miner runs and the arm an ARM or an
 * older x86 runs have been compared on one input consensus never asks for.
 * That is a gap in v8 as it stands today, independent of D1.
 *
 * The two arms are separate copies of the core, not one body behind a macro,
 * and they differ in source on purpose: r2 aliases &c in the hardware arm and
 * &b in the software arm. r2's only consumer is the sweep, so this is precisely
 * the part D1 proposes to delete, and the agreement it produces is the thing
 * most worth checking before and after.
 *
 * WHAT IT CHECKS, in order of what a failure would mean:
 *
 *   1. v8 shipped:   hw == sw over all 5 x 5 x 64 = 1600 consensus draws.
 *   2. v8 no-sweep:  the same 1600, for the D1 candidate.
 *   3. v8 != no-sweep on every case, so a pass in 2 cannot come from the
 *      variant having been compiled without CN_V8_NO_SWEEP by accident.
 *   4. the chain entry points, both variants, where the arms must also agree
 *      on the 32-byte seed handed to the salt callback, since that is consensus
 *      input to HC-128 and comparing only the final hash covers it indirectly.
 *   5. a handful of out-of-domain (xx, yy), including xx = 1 and yy = 1 where
 *      the sweep loops do not execute at all, so a widened draw range later
 *      does not walk into an untested corner.
 *
 * Salt and random_values are varied per case from splitmix64, not left zeroed,
 * because a zero salt is the one input where the sweeps have least to do.
 *
 * Build: sh contrib/powbench/build-v8-grid.sh
 * Exit status is 0 only if every check passes.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <cpuid.h>

#include "hash-ops.h"

/* The four cores, called directly rather than through the dispatchers: the
 * point is to run both arms on one machine, which the dispatcher will not do.
 * The ns pair is built from contrib/powbench/v8ns-hw.c and v8ns-sw.c. */
extern void cn_slow_hash_v14_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14_sw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14ns_hw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
extern void cn_slow_hash_v14ns_sw(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);

extern void cn_slow_hash_v14_chain_hw(cn_hash_context_t *, const void *, size_t, char *, uint8_t, cn_v8_salt_fn, void *);
extern void cn_slow_hash_v14_chain_sw(cn_hash_context_t *, const void *, size_t, char *, uint8_t, cn_v8_salt_fn, void *);
extern void cn_slow_hash_v14ns_chain_hw(cn_hash_context_t *, const void *, size_t, char *, uint8_t, cn_v8_salt_fn, void *);
extern void cn_slow_hash_v14ns_chain_sw(cn_hash_context_t *, const void *, size_t, char *, uint8_t, cn_v8_salt_fn, void *);

/* slow-hash.c calls this; the real one is in a C++ TU that is not linked here.
 * Same answer, so the build behaves as the daemon's does. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

typedef void (*v8_fn)(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
typedef void (*v8_chain_fn)(cn_hash_context_t *, const void *, size_t, char *, uint8_t, cn_v8_salt_fn, void *);

static uint64_t sm64(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* FNV-1a, so a run reports one number per arm that a reader can compare across
 * machines without the whole 1600-case table. */
static void fnv(uint64_t *h, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    size_t i;
    for (i = 0; i < n; i++) { *h ^= b[i]; *h *= 0x100000001b3ULL; }
}

/* Everything a case feeds the hash. Rebuilt from the case seed alone, so the
 * two arms and the two variants see byte-identical state. */
typedef struct { char input[76]; uint16_t xx, yy; uint32_t iters; uint64_t seed; } gcase_t;

static void case_init(const gcase_t *g, cn_hash_context_t *ctx, char input[76])
{
    uint64_t s = g->seed;
    size_t i;

    for (i = 0; i < 76; i++)
        input[i] = (char)(sm64(&s) & 0xff);

    for (i = 0; i < CN_SALT_MEMORY; i += 8)
    {
        uint64_t v = sm64(&s);
        memcpy(ctx->salt + i, &v, 8);
    }

    /* the same shapes db_lmdb.cpp produces: operators are a byte >> 5, so
     * [0, 7]; indices are reduced mod the pad; values are a signed byte. */
    for (i = 0; i < CN_RANDOM_VALUES; i++)
    {
        uint64_t v = sm64(&s);
        ctx->random_values.operators[i] = (uint8_t)((v & 0xff) >> 5);
        ctx->random_values.values[i] = (int8_t)((v >> 8) & 0xff);
        ctx->random_values.indices[i] = (uint32_t)((v >> 16) % CN_SCRATCHPAD_MEMORY_V8);
    }
}

/* Fixed draws and a varying salt, so the chain cases exercise the callback hook
 * without the callback being the thing under test. user receives the 32-byte
 * seed the hash handed in, which the two arms must agree on. */
static uint64_t g_chain_salt_seed = 0;

static void chain_salt(void *user, const unsigned char seed[32], char *salt_out, cn_v8_draw_t *draw_out)
{
    uint64_t s = g_chain_salt_seed;
    size_t i;
    if (user != NULL && seed != NULL)
        memcpy(user, seed, 32);
    for (i = 0; i < CN_SALT_MEMORY; i += 8)
    {
        uint64_t v = sm64(&s);
        memcpy(salt_out + i, &v, 8);
    }
    if (draw_out != NULL)
    {
        draw_out->xx = (uint16_t)(4 + (g_chain_salt_seed % 5));
        draw_out->yy = (uint16_t)(4 + ((g_chain_salt_seed / 5) % 5));
        draw_out->iters = (size_t)(g_chain_salt_seed % 64);
    }
}

/* One (xx, yy, iters) case against one pair of arms. Returns 0 on agreement.
 * out receives the hardware digest, which check 3 compares across variants. */
static int run_pair(cn_hash_context_t *ctx, const gcase_t *g, v8_fn hw, v8_fn sw,
                    uint64_t *dhw, uint64_t *dsw, char out[HASH_SIZE])
{
    char a[HASH_SIZE], b[HASH_SIZE], in[76];

    case_init(g, ctx, in);
    hw(ctx, in, sizeof(in), a, g->iters, CN_V8_INIT_SIZE_BLK, g->xx, g->yy);

    /* rebuilt, not reused: the hash writes through the salt it was given, so
     * the software arm has to start from the same bytes rather than from what
     * the hardware arm left behind. That is the trap the sweep A/B harness hit
     * and it reads as agreement when it is not. */
    case_init(g, ctx, in);
    sw(ctx, in, sizeof(in), b, g->iters, CN_V8_INIT_SIZE_BLK, g->xx, g->yy);

    fnv(dhw, a, HASH_SIZE);
    fnv(dsw, b, HASH_SIZE);
    memcpy(out, a, HASH_SIZE);
    return memcmp(a, b, HASH_SIZE) != 0;
}

static int run_chain_pair(cn_hash_context_t *ctx, const gcase_t *g,
                          v8_chain_fn hw, v8_chain_fn sw, unsigned *seed_bad)
{
    char a[HASH_SIZE], b[HASH_SIZE], in[76];
    uint8_t sa[32], sb[32];

    g_chain_salt_seed = g->seed;

    case_init(g, ctx, in);
    memset(sa, 0, 32);
    hw(ctx, in, sizeof(in), a, CN_V8_INIT_SIZE_BLK, chain_salt, sa);

    case_init(g, ctx, in);
    memset(sb, 0, 32);
    sw(ctx, in, sizeof(in), b, CN_V8_INIT_SIZE_BLK, chain_salt, sb);

    if (memcmp(sa, sb, 32) != 0) (*seed_bad)++;
    return memcmp(a, b, HASH_SIZE) != 0;
}

int main(void)
{
    cn_hash_context_t *ctx;
    gcase_t g;
    uint16_t xx, yy;
    uint32_t it;
    unsigned n = 0, bad_v8 = 0, bad_ns = 0, same = 0, bad_chain = 0, seed_bad = 0;
    uint64_t d_v8_hw = 0xcbf29ce484222325ULL, d_v8_sw = 0xcbf29ce484222325ULL;
    uint64_t d_ns_hw = 0xcbf29ce484222325ULL, d_ns_sw = 0xcbf29ce484222325ULL;
    char h_v8[HASH_SIZE], h_ns[HASH_SIZE];
    int i;

    /* The out-of-domain corners. xx = 1 and yy = 1 skip the sweep loops
     * entirely, which is the shape D1 makes permanent. */
    static const uint16_t edge[][2] = { {1,1}, {1,8}, {8,1}, {2,2}, {3,3}, {9,9}, {16,4}, {4,16} };

    printf("CNA v8, hardware AES against software AES over the consensus domain\n");
    printf("xx and yy in [4, 8], iters in [0, 63], salt and random_values varied per case\n\n");

    if (!cn_hardware_aes_supported())
    {
        printf("NO HARDWARE AES on this CPU. Both arms would be the software one,\n"
               "so this run would prove nothing. Refusing.\n");
        return 1;
    }

    ctx = cn_hash_context_create();
    if (ctx == NULL) { printf("context allocation failed\n"); return 1; }

    /* the dispatchers allocate the salt lazily, so get one hash in first */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14(ctx, "warm", 4, h_v8, 0, CN_V8_INIT_SIZE_BLK, 4, 4);
    if (ctx->salt == NULL) { printf("salt allocation failed\n"); return 1; }

    for (xx = 4; xx <= 8; xx++)
        for (yy = 4; yy <= 8; yy++)
            for (it = 0; it < 64; it++)
            {
                g.xx = xx; g.yy = yy; g.iters = it;
                g.seed = ((uint64_t)xx << 40) ^ ((uint64_t)yy << 24) ^ it ^ 0xa5a5a5a5ULL;

                bad_v8 += run_pair(ctx, &g, cn_slow_hash_v14_hw, cn_slow_hash_v14_sw,
                                   &d_v8_hw, &d_v8_sw, h_v8);
                bad_ns += run_pair(ctx, &g, cn_slow_hash_v14ns_hw, cn_slow_hash_v14ns_sw,
                                   &d_ns_hw, &d_ns_sw, h_ns);
                if (memcmp(h_v8, h_ns, HASH_SIZE) == 0) same++;
                n++;
            }

    printf("1. v8 shipped,  hw == sw over %u cases: %s", n, bad_v8 ? "FAIL" : "PASS");
    if (bad_v8) printf("  (%u mismatches)", bad_v8);
    printf("\n");

    printf("2. v8 no-sweep, hw == sw over %u cases: %s", n, bad_ns ? "FAIL" : "PASS");
    if (bad_ns) printf("  (%u mismatches)", bad_ns);
    printf("\n");

    printf("3. no-sweep differs from shipped on every case: %s", same ? "FAIL" : "PASS");
    if (same) printf("  (%u identical, so the variant may not be built with CN_V8_NO_SWEEP)", same);
    printf("\n");

    /* 4. the chain entry, where the seed must agree as well as the hash */
    for (i = 0; i < 32; i++)
    {
        g.xx = 0; g.yy = 0; g.iters = 0;
        g.seed = 0x5eed0000ULL + (uint64_t)i;
        bad_chain += run_chain_pair(ctx, &g, cn_slow_hash_v14_chain_hw, cn_slow_hash_v14_chain_sw, &seed_bad);
        bad_chain += run_chain_pair(ctx, &g, cn_slow_hash_v14ns_chain_hw, cn_slow_hash_v14ns_chain_sw, &seed_bad);
    }
    printf("4. chain entry, both variants, 64 pairs:  %s", bad_chain ? "FAIL" : "PASS");
    if (bad_chain) printf("  (%u hash mismatches)", bad_chain);
    printf("\n   fill seed handed to the callback agrees: %s\n", seed_bad ? "FAIL" : "PASS");

    /* 5. out of the drawn range, including the loops not running at all */
    {
        unsigned bad_edge = 0, ne = 0;
        size_t e;
        for (e = 0; e < sizeof(edge) / sizeof(edge[0]); e++)
            for (it = 0; it < 4; it++)
            {
                uint64_t throw_hw = 0, throw_sw = 0;
                g.xx = edge[e][0]; g.yy = edge[e][1];
                g.iters = it * 21;
                g.seed = 0xed6e0000ULL + (uint64_t)(e * 4 + it);
                bad_edge += run_pair(ctx, &g, cn_slow_hash_v14_hw, cn_slow_hash_v14_sw,
                                     &throw_hw, &throw_sw, h_v8);
                bad_edge += run_pair(ctx, &g, cn_slow_hash_v14ns_hw, cn_slow_hash_v14ns_sw,
                                     &throw_hw, &throw_sw, h_ns);
                ne += 2;
            }
        printf("5. out-of-domain xx and yy, %u pairs:     %s", ne, bad_edge ? "FAIL" : "PASS");
        if (bad_edge) printf("  (%u mismatches)", bad_edge);
        printf("\n");
        bad_v8 += bad_edge;
    }

    /* 6. after D1 the three loops have the same body, so only their total
     * length can matter. If that is true, every (xx, yy, iters) with the same
     * (xx - 1) * yy + iters must give the no-sweep hash the same answer, and
     * must give the shipped hash different ones, since the sweeps read xx, yy
     * and iters individually. Checked rather than read off the source, because
     * it is the claim that decides whether the daemon should keep drawing
     * three numbers after D1. */
    {
        /* each row is {xx, yy, iters}; rows within a group total the same */
        static const uint16_t eq[][3] = {
            { 4, 4,  0 }, { 1, 1, 12 }, { 1, 8, 12 }, { 2, 4,  8 }, { 3, 6,  0 },
        };
        static const uint16_t eq2[][3] = {
            { 8, 8, 63 }, { 1, 1,119 }, { 5, 8, 87 }, { 4, 5, 104 },
        };
        unsigned bad_eq = 0, split_ok = 1;
        char ref_ns[HASH_SIZE], ref_v8[HASH_SIZE], cur_ns[HASH_SIZE], cur_v8[HASH_SIZE];
        uint64_t t1 = 0, t2 = 0;
        size_t e;
        int grp;

        for (grp = 0; grp < 2; grp++)
        {
            const uint16_t (*rows)[3] = grp ? eq2 : eq;
            size_t nrows = grp ? sizeof(eq2) / sizeof(eq2[0]) : sizeof(eq) / sizeof(eq[0]);
            for (e = 0; e < nrows; e++)
            {
                /* one fixed seed across the group: the input, salt and
                 * random_values must be identical or the comparison is empty */
                g.seed = grp ? 0xe900beefULL : 0xe900cafeULL;
                g.xx = rows[e][0]; g.yy = rows[e][1]; g.iters = rows[e][2];
                run_pair(ctx, &g, cn_slow_hash_v14ns_hw, cn_slow_hash_v14ns_sw, &t1, &t2, cur_ns);
                run_pair(ctx, &g, cn_slow_hash_v14_hw, cn_slow_hash_v14_sw, &t1, &t2, cur_v8);
                if (e == 0)
                {
                    memcpy(ref_ns, cur_ns, HASH_SIZE);
                    memcpy(ref_v8, cur_v8, HASH_SIZE);
                }
                else
                {
                    if (memcmp(ref_ns, cur_ns, HASH_SIZE) != 0) bad_eq++;
                    if (memcmp(ref_v8, cur_v8, HASH_SIZE) == 0) split_ok = 0;
                }
            }
        }

        printf("6. no-sweep depends only on (xx-1)*yy+iters:  %s", bad_eq ? "FAIL" : "PASS");
        if (bad_eq) printf("  (%u rows disagreed within a group)", bad_eq);
        printf("\n   shipped v8 still separates those draws:    %s\n", split_ok ? "PASS" : "FAIL");
        bad_ns += bad_eq;
        if (!split_ok) bad_v8++;
    }

    printf("\ndigests over the %u in-domain cases, to compare across machines:\n", n);
    printf("  v8 shipped   hw %016llx  sw %016llx\n",
           (unsigned long long)d_v8_hw, (unsigned long long)d_v8_sw);
    printf("  v8 no-sweep  hw %016llx  sw %016llx\n",
           (unsigned long long)d_ns_hw, (unsigned long long)d_ns_sw);

    cn_hash_context_free(ctx);
    return (bad_v8 || bad_ns || same || bad_chain || seed_bad) ? 1 : 0;
}
