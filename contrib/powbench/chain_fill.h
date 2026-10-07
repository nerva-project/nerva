#pragma once
// The per-nonce chain salt, ported from BlockchainLMDB::get_cna_v5_data and
// get_cna_v6_data (src/blockchain_db/lmdb/db_lmdb.cpp).
//
// WHY THIS IS HERE. The benchmark used to measure cn_slow_hash only, and that
// made the CPU column about 4x faster than a real miner on v5: 26k H/s here
// against 6.38k measured on the same 7950X. The missing work is this fill, a
// fixed ~1.5 ms per nonce, which is most of a v5 nonce and almost none of a
// v7 one. Leaving it out flattered v5 specifically.
//
// WHY IT IS CHARGED TO THE CPU ONLY. A GPU rig does not pay this on the
// hashing device. 256 KB per nonce is ~62 MB/s of PCIe at a few hundred H/s
// and well under one host core to generate, so the host feeds it. A CPU miner
// pays it on the same thread that does the hashing. That asymmetry is real and
// is the point of modelling it.
//
// WHY PORTED RATHER THAN A MEASURED CONSTANT. The cost is dominated by DRAM
// latency into the block cache and by HC-128 throughput, both of which differ
// per machine. A constant timed on one box would be wrong on the next.
//
// NOT MODELLED: LMDB itself. build_block_cache() is a no-op once warm, and the
// reads go to the in-RAM cache, so a resident array is the right model.
#include <stdint.h>
#include <string.h>
#include <vector>
#include "hc128.h"

// One entry per block: crypto::hash + timestamp + diff_lo + coins.
// 56 bytes, matching struct block_cache_data in db_lmdb.h.
#pragma pack(push, 1)
struct blk_cache_ent { uint8_t hash[32]; uint64_t timestamp, diff_lo, coins; };
#pragma pack(pop)

// Mainnet height at the time of measurement. The cache grows with the chain,
// so this is part of the cost and is deliberately not a small round number.
#define CHAIN_HEIGHT        4414470u
#define CNA_V6_WINDOW_BLOCKS     100000u
#define CNA_V6_FULL_HISTORY_ODDS 13u
/* D3 raised this to 256 for v14 only, 5d1e889. gen 11 (v8 as shipped)
 * uses 256; gens 5 to 10 keep 13 so historical rows stay comparable. */
static uint32_t g_fill_odds = CNA_V6_FULL_HISTORY_ODDS;
#define SALT_BYTES          262144

static std::vector<blk_cache_ent> g_blk_cache;
static void chain_cache_init() {
    if (!g_blk_cache.empty()) return;
    g_blk_cache.resize(CHAIN_HEIGHT);
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    for (uint32_t i = 0; i < CHAIN_HEIGHT; i++) {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        memcpy(g_blk_cache[i].hash, &x, 8);
        g_blk_cache[i].timestamp = x ^ i;
        g_blk_cache[i].diff_lo   = x + i;
        g_blk_cache[i].coins     = x * 3u;
    }
}

// get_cna_v5_data: every index drawn uniformly over the whole history, so the
// reads land anywhere in ~247 MB and are DRAM-latency bound.
static void chain_fill_v5(unsigned char *out, HC128_State *rng)
{
    const blk_cache_ent *C = g_blk_cache.data();
    const uint32_t height = CHAIN_HEIGHT;
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    while (count < 2048) {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) {
            memcpy(msg,      C[HC128_U32(rng, &ki, height)].hash, 32);
            memcpy(msg + 32, &C[HC128_U32(rng, &ki, height)].timestamp, 8);
            memcpy(msg + 40, &C[HC128_U32(rng, &ki, height)].diff_lo,   8);
            memcpy(msg + 48, &C[HC128_U32(rng, &ki, height)].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
        unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
        HC128_Init(rng, key, iv);
    }
    for (int r = 0; r < 4; r++)
        memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072u - 16u), 16);
    HC128_EncryptMessage(rng, msg, optr, 64);
    HC128_Init(rng, optr, optr + 16);
    while (count < 4096) {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) {
            memcpy(msg,      C[HC128_U32(rng, &ki, height)].hash, 32);
            memcpy(msg + 32, &C[HC128_U32(rng, &ki, height)].timestamp, 8);
            memcpy(msg + 40, &C[HC128_U32(rng, &ki, height)].diff_lo,   8);
            memcpy(msg + 48, &C[HC128_U32(rng, &ki, height)].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
        unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
        HC128_Init(rng, key, iv);
    }
}

// get_cna_v6_data: 95% of picks come from the last CNA_V6_WINDOW_BLOCKS
// (~5.6 MB, L3-resident), the rest from full history. Trades DRAM latency for
// an extra HC-128 draw per pick, which is why v6's fill costs more compute and
// less memory than v5's.
static void chain_fill_v6(unsigned char *out, HC128_State *rng)
{
    const blk_cache_ent *C = g_blk_cache.data();
    const uint32_t height = CHAIN_HEIGHT;
    const uint32_t wsz  = height > CNA_V6_WINDOW_BLOCKS ? CNA_V6_WINDOW_BLOCKS : height;
    const uint32_t wbase = height - wsz;
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    #define PICK() ( (HC128_U32(rng, &ki, 256) < g_fill_odds) \
                     ? HC128_U32(rng, &ki, height)                          \
                     : (wbase + HC128_U32(rng, &ki, wsz)) )
    while (count < 4096) {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) {
            memcpy(msg,      C[PICK()].hash, 32);
            memcpy(msg + 32, &C[PICK()].timestamp, 8);
            memcpy(msg + 40, &C[PICK()].diff_lo,   8);
            memcpy(msg + 48, &C[PICK()].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
        unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
        HC128_Init(rng, key, iv);
    }
    #undef PICK
}

/* The RUN-AHEAD fill, 4fe2a39, which is what consensus actually runs.
 *
 * ADDED 2026-10-07. The serial loop above is the reference arm in db_lmdb.cpp
 * and was all this header modelled, which made every CPU column here the cost
 * of code the daemon does not execute. It did not matter much at odds 13, when
 * 95% of reads were window hits with nothing to prefetch. D3 took the odds to
 * 256 and it matters a great deal: the whole point of issuing all 64 indices
 * before reading any of them is to overlap DRAM latency, and at odds 256 every
 * read is a DRAM miss.
 *
 * Structure mirrors cna_v6_data_run_ahead: pick and prefetch all 64 indices for
 * a block, capture the keystream for all 16 messages, then do the gathers. */
static void chain_fill_v6_run(unsigned char *out, HC128_State *rng)
{
    const blk_cache_ent *C = g_blk_cache.data();
    const uint32_t height = CHAIN_HEIGHT;
    const uint32_t wsz  = height > CNA_V6_WINDOW_BLOCKS ? CNA_V6_WINDOW_BLOCKS : height;
    const uint32_t wbase = height - wsz;
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    uint64_t idx[16][4];
    uint32_t ks[16][16];

    while (count < 4096) {
        HC128_NextKeys(rng);
        for (size_t k = 0; k < 16; k++) {
            for (size_t j = 0; j < 4; j++) {
                idx[k][j] = (HC128_U32(rng, &ki, 256) < g_fill_odds)
                              ? HC128_U32(rng, &ki, height)
                              : (wbase + HC128_U32(rng, &ki, wsz));
#if defined(__GNUC__)
                __builtin_prefetch(&C[idx[k][j]]);
#endif
            }
            HC128_NextKeys(rng);
            memcpy(ks[k], rng->keystream, sizeof(ks[k]));
        }
        for (size_t k = 0; k < 16; k++) {
            memcpy(msg,      C[idx[k][0]].hash, 32);
            memcpy(msg + 32, &C[idx[k][1]].timestamp, 8);
            memcpy(msg + 40, &C[idx[k][2]].diff_lo,   8);
            memcpy(msg + 48, &C[idx[k][3]].coins,     8);
            memcpy(msg + 56, &count, 8);
            for (size_t j = 0; j < 16; j++) {
                uint32_t w;
                memcpy(&w, msg + j * 4, 4);
                w ^= ks[k][j];
                memcpy(optr + j * 4, &w, 4);
            }
            optr += 64;
            count++;
        }
        unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
        unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
        HC128_Init(rng, key, iv);
    }
}

/* false reverts to the serial reference loop, for measuring what the
 * run-ahead is worth at a given odds. gpubench: pass "serialfill". */
static bool g_fill_runahead = true;

/* The run-ahead must produce exactly what the serial loop produces. db_lmdb.cpp
 * enforces that in the daemon; this is the same check for this harness, because
 * a reordering that changed keystream consumption would be a faster fill that
 * computes something else, which is the one failure that would quietly flatter
 * every CPU column here. */
static bool chain_fill_self_check(void)
{
    unsigned char a[SALT_BYTES], b[SALT_BYTES], seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 3);
    for (int pass = 0; pass < 2; pass++) {
        g_fill_odds = pass ? 256u : CNA_V6_FULL_HISTORY_ODDS;
        HC128_State r1, r2;
        HC128_Init(&r1, seed, seed + 16); HC128_NextKeys(&r1);
        HC128_Init(&r2, seed, seed + 16); HC128_NextKeys(&r2);
        chain_fill_v6(a, &r1);
        chain_fill_v6_run(b, &r2);
        if (memcmp(a, b, SALT_BYTES) != 0) return false;
    }
    g_fill_odds = CNA_V6_FULL_HISTORY_ODDS;
    return true;
}

// One per-nonce fill, seeded from the nonce the way get_block_longhash does
// (blob hash into HC128_Init, then NextKeys before first use).
static void chain_fill(unsigned char *salt, int gen, uint64_t gid)
{
    unsigned char seed[32];
    uint64_t x = gid * 0x9e3779b97f4a7c15ULL + 0xFEEDULL;
    for (int i = 0; i < 4; i++) {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        memcpy(seed + i * 8, &x, 8);
    }
    HC128_State rng;
    HC128_Init(&rng, seed, seed + 16);
    HC128_NextKeys(&rng);
    g_fill_odds = (gen == 11) ? 256u : CNA_V6_FULL_HISTORY_ODDS;  /* 12 = D1 alone */
    if (gen == 5) chain_fill_v5(salt, &rng);
    else if (g_fill_runahead) chain_fill_v6_run(salt, &rng);
    else          chain_fill_v6(salt, &rng);
}
