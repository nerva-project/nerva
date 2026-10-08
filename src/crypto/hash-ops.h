// Copyright (c) 2018-2026, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#if !defined(__cplusplus)

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "int-util.h"
#include "warnings.h"

static inline void *padd(void *p, size_t i) {
  return (char *) p + i;
}

static inline const void *cpadd(const void *p, size_t i) {
  return (const char *) p + i;
}

PUSH_WARNINGS
DISABLE_VS_WARNINGS(4267)
static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "size_t must be 4 or 8 bytes long");
static inline void place_length(uint8_t *buffer, size_t bufsize, size_t length) {
  if (sizeof(size_t) == 4) {
    *(uint32_t *) padd(buffer, bufsize - 4) = swap32be(length);
  } else {
    *(uint64_t *) padd(buffer, bufsize - 8) = swap64be(length);
  }
}
POP_WARNINGS

#pragma pack(push, 1)
union hash_state {
  uint8_t b[200];
  uint64_t w[25];
};
#pragma pack(pop)
static_assert(sizeof(union hash_state) == 200, "Invalid structure size");

void hash_permutation(union hash_state *state);
void hash_process(union hash_state *state, const uint8_t *buf, size_t count);

#endif

enum {
  HASH_SIZE = 32,
  HASH_DATA_AREA = 136
};

void hash_extra_blake(const void *data, size_t length, char *hash);
void hash_extra_groestl(const void *data, size_t length, char *hash);
void hash_extra_jh(const void *data, size_t length, char *hash);
void hash_extra_skein(const void *data, size_t length, char *hash);

void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash);

void cn_fast_hash(const void *data, size_t length, char *hash);

#define CN_SCRATCHPAD_MEMORY    1048576         // 1 MB — used by v9–v12
#define CN_SCRATCHPAD_MEMORY_V13 (8*1024*1024)  // 8 MB — v13: a bigger pad keeps hashing memory-bound
                                                // (1 CPU = 1 vote) and costlier to put on an ASIC
/* CNA v8 (HF14) pad size. v8's translation units redefine
 * CN_SCRATCHPAD_MEMORY to this. */
#define CN_SCRATCHPAD_MEMORY_V8 (1024*1024)

/* v8 uses a fixed init_size_blk instead of drawing it per nonce: the width
 * changes timing but not the number of AES operations. */
#define CN_V8_INIT_SIZE_BLK 8

/* v8 fetches its chain salt from inside the hash, after the AES fill. The
 * callback gets a 32-byte seed folded from all eight lanes of the fill's final
 * state, writes the salt, and returns the per-nonce draws, which come from the
 * keystream the salt fetch leaves behind. */
typedef struct {
    uint16_t xx;
    uint16_t yy;
    size_t   iters;
} cn_v8_draw_t;

typedef void (*cn_v8_salt_fn)(void *user, const unsigned char seed[32],
                              char *salt_out, cn_v8_draw_t *draw_out);

#define CN_SALT_MEMORY 262144

/* v13's window of recent blocks (~5.6 MB) for the chain fill. v14's odds are
 * 256, so v14 never reads it; db_lmdb.cpp asserts that. */
#define CNA_V6_WINDOW_BLOCKS_V13 100000U
#define CNA_V6_FULL_HISTORY_ODDS 13U            // out of 256 (~5%) go to full history

/* v14 draws every chain-fill pick from full history. v13 keeps the value
 * above because it validates mainnet. */
#define CNA_V6_FULL_HISTORY_ODDS_V14 256U       // every pick draws from full history

/* Sixteen-message blocks the chain fill runs between HC-128 reseeds; each
 * reseed keys HC-128 from salt already written. v13 reseeds after every block
 * and validates mainnet; v14 after every 16th. Must divide 256 so the last
 * block still reseeds. */
#define CNA_V6_RESEED_BLOCKS 1U
#define CNA_V6_RESEED_BLOCKS_V14 16U
#define CN_RANDOM_VALUES 32

enum {
  NOP = 0,
  ADD,
  SUB,
  XOR,
  OR,
  AND,
  COMP,
  EQ
};

typedef struct cn_random_values
{
  uint8_t operators[CN_RANDOM_VALUES];
  uint32_t indices[CN_RANDOM_VALUES];
  int8_t values[CN_RANDOM_VALUES];
} cn_random_values_t;

/* Backing-page tier of a scratchpad/salt allocation. Stored in the
 * *_is_mapped context fields; ordered so any tier >= CN_PAGES_PLAIN_MMAP
 * is released with munmap/VirtualFree and 0 keeps the legacy meaning
 * "release with free()". Higher tier = fewer TLB misses on the 8 MB pad. */
#define CN_PAGES_MALLOC     0   /* plain malloc, base pages (worst case)   */
#define CN_PAGES_PLAIN_MMAP 1   /* mmap, base pages                        */
#define CN_PAGES_THP        2   /* mmap + THP/superpage hint (best effort) */
#define CN_PAGES_HUGE       3   /* explicit hugetlb / large pages          */

/* Human-readable name for a CN_PAGES_* tier (miner logs / status). */
const char *cn_page_tier_name(int tier);

/* The tier a mapping actually ended up on, which on Linux can be worse than the
 * one that was asked for. Call it after the pages have been faulted in. */
int cn_page_tier_actual(const void *p, size_t size, int requested_tier);

typedef struct cn_hash_context
{
  /* Software-AES path always has its context allocated so the runtime
   * dispatcher can fall back to it without a hash-time allocation. */
  void *oaes_ctx;
  uint8_t *scratchpad;       // 1 MB  — v9–v12
  int scratchpad_is_mapped;
  uint8_t *cna_scratchpad;   // 8 MB  — v13 (CryptoNight-Adaptive v6)
  int cna_scratchpad_is_mapped;
  char *salt;
  int salt_is_mapped;
  cn_random_values_t random_values;
  uint64_t cached_height;
} cn_hash_context_t;

/* The actual tier of the buffer that carries the hashrate at a fork version,
 * as the kernel backed it rather than as it was requested. */
int cn_page_tier_for_version(const cn_hash_context_t *ctx, uint8_t major_version);

cn_hash_context_t *cn_hash_context_create(void);
void cn_hash_context_free(cn_hash_context_t *context);

/* Per-thread switch to fill the pad with streaming stores. Off by default:
 * v8's pad stays in cache, where streaming stores are slower. Kept for
 * benchmarks. The hash is identical either way. Affects every version that
 * fills through expand_key(): v8, v11, v10 and v9. */
int cn_nt_fill_enable(int on);
int cn_nt_fill(void);

/* Returns 1 if the CPU supports the AES-NI instruction set, 0 otherwise.
 * Wraps crypto::has_aesni() so it's callable from C TUs. */
int crypto_has_aesni(void);

/* Returns 1 if cn_slow_hash will dispatch to the hardware-AES implementation,
 * 0 if it will fall back to software AES. Useful for startup logging and for
 * the optional HW-vs-SW self-test. */
int cn_hardware_aes_supported(void);

/* Hashes a fixed input with both the HW and SW paths and compares. Returns 1
 * on success or when the HW path isn't built/active (nothing to verify), and
 * 0 if HW and SW disagree, which would mean wrong PoW. */
int cn_slow_hash_self_test(void);
/* Known-answer vectors for v10, v11, v13 and v14. Runs on every platform,
 * unlike cn_slow_hash_self_test which needs hardware AES to compare against.
 * Returns 1 on pass. */
int cn_slow_hash_known_answer_test(void);

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
/* v14 (CNA v8): v11's core at a 1 MB pad without salt_pad, with a
 * caller-supplied salt (benchmarks and self-tests). The hash depends on xx, yy
 * and iters only through (xx-1)*yy + iters. Named for the hard fork, not the
 * CNA generation. */
void cn_slow_hash_v14(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
/* Consensus entry for v8: salt fetched inside the hash via salt_fn, seeded
 * from the AES fill. iters/xx/yy come back through the callback. */
void cn_slow_hash_v14_chain(cn_hash_context_t *context, const void *data, size_t length, char *hash, uint8_t init_size_blk, cn_v8_salt_fn salt_fn, void *salt_user);
void cn_slow_hash_v13(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed);
void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
