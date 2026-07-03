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
#define CN_SALT_MEMORY 262144
#define CNA_V6_WINDOW_BLOCKS     100000U        // recent-block window for sliding reads (~5.6 MB)
#define CNA_V6_FULL_HISTORY_ODDS 13U            // out of 256 (~5%) go to full history
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

cn_hash_context_t *cn_hash_context_create(void);
void cn_hash_context_free(cn_hash_context_t *context);

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

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
void cn_slow_hash_v13(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed);
void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
