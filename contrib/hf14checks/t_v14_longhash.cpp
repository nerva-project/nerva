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

// End-to-end known-answer test for get_block_longhash_v14: the code in
// cryptonote_tx_utils.cpp between the database and the hash core. That is the
// salt callback (keying HC-128 from the fill's seed, the three per-nonce draws
// and their ranges, the iters formula) and the random_values fetch with its
// 1 MB bound, which no startup check reaches: the hash vectors in slow-hash.c
// supply salt and draws through a test callback, and the chain fill's test in
// db_lmdb.cpp stops at the fill.
//
// The database is a fake whose answers are derived from every argument it is
// given, so a wrong height, bound, odds or reseed interval changes the hash.
// The arguments are also checked directly, and so is the invalidation of the
// random_values cache that v13 shares. The real chain fill is pinned
// separately, at every database open.
//
//   t_v14_longhash           check against the pinned vectors
//   t_v14_longhash --print   print the vectors (only when v14 changes on purpose)
//   t_v14_longhash --search  find blob seeds for the corner cases in EDGES
#include "check.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "blockchain_db/testdb.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

extern "C" {
#include "crypto/hash-ops.h"
#include "crypto/hc128.h"
}

namespace
{
  uint64_t splitmix(uint64_t &s)
  {
    uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
  }

  class FakeChainDB : public cryptonote::BaseTestDB
  {
  public:
    uint64_t v2_height = 0, v6_height = 0;
    uint32_t v2_bound = 0, v6_odds = 0, v6_reseed = 0;
    int v2_calls = 0, v6_calls = 0;
    HC128_State after_fill;   // the generator as the fill hands it back

    void get_cna_v2_data(crypto::cn_random_values_t *rv, uint64_t height, uint32_t bound) override
    {
      v2_calls++; v2_height = height; v2_bound = bound;
      // A bound larger than v8's pad would write past it, so reduce by a
      // different in-range modulus instead: the hash still moves, the run
      // fails cleanly rather than crashing, and the bound check says why.
      const uint32_t mod = bound <= CN_SCRATCHPAD_MEMORY_V8 ? bound : CN_SCRATCHPAD_MEMORY_V8 - 4096;
      uint64_t s = height * 0x100000001b3ULL ^ bound;
      for (int i = 0; i < CN_RANDOM_VALUES; i++)
      {
        const uint64_t z = splitmix(s);
        rv->operators[i] = (uint8_t)(z % 7 + 1);   // ADD..EQ, never NOP
        rv->values[i] = (int8_t)(z >> 8);
        rv->indices[i] = (uint32_t)((z >> 32) % mod);
      }
    }

    // Advances the generator the way a fill does and folds every argument into
    // the 256 KB it writes, so the state v14_fetch_salt draws from afterwards,
    // and the salt itself, both depend on what was passed.
    void get_cna_v6_data(char *out, HC128_State *rng, uint64_t height, uint32_t odds, uint32_t reseed) override
    {
      v6_calls++; v6_height = height; v6_odds = odds; v6_reseed = reseed;
      const uint32_t mix = (uint32_t)(height * 2654435761ULL) ^ (odds << 16) ^ (reseed << 24);
      for (uint32_t k = 0; k < CN_SALT_MEMORY / 64; k++)
      {
        HC128_NextKeys(rng);
        for (int j = 0; j < 16; j++)
        {
          const uint32_t w = rng->keystream[j] ^ mix ^ (k * 16 + (uint32_t)j);
          std::memcpy(out + k * 64 + j * 4, &w, 4);
        }
      }
      after_fill = *rng;
    }

    void get_cna_v3_data(char *, uint64_t, uint32_t) override { throw std::logic_error("v3 not used by v14"); }
    void get_cna_v4_data(char *, uint64_t, uint32_t) override { throw std::logic_error("v4 not used by v14"); }
    void get_cna_v5_data(char *, HC128_State *, uint64_t) override { throw std::logic_error("v5 not used by v14"); }
  };

  // The three per-nonce draws v14_fetch_salt takes from the state the fill
  // leaves behind. Only used to find and label the edge cases below; the
  // pinned hashes are what check the real code.
  struct Draws { unsigned xx, yy, iters; };
  Draws replay_draws(const FakeChainDB &db, uint64_t height)
  {
    HC128_State st = db.after_fill;
    HC128_NextKeys(&st);
    size_t k = 0;
    Draws d;
    d.xx = 4 + HC128_U32(&st, &k, 5);
    d.yy = 4 + HC128_U32(&st, &k, 5);
    const uint32_t divisor = 1 + HC128_U32(&st, &k, 64);
    d.iters = (unsigned)((height + 1) % divisor);
    return d;
  }

  struct Case { uint64_t height; uint8_t blob_seed; unsigned char want[32]; };

  // Pinned with --print. Heights cover the lowest hashable one, small chains
  // and mainnet scale.
  Case CASES[] = {
    {     511, 1, {0x9d,0xb9,0x57,0x5b,0x35,0x67,0xd5,0x07,0xc2,0xf5,0xf0,0x17,0xe7,0x8e,0xdb,0xd9,0xb4,0x4c,0x0a,0x03,0x7e,0x5a,0xf5,0xf4,0x6f,0x8b,0xd1,0x1e,0xc9,0x34,0xd3,0xd8} },
    {     512, 2, {0x84,0x7a,0x8a,0xe8,0x5f,0xa6,0x88,0x68,0xe8,0x31,0xbf,0xaf,0x3a,0x9a,0x41,0xec,0x25,0x6a,0xdf,0x5b,0x1a,0x07,0x68,0x73,0x0f,0x5a,0x4d,0x5c,0x73,0x65,0x48,0x2a} },
    {    1000, 3, {0x67,0x05,0xa7,0xa0,0xb0,0x00,0x27,0xaf,0x88,0x8e,0xae,0x98,0x45,0x3d,0x6f,0x2e,0x0b,0xfa,0xc2,0x61,0x50,0x55,0x3d,0x25,0x1a,0x75,0xc7,0xb8,0x66,0x04,0x91,0x36} },
    { 1000003, 4, {0xaa,0xe2,0x67,0x69,0xa2,0x5f,0x82,0x6f,0x30,0x8b,0x08,0x7c,0xf9,0xa9,0x17,0xaa,0x8c,0xe5,0x07,0xee,0xf0,0x0b,0x44,0x6b,0x36,0x71,0xec,0x91,0xe4,0x7b,0x16,0x18} },
    { 4500123, 5, {0x6c,0x01,0xe7,0x10,0x37,0x31,0xd1,0xb9,0x86,0x6b,0x5c,0xd8,0x6b,0x52,0x37,0x02,0x88,0x2d,0xf9,0xbf,0xd2,0x2c,0x46,0x28,0x5d,0x96,0x28,0x4f,0x4b,0x5e,0xc0,0x39} },
  };

  // The corners of the draw domain, found with --search rather than left to
  // sampling: random cases rarely reach the top of iters or the largest step
  // count. (8, 8, 63) is the most steps consensus can draw, 119; (4, 4, 0) the
  // fewest, 12. Each case also checks it still produces the draws it was found
  // for, so a change to the fake cannot silently move it off its corner.
  struct Edge { uint64_t height; uint64_t blob_seed; unsigned xx, yy, iters; unsigned char want[32]; };
  Edge EDGES[] = {
    { 1280062, 11348, 8, 8, 63, {0x09,0x39,0xa9,0xf3,0x80,0x2f,0x56,0x38,0x77,0xc3,0xff,0x3c,0x09,0xec,0x63,0xa9,0x94,0xfd,0x47,0xb2,0xab,0xd9,0x3e,0x1c,0xeb,0xd8,0x94,0x0e,0x3f,0x2f,0xe8,0x0e} },
    { 3000062, 11483, 4, 4, 63, {0x9a,0xf8,0x63,0x79,0x74,0x68,0x31,0xd0,0x2e,0x6a,0x38,0x09,0xf1,0x3b,0x26,0xdd,0x52,0x39,0x23,0x13,0x33,0x2e,0xff,0x86,0x57,0xc8,0xfb,0x48,0x2b,0x83,0x9f,0x96} },
    { 1280063, 10222, 8, 8, 0, {0x93,0x9e,0x6a,0xd9,0x2d,0x69,0xac,0x10,0xb3,0x93,0x4b,0x4c,0x78,0xae,0x24,0x16,0x52,0x52,0xeb,0xdf,0xef,0x87,0xe0,0x7e,0x26,0xa8,0x69,0x72,0x65,0x76,0x2f,0xdd} },
    { 3000063, 10331, 4, 4, 0, {0x55,0xa1,0x8a,0x94,0x0a,0x8e,0xb8,0x59,0x6f,0x63,0x65,0x0a,0x36,0xca,0x89,0x2d,0xd2,0xf2,0x3f,0xd1,0xa3,0x63,0x4e,0x0e,0x92,0xff,0x43,0xa7,0x7d,0xc1,0xf4,0xa8} },
  };

  void make_blob(uint64_t seed, std::string &blob)
  {
    // the size of a real hashing blob, so the tweak at offset 35 is in bounds
    blob.resize(76);
    uint64_t s = seed;
    for (size_t i = 0; i < blob.size(); i++) blob[i] = (char)(splitmix(s) & 0xff);
  }

  bool g_print = false;

  // Search for blob seeds that land on each corner at heights chosen so the
  // iters formula can reach it: (height + 1) % 64 == 63 needs height = 64k + 62
  // and a divisor of 64; iters == 0 at height = 64k + 63 needs a divisor of 64.
  void search_edges(crypto::cn_hash_context_t *ctx)
  {
    struct Target { uint64_t height; unsigned xx, yy, iters; };
    static const Target targets[] = {
      { 1280062, 8, 8, 63 },
      { 3000062, 4, 4, 63 },
      { 1280063, 8, 8, 0 },
      { 3000063, 4, 4, 0 },
    };
    for (const Target &t : targets)
    {
      for (uint64_t seed = 10000; seed < 10000 + 200000; seed++)
      {
        FakeChainDB db;
        std::string blob;
        make_blob(seed, blob);
        crypto::hash res;
        if (!cryptonote::get_block_longhash(ctx, db, 14, blob, res, t.height)) continue;
        const Draws d = replay_draws(db, t.height);
        if (d.xx != t.xx || d.yy != t.yy || d.iters != t.iters) continue;
        std::printf("    { %llu, %llu, %u, %u, %u, {", (unsigned long long)t.height,
                    (unsigned long long)seed, d.xx, d.yy, d.iters);
        for (int i = 0; i < 32; i++) std::printf("0x%02x%s", (unsigned char)res.data[i], i < 31 ? "," : "");
        std::printf("} },\n");
        break;
      }
    }
  }

  void test_v14_end_to_end()
  {
    crypto::cn_hash_context_t *ctx = crypto::cn_hash_context_create();
    CHECK_TRUE(ctx != NULL);
    if (!ctx) return;

    for (Case &c : CASES)
    {
      FakeChainDB db;
      std::string blob;
      make_blob(c.blob_seed, blob);
      crypto::hash res;
      // as if v13 had just cached random_values for this height: v14 must not
      // reuse them (its bound differs) and must leave the cache invalidated
      ctx->cached_height = c.height;
      const bool ok = cryptonote::get_block_longhash(ctx, db, 14, blob, res, c.height);
      CHECK_TRUE(ok);
      CHECK_TRUE(ctx->cached_height == (uint64_t)-1);

      // the arguments themselves, so a failure says which one moved
      CHECK_TRUE(db.v2_calls == 1 && db.v6_calls == 1);
      CHECK_TRUE(db.v2_height == c.height - 256);
      CHECK_TRUE(db.v6_height == c.height - 256);
      CHECK_TRUE(db.v2_bound == CN_SCRATCHPAD_MEMORY_V8);
      CHECK_TRUE(db.v6_odds == CNA_V6_FULL_HISTORY_ODDS_V14);
      CHECK_TRUE(db.v6_reseed == CNA_V6_RESEED_BLOCKS_V14);

      if (g_print)
      {
        std::printf("    { %7llu, %u, {", (unsigned long long)c.height, (unsigned)c.blob_seed);
        for (int i = 0; i < 32; i++) std::printf("0x%02x%s", (unsigned char)res.data[i], i < 31 ? "," : "");
        std::printf("} },\n");
      }
      else
        CHECK_TRUE(std::memcmp(res.data, c.want, 32) == 0);
    }

    for (Edge &e : EDGES)
    {
      FakeChainDB db;
      std::string blob;
      make_blob(e.blob_seed, blob);
      crypto::hash res;
      CHECK_TRUE(cryptonote::get_block_longhash(ctx, db, 14, blob, res, e.height));
      const Draws d = replay_draws(db, e.height);
      CHECK_TRUE(d.xx == e.xx && d.yy == e.yy && d.iters == e.iters);
      if (g_print)
      {
        std::printf("    { %llu, %llu, %u, %u, %u, {", (unsigned long long)e.height,
                    (unsigned long long)e.blob_seed, e.xx, e.yy, e.iters);
        for (int i = 0; i < 32; i++) std::printf("0x%02x%s", (unsigned char)res.data[i], i < 31 ? "," : "");
        std::printf("} },\n");
      }
      else
        CHECK_TRUE(std::memcmp(res.data, e.want, 32) == 0);
    }

    // 1,024 more cases folded into one digest, so a change that moves only a
    // few draws cannot pass by landing on unaffected ones. A divisor range off
    // by one moves about 1.35% of hashes: a random set of this size would miss
    // that about once in a million, and this set catches it.
    {
      static const unsigned char want_all[32] = {0x2c,0x19,0x06,0xa3,0x52,0x35,0x38,0xc6,0x51,0x79,0x7f,0xb1,0x62,0xce,0x7d,0xfb,0xd8,0x2d,0x2d,0xe3,0x1e,0x88,0xca,0xf0,0xa0,0x11,0xb1,0xb3,0x13,0xaf,0x70,0xc7};
      std::string all;
      uint64_t s = 0x76313468ULL;
      for (int i = 0; i < 1024; i++)
      {
        FakeChainDB db;
        std::string blob;
        make_blob(100 + (uint64_t)i, blob);
        const uint64_t height = 511 + splitmix(s) % 5000000;
        crypto::hash res;
        CHECK_TRUE(cryptonote::get_block_longhash(ctx, db, 14, blob, res, height));
        all.append(res.data, 32);
      }
      crypto::hash digest;
      crypto::cn_fast_hash(all.data(), all.size(), digest);
      if (g_print)
      {
        std::printf("  aggregate over 1024 cases: {");
        for (int i = 0; i < 32; i++) std::printf("0x%02x%s", (unsigned char)digest.data[i], i < 31 ? "," : "");
        std::printf("}\n");
      }
      else
        CHECK_TRUE(std::memcmp(digest.data, want_all, 32) == 0);
    }

    // below the lowest hashable height the function refuses rather than hashing
    {
      FakeChainDB db;
      std::string blob;
      make_blob(9, blob);
      crypto::hash res;
      CHECK_FALSE(cryptonote::get_block_longhash(ctx, db, 14, blob, res, 510));
      CHECK_TRUE(db.v2_calls == 0 && db.v6_calls == 0);
      CHECK_FALSE(cryptonote::get_longhash_height_supported(14, 510));
      CHECK_TRUE(cryptonote::get_longhash_height_supported(14, 511));
    }

    crypto::cn_hash_context_free(ctx);
  }
}

int main(int argc, char **argv)
{
  g_print = argc > 1 && std::strcmp(argv[1], "--print") == 0;
  if (argc > 1 && std::strcmp(argv[1], "--search") == 0)
  {
    crypto::cn_hash_context_t *ctx = crypto::cn_hash_context_create();
    if (!ctx) return 1;
    search_edges(ctx);
    crypto::cn_hash_context_free(ctx);
    return 0;
  }
  std::printf("== v14 longhash, end to end over a fake chain ==\n");
  RUN(test_v14_end_to_end);
  return check_summary("t_v14_longhash");
}
