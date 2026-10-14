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

// Recomputes the proof of work of real mainnet blocks for every fork version
// that reads the block cache (v7 to v13) and checks each against the block's
// recorded difficulty. A hash computed from the wrong chain data fails that
// check with probability about 1 - 1/difficulty, so a pass on every sampled
// block shows each cache reader still returns what it did when the block was
// mined. The hashes are printed, so two builds can also be diffed directly.
//
// Needs a copy of the mainnet database; the daemon must not have it open.
//
//   t_pow_history <lmdb directory> [blocks per version]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/difficulty.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "string_tools.h"

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    std::fprintf(stderr, "usage: t_pow_history <lmdb directory> [blocks per version]\n");
    return 2;
  }
  const uint64_t per = argc > 2 ? std::strtoull(argv[2], NULL, 10) : 40;

  cryptonote::BlockchainLMDB db;
  db.open(argv[1], DBF_RDONLY);
  const uint64_t top = db.height();

  // mainnet fork heights, cryptonote_config.h
  struct Range { unsigned version; uint64_t from, to; };
  const Range ranges[] = {
    {  7,  173500,  180000 },
    {  8,  180000,  240500 },
    {  9,  240500,  341000 },
    { 10,  341000,  500000 },
    { 11,  500000,  930000 },
    { 12,  930000, 4320000 },
    { 13, 4320000,     top },
  };

  crypto::cn_hash_context_t *ctx = crypto::cn_hash_context_create();
  if (!ctx) { std::fprintf(stderr, "no hash context\n"); return 2; }

  unsigned failed = 0, total = 0;
  for (const Range &r : ranges)
  {
    const uint64_t to = r.to < top ? r.to : top;
    unsigned pass = 0, n = 0;
    for (uint64_t k = 0; k < per && r.from + k < to; k++)
    {
      // spread over the range, plus its first and last blocks
      const uint64_t h = k == 0 ? r.from : k == per - 1 ? to - 1 : r.from + (to - r.from) * k / per;
      const cryptonote::block b = db.get_block_from_height(h);
      if (b.major_version != r.version)
      {
        std::printf("v%u %llu: block is version %u, range table is wrong\n", r.version,
                    (unsigned long long)h, (unsigned)b.major_version);
        failed++;
        continue;
      }
      crypto::hash res;
      const bool ok = cryptonote::get_block_longhash(ctx, db, b, res, h);
      const uint64_t diff = db.get_block_difficulty(h);
      const bool meets = ok && cryptonote::check_hash(res, diff);
      std::printf("v%u %llu %s %s\n", r.version, (unsigned long long)h,
                  epee::string_tools::pod_to_hex(res).c_str(), meets ? "ok" : "FAIL");
      n++;
      if (meets) pass++; else failed++;
    }
    total += n;
    std::fprintf(stderr, "v%u: %u of %u blocks meet their difficulty\n", r.version, pass, n);
  }

  crypto::cn_hash_context_free(ctx);
  db.close();
  std::fprintf(stderr, "%u blocks, %u failed\n", total, failed);
  return failed ? 1 : 0;
}
