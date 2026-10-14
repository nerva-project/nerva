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

// v14 hashrate through the daemon's own code: get_block_longhash at version 14
// over a real mainnet database, so the chain fill reads the real block cache at
// mainnet height. One hash context per thread, as the miner keeps.
//
// Needs a copy of the mainnet database; the daemon must not have it open.
//
//   t_v14_bench <lmdb directory> <threads> <seconds> [rounds]
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

int main(int argc, char **argv)
{
  if (argc < 4)
  {
    std::fprintf(stderr, "usage: t_v14_bench <lmdb directory> <threads> <seconds> [rounds]\n");
    return 2;
  }
  const unsigned threads = (unsigned)std::atoi(argv[2]);
  const double seconds = std::atof(argv[3]);
  const int rounds = argc > 4 ? std::atoi(argv[4]) : 3;

  cryptonote::BlockchainLMDB db;
  db.open(argv[1], DBF_RDONLY);
  const uint64_t height = db.height();

  auto run = [&](double secs) {
    std::atomic<bool> stop(false);
    std::atomic<uint64_t> total(0);
    std::vector<std::thread> th;
    for (unsigned t = 0; t < threads; t++)
      th.emplace_back([&, t]() {
        crypto::cn_hash_context_t *ctx = crypto::cn_hash_context_create();
        cryptonote::blobdata blob(76, '\0');
        for (size_t i = 0; i < blob.size(); i++) blob[i] = (char)(i * 13 + t);
        uint64_t n = 0;
        uint32_t nonce = t * 0x01000000u;
        crypto::hash res;
        while (!stop.load(std::memory_order_relaxed))
        {
          std::memcpy(&blob[39], &nonce, 4);
          nonce++;
          if (!cryptonote::get_block_longhash(ctx, db, 14, blob, res, height))
            std::abort();
          n++;
        }
        crypto::cn_hash_context_free(ctx);
        total += n;
      });
    const auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::duration<double>(secs));
    stop = true;
    for (auto &x : th) x.join();
    return total / std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  };

  run(2.0);   // untimed: builds the block cache and faults in the pads
  std::vector<double> got;
  for (int r = 0; r < rounds; r++)
  {
    got.push_back(run(seconds));
    std::printf("  round %d: %.0f H/s\n", r, got.back());
    std::fflush(stdout);
  }
  std::sort(got.begin(), got.end());
  std::printf("v14 at height %llu, %u threads: median %.0f H/s (%.0f..%.0f)\n",
              (unsigned long long)height, threads, got[got.size() / 2], got.front(), got.back());
  db.close();
  return 0;
}
