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
//   t_v14_bench <lmdb directory> <threads> <seconds> [rounds] [pin]
//
// pin: place threads as the miner's --mining-affinity does (Windows).
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

#if defined(_WIN32)
#include <windows.h>
// The plan --mining-affinity makes (miner.cpp): one thread per physical core,
// inside one L3 group when they all fit there, otherwise across groups in
// enumeration order; threads past the core count stay unpinned.
namespace
{
  typedef struct { KAFFINITY Mask; WORD Group; WORD Reserved[3]; } group_affinity_t;
  typedef struct { BYTE Flags; BYTE EfficiencyClass; BYTE Reserved[20]; WORD GroupCount; group_affinity_t GroupMask[1]; } processor_rel_t;
  typedef struct { BYTE Level; BYTE Associativity; WORD LineSize; DWORD CacheSize; DWORD Type; BYTE Reserved[20]; group_affinity_t GroupMask; } cache_rel_t;
  typedef struct { DWORD Relationship; DWORD Size; union { processor_rel_t Processor; cache_rel_t Cache; } u; } slpi_ex_t;
  typedef BOOL (WINAPI *glpi_ex_t)(DWORD, slpi_ex_t *, PDWORD);
  typedef BOOL (WINAPI *set_ga_t)(HANDLE, const group_affinity_t *, group_affinity_t *);
  struct slot { WORD group; int cpu; long l3; };

  std::vector<slot> plan_affinity(size_t threads)
  {
    std::vector<slot> cores, plan;
    const glpi_ex_t glpi = (glpi_ex_t)(void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetLogicalProcessorInformationEx");
    DWORD len = 0;
    if (!glpi) return plan;
    glpi(0xffff, NULL, &len);
    std::vector<BYTE> buf(len);
    if (!len || !glpi(0xffff, (slpi_ex_t *)buf.data(), &len)) return plan;
    std::vector<group_affinity_t> l3s;
    for (BYTE *q = buf.data(); q < buf.data() + len; q += ((slpi_ex_t *)q)->Size)
    {
      const slpi_ex_t *i = (const slpi_ex_t *)q;
      if (i->Relationship == 2 && i->u.Cache.Level == 3) l3s.push_back(i->u.Cache.GroupMask);
    }
    for (BYTE *q = buf.data(); q < buf.data() + len; q += ((slpi_ex_t *)q)->Size)
    {
      const slpi_ex_t *i = (const slpi_ex_t *)q;
      if (i->Relationship != 0) continue;
      const group_affinity_t &ga = i->u.Processor.GroupMask[0];
      int bit = -1;
      for (int b = 0; b < (int)(8 * sizeof(KAFFINITY)); ++b)
        if (ga.Mask & ((KAFFINITY)1 << b)) { bit = b; break; }
      if (bit < 0) continue;
      long l3 = -1;
      for (size_t k = 0; k < l3s.size(); ++k)
        if (l3s[k].Group == ga.Group && (l3s[k].Mask & ga.Mask)) { l3 = (long)k; break; }
      cores.push_back(slot{ ga.Group, bit, l3 });
    }
    if (threads == 0 || cores.size() < 2) return plan;
    for (long g = (long)l3s.size() - 1; g >= 0; --g)
    {
      std::vector<slot> in;
      for (const slot &c : cores) if (c.l3 == g) in.push_back(c);
      if (in.size() >= threads) return std::vector<slot>(in.begin(), in.begin() + threads);
    }
    for (size_t k = 0; k < cores.size() && k < threads; ++k) plan.push_back(cores[k]);
    return plan;
  }

  bool pin(const slot &s)
  {
    static const set_ga_t set_ga = (set_ga_t)(void *)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetThreadGroupAffinity");
    if (!set_ga) return false;
    group_affinity_t ga;
    std::memset(&ga, 0, sizeof(ga));
    ga.Group = s.group;
    ga.Mask = (KAFFINITY)1 << s.cpu;
    return set_ga(GetCurrentThread(), &ga, NULL) != 0;
  }
}
#endif

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
  const bool pinned = argc > 5 && std::strcmp(argv[5], "pin") == 0;
#if defined(_WIN32)
  const std::vector<slot> plan = pinned ? plan_affinity(threads) : std::vector<slot>();
  if (pinned)
    std::printf("pinning %zu of %u threads, one per physical core\n", plan.size(), threads);
#endif

  cryptonote::BlockchainLMDB db;
  db.open(argv[1], DBF_RDONLY);
  const uint64_t height = db.height();

  auto run = [&](double secs) {
    std::atomic<bool> stop(false);
    std::atomic<uint64_t> total(0);
    std::vector<std::thread> th;
    for (unsigned t = 0; t < threads; t++)
      th.emplace_back([&, t]() {
#if defined(_WIN32)
        if (t < plan.size()) pin(plan[t]);
#endif
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
