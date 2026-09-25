// PoW cost benchmark for the HF14 review. Answers two questions the design
// notes assert but nothing in tree measures:
//   1. how much more expensive is a v14 hash than a v13 one, on this box
//   2. does the 24 MB chase buffer stay DRAM-bound once every core is busy,
//      or does it sit in L3 at low thread counts
// Prints ns per chase hop so the numbers compare directly against the
// 57.6 ns (1 thread) / 87-94 ns (2+ threads) figures the design rests on.
#include "check.h"

#include <cstdint>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>

using std::uint8_t; using std::uint64_t; using std::size_t;

extern "C" {
#include "crypto/hash-ops.h"
#include "crypto/cna-vm.h"
}

static const char SAMPLE[] =
  "nerva hf14 pow benchmark input, long enough for the variant 1 tweak at 35";

// hops per v14 hash: passes x hops-per-pass
static const uint64_t V7_HOPS_PER_HASH =
  (uint64_t)CN_VM_ITERATIONS_V14 * (uint64_t)CN_V7_HOPS;

static void make_seed(uint8_t seed[32], unsigned salt)
{
  for (unsigned i = 0; i < 32; i++)
    seed[i] = (uint8_t)(i * 47u + 11u + salt * 31u);
}

// One thread: reset the chain-derived inputs, then time n hashes.
static double run_hashes(int version, unsigned n, unsigned salt)
{
  cn_hash_context_t *ctx = cn_hash_context_create();
  if (ctx == NULL) { std::fprintf(stderr, "context alloc failed\n"); return -1.0; }

  uint8_t seed[32];
  make_seed(seed, salt);
  std::memset(&ctx->random_values, 0, sizeof(ctx->random_values));
  std::memset(ctx->salt, 0, CN_SALT_MEMORY);

  char out[HASH_SIZE];
  // one warm-up so the lazy pad/buffer allocation is not in the timing
  if (version == 13) cn_slow_hash_v13(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, seed);
  else               cn_slow_hash_v14(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, seed);

  const auto t0 = std::chrono::steady_clock::now();
  for (unsigned i = 0; i < n; i++)
  {
    if (version == 13) cn_slow_hash_v13(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, seed);
    else               cn_slow_hash_v14(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, seed);
  }
  const auto t1 = std::chrono::steady_clock::now();
  cn_hash_context_free(ctx);

  const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  return ms / (double)n;   // ms per hash
}

// N threads at once, each with its own context and its own 24 MB buffer.
static double run_parallel(int version, unsigned threads, unsigned n)
{
  std::vector<double> per(threads, 0.0);
  std::vector<std::thread> pool;
  pool.reserve(threads);
  for (unsigned t = 0; t < threads; t++)
    pool.emplace_back([&, t]{ per[t] = run_hashes(version, n, t); });
  for (auto &th : pool) th.join();
  // report the median thread so one descheduled worker does not skew it
  std::sort(per.begin(), per.end());
  return per[threads / 2];
}

static void bench_v13_vs_v14()
{
  const double v13 = run_hashes(13, 3, 0);
  const double v14 = run_hashes(14, 3, 0);
  std::printf("  v13  %8.1f ms/hash\n", v13);
  std::printf("  v14  %8.1f ms/hash   (%.2fx v13)\n", v14, v14 / v13);
  std::printf("  v14  %8.1f ns/hop    (%llu hops/hash)\n",
              v14 * 1e6 / (double)V7_HOPS_PER_HASH,
              (unsigned long long)V7_HOPS_PER_HASH);
  CHECK_TRUE(v13 > 0.0 && v14 > 0.0);
}

static void bench_thread_scaling()
{
  const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
  std::printf("  hardware_concurrency = %u, buffer = %u MB/thread\n",
              hw, (unsigned)(CN_V7_BUFFER / (1024 * 1024)));
  for (unsigned t = 1; t <= hw; t *= 2)
  {
    const double ms = run_parallel(14, t, 2);
    std::printf("  %2u thread(s)  %8.1f ms/hash  %6.1f ns/hop  %6.2f H/s total  %4u MB resident\n",
                t, ms, ms * 1e6 / (double)V7_HOPS_PER_HASH,
                (double)t * 1000.0 / ms,
                (unsigned)(t * CN_V7_BUFFER / (1024 * 1024)));
  }
  if (hw > 1)
  {
    const double ms = run_parallel(14, hw, 2);
    std::printf("  %2u thread(s)  %8.1f ms/hash  %6.1f ns/hop  %6.2f H/s total  %4u MB resident  <- full occupancy\n",
                hw, ms, ms * 1e6 / (double)V7_HOPS_PER_HASH,
                (double)hw * 1000.0 / ms,
                (unsigned)(hw * CN_V7_BUFFER / (1024 * 1024)));
  }
  CHECK_TRUE(hw >= 1);
}

int main()
{
  std::printf("== v13 vs v14 cost ==\n");
  RUN(bench_v13_vs_v14);
  std::printf("== v14 thread scaling (L3 residency) ==\n");
  RUN(bench_thread_scaling);
  return check_summary("t_bench_pow");
}
