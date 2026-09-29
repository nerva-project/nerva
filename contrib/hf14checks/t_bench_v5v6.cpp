// v5 across pad sizes, plus v6 and v7, on the REAL hash functions.
//
// v5 (cn_slow_hash_v11) draws its loop counts, AES block size and iteration
// count per nonce, so a single-point measurement misrepresents it. Parameters
// here come from the same ranges get_block_longhash_v5 uses:
//   xx  = 4 + rand(5)              [4,8]
//   yy  = 4 + rand(5)              [4,8]
//   init_size_blk = 2 << rand(3)   2, 4 or 8
//   iters = rand(1 + rand(64))     [0,62]
//
// The pad rows are separate compilations of the same source at a different
// CN_SCRATCHPAD_MEMORY (see v5pad.inc). Consensus code is untouched, and the
// shipped 1 MB v11 is measured alongside them as the reference.
//
// A control row guards the comparison rather than assuming it: 1MB ref is the
// shipped function out of libcncrypto.a, 1MB ctl is the same source recompiled
// here at the same size. They should agree. If they do not, the recompiled
// rows are not measuring what the shipped one measures, and nothing below
// this line means anything.
//
// On the two odd sizes: 1.25 and 1.5 MB have a pad block count that is not a
// power of two, so they cannot use the shipped mask index and take a modulo
// instead (see v5pad.inc). That was verified in the disassembly rather than
// assumed. The masked builds carry and $0xffff0 / $0x1ffff0 / $0x3ffff0 /
// $0x7ffff0, exactly (blocks - 1) << 4 for 1/2/4/8 MB; the modulo builds carry
// no mask and instead the division magic for 81920 = 5 << 14 and 98304 =
// 3 << 15. The extra cost is a multiply-high and a shift on roughly 90
// state_index evaluations per hash, since v5 runs about (xx-1)*yy + iters AES
// rounds and each does two. That is a few hundred cycles against a hash
// costing milliseconds. It is also visible for free in the ms-per-MB column
// below: if the modulo mattered, the two modulo rows would sit off the curve
// traced by the four masked ones.
//
// Reports mean/min/max per hash and thread scaling, which is where the
// cache-residency behaviour that drives CPU fairness shows up.
#include "check.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>
#include <atomic>

using std::uint8_t; using std::uint64_t; using std::size_t;

extern "C" {
#include "crypto/hash-ops.h"
#include "crypto/cna-vm.h"
}

static const char SAMPLE[] =
  "nerva v5 v6 v7 comparison input, long enough for the variant 1 tweak at 35";

typedef void (*v5fn)(cn_hash_context_t *, const void *, size_t, char *,
                     size_t, uint8_t, uint16_t, uint16_t);

// the resized compilations of cn_slow_hash_v11; no header declares these
// because v5pad.inc renames them after hash-ops.h has been parsed
extern "C" {
void cn_slow_hash_v11_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p1_25(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p1_5(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p2(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v11_p8(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
/* CNA v8 at the same two sizes. v8 is v11 with salt_pad's extra-hash selector
 * widened to four entries, so it shares the signature and the pad. 1 MB
 * isolates the selector change against v5 at the size v5 ships; 4 MB is where
 * v8 is meant to live and exercises v5pad.inc's salt wrap, a different path. */
void cn_slow_hash_v14_p1(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v14_p4(cn_hash_context_t *, const void *, size_t, char *, size_t, uint8_t, uint16_t, uint16_t);
}

enum Gen { GEN_V5 = 5, GEN_V6 = 6 };

struct V {
  const char *key;        // short id used by the ratio lines below
  const char *name;
  Gen         gen;
  v5fn        fn;         // GEN_V5 only
  size_t      own_pad;    // bytes we must supply; 0 = the function allocates
  size_t      pad_kb;     // what the hash actually walks, for the report
  unsigned    single_n;
  unsigned    per_thread;   // unused by the scaling pass, which sizes itself
  bool        scale;      // include in the thread-scaling pass
};

// own_pad is 0 exactly for the three functions reached through the dispatchers
// in slow-hash.c, which call cn_pads_require for themselves. Every resized
// compilation is an inner function that reads context->scratchpad with no
// allocation of its own, so it must be handed a buffer, the 1 MB ones included.
static const V VS[] = {
  // single_n is 2000 on the rows that carry the v5-against-v8 comparison, not
  // the 60 the pad-sweep rows use. v5 draws its work per nonce and the spread
  // is about 4.7x, so at n=60 the standard error on the mean is near 4.5% and
  // a 2% gate cannot be resolved. Worse, the Rng seed is fixed, so a small
  // sample repeats the same draw every run: a difference that is pure sampling
  // looks stable across runs and reads as a real result. n=2000 costs about
  // 1.6 s a row here and brings the error under 1%.
  { "v5ref",  "v5 1MB ref",  GEN_V5, cn_slow_hash_v11,       0,            1024, 2000, 20, true  },
  { "v5ctl",  "v5 1MB ctl",  GEN_V5, cn_slow_hash_v11_p1,    1024ull*1024, 1024, 2000, 20, false },
  { "v5_125", "v5 1.25MB",   GEN_V5, cn_slow_hash_v11_p1_25, 1280ull*1024, 1280, 40, 14, true  },
  { "v5_15",  "v5 1.5MB",    GEN_V5, cn_slow_hash_v11_p1_5,  1536ull*1024, 1536, 35, 12, true  },
  { "v5_2",   "v5 2MB",      GEN_V5, cn_slow_hash_v11_p2,    2048ull*1024, 2048, 30, 10, true  },
  { "v5_4",   "v5 4MB",      GEN_V5, cn_slow_hash_v11_p4,    4096ull*1024, 4096, 600, 10, true  },
  { "v5_8",   "v5 8MB",      GEN_V5, cn_slow_hash_v11_p8,    8192ull*1024, 8192, 20,  6, true  },
  { "v6",     "v6 (HF13)",   GEN_V6, NULL,                   0,            8192, 20,  6, true  },
  // CNA v8. v8ref comes out of libcncrypto.a, v8ctl is the same source
  // recompiled here, exactly as v5ref/v5ctl pair up. The comparison that
  // decides Phase 1 is v5ctl against v8ctl and v5_4 against v8_4: same
  // translation unit, same flags, same pad, one token of difference.
  { "v8ref",  "v8 1MB ref",  GEN_V5, cn_slow_hash_v14,       0,            1024, 2000, 20, true  },
  { "v8ctl",  "v8 1MB ctl",  GEN_V5, cn_slow_hash_v14_p1,    1024ull*1024, 1024, 2000, 20, false },
  { "v8_4",   "v8 4MB",      GEN_V5, cn_slow_hash_v14_p4,    4096ull*1024, 4096, 600, 10, true  },
};
static const size_t NVS = sizeof(VS) / sizeof(VS[0]);

// the context allocates its pads lazily; the resized variants get their own
struct BigPad {
  cn_hash_context_t *ctx; uint8_t *orig; void *mem;
  BigPad(cn_hash_context_t *c, size_t bytes) : ctx(NULL), orig(NULL), mem(NULL) {
    if (bytes == 0) return;
    mem = _aligned_malloc(bytes, 4096);
    if (mem == NULL) return;
    std::memset(mem, 0, bytes);
    ctx = c; orig = c->scratchpad; c->scratchpad = (uint8_t *)mem;
  }
  bool ok() const { return mem != NULL || ctx == NULL; }
  // must run before cn_hash_context_free, or the free sees our buffer
  void release() {
    if (ctx) { ctx->scratchpad = orig; ctx = NULL; }
    if (mem) { _aligned_free(mem); mem = NULL; }
  }
  ~BigPad() { release(); }
};

static void make_seed(uint8_t seed[32], unsigned salt)
{
  for (unsigned i = 0; i < 32; i++)
    seed[i] = (uint8_t)(i * 47u + 11u + salt * 31u);
}

struct Rng { uint32_t s; uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; } };

// one hash of the given variant; v5 parameters are drawn per call
static void one_hash(const V &v, cn_hash_context_t *ctx, const uint8_t *seed, Rng &rng, char *out)
{
  switch (v.gen)
  {
  case GEN_V5: {
    const uint16_t xx  = (uint16_t)(4u + rng.next() % 5u);
    const uint16_t yy  = (uint16_t)(4u + rng.next() % 5u);
    const uint8_t  blk = (uint8_t)(2u << (rng.next() % 3u));
    const size_t   it  = (size_t)(rng.next() % (1u + rng.next() % 64u));
    v.fn(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, it, blk, xx, yy);
    break;
  }
  case GEN_V6: cn_slow_hash_v13(ctx, SAMPLE, sizeof(SAMPLE) - 1, out, seed); break;
  }
}

static void prepare(cn_hash_context_t *ctx, unsigned salt, uint8_t seed[32])
{
  make_seed(seed, salt);
  std::memset(&ctx->random_values, 0, sizeof(ctx->random_values));
  std::memset(ctx->salt, 0, CN_SALT_MEMORY);
}

// single-thread: mean, min, max ms per hash over single_n hashes
static void bench_single(const V &v, double &mean, double &lo, double &hi)
{
  mean = lo = hi = -1.0;
  cn_hash_context_t *ctx = cn_hash_context_create();
  if (ctx == NULL) return;
  uint8_t seed[32]; prepare(ctx, 1, seed);
  BigPad pad(ctx, v.own_pad);
  if (!pad.ok()) { cn_hash_context_free(ctx); return; }
  char out[HASH_SIZE];
  Rng rng{0x12345678u};

  one_hash(v, ctx, seed, rng, out);          // warm

  lo = 1e30; hi = 0.0; double total = 0.0;
  for (unsigned i = 0; i < v.single_n; i++)
  {
    const auto a = std::chrono::steady_clock::now();
    one_hash(v, ctx, seed, rng, out);
    const double ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - a).count();
    total += ms; if (ms < lo) lo = ms; if (ms > hi) hi = ms;
  }
  pad.release();
  cn_hash_context_free(ctx);
  mean = total / (double)v.single_n;
}

// Throughput across t threads, each with its own context and pad.
//
// Every thread allocates a pad and memsets it, and at 32 threads that is up to
// 768 MB of memset for v7. Timing that alongside the hashing made the wide
// thread counts look like a collapse in the algorithm when it was really the
// allocator: 8 MB read 0.04x of linear. So each thread sets up, faults its pad
// in with one warm hash, and only then waits at a barrier. The clock covers
// the hashing and nothing else.
static double bench_threads(const V &v, unsigned threads, unsigned per_thread)
{
  const int total = (int)(threads * per_thread);
  std::atomic<uint64_t> sink(0);
  std::atomic<unsigned> ready(0);
  std::atomic<bool> go(false);
  std::atomic<unsigned> failed(0);
  std::atomic<int> remaining(total);

  auto worker = [&](unsigned id) {
    cn_hash_context_t *ctx = cn_hash_context_create();
    if (ctx == NULL) { failed++; ready++; return; }
    uint8_t seed[32]; prepare(ctx, id + 1, seed);
    BigPad pad(ctx, v.own_pad);
    if (!pad.ok()) { failed++; ready++; cn_hash_context_free(ctx); return; }
    char out[HASH_SIZE];
    Rng rng{0x9e3779b9u ^ (id * 2654435761u)};

    one_hash(v, ctx, seed, rng, out);      // fault the pad in, off the clock
    ready++;
    while (!go.load(std::memory_order_acquire)) std::this_thread::yield();

    uint64_t acc = 0;
    while (remaining.fetch_sub(1, std::memory_order_relaxed) > 0)
    {
      one_hash(v, ctx, seed, rng, out);
      acc ^= (uint64_t)out[0];
    }
    pad.release();
    cn_hash_context_free(ctx);
    sink ^= acc;
  };

  std::vector<std::thread> ts;
  for (unsigned i = 0; i < threads; i++) ts.emplace_back(worker, i);
  while (ready.load() < threads) std::this_thread::yield();

  const auto t0 = std::chrono::steady_clock::now();
  go.store(true, std::memory_order_release);
  for (auto &t : ts) t.join();
  const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

  if (sink.load() == 1) std::printf("");
  if (failed.load() != 0) return -1.0;
  return total / secs;
}

static double means[NVS];

static double mean_of(const char *key)
{
  for (size_t i = 0; i < NVS; i++)
    if (std::strcmp(VS[i].key, key) == 0) return means[i];
  return -1.0;
}

static void bench_v5_v6_v7()
{
  std::printf("  %-12s %8s %11s %11s %11s %10s\n",
              "VERSION", "pad KB", "mean ms", "min ms", "max ms", "H/s");
  for (size_t i = 0; i < NVS; i++)
  {
    double mean, lo, hi;
    bench_single(VS[i], mean, lo, hi);
    means[i] = mean;
    if (mean <= 0.0) { std::printf("  %-12s %8zu  FAILED\n", VS[i].name, VS[i].pad_kb); continue; }
    std::printf("  %-12s %8zu %11.2f %11.2f %11.2f %10.1f\n",
                VS[i].name, VS[i].pad_kb, mean, lo, hi, 1000.0 / mean);
  }

  const double ref = mean_of("v5ref"), ctl = mean_of("v5ctl");
  std::printf("\n  == control, should land near 1.00x ==\n");
  std::printf("  1MB ctl / 1MB ref = %.3fx   recompiled here vs shipped in libcncrypto.a\n", ctl / ref);
  std::printf("  Away from 1.00x means the two are not built alike and no row below is comparable.\n");

  std::printf("\n  == v5 pad scaling, against the 1MB control ==\n");
  std::printf("  %-12s %10s %12s %14s\n", "VERSION", "x of 1MB", "x of pad", "ms per MB");
  for (size_t i = 0; i < NVS; i++)
  {
    if (VS[i].gen != GEN_V5 || means[i] <= 0.0) continue;
    const double mb = (double)VS[i].pad_kb / 1024.0;
    std::printf("  %-12s %9.2fx %11.2fx %14.2f\n", VS[i].name, means[i] / ctl, mb, means[i] / mb);
  }
  std::printf("  A flat ms-per-MB column means the pad is only buying more of the same work.\n");
  std::printf("  A rising one means the pad has left a cache level and every byte costs more.\n");

  std::printf("\n  v6 / v5 1MB = %.2fx   v6 / v5 8MB = %.2fx   v8ctl / v5ctl = %.3fx\n",
              mean_of("v6") / ref, mean_of("v6") / mean_of("v5_8"),
              mean_of("v8ctl") / mean_of("v5ctl"));

  unsigned hw = std::thread::hardware_concurrency(); if (!hw) hw = 4;
  std::printf("\n  == thread scaling (H/s total), hardware_concurrency = %u ==\n", hw);
  std::printf("  %-12s", "THREADS");
  std::vector<unsigned> counts;
  for (unsigned t = 1; t <= hw; t *= 2) counts.push_back(t);
  if (counts.back() != hw) counts.push_back(hw);
  for (unsigned t : counts) std::printf(" %9u", t);
  std::printf("   scaling\n");

  for (size_t i = 0; i < NVS; i++)
  {
    if (!VS[i].scale || means[i] <= 0.0) continue;
    // Hashes are pulled from one shared counter rather than split up front, so
    // a thread that draws a run of expensive nonces cannot set the elapsed
    // time on its own. v5 nonces vary about 2.5x in cost, and with only a
    // handful of hashes each the slowest thread was deciding the result.
    // Sized from the measured single-thread mean so every cell runs about
    // the same wall time whatever the pad costs.
    unsigned pt = (unsigned)(700.0 / means[i]);
    if (pt < 8) pt = 8;
    if (pt > 3000) pt = 3000;
    std::printf("  %-12s", VS[i].name);
    double first = 0.0, last = 0.0;
    for (unsigned t : counts)
    {
      const double hs = bench_threads(VS[i], t, pt);
      if (first == 0.0) first = hs;
      last = hs;
      std::printf(" %9.1f", hs);
    }
    std::printf("   %6.2fx of linear\n", (last / first) / (double)counts.back());
  }
  std::printf("\n  A version that scales close to linear is cache-resident and rewards\n");
  std::printf("  core count. One that falls away is memory-bound and equalises CPUs.\n");

  for (size_t i = 0; i < NVS; i++) CHECK_TRUE(means[i] > 0.0);
}

int main()
{
  setvbuf(stdout, NULL, _IONBF, 0);
  std::printf("== v5 pad sweep vs v6 vs v7, real hash functions ==\n");
  RUN(bench_v5_v6_v7);
  return check_summary("t_bench_v5v6");
}
