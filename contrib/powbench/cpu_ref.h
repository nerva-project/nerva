#pragma once
// CPU reference: same work as the kernels. v5/v6 fill with AES-NI (what a real
// CPU miner uses), v7 fills with splitmix, which is what v7 actually does.
#include <stdint.h>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <wmmintrin.h>

static inline uint64_t mulhi64(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
}

// 10 AES rounds per 16-byte block, 8 blocks, iters times: matches aes_pseudo_round.
static void aes_fill_pad_cpu(uint8_t *buf, unsigned iters, const __m128i *rk, uint64_t gid) {
    __m128i s[8];
    uint32_t seed = (uint32_t)gid * 2654435761u + 1u;
    uint32_t w[32];
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; w[i] = seed; }
    for (int b = 0; b < 8; b++) s[b] = _mm_loadu_si128((const __m128i *)(w + b * 4));
    for (unsigned it = 0; it < iters; it++) {
        for (int b = 0; b < 8; b++) {
            __m128i t = s[b];
            t = _mm_aesenc_si128(t, rk[0]); t = _mm_aesenc_si128(t, rk[1]);
            t = _mm_aesenc_si128(t, rk[2]); t = _mm_aesenc_si128(t, rk[3]);
            t = _mm_aesenc_si128(t, rk[4]); t = _mm_aesenc_si128(t, rk[5]);
            t = _mm_aesenc_si128(t, rk[6]); t = _mm_aesenc_si128(t, rk[7]);
            t = _mm_aesenc_si128(t, rk[8]); t = _mm_aesenc_si128(t, rk[9]);
            s[b] = t;
        }
        uint8_t *dst = buf + (size_t)it * 128;
        for (int b = 0; b < 8; b++) _mm_storeu_si128((__m128i *)(dst + b * 16), s[b]);
    }
}

static uint64_t cpu_chase_v7(uint64_t *buf, uint64_t qw, unsigned passes, unsigned hops, uint64_t gid) {
    uint64_t fx = 0x9e3779b97f4a7c15ULL ^ (gid * 0x2545F4914F6CDD1DULL);
    for (uint64_t i = 0; i < qw; i++) { fx = (fx ^ (fx >> 29)) * 0xbf58476d1ce4e5b9ULL; buf[i] = fx; }
    uint64_t chain = fx, reg = fx ^ 0x1234567ULL;
    for (unsigned p = 0; p < passes; p++)
        for (unsigned h = 0; h < hops; h++) {
            uint64_t am = reg + (uint64_t)h + chain;
            uint64_t idx = mulhi64(am, qw);
            uint64_t v = buf[idx];
            buf[idx] = v ^ am;
            chain = v + (uint64_t)h;
            reg ^= v;
        }
    return chain ^ reg;
}

static uint64_t cpu_chase_v6(uint64_t *buf, uint64_t qw, unsigned steps, const __m128i *rk, uint64_t gid) {
    aes_fill_pad_cpu((uint8_t *)buf, (unsigned)(qw * 8 / 128), rk, gid);
    // mulhi64 maps uniformly into [0,qw) for ANY qw, matching the kernel. The
    // old (qw-1) mask required a power-of-two pad, which 1.25 and 1.5 MB are
    // not. Both sides must index the same way or GPU:CPU means nothing.
    uint64_t chain = 0, reg = buf[0];
    for (unsigned s = 0; s < steps; s++) {
        uint64_t addr = mulhi64(reg + (uint64_t)s + chain, qw);
        uint64_t v = buf[addr];
        if ((s & 7u) < 3u) { buf[addr] = v ^ reg; chain += v ^ reg; }
        else               { chain = v; }
        reg += v;
    }
    return chain ^ reg;
}

static uint64_t cpu_chase_v5(uint64_t *buf, uint64_t qw, unsigned steps, const __m128i *rk, uint64_t gid) {
    aes_fill_pad_cpu((uint8_t *)buf, (unsigned)(qw * 8 / 128), rk, gid);
    uint64_t a = buf[0], b = buf[1];
    for (unsigned s = 0; s < steps; s++) {
        uint64_t addr = mulhi64(a, qw);      // see cpu_chase_v6 on why not a mask
        uint64_t v = buf[addr];
        uint64_t t = v ^ b;
        buf[addr] = t;
        b = v;
        a = t + (a >> 3);
    }
    return a ^ b;
}


// proposal: 256 KB pad, AES-NI inside the dependency chain
static uint64_t cpu_chase_v8(uint64_t *buf, uint64_t qw, unsigned steps, const __m128i *rk, uint64_t gid) {
    aes_fill_pad_cpu((uint8_t *)buf, (unsigned)(qw * 8 / 128), rk, gid);
    const uint64_t blocks = qw / 2;
    __m128i acc = _mm_loadu_si128((const __m128i *)buf);
    uint64_t chain = buf[0];
    for (unsigned s = 0; s < steps; s++) {
        uint64_t idx = (chain ^ (uint64_t)s) % blocks;
        __m128i *blk = (__m128i *)(buf + idx * 2);
        __m128i b = _mm_loadu_si128(blk);
        acc = _mm_aesenc_si128(_mm_xor_si128(acc, b), rk[0]);
        _mm_storeu_si128(blk, acc);
        chain = (uint64_t)_mm_cvtsi128_si64(acc);
    }
    uint64_t tmp[2]; _mm_storeu_si128((__m128i *)tmp, acc);
    return chain ^ tmp[1];
}


// v7b: shared read-only dataset + 256 KB per-nonce pad, divergent program
static uint64_t cpu_chase_v7b(uint64_t *pad, uint64_t pad_qw,
                              const uint64_t *dataset, uint64_t ds_qw,
                              unsigned passes, uint64_t gid) {
    const uint64_t pad_mask = pad_qw - 1;
    unsigned char op[64], dst[64], src[64]; uint32_t imm[64];
    uint32_t r = (uint32_t)gid * 2654435761u + 12345u;
    for (int i = 0; i < 64; i++) {
        r ^= r << 13; r ^= r >> 17; r ^= r << 5;
        op[i] = (unsigned char)(r % 7u); dst[i] = (unsigned char)((r >> 8) & 7u);
        src[i] = (unsigned char)((r >> 12) & 7u); imm[i] = r;
    }
    uint64_t regs[8];
    for (int i = 0; i < 8; i++) { r ^= r << 13; r ^= r >> 17; r ^= r << 5; regs[i] = (uint64_t)r * 0x9e3779b97f4a7c15ULL; }
    uint64_t chain = regs[0], wchain = 0;
    for (unsigned p = 0; p < passes; p++) {
        int pc = 0;
        for (int seg = 0; seg < 8; seg++) {
            chain ^= regs[seg & 7];
            for (int h = 0; h < 128; h++) {
                uint64_t idx = mulhi64(chain, ds_qw);
                uint64_t v = dataset[idx];
                chain = v + (uint64_t)h;
            }
            for (int s = 0; s < 8; s++) {
                int i = pc & 63;
                unsigned char o = op[i], d = dst[i], sc = src[i];
                if (o == 0) regs[d] += regs[sc] << (imm[i] & 3);
                else if (o == 1) regs[d] -= regs[sc];
                else if (o == 2) regs[d] *= regs[sc];
                else if (o == 3) regs[d] ^= regs[sc];
                else if (o == 4) { unsigned sh = (unsigned)(regs[sc] & 63); regs[d] = (regs[d] >> sh) | (regs[d] << ((64 - sh) & 63)); }
                else if (o == 5) { if (regs[d] & ((uint64_t)imm[i] | 1ULL)) pc += (int)(imm[i] & 7) - 4; }
                else { uint64_t a2 = (regs[d] + chain) & pad_mask; uint64_t t = pad[a2] ^ regs[sc]; pad[a2] = t; wchain += t; }
                pc++;
            }
        }
    }
    return chain ^ wchain ^ regs[0];
}

static std::vector<uint64_t> g_dataset;
static void ensure_dataset(uint64_t qw) {
    if (g_dataset.size() == qw) return;
    g_dataset.resize(qw);
    uint64_t fx = 0x9e3779b97f4a7c15ULL;
    for (uint64_t i = 0; i < qw; i++) { fx = (fx ^ (fx >> 29)) * 0xbf58476d1ce4e5b9ULL; g_dataset[i] = fx; }
}

static double cpu_bench(int which, size_t buf_kb, unsigned passes, unsigned hops,
                        unsigned steps, unsigned threads, unsigned per) {
    const uint64_t qw = (uint64_t)buf_kb * 1024 / 8;
    __m128i rk[10];
    for (int i = 0; i < 10; i++) {
        uint32_t v[4]; for (int j = 0; j < 4; j++) v[j] = 0x9e3779b9u * (uint32_t)(i * 4 + j + 1);
        rk[i] = _mm_loadu_si128((const __m128i *)v);
    }
    if (which == 9) ensure_dataset(256ull * 1024 * 1024 / 8);

    // Two things used to be inside the clock and are not any more.
    // 1. Each thread allocates and zeroes its pad. At 32 threads that is up to
    //    768 MB of memset for v7, which made wide thread counts look like the
    //    algorithm collapsing when it was really the allocator. Threads now set
    //    up and run one warm nonce, then wait at a barrier.
    // 2. Work was split evenly up front, so the unluckiest thread set the
    //    elapsed time. Nonces now come from one shared counter.
    const int total = (int)(threads * per);
    std::atomic<uint64_t> sink(0);
    std::atomic<unsigned> ready(0);
    std::atomic<bool> go(false);
    std::atomic<int> remaining(total);

    auto worker = [&](unsigned t) {
        std::vector<uint64_t> buf(qw);
        uint64_t acc = 0;
        auto one = [&](uint64_t gid) -> uint64_t {
            if (which == 9)      return cpu_chase_v7b(buf.data(), qw, g_dataset.data(), g_dataset.size(), passes, gid);
            else if (which == 8) return cpu_chase_v8(buf.data(), qw, steps, rk, gid);
            else if (which == 7) return cpu_chase_v7(buf.data(), qw, passes, hops, gid);
            else if (which == 6) return cpu_chase_v6(buf.data(), qw, steps, rk, gid);
            else                 return cpu_chase_v5(buf.data(), qw, steps, rk, gid);
        };
        acc ^= one(t * 1000);                       // warm, faults the pad in
        ready++;
        while (!go.load(std::memory_order_acquire)) std::this_thread::yield();

        unsigned i = 0;
        while (remaining.fetch_sub(1, std::memory_order_relaxed) > 0)
            acc ^= one(t * 1000 + (++i));
        sink ^= acc;
    };

    std::vector<std::thread> ts;
    for (unsigned t = 0; t < threads; t++) ts.emplace_back(worker, t);
    while (ready.load() < threads) std::this_thread::yield();

    const auto t0 = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto &t : ts) t.join();
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (sink.load() == 1) printf("");
    return total / secs;
}

// One nonce, single thread, so the caller can size the real runs. The two
// machines this runs on differ by several times in speed, and fixed counts
// tuned on one of them make the other either crawl or measure noise.
static double cpu_one_ms(int which, size_t buf_kb, unsigned passes, unsigned hops, unsigned steps) {
    // take it from cpu_bench's own clock, which already excludes the warm
    // nonce and the allocation
    const double hs = cpu_bench(which, buf_kb, passes, hops, steps, 1, 1);
    return hs > 0.0 ? 1000.0 / hs : 1e9;
}
