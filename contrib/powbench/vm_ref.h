#pragma once
// CPU side of the faithful CNA cores. Mirrors vm_kernels.cl.h instruction for
// instruction, and is checked against it: main.cpp compares per-nonce
// checksums and refuses to report any row where the GPU and CPU disagree.
// That check is the only thing keeping these two copies honest, so do not
// remove it.
//
// Ported from src/crypto/cna-vm.c and src/crypto/slow-hash-impl.h.
#include <stdint.h>
#include <string.h>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <wmmintrin.h>

#define CN_REG_COUNT    8
#define CN_PROGRAM_SIZE 512
#define CN_VM_ITERATIONS 2048
#define CN_V7_HOPS      1024
#define CN_V7_SEGMENTS  8
#define CN_V7_SEG_MIN   80
#define CN_SALT_MEMORY  262144
#define CN_V7_PAD_BYTES (256 * 1024)

enum { CN_OP_IADD_RS = 0, CN_OP_ISUB, CN_OP_IMUL, CN_OP_IXOR, CN_OP_IROR,
       CN_OP_CBRANCH, CN_OP_SP_READ, CN_OP_SP_WRITE, CN_OP_MIX };

#pragma pack(push, 1)
struct cn_ins_t { uint8_t op, dst, src, shift; uint32_t imm; };
#pragma pack(pop)

static inline uint64_t vm_ror64(uint64_t x, uint32_t r) {
    r &= 63; if (r == 0) return x;
    return (x >> r) | (x << (64 - r));
}
// cna-vm.c mix64, verbatim
static inline uint64_t vm_mix64(uint64_t val, uint32_t key_material) {
    uint64_t k = (uint64_t)key_material * 0x9e3779b97f4a7c15ULL;
    val ^= k;
    val ^= val >> 30; val *= 0xbf58476d1ce4e5b9ULL;
    val ^= val >> 27; val *= 0x94d049bb133111ebULL;
    val ^= val >> 31;
    return val;
}
static inline uint64_t vm_mulhi(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
}

// Program generator. The real one (cn_vm_generate_program) draws from HC128;
// this draws from splitmix64. The KEYSTREAM differs, the DISTRIBUTION does not:
// same 512 instructions, same 51-63% memory share, same 55/45 read/write split,
// same even weighting over the seven ALU ops, same segment-hop redistribution.
// Timing depends on the distribution, not on which bits the PRNG produced, and
// porting HC128 would cost self-containment for nothing. Both the CPU and GPU
// run the SAME generated programs, uploaded from here, so the checksum test is
// unaffected.
struct SM64 {
    uint64_t s;
    uint64_t next() { uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31); }
    uint32_t u32(uint32_t n) { return (uint32_t)(next() % n); }
};

static void vm_generate_program(cn_ins_t *ins, uint16_t *seg_hops, uint64_t seed)
{
    SM64 r{ seed * 0x9e3779b97f4a7c15ULL + 0x1234567ULL };
    static const uint8_t alu_ops[7] = { CN_OP_IADD_RS, CN_OP_ISUB, CN_OP_IMUL,
                                        CN_OP_IXOR, CN_OP_IROR, CN_OP_CBRANCH, CN_OP_MIX };
    const uint32_t mem_pct = 51u + r.u32(13u);
    for (int i = 0; i < CN_PROGRAM_SIZE; i++) {
        if (r.u32(100u) < mem_pct)
            ins[i].op = (r.u32(100u) < 55u) ? CN_OP_SP_READ : CN_OP_SP_WRITE;
        else
            ins[i].op = alu_ops[r.u32(7u)];
        ins[i].dst   = (uint8_t)r.u32(CN_REG_COUNT);
        ins[i].src   = (uint8_t)r.u32(CN_REG_COUNT);
        ins[i].shift = (uint8_t)r.u32(256);
        uint32_t lo = r.u32(0x10000), hi = r.u32(0x10000);
        ins[i].imm = (hi << 16) | lo;
    }
    for (int i = 0; i < CN_V7_SEGMENTS; i++)
        seg_hops[i] = (uint16_t)(CN_V7_HOPS / CN_V7_SEGMENTS);
    const uint16_t seg_cap = (uint16_t)(CN_V7_HOPS - (CN_V7_SEGMENTS - 1) * CN_V7_SEG_MIN);
    for (int k = 0; k < 24; k++) {
        const int a = (int)r.u32(CN_V7_SEGMENTS), b = (int)r.u32(CN_V7_SEGMENTS);
        uint16_t amt = (uint16_t)r.u32(32u);
        if (a == b) continue;
        if (seg_hops[a] < (uint16_t)(CN_V7_SEG_MIN + amt)) amt = (uint16_t)(seg_hops[a] - CN_V7_SEG_MIN);
        if ((uint16_t)(seg_hops[b] + amt) > seg_cap)       amt = (uint16_t)(seg_cap - seg_hops[b]);
        seg_hops[a] = (uint16_t)(seg_hops[a] - amt);
        seg_hops[b] = (uint16_t)(seg_hops[b] + amt);
    }
}

// AES-NI fill, matching the kernel's T-table fill: 10 rounds per 16-byte block,
// 8 blocks, PAD/128 iterations, same as aes_pseudo_round.
static void vm_aes_fill(uint8_t *buf, unsigned iters, const __m128i *rk, uint64_t gid) {
    __m128i s[8];
    uint32_t seed = (uint32_t)gid * 2654435761u + 1u;
    uint32_t w[32];
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; w[i] = seed; }
    for (int b = 0; b < 8; b++) s[b] = _mm_loadu_si128((const __m128i *)(w + b * 4));
    for (unsigned it = 0; it < iters; it++) {
        for (int b = 0; b < 8; b++) {
            __m128i t = s[b];
            for (int r = 0; r < 10; r++) t = _mm_aesenc_si128(t, rk[r]);
            s[b] = t;
        }
        uint8_t *dst = buf + (size_t)it * 128;
        for (int b = 0; b < 8; b++) _mm_storeu_si128((__m128i *)(dst + b * 16), s[b]);
    }
}

// finalize_hash: the second full AES pass over the pad, XORing each block in
// (aes_pseudo_round_xor). Mirrors aes_finalize in the kernel.
static uint64_t vm_aes_finalize(const uint8_t *buf, unsigned iters, const __m128i *rk, uint64_t gid) {
    __m128i s[8];
    uint32_t seed = (uint32_t)gid * 2654435761u + 99u;
    uint32_t w[32];
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; w[i] = seed; }
    for (int b = 0; b < 8; b++) s[b] = _mm_loadu_si128((const __m128i *)(w + b * 4));
    for (unsigned it = 0; it < iters; it++) {
        const uint8_t *src = buf + (size_t)it * 128;
        for (int b = 0; b < 8; b++) {
            __m128i t = _mm_xor_si128(s[b], _mm_loadu_si128((const __m128i *)(src + b * 16)));
            for (int r = 0; r < 10; r++) t = _mm_aesenc_si128(t, rk[r]);
            s[b] = t;
        }
    }
    uint64_t acc = 0;
    for (int b = 0; b < 8; b++) {
        acc ^= (uint64_t)_mm_cvtsi128_si64(s[b]);
        acc ^= (uint64_t)_mm_extract_epi64(s[b], 1);
    }
    return acc;
}

static void vm_init_regs(uint64_t regs[CN_REG_COUNT], uint64_t gid) {
    uint64_t x = gid * 0x9e3779b97f4a7c15ULL + 0x123456789abcdefULL;
    for (int i = 0; i < CN_REG_COUNT; i++) { x = vm_mix64(x, (uint32_t)i + 1u); regs[i] = x; }
}

// --------------------------------------------------------------------------
// v6: cn_vm_execute against the pad, iters passes.
// --------------------------------------------------------------------------
static uint64_t vm_v6(uint64_t *pad, uint64_t qw, const cn_ins_t *prog,
                      const uint8_t *salt, unsigned iters, const __m128i *rk, uint64_t gid)
{
    vm_aes_fill((uint8_t *)pad, (unsigned)(qw * 8 / 128), rk, gid);
    {
        uint32_t s_off = 0;
        uint32_t *p32 = (uint32_t *)pad;
        const uint32_t n32 = (uint32_t)(qw * 2);
        const uint32_t *s32 = (const uint32_t *)salt;
        for (uint32_t i = 0; i < n32; i++) {
            p32[i] ^= s32[s_off >> 2];
            s_off += 4; if (s_off >= CN_SALT_MEMORY) s_off = 0;
        }
    }
    uint64_t regs[CN_REG_COUNT];
    vm_init_regs(regs, gid);
    const uint64_t sp_mask = ((qw * 8) - 1) & ~7ULL;
    const uint32_t pc_mask = CN_PROGRAM_SIZE - 1;
    for (unsigned pass = 0; pass < iters; pass++) {
        uint32_t pc = 0;
        uint64_t chain = 0;
        for (uint32_t step = 0; step < CN_PROGRAM_SIZE; step++) {
            const cn_ins_t *ins = &prog[pc & pc_mask];
            uint32_t next_pc = pc + 1;
            const uint8_t dst = ins->dst, src = ins->src;
            const uint32_t imm = ins->imm;
            switch (ins->op) {
            case CN_OP_IADD_RS: regs[dst] += regs[src] << (ins->shift & 3); break;
            case CN_OP_ISUB:    regs[dst] -= regs[src]; break;
            case CN_OP_IMUL:    regs[dst] *= regs[src]; break;
            case CN_OP_IXOR:    regs[dst] ^= regs[src]; break;
            case CN_OP_IROR:    regs[dst] = vm_ror64(regs[dst], (uint32_t)(regs[src] & 63)); break;
            case CN_OP_CBRANCH:
                if (regs[dst] & ((uint64_t)imm | 1ULL))
                    next_pc = (uint32_t)(((int)pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & (int)pc_mask);
                break;
            case CN_OP_SP_READ: {
                uint64_t addr = (regs[src] + (uint64_t)imm + chain) & sp_mask;
                regs[dst] = pad[addr >> 3];
                chain = regs[dst];
                break;
            }
            case CN_OP_SP_WRITE: {
                uint64_t addr = (regs[dst] + (uint64_t)imm + chain) & sp_mask;
                uint64_t tmp = pad[addr >> 3] ^ regs[src];
                pad[addr >> 3] = tmp;
                chain += tmp;
                break;
            }
            case CN_OP_MIX: regs[dst] = vm_mix64(regs[dst] ^ regs[src], imm); break;
            default: break;
            }
            pc = next_pc;
        }
    }
    uint64_t acc = 0;
    for (int i = 0; i < CN_REG_COUNT; i++) acc ^= regs[i];
    acc ^= vm_aes_finalize((const uint8_t *)pad, (unsigned)(qw * 8 / 128), rk, gid);
    return acc ? acc : 1ULL;
}

// --------------------------------------------------------------------------
// v7: cn_vm_execute_v7.
// --------------------------------------------------------------------------
static uint64_t vm_v7(uint64_t *buf, uint64_t qw, const cn_ins_t *prog,
                      const uint16_t *seg_hops, uint64_t *vals, uint64_t *pad,
                      uint64_t pad_qw, unsigned iters, const __m128i *rk, uint64_t gid,
                      const uint8_t *salt)
{
    // cn_slow_hash_v14 AES-fills and salt-XORs only the 256 KB pad; the 24 MB
    // buffer gets a cheap splitmix fill. AES-filling the buffer was ~96x the
    // real AES work and, since the GPU pays T-tables against the CPU's AES-NI,
    // that phantom work dominated the GPU measurement.
    vm_aes_fill((uint8_t *)pad, (unsigned)(pad_qw * 8 / 128), rk, gid);
    {
        uint32_t s_off = 0;
        uint32_t *p32 = (uint32_t *)pad;
        const uint32_t n32 = (uint32_t)(pad_qw * 2);
        const uint32_t *s32 = (const uint32_t *)salt;
        for (uint32_t i = 0; i < n32; i++) {
            p32[i] ^= s32[s_off >> 2];
            s_off += 4; if (s_off >= CN_SALT_MEMORY) s_off = 0;
        }
    }
    {
        uint64_t fx = 0x9e3779b97f4a7c15ULL ^ (gid * 0x2545F4914F6CDD1DULL);
        if (fx == 0) fx = 0x9e3779b97f4a7c15ULL;
        for (uint64_t bi = 0; bi < qw; bi++) {
            fx = (fx ^ (fx >> 29)) * 0xbf58476d1ce4e5b9ULL;
            buf[bi] = fx;
        }
    }
    uint64_t regs[CN_REG_COUNT];
    vm_init_regs(regs, gid);
    const uint64_t sp_mask   = ((pad_qw * 8) - 1) & ~7ULL;
    const uint32_t pc_mask   = CN_PROGRAM_SIZE - 1;
    const uint32_t seg_steps = CN_PROGRAM_SIZE / CN_V7_SEGMENTS;
    uint64_t chain = 0;
    for (unsigned pass = 0; pass < iters; pass++) {
        uint32_t pc = 0, consume = 0, filled = 0, walk_pc = 0;
        uint64_t wchain = 0;
        for (uint32_t seg = 0; seg < CN_V7_SEGMENTS; seg++) {
            const uint32_t nh = seg_hops[seg];
            for (uint32_t h = 0; h < nh; h++) {
                const cn_ins_t *hop = &prog[walk_pc & pc_mask];
                const uint32_t hop_reg = (uint32_t)((hop->src + h) & (CN_REG_COUNT - 1));
                const uint64_t am = regs[hop_reg] + (uint64_t)hop->imm + chain;
                const uint64_t idx = vm_mulhi(am, qw);
                const uint64_t v = buf[idx];
                buf[idx] = v ^ am;
                chain = v + (uint64_t)h;
                walk_pc += 1u + (uint32_t)(v & 3u);
                vals[filled++] = v;
            }
            for (uint32_t step = 0; step < seg_steps; step++) {
                const cn_ins_t *ins = &prog[pc & pc_mask];
                uint32_t next_pc = pc + 1;
                const uint8_t dst = ins->dst, src = ins->src;
                const uint32_t imm = ins->imm;
                switch (ins->op) {
                case CN_OP_IADD_RS: regs[dst] += regs[src] << (ins->shift & 3); break;
                case CN_OP_ISUB:    regs[dst] -= regs[src]; break;
                case CN_OP_IMUL:    regs[dst] *= regs[src]; break;
                case CN_OP_IXOR:    regs[dst] ^= regs[src]; break;
                case CN_OP_IROR:    regs[dst] = vm_ror64(regs[dst], (uint32_t)(regs[src] & 63)); break;
                case CN_OP_CBRANCH:
                    if (regs[dst] & ((uint64_t)imm | 1ULL))
                        next_pc = (uint32_t)(((int)pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & (int)pc_mask);
                    break;
                case CN_OP_SP_READ:
                    regs[dst] ^= vals[consume & (CN_V7_HOPS - 1)] + (uint64_t)imm;
                    consume++;
                    break;
                case CN_OP_SP_WRITE: {
                    uint64_t addr = (regs[dst] + (uint64_t)imm + wchain) & sp_mask;
                    uint64_t tmp = pad[addr >> 3] ^ regs[src];
                    pad[addr >> 3] = tmp;
                    wchain += tmp;
                    break;
                }
                case CN_OP_MIX: regs[dst] = vm_mix64(regs[dst] ^ regs[src], imm); break;
                default: break;
                }
                pc = next_pc;
            }
        }
        regs[0] ^= wchain;
    }
    uint64_t acc = 0;
    for (int i = 0; i < CN_REG_COUNT; i++) acc ^= regs[i];
    acc ^= vm_aes_finalize((const uint8_t *)pad, (unsigned)(pad_qw * 8 / 128), rk, gid);
    return acc ? acc : 1ULL;
}


// --------------------------------------------------------------------------
// PLAN-v8 Phase 2: the floating-point stage, mirroring src/crypto/slow-hash-fp.h,
// which is now only at tag archive/cna-v8-fp-stage.
//
// This is the reference the OpenCL kernels are checked against, so it uses the
// real rounding-mode changes rather than the kernels' emulation of them. A row
// that reports ok=yes has therefore proved that the GPU's software emulation
// of directed rounding produces bit-identical results to a CPU's MXCSR or
// FPCR, which is what makes the timing on that row mean anything.
//
// fesetround is called through a noinline wrapper with memory clobbers, for
// the same reason RandomX puts rx_set_rounding_mode in its own translation
// unit: GCC and Clang both ignore #pragma STDC FENV_ACCESS, so without an
// opaque barrier they may assume round-to-nearest throughout and fold
// arithmetic across the mode change.
// --------------------------------------------------------------------------
#include <fenv.h>
#include <math.h>

#define CN_V8_FP_ROUNDS     9600
#define CN_V8_FP_ROUND_MASK 15

#if defined(__GNUC__) || defined(__clang__)
#  define VM_FP_NOINLINE __attribute__((noinline))
#  define VM_FP_BARRIER() __asm__ __volatile__("" ::: "memory")
#elif defined(_MSC_VER)
#  define VM_FP_NOINLINE __declspec(noinline)
#  define VM_FP_BARRIER() _ReadWriteBarrier()
#else
#  define VM_FP_NOINLINE
#  define VM_FP_BARRIER() ((void)0)
#endif

static const int vm_fp_modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };

static VM_FP_NOINLINE void vm_fp_set_round(int mode)
{
    VM_FP_BARRIER();
    fesetround(mode);
    VM_FP_BARRIER();
}

static inline double vm_fp_bits_to_e(uint64_t bits)
{
    const uint64_t e = 0x300ull | ((bits >> 52) & 0xFFull);
    const uint64_t o = (e << 52) | (bits & 0x000FFFFFFFFFFFFFull);
    double d; memcpy(&d, &o, sizeof(d)); return d;
}

static inline uint64_t vm_fp_e_to_bits(double d)
{
    uint64_t u; memcpy(&u, &d, sizeof(u)); return u;
}

// Every result passes through the constraint before anything reads it, so no
// multiply feeds an add and there is no contraction for a compiler to do.
#define VM_FP_ROUND(e)                                                  \
    e[0] = e[0] + e[1]; e[0] = vm_fp_bits_to_e(vm_fp_e_to_bits(e[0]));  \
    e[1] = e[1] - e[2]; e[1] = vm_fp_bits_to_e(vm_fp_e_to_bits(e[1]));  \
    e[2] = e[2] * e[3]; e[2] = vm_fp_bits_to_e(vm_fp_e_to_bits(e[2]));  \
    e[3] = e[3] / e[0]; e[3] = vm_fp_bits_to_e(vm_fp_e_to_bits(e[3]));  \
    e[0] = sqrt(e[0]);  e[0] = vm_fp_bits_to_e(vm_fp_e_to_bits(e[0]));

// fp_mode 0: fixed nearest-even, the matching reference for cna_v8_fp_rne,
// which is not the algorithm but isolates the arithmetic from the mode change.
// fp_mode 1: the algorithm, modes selected from data every sixteenth round.
static void vm_fp_stage(uint64_t *pad, uint64_t nblocks,
                        uint64_t *pa0, uint64_t *pa1, int fp_mode,
                        uint32_t rounds)
{
    const uint64_t mask = nblocks - 1;
    const uint64_t a0 = *pa0, a1 = *pa1;
    uint64_t *p0 = pad + ((a0 >> 4) & mask) * 2;
    uint64_t *p1 = pad + ((a1 >> 4) & mask) * 2;
    double e[4];

    e[0] = vm_fp_bits_to_e(p0[0]);
    e[1] = vm_fp_bits_to_e(p0[1]);
    e[2] = vm_fp_bits_to_e(p1[0] ^ a0);
    e[3] = vm_fp_bits_to_e(p1[1] ^ a1);

    for (uint32_t r = 0; r < rounds; r++) {
        if (fp_mode && (r & CN_V8_FP_ROUND_MASK) == 0)
            vm_fp_set_round(vm_fp_modes[(vm_fp_e_to_bits(e[0]) >> 3) & 3]);
        VM_FP_ROUND(e)
    }
    if (fp_mode) vm_fp_set_round(FE_TONEAREST);

    p1[0] ^= vm_fp_e_to_bits(e[2]);
    p1[1] ^= vm_fp_e_to_bits(e[1]);
    p0[0] ^= vm_fp_e_to_bits(e[0]);
    p0[1] ^= vm_fp_e_to_bits(e[3]);

    *pa0 = a0 ^ vm_fp_e_to_bits(e[0]) ^ vm_fp_e_to_bits(e[2]);
    *pa1 = a1 ^ vm_fp_e_to_bits(e[1]) ^ vm_fp_e_to_bits(e[3]);
}
// --------------------------------------------------------------------------
// v5: cn_slow_hash_v11's inner loop. No VM.
// --------------------------------------------------------------------------
static uint64_t vm_v5(uint64_t *pad, uint64_t qw, const uint8_t *params,
                      uint64_t *salt, uint64_t salt_qw,
                      const __m128i *rk, uint64_t gid, int fp_mode,
                      uint32_t fp_rounds, int no_sweep)
{
    // Per-nonce salt, derived exactly as the kernel does so the checksum gate
    // can compare them. Real v5 gets this from the chain; content does not
    // affect timing.
    { uint64_t sx = gid * 0x9e3779b97f4a7c15ULL + 0xABCDEFULL;
      for (uint32_t i = 0; i < (uint32_t)salt_qw; i++) { sx = vm_mix64(sx, i + 1u); salt[i] = sx; } }

    vm_aes_fill((uint8_t *)pad, (unsigned)(qw * 8 / 128), rk, gid);
    // randomize_scratchpad_256k, which cn_slow_hash_v11 runs right after the
    // fill. One BYTE every four is XORed with successive salt bytes, so it is
    // PAD/4 iterations. Note this is NOT v13's salt pass, which XORs a full
    // 32-bit word every four bytes. Omitting it made v5 read 1.85x too fast.
    {
        uint8_t *sp8 = (uint8_t *)pad;
        const uint8_t *ss8 = (const uint8_t *)salt;
        uint32_t x = 0;
        const uint32_t nb = (uint32_t)(qw * 8);
        for (uint32_t i = 0; i < nb; i += 4) {
            sp8[i] ^= ss8[x++];
            if (x >= CN_SALT_MEMORY) x = 0;
        }
    }
    const uint32_t xx   = 4u + params[0];
    const uint32_t yy   = 4u + params[1];
    const uint32_t it_n = params[2];
    const uint64_t nblocks = qw / 2;
    uint64_t a0 = pad[0], a1 = pad[1], b0 = pad[2], b1 = pad[3];
    uint64_t salt_acc = 0;
    // salt_pad walks hp_state as BYTES with a byte stride, so the sweep runs
    // PAD/offset_2 times, not PAD/4/offset_2. Indexing 32-bit words here did a
    // quarter of the work and made v5 read 4x too fast.
    const uint32_t salt_mask8 = (uint32_t)(salt_qw * 8) - 1;
    uint8_t *p8 = (uint8_t *)pad;
    const uint8_t *s8 = (const uint8_t *)salt;
    const uint32_t nbytes = (uint32_t)(qw * 8);

    #define V5_STEP() do {                                                    \
        uint64_t j = (a0 >> 4) % nblocks;                                     \
        __m128i c = _mm_loadu_si128((const __m128i *)&pad[j*2]);              \
        __m128i ky = _mm_set_epi64x((long long)a1, (long long)a0);            \
        __m128i n = _mm_aesenc_si128(c, ky);                                  \
        uint64_t n0 = (uint64_t)_mm_cvtsi128_si64(n);                         \
        uint64_t n1 = (uint64_t)_mm_extract_epi64(n, 1);                      \
        pad[j*2] = b0 ^ n0; pad[j*2+1] = b1 ^ n1;                             \
        uint64_t j2 = (n0 >> 4) % nblocks;                                    \
        uint64_t p0 = pad[j2*2], p1 = pad[j2*2+1];                            \
        uint64_t hi = vm_mulhi(n0, p0), lo = n0 * p0;                         \
        a0 += hi; a1 += lo;                                                   \
        pad[j2*2] = a0; pad[j2*2+1] = a1;                                     \
        a0 ^= p0; a1 ^= p1;                                                   \
        b0 = n0; b1 = n1;                                                     \
    } while (0)

    for (uint32_t k = 1; k < xx; k++) {
        for (uint32_t l = 0; l < yy; l++) {
            V5_STEP();
            /* D1 deleted this block from consensus, dbd4fd7. no_sweep is a
             * constant at every call site. */
            if (!no_sweep) {
            salt_acc = vm_mix64(salt_acc ^ a0, (uint32_t)(k * 31u + l));
            uint32_t off1 = ((uint32_t)(salt_acc & 63)) + 1u;
            uint32_t off2 = ((((uint32_t)(salt_acc >> 8)) * off1) % 125u) + 4u;
            uint32_t sx = 0;
            for (uint32_t jj = off1; jj < nbytes; jj += off2) {
                p8[jj] ^= s8[sx & salt_mask8];
                sx++;
            }
            }
        }
    }
    // CN_FP_STAGE() in slow-hash-v8-impl.h sits here: after the xx/yy loop,
    // before the iters loop. fp_mode < 0 is v5, which has no stage.
    if (fp_mode >= 0) vm_fp_stage(pad, nblocks, &a0, &a1, fp_mode, fp_rounds);

    for (uint32_t i = 0; i < it_n; i++) V5_STEP();
    #undef V5_STEP
    uint64_t acc = a0 ^ a1 ^ b0 ^ b1 ^ salt_acc;
    acc ^= vm_aes_finalize((const uint8_t *)pad, (unsigned)(qw * 8 / 128), rk, gid);
    return acc ? acc : 1ULL;
}
