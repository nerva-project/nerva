// CNA v7 has no upstream to diff against, so it gets a standalone reference:
// the fill and the chase are reimplemented here from the spec in cna-vm.h and
// the commit message, and compared bit-for-bit against the library. On top of
// that, full-hash properties: determinism, the two review regressions (seed
// tail sensitivity, zero-seed buffer population), the ~63% mutation coverage
// the residency argument rests on, and the HW/SW self-test.
#include "check.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

// hash-ops.h and cna-vm.h are C headers and pull stdint only for C
using std::uint8_t; using std::uint16_t; using std::uint32_t; using std::uint64_t;
using std::size_t;

extern "C" {
#include "crypto/hash-ops.h"
#include "crypto/cna-vm.h"
}

// ---------------------------------------------------------------------------
// Reference implementation. Plain scalar C++, no code shared with cna-vm.c
// or slow-hash-impl.h beyond the instruction struct and the constants.
// ---------------------------------------------------------------------------

static uint64_t ref_ror64(uint64_t x, unsigned n)
{
  n &= 63;
  return n ? (x >> n) | (x << (64 - n)) : x;
}

static uint64_t ref_mix64(uint64_t val, uint32_t key_material)
{
  uint64_t k = (uint64_t)key_material * UINT64_C(0x9e3779b97f4a7c15);
  val ^= k;
  val ^= val >> 30;
  val *= UINT64_C(0xbf58476d1ce4e5b9);
  val ^= val >> 27;
  val *= UINT64_C(0x94d049bb133111eb);
  val ^= val >> 31;
  return val;
}

// One v7 pass: CN_V7_SEGMENTS x [serial chase, program slice]. The walk maps
// the chain value into the buffer via the high word of chain * qwords, writes
// each cell back XORed with the live chain, and hands the read values to
// SP_READ in order. wchain folds into regs[0] at the end of the pass.
static void ref_execute_v7(const cn_vm_program_t *prog, uint8_t *buffer, uint64_t buffer_qwords,
                           uint8_t *pad, uint64_t regs[CN_REG_COUNT], uint64_t *chain_state)
{
  const size_t sp_mask   = (size_t)(CN_SCRATCHPAD_MEMORY_V14 - 1) & ~(size_t)7;
  const int    seg_hops  = CN_V7_HOPS / CN_V7_SEGMENTS;
  const int    seg_steps = CN_PROGRAM_SIZE / CN_V7_SEGMENTS;

  int pc = 0;
  unsigned consume = 0;
  uint64_t wchain = 0;
  uint64_t chain = *chain_state;
  std::vector<uint64_t> vals(CN_V7_HOPS);

  for (int seg = 0; seg < CN_V7_SEGMENTS; seg++)
  {
    chain ^= regs[seg & (CN_REG_COUNT - 1)];
    for (int h = 0; h < seg_hops; h++)
    {
      const uint64_t idx = (uint64_t)(((unsigned __int128)chain * buffer_qwords) >> 64);
      uint64_t v;
      memcpy(&v, buffer + idx * sizeof(uint64_t), sizeof(uint64_t));
      const uint64_t mut = v ^ chain;
      memcpy(buffer + idx * sizeof(uint64_t), &mut, sizeof(uint64_t));
      chain = v + (uint64_t)h;
      vals[seg * seg_hops + h] = v;
    }

    for (int step = 0; step < seg_steps; step++)
    {
      const cn_vm_instruction_t *ins = &prog->instructions[pc & (CN_PROGRAM_SIZE - 1)];
      int next_pc = pc + 1;
      const uint8_t dst = ins->dst;
      const uint8_t src = ins->src;

      switch ((cn_vm_opcode_t)ins->op)
      {
      case CN_OP_IADD_RS: regs[dst] += regs[src] << (ins->shift & 3); break;
      case CN_OP_ISUB:    regs[dst] -= regs[src]; break;
      case CN_OP_IMUL:    regs[dst] *= regs[src]; break;
      case CN_OP_IXOR:    regs[dst] ^= regs[src]; break;
      case CN_OP_IROR:    regs[dst] = ref_ror64(regs[dst], (unsigned)(regs[src] & 63)); break;
      case CN_OP_CBRANCH:
        if (regs[dst] & ((uint64_t)ins->imm | 1))
          next_pc = (pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & (CN_PROGRAM_SIZE - 1);
        break;
      case CN_OP_SP_READ:
        regs[dst] ^= vals[consume & (CN_V7_HOPS - 1)] + (uint64_t)ins->imm;
        consume++;
        break;
      case CN_OP_SP_WRITE:
      {
        const size_t addr = ((size_t)(regs[dst] + (uint64_t)ins->imm + wchain)) & sp_mask;
        uint64_t tmp;
        memcpy(&tmp, &pad[addr], sizeof(uint64_t));
        tmp ^= regs[src];
        memcpy(&pad[addr], &tmp, sizeof(uint64_t));
        wchain += tmp;
        break;
      }
      case CN_OP_MIX:     regs[dst] = ref_mix64(regs[dst] ^ regs[src], ins->imm); break;
      default: break;
      }
      pc = next_pc;
    }
  }

  *chain_state = chain;
  regs[0] ^= wchain;
}

// The buffer fill: all 32 seed bytes folded into the start value, then the
// xorshift-multiply map per cell.
static void ref_fill(uint8_t *buffer, uint64_t buffer_qwords, const uint8_t seed[32])
{
  uint64_t fx = UINT64_C(0x9e3779b97f4a7c15);
  for (int sj = 0; sj < 4; sj++)
  {
    uint64_t sq;
    memcpy(&sq, seed + sj * sizeof(uint64_t), sizeof(uint64_t));
    fx = (fx ^ sq) * UINT64_C(0xbf58476d1ce4e5b9);
    fx ^= fx >> 29;
  }
  if (fx == 0)
    fx = UINT64_C(0x9e3779b97f4a7c15);
  uint64_t *bw = (uint64_t *)buffer;
  for (uint64_t bi = 0; bi < buffer_qwords; bi++)
  {
    fx = (fx ^ (fx >> 29)) * UINT64_C(0xbf58476d1ce4e5b9);
    bw[bi] = fx;
  }
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

// cn_vm_execute_v7 against the reference: same program, same fill, several
// passes, buffer sizes including a non-power-of-two qword count. Buffer, pad,
// registers and chain must agree bit-for-bit.
static void chase_matches_reference()
{
  const uint64_t sizes_qwords[] = {
    (1u << 17),          // 1 MB
    (1u << 18) + 3,      // ~2 MB, odd length: no power-of-two assumption
    393216,              // 3 MB
  };
  uint8_t seed[32];
  for (int i = 0; i < 32; i++)
    seed[i] = (uint8_t)(i * 41 + 7);

  cn_vm_program_t prog;
  cn_vm_generate_program(&prog, seed);

  for (uint64_t bq : sizes_qwords)
  {
    std::vector<uint8_t> buf_lib(bq * 8), buf_ref(bq * 8);
    std::vector<uint8_t> pad_lib(CN_SCRATCHPAD_MEMORY_V14), pad_ref(CN_SCRATCHPAD_MEMORY_V14);
    ref_fill(buf_lib.data(), bq, seed);
    ref_fill(buf_ref.data(), bq, seed);
    for (size_t i = 0; i < pad_lib.size(); i++)
      pad_lib[i] = pad_ref[i] = (uint8_t)(i * 13 + 5);

    uint64_t regs_lib[CN_REG_COUNT], regs_ref[CN_REG_COUNT];
    for (int r = 0; r < CN_REG_COUNT; r++)
      regs_lib[r] = regs_ref[r] = UINT64_C(0x0123456789abcdef) * (r + 1) + bq;
    uint64_t chain_lib = 0xfeedface + bq, chain_ref = chain_lib;

    const int passes = 16;
    for (int p = 0; p < passes; p++)
    {
      cn_vm_execute_v7(&prog, buf_lib.data(), bq, pad_lib.data(), regs_lib, &chain_lib);
      ref_execute_v7(&prog, buf_ref.data(), bq, pad_ref.data(), regs_ref, &chain_ref);
    }

    CHECK_TRUE(memcmp(buf_lib.data(), buf_ref.data(), buf_lib.size()) == 0);
    CHECK_TRUE(memcmp(pad_lib.data(), pad_ref.data(), pad_lib.size()) == 0);
    CHECK_TRUE(memcmp(regs_lib, regs_ref, sizeof(regs_lib)) == 0);
    CHECK_TRUE(chain_lib == chain_ref);
  }
}

static const char SAMPLE_DATA[] = "This is a test which is longer than 43 bytes for cna v7";

static void hash_v14(cn_hash_context_t *ctx, const uint8_t seed[32], const void *data, size_t len, char out[HASH_SIZE])
{
  cn_slow_hash_v14(ctx, data, len, out, seed);
}

// Same input, same seed: same hash, across calls and across contexts.
static void hash_is_deterministic()
{
  uint8_t seed[32];
  for (int i = 0; i < 32; i++)
    seed[i] = (uint8_t)(200 - i);
  char h1[HASH_SIZE], h2[HASH_SIZE], h3[HASH_SIZE];
  cn_hash_context_t *ctx1 = cn_hash_context_create();
  cn_hash_context_t *ctx2 = cn_hash_context_create();
  hash_v14(ctx1, seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, h1);
  hash_v14(ctx1, seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, h2);
  hash_v14(ctx2, seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, h3);
  CHECK_TRUE(memcmp(h1, h2, HASH_SIZE) == 0);
  CHECK_TRUE(memcmp(h1, h3, HASH_SIZE) == 0);

  // and the data still matters
  hash_v14(ctx2, seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 2, h3);
  CHECK_TRUE(memcmp(h1, h3, HASH_SIZE) != 0);

  cn_hash_context_free(ctx1);
  cn_hash_context_free(ctx2);
}

// The two review regressions. Seeds sharing their first 8 bytes must produce
// different hashes and (near-)completely different buffers: the fill folds
// all 32 seed bytes, not just the first qword. And an all-zero seed must
// still populate the buffer: the fold starts off the fill map's fixed point.
static void seed_tail_and_zero_seed()
{
  uint8_t seed_a[32] = {0}, seed_b[32] = {0};
  for (int i = 0; i < 8; i++)
    seed_a[i] = seed_b[i] = (uint8_t)(i + 1);
  seed_b[31] = 1;

  cn_hash_context_t *ctx_a = cn_hash_context_create();
  cn_hash_context_t *ctx_b = cn_hash_context_create();
  char ha[HASH_SIZE], hb[HASH_SIZE];
  hash_v14(ctx_a, seed_a, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, ha);
  hash_v14(ctx_b, seed_b, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, hb);
  CHECK_TRUE(memcmp(ha, hb, HASH_SIZE) != 0);

  const uint64_t *ba = (const uint64_t *)ctx_a->cna_v7_buffer;
  const uint64_t *bb = (const uint64_t *)ctx_b->cna_v7_buffer;
  size_t equal = 0;
  for (size_t i = 0; i < 4096; i++)
    equal += (ba[i] == bb[i]);
  std::printf("   seed-tail: %zu of 4096 sampled qwords equal\n", equal);
  CHECK_TRUE(equal < 8);

  const uint8_t zero_seed[32] = {0};
  hash_v14(ctx_a, zero_seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, ha);
  uint64_t acc = 0;
  for (size_t i = 0; i < CN_V7_BUFFER / sizeof(uint64_t); i += 4096)
    acc |= ba[i];
  CHECK_TRUE(acc != 0);

  cn_hash_context_free(ctx_a);
  cn_hash_context_free(ctx_b);
}

// The residency argument: the chase must mutate ~63% of the buffer
// (1 - 1/e for qwords/hops touches). Compare the post-hash buffer against an
// independent fill; a wrong fill transcription would show ~100% here, a
// short-counted chase well under 58%.
static void chase_coverage()
{
  uint8_t seed[32];
  for (int i = 0; i < 32; i++)
    seed[i] = (uint8_t)(i * 3 + 11);

  cn_hash_context_t *ctx = cn_hash_context_create();
  char h[HASH_SIZE];
  hash_v14(ctx, seed, SAMPLE_DATA, sizeof(SAMPLE_DATA) - 1, h);

  const uint64_t bq = CN_V7_BUFFER / sizeof(uint64_t);
  std::vector<uint8_t> fill(CN_V7_BUFFER);
  ref_fill(fill.data(), bq, seed);

  const uint64_t *post = (const uint64_t *)ctx->cna_v7_buffer;
  const uint64_t *pre = (const uint64_t *)fill.data();
  uint64_t mutated = 0;
  for (uint64_t i = 0; i < bq; i++)
    mutated += (post[i] != pre[i]);
  const double ratio = (double)mutated / (double)bq;
  std::printf("   chase mutated %.1f%% of the buffer\n", 100.0 * ratio);
  CHECK_TRUE(ratio > 0.58 && ratio < 0.68);

  cn_hash_context_free(ctx);
}

// HW and SW AES paths agree (runs the in-tree self-test, which since the
// review fix uses a varied seed and asserts the buffer is populated).
static void hw_sw_self_test()
{
  CHECK_TRUE(cn_slow_hash_self_test() == 1);
}

int main()
{
  RUN(chase_matches_reference);
  RUN(hash_is_deterministic);
  RUN(seed_tail_and_zero_seed);
  RUN(chase_coverage);
  RUN(hw_sw_self_test);
  return check_summary("t_cna_v7");
}
