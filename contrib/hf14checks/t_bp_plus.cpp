// Bulletproofs+ battery, ported from Monero master 52f02f2
// tests/unit_tests/bulletproofs_plus.cpp. Test bodies are kept as upstream
// wrote them; only the gtest scaffolding is replaced. Covers valid proofs
// (zero, max, random, multi-output, aggregated batches), invalid scalars,
// and torsioned points on every proof element.
#include "check.h"

#include "string_tools.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/bulletproofs_plus.h"
#include "crypto/crypto.h"

using namespace rct;

static void valid_zero()
{
  BulletproofPlus proof = bulletproof_plus_PROVE(0, skGen());
  CHECK_TRUE(bulletproof_plus_VERIFY(proof));
}

static void valid_max()
{
  BulletproofPlus proof = bulletproof_plus_PROVE(0xffffffffffffffff, skGen());
  CHECK_TRUE(bulletproof_plus_VERIFY(proof));
}

static void valid_random()
{
  for (int n = 0; n < 8; ++n)
  {
    BulletproofPlus proof = bulletproof_plus_PROVE(crypto::rand<uint64_t>(), skGen());
    CHECK_TRUE(bulletproof_plus_VERIFY(proof));
  }
}

static void valid_multi_random()
{
  for (int n = 0; n < 8; ++n)
  {
    size_t outputs = 2 + n;
    std::vector<uint64_t> amounts;
    keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(crypto::rand<uint64_t>());
      gamma.push_back(skGen());
    }
    BulletproofPlus proof = bulletproof_plus_PROVE(amounts, gamma);
    CHECK_TRUE(bulletproof_plus_VERIFY(proof));
  }
}

static void valid_aggregated()
{
  static const size_t N_PROOFS = 8;
  std::vector<BulletproofPlus> proofs(N_PROOFS);
  for (size_t n = 0; n < N_PROOFS; ++n)
  {
    size_t outputs = 2 + n;
    std::vector<uint64_t> amounts;
    keyV gamma;
    for (size_t i = 0; i < outputs; ++i)
    {
      amounts.push_back(crypto::rand<uint64_t>());
      gamma.push_back(skGen());
    }
    proofs[n] = bulletproof_plus_PROVE(amounts, gamma);
  }
  CHECK_TRUE(bulletproof_plus_VERIFY(proofs));
}

static void invalid_8()
{
  key invalid_amount = zero();
  invalid_amount[8] = 1;
  BulletproofPlus proof = bulletproof_plus_PROVE(invalid_amount, skGen());
  CHECK_FALSE(bulletproof_plus_VERIFY(proof));
}

static void invalid_31()
{
  key invalid_amount = zero();
  invalid_amount[31] = 1;
  BulletproofPlus proof = bulletproof_plus_PROVE(invalid_amount, skGen());
  CHECK_FALSE(bulletproof_plus_VERIFY(proof));
}

static const char * const torsion_elements[] =
{
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
};

static void invalid_torsion()
{
  BulletproofPlus proof = bulletproof_plus_PROVE(7329838943733, skGen());
  CHECK_TRUE(bulletproof_plus_VERIFY(proof));
  for (const auto &xs: torsion_elements)
  {
    key x;
    CHECK_TRUE(epee::string_tools::hex_to_pod(xs, x));
    CHECK_FALSE(isInMainSubgroup(x));
    for (auto &k: proof.V)
    {
      const key org_k = k;
      addKeys(k, org_k, x);
      CHECK_FALSE(bulletproof_plus_VERIFY(proof));
      k = org_k;
    }
    for (auto &k: proof.L)
    {
      const key org_k = k;
      addKeys(k, org_k, x);
      CHECK_FALSE(bulletproof_plus_VERIFY(proof));
      k = org_k;
    }
    for (auto &k: proof.R)
    {
      const key org_k = k;
      addKeys(k, org_k, x);
      CHECK_FALSE(bulletproof_plus_VERIFY(proof));
      k = org_k;
    }
    const key org_A = proof.A;
    addKeys(proof.A, org_A, x);
    CHECK_FALSE(bulletproof_plus_VERIFY(proof));
    proof.A = org_A;
    const key org_A1 = proof.A1;
    addKeys(proof.A1, org_A1, x);
    CHECK_FALSE(bulletproof_plus_VERIFY(proof));
    proof.A1 = org_A1;
    const key org_B = proof.B;
    addKeys(proof.B, org_B, x);
    CHECK_FALSE(bulletproof_plus_VERIFY(proof));
    proof.B = org_B;
  }
}

int main()
{
  RUN(valid_zero);
  RUN(valid_max);
  RUN(valid_random);
  RUN(valid_multi_random);
  RUN(valid_aggregated);
  RUN(invalid_8);
  RUN(invalid_31);
  RUN(invalid_torsion);
  return check_summary("t_bp_plus");
}
