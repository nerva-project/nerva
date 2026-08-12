// Real ring signatures for the HF14 glue checks: genRctSimple output at a
// given bp_version, with a synthetic ring per input. bp_version 2 must come
// out type 5 (Bulletproof2), 3 -> type 6 (CLSAG + BP), 4 -> type 7
// (CLSAG + BP+); the callers assert that.
#pragma once

#include <vector>

#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"

static rct::rctSig make_sample_sig(int bp_version, size_t nin, size_t nout, size_t ring_size)
{
  using namespace rct;

  ctkeyV inSk;
  ctkeyM mixRing;
  keyV destinations, amount_keys;
  std::vector<xmr_amount> inamounts, outamounts;
  std::vector<unsigned int> index;
  const xmr_amount fee = 5000;

  xmr_amount total = 0;
  for (size_t i = 0; i < nin; ++i)
  {
    const xmr_amount amount = 1000000 + i;
    total += amount;
    inamounts.push_back(amount);

    ctkey sk, pk;
    skpkGen(sk.dest, pk.dest);
    sk.mask = skGen();
    // v2 = rct::H, the generator every genRctSimple_v2/_v3 commitment uses
    pk.mask = commit(amount, sk.mask, true);
    inSk.push_back(sk);

    ctkeyV ring(ring_size);
    for (size_t j = 0; j < ring_size; ++j)
    {
      ring[j].dest = pkGen();
      ring[j].mask = pkGen();
    }
    const size_t real = i % ring_size;
    ring[real] = pk;
    mixRing.push_back(ring);
    index.push_back((unsigned int)real);
  }

  xmr_amount left = total - fee;
  for (size_t o = 0; o < nout; ++o)
  {
    key osk, opk;
    skpkGen(osk, opk);
    destinations.push_back(opk);
    amount_keys.push_back(skGen());
    const xmr_amount amt = (o + 1 == nout) ? left : (total - fee) / nout;
    outamounts.push_back(amt);
    left -= amt;
  }

  ctkeyV outSk;
  const RCTConfig cfg{RangeProofPaddedBulletproof, bp_version};
  return genRctSimple(zero(), inSk, destinations, inamounts, outamounts, fee,
                      mixRing, amount_keys, NULL, NULL, index, outSk, cfg,
                      hw::get_device("default"));
}
