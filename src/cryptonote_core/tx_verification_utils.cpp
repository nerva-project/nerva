// Copyright (c) 2018-2026, The Nerva Project
// Copyright (c) 2023-2024, The Monero Project
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

#include "cryptonote_core/tx_verification_utils.h"

#include <boost/variant/get.hpp>

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/blockchain.h"
#include "ringct/rctSigs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "verify"

#define MERROR_VER(x) MCERROR("verify", x)

using namespace cryptonote;

// Do RCT expansion, then post-expansion sanity checks, then full
// non-semantics verification, for the simple types.
static bool expand_tx_and_ver_rct_non_sem(transaction& tx, const std::vector<std::vector<rct::ctkey>>& pubkeys)
{
  const crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  if (!Blockchain::expand_transaction(tx, tx_prefix_hash, pubkeys))
  {
    MERROR_VER("Failed to expand rct signatures!");
    return false;
  }

  const rct::rctSig &rv = tx.rct_signatures;

  // check all this, either reconstructed (so should really pass), or not
  {
    if (pubkeys.size() != rv.mixRing.size())
    {
      MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
      return false;
    }
    for (size_t i = 0; i < pubkeys.size(); ++i)
    {
      if (pubkeys[i].size() != rv.mixRing[i].size())
      {
        MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
        return false;
      }
    }

    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        if (pubkeys[n][m].dest != rct::rct2pk(rv.mixRing[n][m].dest))
        {
          MERROR_VER("Failed to check ringct signatures: mismatched pubkey at vin " << n << ", index " << m);
          return false;
        }
        if (pubkeys[n][m].mask != rct::rct2pk(rv.mixRing[n][m].mask))
        {
          MERROR_VER("Failed to check ringct signatures: mismatched commitment at vin " << n << ", index " << m);
          return false;
        }
      }
    }
  }

  if (rct::is_rct_clsag(rv.type))
  {
    if (rv.p.CLSAGs.size() != tx.vin.size())
    {
      MERROR_VER("Failed to check ringct signatures: mismatched CLSAGs/vin sizes");
      return false;
    }
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      if (memcmp(&boost::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.CLSAGs[n].I, 32))
      {
        MERROR_VER("Failed to check ringct signatures: mismatched key image");
        return false;
      }
    }
  }
  else
  {
    if (rv.p.MGs.size() != tx.vin.size())
    {
      MERROR_VER("Failed to check ringct signatures: mismatched MGs/vin sizes");
      return false;
    }
    for (size_t n = 0; n < tx.vin.size(); ++n)
    {
      if (rv.p.MGs[n].II.empty() || memcmp(&boost::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.MGs[n].II[0], 32))
      {
        MERROR_VER("Failed to check ringct signatures: mismatched key image");
        return false;
      }
    }
  }

  if (!(rv.type == rct::RCTTypeSimple || rv.type == rct::RCTTypeBulletproof1Simple ? rct::verRctNonSemanticsSimple_v1(rv) : rct::verRctNonSemanticsSimple(rv)))
  {
    MERROR_VER("Failed to check ringct signatures!");
    return false;
  }

  return true;
}

// Same, but for the full types.
static bool expand_tx_and_ver_full_rct_non_sem(transaction& tx, const std::vector<std::vector<rct::ctkey>>& pubkeys)
{
  const crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

  if (!Blockchain::expand_transaction(tx, tx_prefix_hash, pubkeys))
  {
    MERROR_VER("Failed to expand rct signatures!");
    return false;
  }

  const rct::rctSig &rv = tx.rct_signatures;

  // check all this, either reconstructed (so should really pass), or not
  {
    bool size_matches = true;
    for (size_t i = 0; i < pubkeys.size(); ++i)
      size_matches &= pubkeys[i].size() == rv.mixRing.size();
    for (size_t i = 0; i < rv.mixRing.size(); ++i)
      size_matches &= pubkeys.size() == rv.mixRing[i].size();
    if (!size_matches)
    {
      MERROR_VER("Failed to check ringct signatures: mismatched pubkeys/mixRing size");
      return false;
    }

    for (size_t n = 0; n < pubkeys.size(); ++n)
    {
      for (size_t m = 0; m < pubkeys[n].size(); ++m)
      {
        if (pubkeys[n][m].dest != rct::rct2pk(rv.mixRing[m][n].dest))
        {
          MERROR_VER("Failed to check ringct signatures: mismatched pubkey at vin " << n << ", index " << m);
          return false;
        }
        if (pubkeys[n][m].mask != rct::rct2pk(rv.mixRing[m][n].mask))
        {
          MERROR_VER("Failed to check ringct signatures: mismatched commitment at vin " << n << ", index " << m);
          return false;
        }
      }
    }
  }

  if (rv.p.MGs.size() != 1)
  {
    MERROR_VER("Failed to check ringct signatures: Bad MGs size");
    return false;
  }
  if (rv.p.MGs.empty() || rv.p.MGs[0].II.size() != tx.vin.size())
  {
    MERROR_VER("Failed to check ringct signatures: mismatched II/vin sizes");
    return false;
  }
  for (size_t n = 0; n < tx.vin.size(); ++n)
  {
    if (memcmp(&boost::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.MGs[0].II[n], 32))
    {
      MERROR_VER("Failed to check ringct signatures: mismatched II/vin sizes");
      return false;
    }
  }

  if (!rct::verRct(rv, false))
  {
    MERROR_VER("Failed to check ringct signatures!");
    return false;
  }

  return true;
}

namespace cryptonote
{

uint64_t get_transaction_weight_limit(const uint8_t hf_version)
{
  return get_min_block_weight(hf_version) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}

bool ver_input_proofs_rings(transaction& tx, const std::vector<std::vector<rct::ctkey>>& pubkeys)
{
  // Defensive: this dispatch (and any verification cache built on top of it
  // later) must be revisited before a type newer than BulletproofPlus is
  // allowed through.
  const bool untested_tx = tx.version > 2 || tx.rct_signatures.type > rct::RCTTypeBulletproofPlus;
  CHECK_AND_ASSERT_MES(!untested_tx, false, "Unknown TX type");

  // check ringct signatures
  // obviously, the original and simple rct APIs use a mixRing that's indexes
  // in opposite orders, because it'd be too simple otherwise...
  const rct::rctSig &rv = tx.rct_signatures;
  switch (rv.type)
  {
  case rct::RCTTypeNull:
    // we only accept no signatures for coinbase txes
    MERROR_VER("Null rct signature on non-coinbase tx");
    return false;
  case rct::RCTTypeSimple:
  case rct::RCTTypeBulletproof1Simple:
  case rct::RCTTypeBulletproof2:
  case rct::RCTTypeCLSAG:
  case rct::RCTTypeBulletproofPlus:
    return expand_tx_and_ver_rct_non_sem(tx, pubkeys);
  case rct::RCTTypeFull:
  case rct::RCTTypeBulletproof1Full:
    return expand_tx_and_ver_full_rct_non_sem(tx, pubkeys);
  default:
    MERROR_VER("Unsupported rct type: " << rv.type);
    return false;
  }
}

bool is_canonical_bulletproof_layout(const std::vector<rct::Bulletproof> &proofs)
{
  if (proofs.size() != 1)
    return false;
  const size_t sz = proofs[0].V.size();
  if (sz == 0 || sz > BULLETPROOF_MAX_OUTPUTS)
    return false;
  return true;
}

bool is_canonical_bulletproof_plus_layout(const std::vector<rct::BulletproofPlus> &proofs)
{
  if (proofs.size() != 1)
    return false;
  const size_t sz = proofs[0].V.size();
  if (sz == 0 || sz > BULLETPROOF_PLUS_MAX_OUTPUTS)
    return false;
  return true;
}

}
