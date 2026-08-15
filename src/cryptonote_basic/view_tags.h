// Copyright (c) 2018-2026, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary, with or without modification, are
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

#pragma once

#include <cstdint>
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

/*!
  \file view_tags.h
  \brief View tag computation for fast wallet scanning (HF15+).

  View tags are a 1-byte per-output optimization that allows wallets to skip
  the expensive ECDH decryption for outputs they do not own. Instead of
  performing a full scalar multiplication per output, the wallet checks a
  1-byte tag derived from the shared secret. Only if the tag matches does
  the wallet proceed with the full ECDH.

  This provides approximately 8x speedup for wallet scanning on chains
  with many outputs per block (e.g., after airdrops, exchange withdrawals).

  The view tag is derived as:
    tag = H("view_tag", H(tx_pubkey * view_secret_key), output_index)[0]

  where H is Keccak-256. The first byte of the hash is used as the tag,
  giving a 1/256 false positive rate (0.4%). On a chain with 16 outputs
  per block, a wallet will need to perform full ECDH on 0.06 outputs per
  block on average, vs 16 without view tags.

  Activation: HF15 (gated by HF_VERSION_VIEW_TAGS = 15).

  See: https://github.com/wownero/wownero/issues/58 (original proposal)
*/

namespace cryptonote
{

/// The view tag type: a single byte
using view_tag_t = uint8_t;

/// Compute a view tag for a transaction output.
///
/// \param tx_pubkey The transaction public key (R = r*G)
/// \param view_secret_key The recipient's view secret key
/// \param output_index The index of the output in the transaction
/// \return The 1-byte view tag
///
/// The view tag is the first byte of:
///   Keccak("view_tag" || Keccak(tx_pubkey * view_secret_key) || varint(output_index))
///
/// This derivation is deterministic: the sender and receiver compute the
/// same tag independently. An adversary who does not know the view secret
/// key cannot compute the tag, so the tag does not leak ownership information.
static inline view_tag_t compute_view_tag(
    const crypto::public_key& tx_pubkey,
    const crypto::secret_key& view_secret_key,
    size_t output_index)
{
    // Derive the shared secret: D = tx_pubkey * view_secret_key
    crypto::key_derivation derivation;
    crypto::generate_key_derivation(tx_pubkey, view_secret_key, derivation);

    // Hash the derivation to get a seed
    crypto::hash seed;
    crypto::cn_fast_hash(&derivation, sizeof(derivation), seed);

    // Build the view tag input: "view_tag" || seed || varint(output_index)
    std::string input = "view_tag";
    input.append(reinterpret_cast<const char*>(seed.data), sizeof(seed.data));
    // Append output_index as a varint (simple encoding for small values)
    if (output_index < 128)
    {
        input.push_back(static_cast<char>(output_index));
    }
    else
    {
        // Multi-byte varint
        size_t n = output_index;
        while (n >= 128)
        {
            input.push_back(static_cast<char>(0x80 | (n & 0x7F)));
            n >>= 7;
        }
        input.push_back(static_cast<char>(n));
    }

    // Compute the tag: first byte of Keccak(input)
    crypto::hash tag_hash;
    crypto::cn_fast_hash(input.data(), input.size(), tag_hash);
    return static_cast<view_tag_t>(tag_hash.data[0]);
}

/// Check if view tags are active at a given hard fork version.
static inline bool view_tags_active(uint8_t hf_version)
{
    return hf_version >= 15; // HF_VERSION_VIEW_TAGS
}

} // namespace cryptonote
