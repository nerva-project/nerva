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
#include "crypto/hash.h"

/*!
  \file payment_id_v2.h
  \brief Extended (32-byte) encrypted payment IDs (HF15+).

  The existing encrypted payment ID is 8 bytes (encrypted via ECDH with
  the transaction key). This is sufficient for simple invoice matching
  but too small for e-commerce use cases that need to embed order IDs,
  invoice references, or other metadata.

  This module adds a 32-byte variant (Payment ID v2) using the same ECDH
  encryption scheme but with a larger payload. Both the 8-byte and 32-byte
  variants coexist: the sub-tag in tx_extra_nonce distinguishes them.

  Activation: HF15 (gated by HF_VERSION_PAYMENT_ID_V2 = 15).

  Encryption scheme (same as existing 8-byte variant):
    encrypted_pid = plaintext_pid XOR H(tx_key * recipient_view_key)[:32]

  The wallet decrypts with:
    plaintext_pid = encrypted_pid XOR H(recipient_view_key * tx_key)[:32]

  The 32-byte variant is stored in tx_extra_nonce as:
    TX_EXTRA_NONCE (0x02) || length || TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID_V2 (0x02) || 32 bytes

  Existing 8-byte payment IDs continue to use sub-tag 0x01.
*/

namespace cryptonote
{

/// Sub-tag for the 32-byte encrypted payment ID (v2)
/// Existing 8-byte variant uses TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID_V2 0x02

/// The 32-byte payment ID type (same size as crypto::hash)
using payment_id_v2_t = crypto::hash;

/// Check if payment ID v2 is active at a given hard fork version.
static inline bool payment_id_v2_active(uint8_t hf_version)
{
    return hf_version >= 15; // HF_VERSION_PAYMENT_ID_V2
}

/// Encrypt a 32-byte payment ID using the ECDH shared secret.
///
/// \param plaintext The 32-byte payment ID to encrypt
/// \param shared_secret The ECDH shared secret (tx_key * view_key or view_key * tx_key)
/// \return The encrypted 32-byte payment ID
static inline payment_id_v2_t encrypt_payment_id_v2(
    const payment_id_v2_t& plaintext,
    const crypto::hash& shared_secret)
{
    // Derive the encryption key: H(shared_secret || "payment_id_v2")
    std::string input(reinterpret_cast<const char*>(shared_secret.data), 32);
    input += "payment_id_v2";
    crypto::hash key;
    crypto::cn_fast_hash(input.data(), input.size(), key);

    // XOR the plaintext with the key
    payment_id_v2_t encrypted;
    for (size_t i = 0; i < 32; ++i)
        encrypted.data[i] = plaintext.data[i] ^ key.data[i];
    return encrypted;
}

/// Decrypt a 32-byte payment ID using the ECDH shared secret.
/// This is the inverse of encrypt_payment_id_v2 (XOR is symmetric).
static inline payment_id_v2_t decrypt_payment_id_v2(
    const payment_id_v2_t& encrypted,
    const crypto::hash& shared_secret)
{
    return encrypt_payment_id_v2(encrypted, shared_secret);
}

} // namespace cryptonote
