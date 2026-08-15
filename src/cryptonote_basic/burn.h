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

#include "cryptonote_basic/tx_extra.h"
#include "ringct/rctTypes.h"

/*!
  \file burn.h
  \brief Burn-to-prioritize: EIP-1559-style fee burning (HF15+).

  This module implements a transaction-level fee burning mechanism
  inspired by EIP-1559. A transaction can include a "burn amount" in
  its tx-extra field. The burned amount is deducted from the transaction
  inputs but not credited to any output or the miner. Instead, it is
  permanently removed from circulation.

  The burned amount acts as additional priority for mempool inclusion:
  when selecting transactions for a block template, the miner considers
  fee + burn as the total priority. This creates a deflationary
  pressure while giving users a way to prioritize transactions without
  overpaying miners.

  Activation: HF15 (gated by HF_VERSION_BURN = 15).

  The burn amount is stored in tx-extra as:
    TX_EXTRA_TAG_BURN (0x06) || varint(burn_amount)

  Validation rules (enforced in tx_pool::add_tx and blockchain::check_tx):
  1. The burn amount must be > 0
  2. The sum of outputs + fee + burn must equal the sum of inputs
  3. The burn amount does not affect the miner reward
  4. The burn amount is tracked in a separate counter (get_total_burned RPC)
*/

namespace cryptonote
{

/// New tx-extra tag for burn amounts
/// This value must not conflict with existing tags (0x00-0x04, 0xDE)
#define TX_EXTRA_TAG_BURN 0x06

/// tx_extra_burn structure for serializing the burn amount
struct tx_extra_burn
{
    /// The amount to burn, in atomic units (1 XNV = 10^12 atomic units)
    uint64_t amount;

    BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(amount)
    END_KV_SERIALIZE_MAP()
};

/// Check if burn is active at a given hard fork version.
static inline bool burn_active(uint8_t hf_version)
{
    return hf_version >= 15; // HF_VERSION_BURN
}

/// Validate a burn amount in a transaction.
/// \param burn_amount The amount to burn
/// \param total_inputs Sum of all input amounts (in atomic units)
/// \param total_outputs Sum of all output amounts (in atomic units)
/// \param fee Transaction fee (in atomic units)
/// \return true if the burn is valid (inputs = outputs + fee + burn)
static inline bool validate_burn(uint64_t burn_amount, uint64_t total_inputs,
                                  uint64_t total_outputs, uint64_t fee)
{
    if (burn_amount == 0)
        return true; // No burn is always valid

    // Check: inputs = outputs + fee + burn
    // Guard against overflow
    if (total_outputs > total_inputs)
        return false;
    uint64_t outputs_plus_fee = total_outputs + fee;
    if (outputs_plus_fee < total_outputs)
        return false; // Overflow

    if (outputs_plus_fee + burn_amount < outputs_plus_fee)
        return false; // Overflow

    return outputs_plus_fee + burn_amount == total_inputs;
}

} // namespace cryptonote
