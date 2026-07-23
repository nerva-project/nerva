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

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include "ringct/rctTypes.h"

// Standalone transaction verification helpers, Monero master's
// tx_verification_utils layout. The input-verification cache
// (make_input_verification_id and the pool_supplement machinery around it)
// is not adopted; verification here is stateless.

namespace cryptonote
{

// The maximum weight of a single transaction accepted into the pool.
uint64_t get_transaction_weight_limit(uint8_t hf_version);

// Do RCT expansion, then post-expansion sanity checks, then full
// non-semantics verification of the ring signatures. The mix ring is the
// output keys fetched from the chain for each input, in the same layout
// Blockchain::expand_transaction expects.
bool ver_input_proofs_rings(transaction& tx, const std::vector<std::vector<rct::ctkey>>& pubkeys);

// Canonical range proof layout for the aggregate proof types: exactly one
// proof, with a sane number of commitments.
bool is_canonical_bulletproof_layout(const std::vector<rct::Bulletproof> &proofs);
bool is_canonical_bulletproof_plus_layout(const std::vector<rct::BulletproofPlus> &proofs);

}
