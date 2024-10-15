// Copyright (c) 2018-2024, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <cstdint>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include "crypto/hash.h"

namespace cryptonote
{
    typedef boost::multiprecision::uint128_t difficulty_type_128;

    std::string hex(difficulty_type_128 v);

    bool check_hash(const crypto::hash &hash, uint64_t difficulty);

    uint64_t next_difficulty(std::vector<uint64_t> timestamps, std::vector<difficulty_type_128> cumulative_difficulties, size_t target_seconds);
    uint64_t next_difficulty_v2(std::vector<uint64_t> timestamps, std::vector<difficulty_type_128> cumulative_difficulties, size_t target_seconds);
    uint64_t next_difficulty_v3(std::vector<uint64_t> timestamps, std::vector<difficulty_type_128> cumulative_difficulties, size_t target_seconds, bool v4);
    uint64_t next_difficulty_v6(std::vector<uint64_t> timestamps, std::vector<difficulty_type_128> cumulative_difficulties, size_t target_seconds);
}
