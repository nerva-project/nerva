// Copyright (c) 2026, The Nerva Project
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

/* CNA v8 plus PLAN-v8 Phase 2's floating-point stage, hardware-AES arm.
 *
 * Same body as slow-hash-v8-impl.h under a different symbol, the pattern
 * contrib/hf14checks/v5pad.inc uses for resized builds. Two translation units
 * rather than a runtime flag so both algorithms exist in one binary and can be
 * measured against each other in the same process, on the same pad, with the
 * same inputs. Nothing here is wired into consensus: get_block_longhash still
 * routes HF14 to cn_slow_hash_v14, and PLAN-v8 says to prototype and measure
 * before deciding whether this ships at all.
 */

#include "hash-ops.h"

#undef CN_SCRATCHPAD_MEMORY
#define CN_SCRATCHPAD_MEMORY CN_SCRATCHPAD_MEMORY_V8

#define CN_V8_FP 1
#define cn_slow_hash_v14 cn_slow_hash_v15_hw

#include "slow-hash.h"
#include "slow-hash-v8-impl.h"

/* Exported so the FP determinism check is reachable rather than dead code.
 * Returns 0 when this build computes the reference vector. Nothing in consensus
 * calls v15 yet, so it is declared here rather than in hash-ops.h; it moves
 * there with the dispatcher entry if Phase 2 ships. */
int cn_slow_hash_v15_selftest(void);
int cn_slow_hash_v15_selftest(void) { return cn_fp_selftest(); }

/* Exposes the value-safety scan so the no-denormal, no-infinity, no-NaN claim
 * can be checked on the real round rather than argued from the source. */
void cn_slow_hash_v15_value_scan(unsigned seeds, unsigned rounds, unsigned out[5]);
void cn_slow_hash_v15_value_scan(unsigned seeds, unsigned rounds, unsigned out[5])
{
    cn_fp_value_scan(seeds, rounds, out);
}
