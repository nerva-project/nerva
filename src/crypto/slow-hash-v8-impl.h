// Copyright (c) 2026, The Nerva Project
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

/* CNA v8 hash bodies, in their own translation unit so they can run at their
 * own pad size: expand_key, finalize_hash and state_index bake
 * CN_SCRATCHPAD_MEMORY in at compile time. slow-hash-v8-{hw,sw}.c redefine it
 * to CN_SCRATCHPAD_MEMORY_V8 before pulling in slow-hash.h and then this file,
 * the same pattern contrib/hf14checks/v5pad.inc uses for resized builds.
 *
 * The two bodies differ at r2, &c here and &b in the software arm. That is
 * deliberate: the software path shipped disagreeing with the hardware one until
 * 4d87b5f fixed it in April 2019, and the fix was that register.
 * cn_slow_hash_self_test compares the pair. FINDINGS.md F3.
 */

/* Which buffer v8 hashes in. At 1 MB the legacy allocation is large enough;
 * v5pad.inc overrides this so resized benchmark builds read the buffer the
 * harness hands them, and are measured on the same memory as the v5 rows. */
#if !defined(CN_V8_PAD)
#define CN_V8_PAD(ctx) ((ctx)->scratchpad)
#endif


/* PLAN-v8 Phase 2's floating-point stage, compiled in only when CN_V8_FP is
 * defined, which only slow-hash-v8fp-{hw,sw}.c do. Without that define these
 * expand to nothing and cn_slow_hash_v14 is byte-identical to what it was
 * before Phase 2 existed, which cn_slow_hash_self_test checks rather than
 * assumes. The two builds run side by side so the spread can be measured on
 * the candidate rather than argued about. */
#if defined(CN_V8_FP)
#include "slow-hash-fp.h"
#define CN_FP_STAGE() cn_fp_stage(hp_state, a)
#else
#define CN_FP_STAGE() do { } while (0)
#endif

#if !defined(CN_USE_SOFTWARE_AES)

/* CNA v8, hardware-AES arm. cn_slow_hash_v11 with salt_pad_v8 in place of
 * salt_pad. Separate from v11 because v11 still validates major_version 11 and
 * 12 and its output must stay bit-identical forever. */
void cn_slow_hash_v14(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k_v8(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&c;
    for (k = 1; k < xx; k++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad_v8(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad_v8(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_FP_STAGE();

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

#else /* CN_USE_SOFTWARE_AES */

/* CNA v8, software-AES arm. Copied from cn_slow_hash_v11, not from the
 * hardware arm above: r2 aliases &b here and &c there, deliberately. */
void cn_slow_hash_v14(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k_v8(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&b;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant();
        salt_pad_v8(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad_v8(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_FP_STAGE();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

#endif /* CN_USE_SOFTWARE_AES */
