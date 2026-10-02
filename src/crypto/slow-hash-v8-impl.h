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

/* CNA v8 hash bodies. Included by slow-hash-v8-{hw,sw}.c, which set the pad
 * size first.
 *
 * THE TWO ARMS DIFFER AT r2: &c here, &b in the software arm. Deliberate, and
 * load-bearing. cn_slow_hash_self_test compares the pair.
 */

/* Which buffer v8 hashes in. Overridable so resized benchmark builds can
 * point it at their own allocation. */
#if !defined(CN_V8_PAD)
#define CN_V8_PAD(ctx) ((ctx)->scratchpad)
#endif

/* The salt sweeps are recorded and applied once instead of ~56 times over the
 * pad. Verification-only: the hash is bit-identical either way, which the
 * known-answer vectors are what actually prove. PLAN-v8 Phase 6 A1b. */
#include "slow-hash-v8-defer.h"


/* Floating-point stage, compiled in only by slow-hash-v8fp-{hw,sw}.c.
 * Without CN_V8_FP this expands to nothing and v8 is unchanged. */
#if defined(CN_V8_FP)
#include "slow-hash-fp.h"
#define CN_FP_STAGE() cn_fp_stage(hp_state, a)
#else
#define CN_FP_STAGE() do { } while (0)
#endif

/* Runs between the AES fill and the first thing that reads the salt. `text`
 * holds the fill's final chain state at this point, so the seed cannot be
 * produced without the fill; init_size_byte is 32 at the smallest blk, so
 * text[0..32) is always there. A NULL salt_fn leaves the context's salt and
 * the caller's parameters alone, which is what the benchmarks and the
 * self-test want. PLAN-v8 Phase 6 B2. */
#define CN_V8_FETCH_SALT()                                   \
    if (salt_fn != NULL)                                     \
    {                                                        \
        cn_v8_draw_t draw;                                   \
        draw.xx = xx;                                        \
        draw.yy = yy;                                        \
        draw.iters = iters;                                  \
        salt_fn(salt_user, text, salt, &draw);               \
        xx = draw.xx;                                        \
        yy = draw.yy;                                        \
        iters = draw.iters;                                  \
    }

#if !defined(CN_USE_SOFTWARE_AES)

/* Hardware-AES arm. cn_slow_hash_v11 with salt_pad_v8 in place of salt_pad.
 * Kept separate because v11 still validates major_version 11 and 12. */
static void cn_v8_core(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, cn_v8_salt_fn salt_fn, void *salt_user)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    char salt_hash_memo[4][HASH_SIZE];
    unsigned salt_hash_valid = 0;
    CN_V8_DEFER_LOCALS();
    init_hash();
    expand_key();
    CN_V8_FETCH_SALT();
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
        pre_aes_v8();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant_v8();
        salt_pad_v8_defer(salt, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes_v8();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant_v8();
            salt_pad_v8_defer(salt, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_V8_FLUSH_SWEEPS();
    cn_v8_nsw = 0;

    CN_FP_STAGE();

    for (i = 0; i < iters; i++)
    {
        pre_aes_v8();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant_v8();
    }

    finalize_hash();
}

#else /* CN_USE_SOFTWARE_AES */

/* Software-AES arm. Copied from cn_slow_hash_v11, not from the arm above:
 * r2 aliases &b here and &c there. */
static void cn_v8_core(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, cn_v8_salt_fn salt_fn, void *salt_user)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    char salt_hash_memo[4][HASH_SIZE];
    unsigned salt_hash_valid = 0;
    CN_V8_DEFER_LOCALS();
    init_hash();
    expand_key();
    CN_V8_FETCH_SALT();
    randomize_scratchpad_256k_v8(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&b;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant_v8();
        salt_pad_v8_defer(salt, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant_v8();
            salt_pad_v8_defer(salt, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_V8_FLUSH_SWEEPS();
    cn_v8_nsw = 0;

    CN_FP_STAGE();

    for (i = 0; i < iters; i++) {
        aes_sw_variant_v8();
    }

    finalize_hash();
}

#endif /* CN_USE_SOFTWARE_AES */

/* Salt supplied by the caller. Benchmarks, the self-test and the resized
 * builds use this; nothing in consensus does. */
void cn_slow_hash_v14(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    cn_v8_core(context, data, length, hash, iters, init_size_blk, xx, yy, NULL, NULL);
}

#if defined(CN_V8_EMIT_CHAIN)
/* The consensus entry point. It takes no iters/xx/yy because the callback
 * supplies them, which is the whole point: they are drawn from the keystream
 * the chain fill advanced, so they cannot be known before the fill and the
 * fetch have both happened. */
void cn_slow_hash_v14_chain(cn_hash_context_t *context, const void *data, size_t length, char *hash, uint8_t init_size_blk, cn_v8_salt_fn salt_fn, void *salt_user)
{
    cn_v8_core(context, data, length, hash, 0, init_size_blk, 0, 0, salt_fn, salt_user);
}
#endif
