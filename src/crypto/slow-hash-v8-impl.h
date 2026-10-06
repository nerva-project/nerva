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

/* CN_V8_NO_SWEEP compiles the core WITHOUT salt_pad_v8, which is candidate D1 in
 * PLAN-v8-PHASE8: the sweeps are 21.1% of a nonce by the eager profile and are
 * provably not hard, since A1b reorders 30 of them into two passes and the
 * digest does not move.
 *
 * THIS CHANGES THE HASH. It is not a switch to ship behind; it is a second
 * algorithm compiled beside the first so the two can be costed against each
 * other. v8 has never validated a block, so that is a question we are allowed
 * to ask. Nothing defines it in the daemon build, and the consensus entry
 * points are unaffected.
 *
 * Why the cost delta is not simply the sweep phase: under the deferral,
 * salt_pad_v8_defer only RECORDS a sweep, CN_V8_FLUSH_SWEEPS applies them, and
 * post_aes_variant_v8 reconstructs them on the fly whenever it reads the pad
 * (F51's O(sweeps * patches) per read). Removing the sweeps removes all three,
 * so the saving is larger than any one of them and has to be measured end to
 * end rather than summed. */
/* Three modes, because salt_pad_v8 does two separable jobs and they have very
 * different arguments for and against:
 *
 *   the PAD XOR      sweeps salt across the pad at a data-dependent stride.
 *                    17.9% of a nonce by the eager profile, and provably not
 *                    hard: A1b reorders it and the digest does not move.
 *
 *   the EXTRA HASH   calls one of blake, groestl, jh, skein on the salt and
 *                    patches 32 bytes of the salt with the result. 3.2%, and
 *                    the `& 3` selector that reaches all four IS v8's defining
 *                    difference from v5. Cheap in time, but it is what forces a
 *                    specialised implementation to carry four more hash cores
 *                    than AES and keccak. That is an AREA argument, and F38's
 *                    rule is about time, so the rule does not settle it.
 *
 * CN_V8_NO_SWEEP drops both. CN_V8_NO_PADXOR drops only the pad sweep and keeps
 * the extra hash, which is the middle option and probably the interesting one.
 *
 * THESE CHANGE THE HASH. Not switches to ship behind: variants compiled beside
 * the real thing so they can be costed against it. v8 has never validated a
 * block, so this is a question we are allowed to ask. Nothing in the daemon
 * build defines either. PLAN-v8-PHASE8 D1. */
#if defined(CN_V8_NO_SWEEP)
#define CN_V8_SWEEP(a, b, c, d) do { } while (0)
#define CN_V8_FLUSH()           do { } while (0)
#elif defined(CN_V8_NO_PADXOR)
/* The extra hash and its 32-byte salt patch, without the pad sweep. Mirrors
 * salt_pad_v8_defer's first half exactly, including the memo invalidation when
 * a patch lands inside the window the extra hash reads. */
#define CN_V8_SWEEP(a, b, c, d)                                            \
    do {                                                                   \
        const unsigned sel_ = (unsigned)((a) & 3);                         \
        if (!((salt_hash_valid >> sel_) & 1u))                             \
        {                                                                  \
            extra_hashes[sel_]((salt), 200, salt_hash_memo[sel_]);         \
            salt_hash_valid |= 1u << sel_;                                 \
        }                                                                  \
        temp_1 = (uint16_t)(iters ^ ((b) ^ (c)));                          \
        offset_1 = temp_1 * (((d) % 3) + 1);                               \
        for (j = 0; j < 32; j++)                                           \
            (salt)[offset_1 + j] ^= salt_hash_memo[sel_][j];               \
        if (offset_1 < 200) salt_hash_valid = 0;                           \
    } while (0)
#define CN_V8_FLUSH()           do { } while (0)
#else
#define CN_V8_SWEEP(a, b, c, d) salt_pad_v8_defer(salt, a, b, c, d)
#define CN_V8_FLUSH()           do { CN_V8_FLUSH_SWEEPS(); cn_v8_nsw = 0; } while (0)
#endif


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
    do {                                                     \
        if (salt_fn != NULL)                                 \
        {                                                    \
            cn_v8_draw_t draw;                               \
            draw.xx = xx;                                    \
            draw.yy = yy;                                    \
            draw.iters = iters;                              \
            salt_fn(salt_user, text, salt, &draw);           \
            xx = draw.xx;                                    \
            yy = draw.yy;                                    \
            iters = draw.iters;                              \
        }                                                    \
    } while (0)

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
        CN_V8_SWEEP(r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes_v8();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant_v8();
            CN_V8_SWEEP(r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_V8_FLUSH();

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
        CN_V8_SWEEP(r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant_v8();
            CN_V8_SWEEP(r2[1], r2[3], r2[5], r2[7]);
        }
    }

    CN_V8_FLUSH();

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
