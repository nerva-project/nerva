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
 * The two arms used to differ at r2, &c here and &b in the software arm, which
 * was deliberate and load-bearing. D1 removed the sweeps and the sweep was r2's
 * only consumer, so the arms are now structurally identical and that particular
 * divergence, which would have shown up only on machines without AES-NI and
 * only in the field, is no longer reachable. F58 section 4.
 * cn_slow_hash_self_test still compares the pair.
 */

/* Which buffer v8 hashes in. Overridable so resized benchmark builds can
 * point it at their own allocation. */
#if !defined(CN_V8_PAD)
#define CN_V8_PAD(ctx) ((ctx)->scratchpad)
#endif


/* D1: salt_pad_v8 and its four extra hashes are GONE, adopted 2026-10-07.
 *
 * The sweeps were 23.9% of a nonce, measured in the daemon over a million
 * nonces (F57), and provably not hard: A1b reordered 30 of them into two
 * passes and the digest did not move (F51). Work that can be reordered into a
 * different number of passes without changing the answer is not work an
 * attacker has to do in the form we paid for it.
 *
 * The extra hashes went with them because F56 showed the move is binary: once
 * the pad XOR is severed, blake/groestl/jh/skein still run, still cost cycles
 * and reach the digest through nothing. Two arms whose only difference was the
 * extra hash produced identical digests, which is what dead code looks like
 * from the outside.
 *
 * What this costs, recorded because it is real: the four hash cores were the
 * only thing forcing a specialised implementation to carry more than AES and
 * keccak. That is an area argument, and F65 later priced the ASIC bound as
 * memory-driven rather than area-driven, which is why it was affordable.
 *
 * The deferral (slow-hash-v8-defer.h) went too: it existed to make these
 * sweeps cheap, and there is nothing left to defer.
 *
 * PLAN-v8-PHASE8 D1. THIS CHANGED THE HASH, deliberately, and the
 * known-answer vectors were regenerated in the same commit. */

/* The CN step over v8's 1 MB pad.
 *
 * These used to live in slow-hash-v8-defer.h and read the pad through
 * CN_V8_COMP, because under the deferral the pad held `logical ^ comp` and
 * every read had to materialise the logical value before anything nonlinear
 * saw it. With the sweeps gone there is nothing to compensate for, comp is
 * identically zero, and the deferred forms reduce term for term to the plain
 * v11 steps: the only difference was that the deferred versions worked in a
 * local buffer and copied back where these work in place.
 *
 * So v8's step IS v11's step, over a different pad size. CN_SCRATCHPAD_MEMORY
 * is redefined to CN_SCRATCHPAD_MEMORY_V8 by the TUs that include this, so
 * state_index and e2i index 1 MB rather than 2.
 *
 * That equivalence is not taken on trust: t_v8_grid compares this against the
 * old no-sweep candidate, which reached the same place through the deferred
 * path with zero sweeps recorded, over all 1600 consensus draws. */
#define pre_aes_v8()          pre_aes()
#define post_aes_variant_v8() post_aes_variant()
#define aes_sw_variant_v8()   aes_sw_variant()

/* Floating-point stage, compiled in only by slow-hash-v8fp-{hw,sw}.c.
 * Without CN_V8_FP this expands to nothing and v8 is unchanged. */
#if defined(CN_V8_FP)
#include "slow-hash-fp.h"
#define CN_FP_STAGE() cn_fp_stage(hp_state, a)
#else
#define CN_FP_STAGE() do { } while (0)
#endif

/* Runs between the AES fill and the first thing that reads the salt. `text`
 * holds the fill's final chain state at this point. A NULL salt_fn leaves the
 * context's salt and the caller's parameters alone, which is what the
 * benchmarks and the self-test want. PLAN-v8 Phase 6 B2.
 *
 * The seed folds ALL of `text`, not its first 32 bytes. aes_pseudo_round
 * encrypts each 16-byte lane independently, so the fill is eight separate
 * chains, and text[0..32) is lanes 0 and 1 alone. Seeding from those let a
 * device produce the salt after a quarter of the fill's AES. With the fold,
 * every lane reaches the seed, so the seed needs the whole fill. FINDINGS F81.
 * Byte-wise, so both arms and both byte orders compute the same bytes. */
#define CN_V8_FETCH_SALT()                                   \
    do {                                                     \
        if (salt_fn != NULL)                                 \
        {                                                    \
            unsigned char seed_[32];                         \
            uint32_t s_;                                     \
            cn_v8_draw_t draw;                               \
            memset(seed_, 0, sizeof(seed_));                 \
            for (s_ = 0; s_ < init_size_byte; s_++)          \
                seed_[s_ & 31] ^= text[s_];                  \
            draw.xx = xx;                                    \
            draw.yy = yy;                                    \
            draw.iters = iters;                              \
            salt_fn(salt_user, seed_, salt, &draw);          \
            xx = draw.xx;                                    \
            yy = draw.yy;                                    \
            iters = draw.iters;                              \
        }                                                    \
    } while (0)

#if !defined(CN_USE_SOFTWARE_AES)

/* Hardware-AES arm. cn_slow_hash_v11 with no salt_pad at all, a 1 MB pad, and
 * the chain salt fetched from inside the hash. Kept separate from v11 because
 * v11 still validates major_version 11 and 12. */
static void cn_v8_core(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, cn_v8_salt_fn salt_fn, void *salt_user)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    init_hash();
    expand_key();
    CN_V8_FETCH_SALT();
    randomize_scratchpad_256k_v8(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));


    uint16_t k = 1, l = 1;
    for (k = 1; k < xx; k++)
    {
        pre_aes_v8();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant_v8();

        for (l = 1; l < yy; l++)
        {
            pre_aes_v8();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant_v8();
        }
    }


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

/* Software-AES arm. Still a separate copy rather than one body behind a macro,
 * because pre_aes_v8 and post_aes_variant_v8 differ between the two. It used to
 * diverge further, at r2, but D1 removed the sweep that was r2's only consumer,
 * so the two bodies are now the same statements in the same order. */
static void cn_v8_core(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, cn_v8_salt_fn salt_fn, void *salt_user)
{
    uint8_t * const hp_state = CN_V8_PAD(context);
    char * const salt = context->salt;
    init_hash();
    expand_key();
    CN_V8_FETCH_SALT();
    randomize_scratchpad_256k_v8(context->random_values, salt, hp_state);
    xor_u64();


    uint16_t k = 1, l = 1;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant_v8();

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant_v8();
        }
    }


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
