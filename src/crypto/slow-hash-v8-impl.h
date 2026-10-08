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
 * v8 is v11's core with no salt_pad (no sweeps, no extra hashes), at a 1 MB
 * pad, with the chain salt fetched from inside the hash after the AES fill.
 * The hardware and software arms are the same statements in the same order;
 * cn_slow_hash_self_test compares them at startup.
 */

/* Which buffer v8 hashes in. Overridable so resized benchmark builds can
 * point it at their own allocation. */
#if !defined(CN_V8_PAD)
#define CN_V8_PAD(ctx) ((ctx)->scratchpad)
#endif


/* The CN step. v8's step is v11's step: the TUs that include this redefine
 * CN_SCRATCHPAD_MEMORY to CN_SCRATCHPAD_MEMORY_V8, so state_index and e2i
 * index v8's pad. contrib/powbench/t_v8_grid.c checks the result over all
 * 1600 consensus draws. */
#define pre_aes_v8()          pre_aes()
#define post_aes_variant_v8() post_aes_variant()
#define aes_sw_variant_v8()   aes_sw_variant()

/* Runs between the AES fill and the first thing that reads the salt. `text`
 * holds the fill's final state. A NULL salt_fn leaves the context's salt and
 * the caller's parameters alone (benchmarks and the self-test).
 *
 * The seed folds all of `text`: the fill is eight independent AES lanes, and
 * every lane must reach the seed for the seed to need the whole fill.
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

    for (i = 0; i < iters; i++)
    {
        pre_aes_v8();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant_v8();
    }

    finalize_hash();
}

#else /* CN_USE_SOFTWARE_AES */

/* Software-AES arm. A separate copy rather than one body behind a macro,
 * because the AES step macros differ between the two arms. */
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
