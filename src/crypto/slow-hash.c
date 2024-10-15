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

#include "hash-ops.h"
#include "slow-hash.h"

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct
    {
        uint8_t k[64];
        uint8_t init[128];
    };
};
#pragma pack(pop)

static int allocate_hugepage(size_t size, void **hp)
{
#if defined(_MSC_VER) || defined(__MINGW32__)
    SetLockPagesPrivilege(GetCurrentProcess(), TRUE);
    *hp = VirtualAlloc(*hp, size, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*hp == NULL) {
        *hp = malloc(size);
        return 0;
    }
#else
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, 0, 0);
#else
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 0, 0);
#endif
    if (*hp == MAP_FAILED) {
        *hp = malloc(size);
        return 0;
    }
#endif

    return 1;
}

static void free_hugepage(void *hp, size_t size, int is_mapped)
{
    if (is_mapped) {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp, 0, MEM_RELEASE);
#else
        munmap(hp, size);
#endif
    } else {
        free(hp);
    }
}

cn_hash_context_t *cn_hash_context_create(void)
{
    cn_hash_context_t *ctx = (cn_hash_context_t *)malloc(sizeof(cn_hash_context_t));
    if (ctx == NULL) {
        return NULL;
    }
    #if defined(CN_USE_SOFTWARE_AES)
    ctx->oaes_ctx = oaes_alloc();
    if (ctx->oaes_ctx == NULL) {
        free(ctx);
        return NULL;
    }
    #endif
    ctx->scratchpad_is_mapped = allocate_hugepage(CN_SCRATCHPAD_MEMORY, (void **)&(ctx->scratchpad));
    if (ctx->scratchpad == NULL) {
        cn_hash_context_free(ctx);
        return NULL;
    }
    ctx->salt_is_mapped = allocate_hugepage(CN_SALT_MEMORY, (void **)&(ctx->salt));
    if (ctx->salt == NULL) {
        cn_hash_context_free(ctx);
        return NULL;
    }

    return ctx;
}

void cn_hash_context_free(cn_hash_context_t *context)
{
    if (context == NULL)
        return;

#if defined(CN_USE_SOFTWARE_AES)
    if (context->oaes_ctx != NULL) {
        oaes_free((OAES_CTX **)&(context->oaes_ctx));
    }
#endif

    if (context->scratchpad != NULL) {
        free_hugepage(context->scratchpad, CN_SCRATCHPAD_MEMORY, context->scratchpad_is_mapped);
        context->scratchpad = NULL;
    }
    
    if (context->salt != NULL) {
        free_hugepage(context->salt, CN_SALT_MEMORY, context->salt_is_mapped);
        context->salt = NULL;
    }

    free(context);
}


#if !defined(CN_USE_SOFTWARE_AES)

void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
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
        salt_pad(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
        salt_pad(salt, salt_hash, r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
            salt_pad(salt, salt_hash, r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                pre_aes();
                _c = _mm_aesenc_si128(_c, _a);
                post_aes_variant();
                salt_pad(salt, salt_hash, r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad_4k(context->random_values, salt, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for(i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(context->random_values, hp_state);
    xor_u64();

    _b = _mm_load_si128(R128(b));

    for (i = 0; i < iters; i++)
    {
        pre_aes();
        _c = _mm_aesenc_si128(_c, _a);
        post_aes_variant();
    }

    finalize_hash();
}

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{ 
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);

    memcpy(text, state.init, init_size_byte);
    const uint64_t tweak1_2 = variant > 0 ? (state.hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER))) : 0;

    aes_expand_key(state.hs.b, expandedKey);
    for(i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)
    {
        aes_pseudo_round(text, text, expandedKey, INIT_SIZE_BLK);
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    _b = _mm_load_si128(R128(b));

    if (variant > 0)
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_variant();
        }
    }
    else
    {
        for(i = 0; i < iters; i++)
        {
            pre_aes();
            _c = _mm_aesenc_si128(_c, _a);
            post_aes_novariant();
        }   
    }

    finalize_hash();
}

#else

void cn_slow_hash_v11(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t k = 1, l = 1;
    uint16_t *r2 = (uint16_t *)&b;
    for (k = 1; k < xx; k++)
    {
        aes_sw_variant();
        salt_pad(salt, salt_hash, r2[0], r2[2], r2[4], r2[6]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(salt, salt_hash, r2[1], r2[3], r2[5], r2[7]);
        }
    }

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v10(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_256k(context->random_values, salt, hp_state);
    xor_u64();

    uint16_t temp_1 = 0;
    uint32_t offset_1 = 0;
    uint32_t offset_2 = 0;

    uint16_t r2[6] = {xx ^ yy, xx ^ zz, xx ^ ww, yy ^ zz, yy ^ ww, zz ^ ww};
    uint16_t k = 1, l = 1, m = 1;

    for (k = 1; k < xx; k++)
    {
        r2[0] ^= r2[1];
        r2[1] ^= r2[2];
        r2[2] ^= r2[3];
        r2[3] ^= r2[4];
        r2[4] ^= r2[5];
        r2[5] ^= r2[0];

        aes_sw_variant();
        salt_pad(salt, salt_hash, r2[0], r2[3], r2[1], r2[4]);
        r2[0] ^= (r2[1] ^ r2[3]);
        r2[1] ^= (r2[0] ^ r2[2]);

        for (l = 1; l < yy; l++)
        {
            aes_sw_variant();
            salt_pad(salt, salt_hash, r2[1], r2[4], r2[2], r2[5]);
            r2[2] ^= (r2[3] ^ r2[5]);
            r2[3] ^= (r2[2] ^ r2[4]);

            for (m = 1; m < zz; m++)
            {
                aes_sw_variant();
                salt_pad(salt, salt_hash, r2[2], r2[5], r2[3], r2[0]);
                r2[4] ^= (r2[5] ^ r2[1]);
                r2[5] ^= (r2[4] ^ r2[0]);
            }
        }
    }

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v9(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    char * const salt = context->salt;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    char salt_hash[HASH_SIZE];
    init_hash();
    expand_key();
    randomize_scratchpad_4k(context->random_values, salt, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash_v7_8(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();
    expand_key();
    randomize_scratchpad(context->random_values, hp_state);
    xor_u64();

    for (i = 0; i < iters; i++) {
        aes_sw_variant();
    }

    finalize_hash();
}

void cn_slow_hash(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    uint8_t * const hp_state = context->scratchpad;
    const uint8_t init_size_blk = INIT_SIZE_BLK;
    init_hash();

    if (prehashed)
        memcpy(&state.hs, data, length);
    else
        hash_process(&state.hs, data, length);
    
    memcpy(text, state.init, init_size_byte);
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);

    uint8_t tweak1_2[8] = {0};
    if (variant > 0)
    {
        memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2));
        xor64(tweak1_2, NONCE_POINTER);
    }

    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++) {
        for (j = 0; j < INIT_SIZE_BLK; j++) {
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data);
        }
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);
    }

    xor_u64();

    if (variant > 0) {
        for (i = 0; i < iters; i++) {
            aes_sw_variant();
        }
    } else {
        for (i = 0; i < iters; i++) {
            aes_sw_novariant();
        }
    }

    finalize_hash();
}

#endif // !defined(CN_USE_SOFTWARE_AES)
