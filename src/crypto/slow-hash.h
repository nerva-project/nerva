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

#ifndef SLOW_HASH_H
#define SLOW_HASH_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>

#include "hash-ops.h"
#include "int-util.h"
#include "oaes_lib.h"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define INIT_SIZE_BLK 8
extern void aesb_single_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);
extern void aesb_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey);

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[128];
    };
};
#pragma pack(pop)

#if defined(_MSC_VER)
  #include <windows.h>
  #define STATIC
  #define INLINE __inline
  #if !defined(RDATA_ALIGN16)
    #define RDATA_ALIGN16 __declspec(align(16))
  #endif
#elif defined(__MINGW32__)
  #include <windows.h>
  #define STATIC static
  #define INLINE inline
  #if !defined(RDATA_ALIGN16)
    #define RDATA_ALIGN16 __attribute__((aligned(16)))
  #endif
#else
  #include <sys/mman.h>
  #define STATIC static
  #define INLINE inline
  #if !defined(RDATA_ALIGN16)
    #define RDATA_ALIGN16 __attribute__((aligned(16)))
  #endif
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
static BOOL SetLockPagesPrivilege(HANDLE hProcess, BOOL bEnable)
{
    struct
    {
        DWORD count;
        LUID_AND_ATTRIBUTES privilege[1];
    } info;

    HANDLE token;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &token))
        return FALSE;

    info.count = 1;
    info.privilege[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &(info.privilege[0].Luid)))
        return FALSE;

    if (!AdjustTokenPrivileges(token, FALSE, (PTOKEN_PRIVILEGES)&info, 0, NULL, NULL))
        return FALSE;

    if (GetLastError() != ERROR_SUCCESS)
        return FALSE;

    CloseHandle(token);

    return TRUE;
}
#endif

#define NONCE_POINTER (((const uint8_t *)data) + 35)

#define VARIANT1_1(p)                                          \
    const uint8_t tmp = ((const uint8_t *)(p))[11];            \
    static const uint32_t table = 0x75310;                     \
    const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
    ((uint8_t *)(p))[11] = tmp ^ ((table >> index) & 0x30);

#define VARIANT1_2(p) \
    xor64(p, tweak1_2);

#define salt_pad(salt, salt_hash, a, b, c, d)          \
    extra_hashes[a % 3](salt, 200, salt_hash);         \
    temp_1 = (uint16_t)(iters ^ (b ^ c));              \
    offset_1 = temp_1 * ((d % 3) + 1);                 \
    for (j = 0; j < 32; j++)                           \
        (salt)[offset_1 + j] ^= (salt_hash)[j];        \
    x = 0;                                             \
    offset_1 = (d % 64) + 1;                           \
    offset_2 = ((temp_1 * offset_1) % 125) + 4;        \
    for (j = offset_1; j < CN_SCRATCHPAD_MEMORY; j += offset_2)      \
        hp_state[j] ^= (salt)[x++];

#define randomize_scratchpad(r, scratchpad)            \
    for (int i = 0; i < CN_RANDOM_VALUES; i++)         \
    {                                                  \
        switch ((r).operators[i])                       \
        {                                              \
        case ADD:                                      \
            scratchpad[(r).indices[i]] += (r).values[i]; \
            break;                                     \
        case SUB:                                      \
            scratchpad[(r).indices[i]] -= (r).values[i]; \
            break;                                     \
        case XOR:                                      \
            scratchpad[(r).indices[i]] ^= (r).values[i]; \
            break;                                     \
        case OR:                                       \
            scratchpad[(r).indices[i]] |= (r).values[i]; \
            break;                                     \
        case AND:                                      \
            scratchpad[(r).indices[i]] &= (r).values[i]; \
            break;                                     \
        case COMP:                                     \
            scratchpad[(r).indices[i]] = ~(r).values[i]; \
            break;                                     \
        case EQ:                                       \
            scratchpad[(r).indices[i]] = (r).values[i];  \
            break;                                     \
        }                                              \
    }

#define randomize_scratchpad_256k(r, salt, scratchpad)     \
    uint32_t x = 0;                                        \
    for (uint32_t i = 0; i < CN_SCRATCHPAD_MEMORY; i += 4) \
        scratchpad[i] ^= salt[x++];                        \
    randomize_scratchpad(r, scratchpad);

#define randomize_scratchpad_4k(r, salt, scratchpad)         \
    uint32_t x = 0;                                          \
    for (uint32_t i = 0; i < CN_SCRATCHPAD_MEMORY; i += 256) \
        scratchpad[i] ^= salt[x++];                          \
    randomize_scratchpad(r, scratchpad);


#if !defined(CN_FORCE_SOFTWARE_AES) && !defined(NO_AES) && (         \
        defined(__x86_64__) ||                                       \
        (defined(_MSC_VER) && defined(_WIN64)) ||                    \
        (defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)))

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)

#include <arm_neon.h>

/* Polyfills mapping the subset of x86 SSE2 / AES-NI intrinsics used by
 * Cryptonight onto ARMv8 NEON + Crypto Extensions. The semantics match the
 * x86 instruction exactly so the macro bodies in slow-hash.c can stay shared
 * between architectures. */
#define __m128i uint8x16_t

static inline uint8x16_t cn_arm_load_u128(const void *p)
{
    return vld1q_u8((const uint8_t *)p);
}
static inline void cn_arm_store_u128(void *p, uint8x16_t v)
{
    vst1q_u8((uint8_t *)p, v);
}
/* x86 AES-NI: out = MixColumns(SubBytes(ShiftRows(a))) XOR k.
 * ARMv8: vaeseq_u8(a,k') = SubBytes(ShiftRows(a XOR k')); vaesmcq_u8 = MixColumns.
 * Feed a zero round key into vaese to get SubBytes∘ShiftRows alone, then mix,
 * then XOR the real round key. Same final value as x86's aesenc. */
static inline uint8x16_t cn_arm_aesenc(uint8x16_t a, uint8x16_t k)
{
    return veorq_u8(vaesmcq_u8(vaeseq_u8(a, vdupq_n_u8(0))), k);
}

#define _mm_load_si128(p)        cn_arm_load_u128(p)
#define _mm_loadu_si128(p)       cn_arm_load_u128(p)
#define _mm_store_si128(p, v)    cn_arm_store_u128(p, v)
#define _mm_storeu_si128(p, v)   cn_arm_store_u128(p, v)
#define _mm_xor_si128(a, b)      veorq_u8((a), (b))
#define _mm_aesenc_si128(a, k)   cn_arm_aesenc((a), (k))

#else /* x86 */

#include <emmintrin.h>
#if defined(_MSC_VER)
  #include <intrin.h>
#elif defined(__MINGW32__)
  #include <intrin.h>
#else
  #include <wmmintrin.h>
#endif

#endif /* __aarch64__ + crypto */

#if defined(__INTEL_COMPILER)
  #define ASM __asm__
#elif !defined(_MSC_VER)
  #define ASM __asm__
#else
  #define ASM __asm
#endif

#define U64(x) ((uint64_t *)(x))
#define R128(x) ((__m128i *)(x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & ((CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) - 1)) << 4)
#if defined(_MSC_VER)
  #if !defined(_WIN64)
    #define __mul() lo = mul128(c[0], b[0], &hi);
  #else
    #define __mul() lo = _umul128(c[0], b[0], &hi);
  #endif
#else
  #if defined(__x86_64__)
    #define __mul() ASM("mulq %3\n\t" \
      : "=d"(hi), "=a"(lo)     \
      : "%a"(c[0]), "rm"(b[0]) \
      : "cc");
  #elif defined(__aarch64__) && !defined(NO_OPTIMIZED_MULTIPLY_ON_ARM)
    #define __mul() ASM("mul %0, %1, %2\n\t"   : "=r"(lo) : "r"(c[0]), "r"(b[0])); \
                    ASM("umulh %0, %1, %2\n\t" : "=r"(hi) : "r"(c[0]), "r"(b[0]));
  #else
    #define __mul() lo = mul128(c[0], b[0], &hi);
  #endif
#endif

#define pre_aes()                            \
    j = state_index(a);                      \
    _c = _mm_load_si128(R128(&hp_state[j])); \
    _a = _mm_load_si128(R128(a));

#define post_aes_novariant()                 \
    _mm_store_si128(R128(c), _c);            \
    _b = _mm_xor_si128(_b, _c);              \
    _mm_store_si128(R128(&hp_state[j]), _b); \
    j = state_index(c);                      \
    p = U64(&hp_state[j]);                   \
    b[0] = p[0];                             \
    b[1] = p[1];                             \
    __mul();                                 \
    a[0] += hi;                              \
    a[1] += lo;                              \
    p = U64(&hp_state[j]);                   \
    p[0] = a[0];                             \
    p[1] = a[1];                             \
    a[0] ^= b[0];                            \
    a[1] ^= b[1];                            \
    _b = _c;

#define post_aes_variant()                   \
    _mm_store_si128(R128(c), _c);            \
    _b = _mm_xor_si128(_b, _c);              \
    _mm_store_si128(R128(&hp_state[j]), _b); \
    VARIANT1_1(&hp_state[j]);                \
    j = state_index(c);                      \
    p = U64(&hp_state[j]);                   \
    b[0] = p[0];                             \
    b[1] = p[1];                             \
    __mul();                                 \
    a[0] += hi;                              \
    a[1] += lo;                              \
    p = U64(&hp_state[j]);                   \
    p[0] = a[0];                             \
    p[1] = a[1];                             \
    a[0] ^= b[0];                            \
    a[1] ^= b[1];                            \
    VARIANT1_2(p + 1);                       \
    _b = _c;

#define init_hash()                                                             \
    uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);                 \
    RDATA_ALIGN16 uint8_t expandedKey[240];                                     \
    uint8_t *text = (uint8_t *)malloc(init_size_byte);                          \
    RDATA_ALIGN16 uint64_t a[2];                                                \
    RDATA_ALIGN16 uint64_t b[4];                                                \
    RDATA_ALIGN16 uint64_t c[2];                                                \
    union cn_slow_hash_state state;                                             \
    __m128i _a, _b, _c;                                                         \
    uint64_t hi, lo;                                                            \
    size_t i, j;                                                                \
    uint64_t *p = NULL;                                                         \
    static void (*const extra_hashes[4])(const void *, size_t, char *) = {      \
        hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein}; \

#define xor_u64()                                            \
    U64(a)[0] = U64(&state.k[0])[0] ^ U64(&state.k[32])[0];  \
    U64(a)[1] = U64(&state.k[0])[1] ^ U64(&state.k[32])[1];  \
    U64(b)[0] = U64(&state.k[16])[0] ^ U64(&state.k[48])[0]; \
    U64(b)[1] = U64(&state.k[16])[1] ^ U64(&state.k[48])[1];

#define expand_key()                                                                   \
    hash_process(&state.hs, data, length);                                             \
    memcpy(text, state.init, init_size_byte);                                          \
    const uint64_t tweak1_2 = (state.hs.w[24] ^ (*((const uint64_t *)NONCE_POINTER))); \
    aes_expand_key((OAES_CTX *)context->oaes_ctx, state.hs.b, expandedKey);            \
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)                        \
    {                                                                                  \
        aes_pseudo_round(text, text, expandedKey, init_size_blk);                      \
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);                   \
    }

#define finalize_hash()                                                                              \
    memcpy(text, state.init, init_size_byte);                                                        \
    aes_expand_key((OAES_CTX *)context->oaes_ctx, &state.hs.b[32], expandedKey);                     \
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)                                      \
    {                                                                                                \
        aes_pseudo_round_xor(text, text, expandedKey, &hp_state[i * init_size_byte], init_size_blk); \
    }                                                                                                \
    memcpy(state.init, text, init_size_byte);                                                        \
    hash_permutation(&state.hs);                                                                     \
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);                                              \
    free(text);

STATIC INLINE void xor_blocks(uint8_t *a, const uint8_t *b)
{
    U64(a)[0] ^= U64(b)[0];
    U64(a)[1] ^= U64(b)[1];
}

STATIC INLINE void xor64(uint64_t *a, const uint64_t b)
{
    *a ^= b;
}

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)

/* ARMv8 Cryptonight AES key schedule. Defers to oaes_lib so the produced
 * expanded key is bit-for-bit identical to the one the software-AES path
 * uses (oaes_key_import_data + aesb_pseudo_round). Matching schedules is a
 * correctness requirement: if HW and SW disagree by one byte here, the
 * scratchpad init diverges and the final hash differs.
 *
 * We tried an inline-asm AES-256 schedule borrowed from Monero upstream
 * (which forces NO_AES on ARM, so that asm has never actually run in
 * production); the self-test in check_aesni() caught a mismatch.
 *
 * The oaes context is borrowed from cn_hash_context_t (which already owns
 * one for the SW path) to avoid a malloc/free pair on every hash. */
STATIC INLINE void aes_expand_key(OAES_CTX *oaes, const uint8_t *key, uint8_t *expandedKey)
{
    if (oaes == NULL) {
        memset(expandedKey, 0, 240);
        return;
    }
    oaes_key_import_data(oaes, key, AES_KEY_SIZE);
    const oaes_ctx *c = (const oaes_ctx *)oaes;
    const size_t copy_len = c->key->exp_data_len < 240 ? c->key->exp_data_len : 240;
    memcpy(expandedKey, c->key->exp_data, copy_len);
}

/* Cryptonight pseudo-round: 10 AES rounds with no initial AddRoundKey.
 * Reformulated for ARM's (X(k) ∘ SR ∘ SB) + MC slicing so the structure
 * matches what aes_expand_key emits. The closing veorq applies the last
 * round key as a plain XOR, matching x86 aesenc's terminal AddRoundKey. */
STATIC INLINE void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks)
{
    const uint8x16_t *k = (const uint8x16_t *)expandedKey;
    const uint8x16_t zero = vdupq_n_u8(0);
    int i;
    for (i = 0; i < nblocks; i++) {
        uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
        tmp = vaeseq_u8(tmp, zero);
        tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[0]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[1]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[2]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[3]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[4]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[5]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[6]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[7]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[8]);  tmp = vaesmcq_u8(tmp);
        tmp = veorq_u8(tmp, k[9]);
        vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
    }
}

STATIC INLINE void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *xo, int nblocks)
{
    const uint8x16_t *k = (const uint8x16_t *)expandedKey;
    const uint8x16_t *x = (const uint8x16_t *)xo;
    int i;
    for (i = 0; i < nblocks; i++) {
        uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
        tmp = vaeseq_u8(tmp, x[i]);
        tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[0]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[1]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[2]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[3]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[4]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[5]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[6]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[7]);  tmp = vaesmcq_u8(tmp);
        tmp = vaeseq_u8(tmp, k[8]);  tmp = vaesmcq_u8(tmp);
        tmp = veorq_u8(tmp, k[9]);
        vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
    }
}

#else /* x86 path */

STATIC INLINE void aes_256_assist1(__m128i *t1, __m128i *t2)
{
    __m128i t4;
    *t2 = _mm_shuffle_epi32(*t2, 0xff);
    t4 = _mm_slli_si128(*t1, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t1 = _mm_xor_si128(*t1, t4);
    *t1 = _mm_xor_si128(*t1, *t2);
}

STATIC INLINE void aes_256_assist2(__m128i *t1, __m128i *t3)
{
    __m128i t2, t4;
    t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
    t2 = _mm_shuffle_epi32(t4, 0xaa);
    t4 = _mm_slli_si128(*t3, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    t4 = _mm_slli_si128(t4, 0x04);
    *t3 = _mm_xor_si128(*t3, t4);
    *t3 = _mm_xor_si128(*t3, t2);
}

STATIC INLINE void aes_expand_key(OAES_CTX *oaes, const uint8_t *key, uint8_t *expandedKey)
{
    /* x86 uses the AES-NI key-schedule intrinsic, not oaes. */
    (void)oaes;
    __m128i *ek = R128(expandedKey);
    __m128i t1, t2, t3;

    t1 = _mm_loadu_si128(R128(key));
    t3 = _mm_loadu_si128(R128(key + 16));

    ek[0] = t1;
    ek[1] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x01);
    aes_256_assist1(&t1, &t2);
    ek[2] = t1;
    aes_256_assist2(&t1, &t3);
    ek[3] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x02);
    aes_256_assist1(&t1, &t2);
    ek[4] = t1;
    aes_256_assist2(&t1, &t3);
    ek[5] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x04);
    aes_256_assist1(&t1, &t2);
    ek[6] = t1;
    aes_256_assist2(&t1, &t3);
    ek[7] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x08);
    aes_256_assist1(&t1, &t2);
    ek[8] = t1;
    aes_256_assist2(&t1, &t3);
    ek[9] = t3;

    t2 = _mm_aeskeygenassist_si128(t3, 0x10);
    aes_256_assist1(&t1, &t2);
    ek[10] = t1;
}

STATIC INLINE void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i d;
    int i;

    for (i = 0; i < nblocks; i++)
    {
        d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
        d = _mm_aesenc_si128(d, *R128(&k[0]));
        d = _mm_aesenc_si128(d, *R128(&k[1]));
        d = _mm_aesenc_si128(d, *R128(&k[2]));
        d = _mm_aesenc_si128(d, *R128(&k[3]));
        d = _mm_aesenc_si128(d, *R128(&k[4]));
        d = _mm_aesenc_si128(d, *R128(&k[5]));
        d = _mm_aesenc_si128(d, *R128(&k[6]));
        d = _mm_aesenc_si128(d, *R128(&k[7]));
        d = _mm_aesenc_si128(d, *R128(&k[8]));
        d = _mm_aesenc_si128(d, *R128(&k[9]));
        _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
    }
}

STATIC INLINE void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *xo, int nblocks)
{
    __m128i *k = R128(expandedKey);
    __m128i *x = R128(xo);
    __m128i d;
    int i;

    for (i = 0; i < nblocks; i++)
    {
        d = _mm_loadu_si128(R128(in + i * AES_BLOCK_SIZE));
        d = _mm_xor_si128(d, *R128(x++));
        d = _mm_aesenc_si128(d, *R128(&k[0]));
        d = _mm_aesenc_si128(d, *R128(&k[1]));
        d = _mm_aesenc_si128(d, *R128(&k[2]));
        d = _mm_aesenc_si128(d, *R128(&k[3]));
        d = _mm_aesenc_si128(d, *R128(&k[4]));
        d = _mm_aesenc_si128(d, *R128(&k[5]));
        d = _mm_aesenc_si128(d, *R128(&k[6]));
        d = _mm_aesenc_si128(d, *R128(&k[7]));
        d = _mm_aesenc_si128(d, *R128(&k[8]));
        d = _mm_aesenc_si128(d, *R128(&k[9]));
        _mm_storeu_si128((R128(out + i * AES_BLOCK_SIZE)), d);
    }
}

#endif /* ARM vs x86 within the HW-AES branch */

#else

#define CN_USE_SOFTWARE_AES 1

STATIC size_t e2i(const uint8_t *a, size_t count) { return (*((uint64_t *)a) / AES_BLOCK_SIZE) & (count - 1); }

STATIC void mul(const uint8_t *a, const uint8_t *b, uint8_t *res)
{
    uint64_t a0, b0;
    uint64_t hi, lo;

    a0 = SWAP64LE(((uint64_t *)a)[0]);
    b0 = SWAP64LE(((uint64_t *)b)[0]);
    lo = mul128(a0, b0, &hi);
    ((uint64_t *)res)[0] = SWAP64LE(hi);
    ((uint64_t *)res)[1] = SWAP64LE(lo);
}

STATIC void sum_half_blocks(uint8_t *a, const uint8_t *b)
{
    uint64_t a0, a1, b0, b1;

    a0 = SWAP64LE(((uint64_t *)a)[0]);
    a1 = SWAP64LE(((uint64_t *)a)[1]);
    b0 = SWAP64LE(((uint64_t *)b)[0]);
    b1 = SWAP64LE(((uint64_t *)b)[1]);
    a0 += b0;
    a1 += b1;
    ((uint64_t *)a)[0] = SWAP64LE(a0);
    ((uint64_t *)a)[1] = SWAP64LE(a1);
}

#define U64(x) ((uint64_t *)(x))

STATIC void copy_block(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, AES_BLOCK_SIZE);
}

STATIC void swap_blocks(uint8_t *a, uint8_t *b)
{
    uint64_t t[2];
    U64(t)[0] = U64(a)[0];
    U64(t)[1] = U64(a)[1];
    U64(a)[0] = U64(b)[0];
    U64(a)[1] = U64(b)[1];
    U64(b)[0] = U64(t)[0];
    U64(b)[1] = U64(t)[1];
}

STATIC void xor_blocks(uint8_t *a, const uint8_t *b)
{
    size_t i;
    for (i = 0; i < AES_BLOCK_SIZE; i++)
        a[i] ^= b[i];
}

STATIC void xor64(uint8_t *left, const uint8_t *right)
{
    size_t i;
    for (i = 0; i < 8; ++i)
        left[i] ^= right[i];
}

#define aes_sw_variant()                                   \
    j = e2i(a, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  \
    copy_block(c1, &hp_state[j]);                          \
    aesb_single_round(c1, c1, a);                          \
    copy_block(&hp_state[j], c1);                          \
    xor_blocks(&hp_state[j], b);                           \
    VARIANT1_1(&hp_state[j]);                              \
    j = e2i(c1, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; \
    copy_block(c2, &hp_state[j]);                          \
    mul(c1, c2, d);                                        \
    swap_blocks(a, c1);                                    \
    sum_half_blocks(c1, d);                                \
    swap_blocks(c1, c2);                                   \
    xor_blocks(c1, c2);                                    \
    VARIANT1_2(c2 + 8);                                    \
    copy_block(&hp_state[j], c2);                          \
    copy_block(b, a);                                      \
    copy_block(a, c1);

#define aes_sw_novariant()                                 \
    j = e2i(a, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  \
    copy_block(c1, &hp_state[j]);                          \
    aesb_single_round(c1, c1, a);                          \
    copy_block(&hp_state[j], c1);                          \
    xor_blocks(&hp_state[j], b);                           \
    j = e2i(c1, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; \
    copy_block(c2, &hp_state[j]);                          \
    mul(c1, c2, d);                                        \
    swap_blocks(a, c1);                                    \
    sum_half_blocks(c1, d);                                \
    swap_blocks(c1, c2);                                   \
    xor_blocks(c1, c2);                                    \
    copy_block(&hp_state[j], c2);                          \
    copy_block(b, a);                                      \
    copy_block(a, c1);

#define init_hash()                                                                                          \
    union cn_slow_hash_state state;                                                                          \
    uint32_t init_size_byte = (init_size_blk * AES_BLOCK_SIZE);                                              \
    uint8_t *text = (uint8_t *)malloc(init_size_byte);                                                       \
    uint8_t a[AES_BLOCK_SIZE];                                                                               \
    uint8_t b[AES_BLOCK_SIZE];                                                                               \
    uint8_t c1[AES_BLOCK_SIZE];                                                                              \
    uint8_t c2[AES_BLOCK_SIZE];                                                                              \
    uint8_t d[AES_BLOCK_SIZE];                                                                               \
    size_t i, j;                                                                                             \
    uint8_t aes_key[AES_KEY_SIZE];                                                                           \
    oaes_ctx * const aes_ctx = (oaes_ctx *)context->oaes_ctx;                                                \
    static void (*const extra_hashes[4])(const void *, size_t, char *) = {                                   \
    hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein};                                  \

#define expand_key()                                                                                         \
    hash_process(&state.hs, data, length);                                                                   \
    memcpy(text, state.init, init_size_byte);                                                                \
    memcpy(aes_key, state.hs.b, AES_KEY_SIZE);                                                               \
    uint8_t tweak1_2[8];                                                                                     \
    memcpy(&tweak1_2, &state.hs.b[192], sizeof(tweak1_2));                                                   \
    xor64(tweak1_2, NONCE_POINTER);                                                                          \
    oaes_key_import_data(aes_ctx, aes_key, AES_KEY_SIZE);                                                    \
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)                                              \
    {                                                                                                        \
        for (j = 0; j < init_size_blk; j++)                                                                  \
        {                                                                                                    \
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data); \
        }                                                                                                    \
        memcpy(&hp_state[i * init_size_byte], text, init_size_byte);                                         \
    }

#define finalize_hash()                                                                                      \
    memcpy(text, state.init, init_size_byte);                                                                \
    oaes_key_import_data(aes_ctx, &state.hs.b[32], AES_KEY_SIZE);                                            \
    for (i = 0; i < CN_SCRATCHPAD_MEMORY / init_size_byte; i++)                                              \
    {                                                                                                        \
        for (j = 0; j < init_size_blk; j++)                                                                  \
        {                                                                                                    \
            xor_blocks(&text[j * AES_BLOCK_SIZE], &hp_state[i * init_size_byte + j * AES_BLOCK_SIZE]);       \
            aesb_pseudo_round(&text[AES_BLOCK_SIZE * j], &text[AES_BLOCK_SIZE * j], aes_ctx->key->exp_data); \
        }                                                                                                    \
    }                                                                                                        \
    memcpy(state.init, text, init_size_byte);                                                                \
    hash_permutation(&state.hs);                                                                             \
    extra_hashes[state.hs.b[0] & 3](&state, 200, hash);                                                      \
    free(text);                                                                                              

#define xor_u64()                                                             \
    for (i = 0; i < AES_BLOCK_SIZE; i++)                                      \
    {                                                                         \
        a[i] = state.k[i] ^ state.k[AES_BLOCK_SIZE * 2 + i];                  \
        b[i] = state.k[AES_BLOCK_SIZE + i] ^ state.k[AES_BLOCK_SIZE * 3 + i]; \
    }

#endif // !defined(CN_FORCE_SOFTWARE_AES) && !defined(NO_AES) && (HW-AES-capable targets)

#endif // SLOW_HASH_H
