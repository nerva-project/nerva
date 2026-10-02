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
//
// Sweep deferral for CryptoNight-Adaptive v8. Verification-only: the hash it
// computes is bit-identical to the eager form, which is the whole point.
//
// FINDINGS.md F44 has the measurement, PLAN-v8.md Phase 6 A1b the design.
//
// Why this is a separate header and not an edit to slow-hash.h: `pre_aes`,
// `post_aes_variant` and `aes_sw_variant` are expanded by cn_slow_hash_v10,
// v11 and v13, every one of which validates mainnet today. PLAN-v8's standing
// rule is that v8 gets private copies rather than the shared macro growing a
// parameter. Nothing here is included by any live algorithm.
//
// Everything is written in terms of CN_SCRATCHPAD_MEMORY and CN_SALT_MEMORY
// rather than against a 1 MB pad, so the resized benchmark builds in
// contrib/hf14checks/v5pad.inc need no mirror of it. F26 records four separate
// occasions when a private copy in that file silently diverged from the
// shipped macro, three of which produced confident wrong numbers rather than a
// build failure.

#pragma once

#include <string.h>
#include <stdint.h>

/* (xx-1)*yy sweeps, and xx, yy are each drawn in [4,8], so 7*8 = 56. */
#define CN_V8_MAX_SWEEPS 64

/* Tile for the finalize pass. Small enough to stay resident while ~56 sweeps
 * are applied to it, which is the entire reason deferral is faster: the eager
 * form makes that many scattered passes over the whole pad instead. */
#define CN_V8_TILE (32 * 1024)

typedef struct
{
    uint32_t start;   /* first pad index the sweep touches */
    uint32_t stride;  /* pad step; [4,128] at 1 MB */
    uint32_t npatch;  /* salt patches applied before this sweep ran */
} cn_v8_sweep_t;

typedef struct
{
    uint32_t      off;             /* salt offset the 32 bytes landed at */
    unsigned char dig[HASH_SIZE];  /* what was XORed in */
} cn_v8_patch_t;

/* The salt is patched in place between sweeps, so sweep k read a different
 * salt than sweep k+1. XOR is its own inverse, so the byte sweep k saw is the
 * final byte with every later patch undone. */
static inline unsigned char cn_v8_salt_at(const char *salt, const cn_v8_patch_t *pt,
                                          uint32_t npt, uint32_t from, uint32_t x)
{
    unsigned char v = (unsigned char)salt[x];
    uint32_t p;
    for (p = from; p < npt; p++)
        if (x >= pt[p].off && x - pt[p].off < HASH_SIZE)
            v ^= pt[p].dig[x - pt[p].off];
    return v;
}

/* The deferred contribution to the 16 bytes at [j, j+16), over the sweeps
 * logged so far. A CN step reads pad^comp and writes result^comp, so a cell
 * stored at step m and read at step m' picks up exactly the sweeps in between,
 * which is what the eager form would have applied to it. */
static inline void cn_v8_comp16(unsigned char out[16], const cn_v8_sweep_t *sw, uint32_t nsw,
                                const char *salt, const cn_v8_patch_t *pt, uint32_t npt,
                                uint32_t j)
{
    uint32_t k;
    memset(out, 0, 16);
    for (k = 0; k < nsw; k++)
    {
        const uint32_t o = sw[k].start, s = sw[k].stride;
        uint32_t x = (j <= o) ? 0u : ((j - o) + s - 1u) / s;
        uint32_t pos = o + x * s;
        for (; pos < j + 16u; pos += s, x++)
            out[pos - j] ^= cn_v8_salt_at(salt, pt, npt, sw[k].npatch, x);
    }
}

static inline void cn_v8_patch_xor(char *salt, const cn_v8_patch_t *p)
{
    uint32_t i;
    for (i = 0; i < HASH_SIZE; i++)
        salt[p->off + i] ^= (char)p->dig[i];
}

/* Apply every logged sweep to the pad, turning stored values into logical
 * ones. Tiled, so the pad is walked once rather than once per sweep.
 *
 * Inside a tile the sweeps run newest first, undoing a patch whenever the next
 * sweep needs an older salt, then the patches are redone so the salt is left
 * as it was found. That is what lets the tiling and the exact per-sweep salt
 * history coexist: scanning the patch list per salt byte instead would cost
 * more than the sweeps themselves. The patch traffic is ~2*npt*32 bytes per
 * tile, which is small against the sweep work in the same tile. */
static inline void cn_v8_apply_sweeps(uint8_t *hp_state, const cn_v8_sweep_t *sw, uint32_t nsw,
                                      char *salt, const cn_v8_patch_t *pt, uint32_t npt)
{
    uint32_t t;
    if (nsw == 0)
        return;
    for (t = 0; t < CN_SCRATCHPAD_MEMORY; t += CN_V8_TILE)
    {
        const uint32_t hi = (t + CN_V8_TILE < CN_SCRATCHPAD_MEMORY)
                          ? t + CN_V8_TILE : (uint32_t)CN_SCRATCHPAD_MEMORY;
        uint32_t cur = npt;
        uint32_t k = nsw;
        while (k--)
        {
            const uint32_t o = sw[k].start, s = sw[k].stride;
            uint32_t x, pos;
            while (cur > sw[k].npatch)
                cn_v8_patch_xor(salt, &pt[--cur]);
            x = (t <= o) ? 0u : ((t - o) + s - 1u) / s;
            pos = o + x * s;
            for (; pos < hi; pos += s, x++)
                hp_state[pos] ^= (uint8_t)salt[x];
        }
        while (cur < npt)
            cn_v8_patch_xor(salt, &pt[cur++]);
    }
}

/* salt_pad_v8 with the pad sweep recorded instead of performed. The patch half
 * is unchanged and still happens eagerly, because the next call's selector and
 * offsets are read back out of the salt. */
#define salt_pad_v8_defer(salt, a, b, c, d)                                     \
    do {                                                                        \
        const unsigned sel_ = (unsigned)((a) & 3);                              \
        if (!((salt_hash_valid >> sel_) & 1u))                                  \
        {                                                                       \
            extra_hashes[sel_]((salt), 200, salt_hash_memo[sel_]);              \
            salt_hash_valid |= 1u << sel_;                                      \
        }                                                                       \
        temp_1 = (uint16_t)(iters ^ ((b) ^ (c)));                               \
        offset_1 = temp_1 * (((d) % 3) + 1);                                    \
        cn_v8_ptlog[cn_v8_npt].off = offset_1;                                  \
        memcpy(cn_v8_ptlog[cn_v8_npt].dig, salt_hash_memo[sel_], HASH_SIZE);      \
        for (j = 0; j < 32; j++)                                                \
            (salt)[offset_1 + j] ^= salt_hash_memo[sel_][j];                    \
        cn_v8_npt++;                                                            \
        if (offset_1 < 200) salt_hash_valid = 0;                                \
        offset_1 = ((d) % 64) + 1;                                              \
        offset_2 = ((temp_1 * offset_1) % CN_V8_STRIDE_MOD) + CN_V8_SALT_STEP;  \
        cn_v8_swlog[cn_v8_nsw].start  = offset_1;                               \
        cn_v8_swlog[cn_v8_nsw].stride = offset_2;                               \
        cn_v8_swlog[cn_v8_nsw].npatch = cn_v8_npt;                              \
        cn_v8_nsw++;                                                            \
    } while (0)

/* Declared together so the two arms cannot drift. */
#define CN_V8_DEFER_LOCALS()                        \
    cn_v8_sweep_t cn_v8_swlog[CN_V8_MAX_SWEEPS];    \
    cn_v8_patch_t cn_v8_ptlog[CN_V8_MAX_SWEEPS];    \
    uint32_t cn_v8_nsw = 0, cn_v8_npt = 0;          \
    RDATA_ALIGN16 unsigned char cn_v8_cmp[16];      \
    RDATA_ALIGN16 unsigned char cn_v8_lgb[16]

#define CN_V8_COMP(dst, idx) \
    cn_v8_comp16((dst), cn_v8_swlog, cn_v8_nsw, salt, cn_v8_ptlog, cn_v8_npt, (uint32_t)(idx))

#define CN_V8_FLUSH_SWEEPS() \
    cn_v8_apply_sweeps(hp_state, cn_v8_swlog, cn_v8_nsw, salt, cn_v8_ptlog, cn_v8_npt)

static inline void cn_v8_xor16(void *dst, const void *src, const unsigned char *cmp)
{
    uint32_t i;
    for (i = 0; i < 16; i++)
        ((uint8_t *)dst)[i] = ((const uint8_t *)src)[i] ^ cmp[i];
}

/* The CN step, hardware arm, reading and writing through the deferred sweeps.
 *
 * The pad holds `logical ^ comp`, so every read materialises the logical value
 * before anything nonlinear sees it. VARIANT1_1 is the reason that matters: it
 * indexes a table with bits of pad byte 11 and writes the byte back, and XOR
 * does not commute with it. Applying it to a masked value would be wrong in a
 * way no amount of XOR algebra afterwards could undo. */
#define pre_aes_v8()                                                       \
    j = state_index(a);                                                    \
    CN_V8_COMP(cn_v8_cmp, j);                                              \
    _c = _mm_xor_si128(_mm_load_si128(R128(&hp_state[j])),                 \
                       _mm_load_si128((const __m128i *)cn_v8_cmp));        \
    _a = _mm_load_si128(R128(a));

#define post_aes_variant_v8()                                              \
    _mm_store_si128(R128(c), _c);                                          \
    _b = _mm_xor_si128(_b, _c);                                            \
    _mm_store_si128((__m128i *)cn_v8_lgb, _b);                             \
    { VARIANT1_1(cn_v8_lgb); }                                             \
    _mm_store_si128(R128(&hp_state[j]),                                    \
        _mm_xor_si128(_mm_load_si128((const __m128i *)cn_v8_lgb),          \
                      _mm_load_si128((const __m128i *)cn_v8_cmp)));        \
    j = state_index(c);                                                    \
    CN_V8_COMP(cn_v8_cmp, j);                                              \
    _mm_store_si128((__m128i *)cn_v8_lgb,                                  \
        _mm_xor_si128(_mm_load_si128(R128(&hp_state[j])),                  \
                      _mm_load_si128((const __m128i *)cn_v8_cmp)));        \
    p = U64(cn_v8_lgb);                                                    \
    b[0] = p[0];                                                           \
    b[1] = p[1];                                                           \
    __mul();                                                               \
    a[0] += hi;                                                            \
    a[1] += lo;                                                            \
    p[0] = a[0];                                                           \
    p[1] = a[1];                                                           \
    a[0] ^= b[0];                                                          \
    a[1] ^= b[1];                                                          \
    VARIANT1_2(p + 1);                                                     \
    _mm_store_si128(R128(&hp_state[j]),                                    \
        _mm_xor_si128(_mm_load_si128((const __m128i *)cn_v8_lgb),          \
                      _mm_load_si128((const __m128i *)cn_v8_cmp)));        \
    _b = _c;

/* The same step, software arm. Structurally identical; it reads the pad into a
 * local, works there, and masks on the way back out. */
#define aes_sw_variant_v8()                                                \
    j = e2i(a, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;    \
    CN_V8_COMP(cn_v8_cmp, j);                                              \
    cn_v8_xor16(cn_v8_lgb, &hp_state[j], cn_v8_cmp);                       \
    copy_block(c1, cn_v8_lgb);                                             \
    aesb_single_round(c1, c1, a);                                          \
    copy_block(cn_v8_lgb, c1);                                             \
    xor_blocks(cn_v8_lgb, b);                                              \
    { VARIANT1_1(cn_v8_lgb); }                                             \
    cn_v8_xor16(&hp_state[j], cn_v8_lgb, cn_v8_cmp);                       \
    j = e2i(c1, CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;   \
    CN_V8_COMP(cn_v8_cmp, j);                                              \
    cn_v8_xor16(cn_v8_lgb, &hp_state[j], cn_v8_cmp);                       \
    copy_block(c2, cn_v8_lgb);                                             \
    mul(c1, c2, d);                                                        \
    swap_blocks(a, c1);                                                    \
    sum_half_blocks(c1, d);                                                \
    swap_blocks(c1, c2);                                                   \
    xor_blocks(c1, c2);                                                    \
    VARIANT1_2(c2 + 8);                                                    \
    cn_v8_xor16(&hp_state[j], c2, cn_v8_cmp);                              \
    copy_block(b, a);                                                      \
    copy_block(a, c1);
