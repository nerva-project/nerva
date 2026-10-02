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

/* Regenerate the known-answer vectors that cn_slow_hash_known_answer_test
 * checks. Emits the v10/v11/v13 tables and, with --v8, the v14 table too.
 *
 * Built against master, so the vectors are master's. The HF14 branch carries
 * them unchanged, which turns "I diffed the function bodies and they are
 * byte-identical" into something CI checks on every platform. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <cpuid.h>
#include "hash-ops.h"

void cn_slow_hash_v10(cn_hash_context_t *, const void *, size_t, char *,
                      size_t, uint8_t, uint16_t, uint16_t, uint16_t, uint16_t);
void cn_slow_hash_v11(cn_hash_context_t *, const void *, size_t, char *,
                      size_t, uint8_t, uint16_t, uint16_t);
void cn_slow_hash_v13(cn_hash_context_t *, const void *, size_t, char *, const uint8_t *);
void cn_slow_hash_v14(cn_hash_context_t *, const void *, size_t, char *,
                      size_t, uint8_t, uint16_t, uint16_t);

int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

static void emit(const char *h)
{
    int i;
    printf("{");
    for (i = 0; i < 32; i++) printf("%s0x%02x", i ? "," : "", (unsigned char)h[i]);
    printf("}");
}

static const char in[] = "nerva live-algorithm known-answer vector";

int main(void)
{
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h[32];
    uint8_t seed[32];
    int i;

    if (!ctx) return 1;
    for (i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7u + 3u);

    /* warm so the pads are allocated before anything is zeroed */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v11(ctx, in, sizeof(in) - 1, h, 8, 8, 4, 4);
    if (!ctx->salt) return 1;

    printf("/* Known-answer vectors for the algorithms that validate mainnet today,\n");
    printf(" * generated from master. v8 must not move these: the branch carries them\n");
    printf(" * unchanged so CI proves on every platform that v10, v11 and v13 are\n");
    printf(" * untouched, rather than a reviewer taking a byte-identical claim on\n");
    printf(" * trust. Input is \"%s\".\n", in);
    printf(" * v13's seed is seed[i] = i * 7 + 3. */\n");

    printf("static const struct { uint32_t iters; uint8_t blk; uint16_t xx, yy, zz, ww;\n");
    printf("                     unsigned char want[32]; } cn_v10_kat[] = {\n");
    {
        const struct { uint32_t it; uint8_t blk; uint16_t xx, yy, zz, ww; } cs[] = {
            { 0, 8, 2, 2, 2, 2 }, { 17, 4, 3, 2, 2, 3 }, { 64, 2, 2, 3, 3, 2 },
        };
        for (i = 0; i < (int)(sizeof(cs) / sizeof(cs[0])); i++) {
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            memset(ctx->salt, 0, CN_SALT_MEMORY);
            cn_slow_hash_v10(ctx, in, sizeof(in) - 1, h, cs[i].it, cs[i].blk,
                             cs[i].xx, cs[i].yy, cs[i].zz, cs[i].ww);
            printf("    { %u, %u, %u, %u, %u, %u, ", cs[i].it, cs[i].blk,
                   cs[i].xx, cs[i].yy, cs[i].zz, cs[i].ww);
            emit(h);
            printf(" },\n");
        }
    }
    printf("};\n\n");

    printf("static const struct { uint32_t iters; uint8_t blk; uint16_t xx, yy;\n");
    printf("                     unsigned char want[32]; } cn_v11_kat[] = {\n");
    {
        const struct { uint32_t it; uint8_t blk; uint16_t xx, yy; } cs[] = {
            { 0, 8, 4, 4 }, { 17, 4, 5, 6 }, { 63, 2, 8, 8 },
        };
        for (i = 0; i < (int)(sizeof(cs) / sizeof(cs[0])); i++) {
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            memset(ctx->salt, 0, CN_SALT_MEMORY);
            cn_slow_hash_v11(ctx, in, sizeof(in) - 1, h, cs[i].it, cs[i].blk, cs[i].xx, cs[i].yy);
            printf("    { %u, %u, %u, %u, ", cs[i].it, cs[i].blk, cs[i].xx, cs[i].yy);
            emit(h);
            printf(" },\n");
        }
    }
    printf("};\n\n");

    printf("static const unsigned char cn_v13_kat[32] = ");
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v13(ctx, in, sizeof(in) - 1, h, seed);
    emit(h);
    printf(";\n");

    /* v14 uses its own input string, which is why it is a separate table. Its
     * blk is not a parameter: consensus pins CN_V8_INIT_SIZE_BLK. */
    printf("\n/* v8 known-answer vectors, generated from the shipped implementation.\n");
    printf(" * salt and random_values are zeroed before each case so the vector\n");
    printf(" * depends only on (input, iters, blk, xx, yy). */\n");
    printf("static const struct { uint16_t xx, yy; uint32_t iters; unsigned char want[32]; } cn_v14_kat[] = {\n");
    {
        static const char v8_in[] = "nerva cna v8 known-answer vector";
        const struct { uint16_t xx, yy; uint32_t it; } cs[] = {
            { 4, 4, 0 }, { 4, 5, 1 }, { 5, 4, 17 },
            { 6, 6, 64 }, { 8, 8, 63 }, { 7, 5, 7 },
        };
        for (i = 0; i < (int)(sizeof(cs) / sizeof(cs[0])); i++) {
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            memset(ctx->salt, 0, CN_SALT_MEMORY);
            cn_slow_hash_v14(ctx, v8_in, sizeof(v8_in) - 1, h,
                             cs[i].it, CN_V8_INIT_SIZE_BLK, cs[i].xx, cs[i].yy);
            printf("    { %u, %u, %u, ", cs[i].xx, cs[i].yy, cs[i].it);
            emit(h);
            printf(" },\n");
        }
    }
    printf("};\n");

    cn_hash_context_free(ctx);
    return 0;
}
