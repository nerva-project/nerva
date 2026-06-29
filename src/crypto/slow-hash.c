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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) || defined(__MINGW32__)
#  include <windows.h>
#else
#  include <sys/mman.h>
#endif

#if defined(__linux__) || defined(__ANDROID__)
#  include <sys/auxv.h>
#  if defined(__aarch64__) && !defined(HWCAP_AES)
#    define HWCAP_AES (1 << 3)
#  endif
#endif

#include "hash-ops.h"
#include "oaes_lib.h"
#include "slow-hash.h"

#if defined(SLOW_HASH_HW_AES_BUILT)
extern void cn_slow_hash_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
extern void cn_slow_hash_v7_8_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v9_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v10_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
extern void cn_slow_hash_v11_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
#endif

extern void cn_slow_hash_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
extern void cn_slow_hash_v7_8_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v9_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v10_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
extern void cn_slow_hash_v11_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);

/* Runtime CPU detection. Cached in a function-static so the per-hash overhead
 * is one branch on a hot variable. Override with NERVA_FORCE_SOFTWARE_AES=1 to
 * exercise the SW path on a HW-capable CPU (useful for self-tests / debugging). */
static int detect_hardware_aes(void)
{
    const char *force_sw = getenv("NERVA_FORCE_SOFTWARE_AES");
    if (force_sw != NULL && force_sw[0] != '\0' && force_sw[0] != '0')
        return 0;

#if !defined(SLOW_HASH_HW_AES_BUILT)
    return 0;
#elif defined(__APPLE__) && defined(__aarch64__)
    /* Apple Silicon always implements the ARMv8 Crypto Extensions. */
    return 1;
#elif (defined(__linux__) || defined(__ANDROID__)) && defined(__aarch64__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined(__x86_64__) || defined(__i386__) || (defined(_MSC_VER) && (defined(_WIN64) || defined(_M_IX86)))
    /* Delegate to the existing C++ helper (crypto::has_aesni in crypto.cpp)
     * via its C-linkage wrapper, so we reuse the project's tested cpuid
     * code instead of writing our own. AES-NI exists in 32-bit mode too. */
    return crypto_has_aesni();
#else
    return 0;
#endif
}

int cn_hardware_aes_supported(void)
{
    static int cached = -1;
    if (cached < 0)
        cached = detect_hardware_aes();
    return cached;
}

#define CN_DISPATCH(call_hw, call_sw) \
    do { \
        if (cn_hardware_aes_supported()) { call_hw; } else { call_sw; } \
    } while (0)

#if !defined(SLOW_HASH_HW_AES_BUILT)
/* No HW path compiled in for this target; reduce dispatch to a direct call.
 * call_hw is dropped without evaluation since the _hw symbols don't exist. */
#undef CN_DISPATCH
#define CN_DISPATCH(call_hw, call_sw) do { call_sw; } while (0)
#endif

void cn_slow_hash(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    CN_DISPATCH(cn_slow_hash_hw(ctx, data, length, hash, variant, prehashed, iters),
                cn_slow_hash_sw(ctx, data, length, hash, variant, prehashed, iters));
}

void cn_slow_hash_v7_8(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters)
{
    CN_DISPATCH(cn_slow_hash_v7_8_hw(ctx, data, length, hash, iters),
                cn_slow_hash_v7_8_sw(ctx, data, length, hash, iters));
}

void cn_slow_hash_v9(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters)
{
    CN_DISPATCH(cn_slow_hash_v9_hw(ctx, data, length, hash, iters),
                cn_slow_hash_v9_sw(ctx, data, length, hash, iters));
}

void cn_slow_hash_v10(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    CN_DISPATCH(cn_slow_hash_v10_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy, zz, ww),
                cn_slow_hash_v10_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy, zz, ww));
}

void cn_slow_hash_v11(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    CN_DISPATCH(cn_slow_hash_v11_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy),
                cn_slow_hash_v11_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy));
}

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
    ctx->oaes_ctx = oaes_alloc();
    if (ctx->oaes_ctx == NULL) {
        free(ctx);
        return NULL;
    }
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

    if (context->oaes_ctx != NULL) {
        oaes_free((OAES_CTX **)&(context->oaes_ctx));
    }

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

int cn_slow_hash_self_test(void)
{
#if !defined(SLOW_HASH_HW_AES_BUILT)
    return 1;
#else
    if (!cn_hardware_aes_supported())
        return 1;

    cn_hash_context_t *ctx = cn_hash_context_create();
    if (ctx == NULL)
        return 1;

    static const char input[] = "nerva-cn-slow-hash-hw-vs-sw-self-test";
    char hw[HASH_SIZE];
    char sw[HASH_SIZE];
    int ok = 1;

    /* v7_8: no salt use, simplest case. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v7_8_hw(ctx, input, sizeof(input) - 1, hw, 64);
    cn_slow_hash_v7_8_sw(ctx, input, sizeof(input) - 1, sw, 64);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    /* v9: reads salt via randomize_scratchpad_4k. Neither path modifies salt
     * in the inner loop, so one reset is enough. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v9_hw(ctx, input, sizeof(input) - 1, hw, 64);
    cn_slow_hash_v9_sw(ctx, input, sizeof(input) - 1, sw, 64);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    /* v10 and v11 call salt_pad in the inner loop, which writes back into
     * salt. Reset between HW and SW so they see the same input.
     *
     * These are the variants that actually secure the chain (mainnet PoW
     * routes through cn_slow_hash_v11), and they're where HW and SW differ
     * in r2's source buffer (&c on HW, &b on SW in slow-hash-impl.h). xx/yy
     * picked small so the test runs in milliseconds but still triggers
     * salt_pad at least once per inner level. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v10_hw(ctx, input, sizeof(input) - 1, hw, 64, 8, 2, 2, 2, 2);
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v10_sw(ctx, input, sizeof(input) - 1, sw, 64, 8, 2, 2, 2, 2);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v11_hw(ctx, input, sizeof(input) - 1, hw, 64, 8, 2, 2);
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v11_sw(ctx, input, sizeof(input) - 1, sw, 64, 8, 2, 2);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    cn_hash_context_free(ctx);
    return ok;
#endif
}
