// Copyright (c) 2018-2026, The Nerva Project
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
#include <stdio.h>
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
#include "cna-vm.h"

#if defined(SLOW_HASH_HW_AES_BUILT)
extern void cn_slow_hash_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
extern void cn_slow_hash_v7_8_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v9_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v10_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
extern void cn_slow_hash_v11_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
extern void cn_slow_hash_v13_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed);
extern void cn_slow_hash_v14_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
extern void cn_slow_hash_v14_chain_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, uint8_t init_size_blk, cn_v8_salt_fn salt_fn, void *salt_user);
extern void cn_slow_hash_v15_hw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
#endif

extern void cn_slow_hash_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters);
extern void cn_slow_hash_v7_8_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v9_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters);
extern void cn_slow_hash_v10_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww);
extern void cn_slow_hash_v11_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
extern void cn_slow_hash_v13_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, const uint8_t *seed);
extern void cn_slow_hash_v14_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
extern void cn_slow_hash_v14_chain_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, uint8_t init_size_blk, cn_v8_salt_fn salt_fn, void *salt_user);
extern void cn_slow_hash_v15_sw(cn_hash_context_t *context, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy);
extern int cn_slow_hash_v15_selftest(void);

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

/* v8 hashes into the legacy buffer, which at 1 MB is large enough. Raising the
 * pad past it means pointing CN_V8_PAD at cna_scratchpad and relaxing this.
 * Here rather than in hash-ops.h because that header is included from C++,
 * where _Static_assert is not a keyword. */
_Static_assert(CN_SCRATCHPAD_MEMORY_V8 <= CN_SCRATCHPAD_MEMORY,
               "v8 pad must fit the legacy buffer it hashes into; see CN_V8_PAD");

/* defined below, next to the allocator it uses */
static void cn_pads_require(cn_hash_context_t *ctx, int legacy, int v6);

void cn_slow_hash(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, int variant, int prehashed, size_t iters)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_hw(ctx, data, length, hash, variant, prehashed, iters),
                cn_slow_hash_sw(ctx, data, length, hash, variant, prehashed, iters));
}

void cn_slow_hash_v7_8(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v7_8_hw(ctx, data, length, hash, iters),
                cn_slow_hash_v7_8_sw(ctx, data, length, hash, iters));
}

void cn_slow_hash_v9(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v9_hw(ctx, data, length, hash, iters),
                cn_slow_hash_v9_sw(ctx, data, length, hash, iters));
}

void cn_slow_hash_v10(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy, uint16_t zz, uint16_t ww)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v10_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy, zz, ww),
                cn_slow_hash_v10_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy, zz, ww));
}

void cn_slow_hash_v11(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v11_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy),
                cn_slow_hash_v11_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy));
}

/* CNA v8, the HF14 hash. Same pads and signature as v11, since it is v11 with
 * a different hash selector inside salt_pad. */
void cn_slow_hash_v14(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    /* v8 runs at CN_SCRATCHPAD_MEMORY_V8, which fits the legacy pad. */
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v14_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy),
                cn_slow_hash_v14_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy));
}

/* The consensus entry: the salt is fetched inside the hash, seeded from the
 * AES fill, and the per-nonce draws come back with it. PLAN-v8 Phase 6 B2. */
void cn_slow_hash_v14_chain(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, uint8_t init_size_blk, cn_v8_salt_fn salt_fn, void *salt_user)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v14_chain_hw(ctx, data, length, hash, init_size_blk, salt_fn, salt_user),
                cn_slow_hash_v14_chain_sw(ctx, data, length, hash, init_size_blk, salt_fn, salt_user));
}

/* CNA v8 plus the floating-point stage. PROTOTYPE: no consensus path routes
 * here. Exists so it can be measured against v14 in the same process. */
void cn_slow_hash_v15(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, size_t iters, uint8_t init_size_blk, uint16_t xx, uint16_t yy)
{
    cn_pads_require(ctx, 1, 0);
    CN_DISPATCH(cn_slow_hash_v15_hw(ctx, data, length, hash, iters, init_size_blk, xx, yy),
                cn_slow_hash_v15_sw(ctx, data, length, hash, iters, init_size_blk, xx, yy));
}

void cn_slow_hash_v13(cn_hash_context_t *ctx, const void *data, size_t length, char *hash, const uint8_t *seed)
{
    cn_pads_require(ctx, 0, 1);
    CN_DISPATCH(cn_slow_hash_v13_hw(ctx, data, length, hash, seed),
                cn_slow_hash_v13_sw(ctx, data, length, hash, seed));
}

/* mmap + MADV_HUGEPAGE on Linux is best effort: the kernel can back the mapping
 * with base pages anyway, and it decides that as the pages are faulted in, well
 * after the allocation returns. So the tier allocate_hugepage recorded is what
 * we asked for, not what we got, and printing it claims huge pages that may not
 * exist. Ask the kernel what actually happened. Only Linux needs this: Windows
 * large pages either come back from VirtualAlloc or they do not, and FreeBSD
 * superpages are transparent with nothing to query. */
int cn_page_tier_actual(const void *p, size_t size, int requested_tier)
{
#if defined(__linux__) && !defined(__ANDROID__)
    if (requested_tier != CN_PAGES_THP || p == NULL)
        return requested_tier;

    FILE *f = fopen("/proc/self/smaps", "r");
    if (f == NULL)
        return requested_tier;   /* cannot tell, do not invent an answer */

    const unsigned long target = (unsigned long)(uintptr_t)p;
    char line[512];
    int in_mapping = 0;
    long huge_kb = -1;
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long from, to;
        if (sscanf(line, "%lx-%lx", &from, &to) == 2)
            in_mapping = (target >= from && target < to);
        else if (in_mapping && strncmp(line, "AnonHugePages:", 14) == 0) {
            sscanf(line + 14, "%ld", &huge_kb);
            break;
        }
    }
    fclose(f);

    if (huge_kb < 0)
        return requested_tier;   /* kernel did not report the field */
    /* most of the mapping has to be huge-page backed to call it that */
    if ((size_t)huge_kb * 1024u < size / 2u)
        return CN_PAGES_PLAIN_MMAP;
    return requested_tier;
#else
    (void)p; (void)size;
    return requested_tier;
#endif
}

/* The page tier of whichever buffer carries the hashrate at this fork version,
 * as the kernel actually backed it: the 8 MB v6 pad at v13, the 1 MB legacy
 * pad everywhere else, v14 included. Call it after a hash of that
 * version has run, or the buffer will not be allocated yet.
 *
 * v13 exactly, not >= 13: v14 hashes from the legacy pad (CN_V8_PAD) and its
 * dispatcher asks for cn_pads_require(ctx, 1, 0), so cna_scratchpad is never
 * allocated at v14. Reading its tier returned the is_mapped field of a NULL
 * buffer, which is CN_PAGES_MALLOC, so every v14 miner was told it was on
 * normal pages no matter what the 1 MB pad actually got. */
int cn_page_tier_for_version(const cn_hash_context_t *ctx, uint8_t major_version)
{
    if (ctx == NULL)
        return CN_PAGES_MALLOC;
    if (major_version == 13)
        return cn_page_tier_actual(ctx->cna_scratchpad, CN_SCRATCHPAD_MEMORY_V13, ctx->cna_scratchpad_is_mapped);
    return cn_page_tier_actual(ctx->scratchpad, CN_SCRATCHPAD_MEMORY, ctx->scratchpad_is_mapped);
}

const char *cn_page_tier_name(int tier)
{
    switch (tier)
    {
    case CN_PAGES_HUGE:       return "huge pages";
    case CN_PAGES_THP:        return "transparent huge pages";
    case CN_PAGES_PLAIN_MMAP: return "normal pages (mmap)";
    default:                  return "normal pages (malloc)";
    }
}

#ifdef __linux__
/* madvise(MADV_HUGEPAGE) returns success even when transparent huge pages
 * are switched off system-wide (transparent_hugepage=never), in which case
 * the hint is a no-op and the region stays on 4 KB pages. Read the mode once
 * so we only claim the THP tier when the hint can actually take effect; a
 * mode we cannot read is treated as "might work" so a real THP mapping is
 * never hidden. */
static int thp_hint_effective(void)
{
    static int effective = -1;
    if (effective < 0)
    {
        char line[128];
        FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
        effective = 1;
        if (f != NULL)
        {
            if (fgets(line, sizeof(line), f) && strstr(line, "[never]"))
                effective = 0;
            fclose(f);
        }
    }
    return effective;
}
#endif

/* Allocate `size` bytes on the largest page size the OS will give us, and
 * return the CN_PAGES_* tier it landed on (hash-ops.h). Stays silent on
 * purpose; the caller decides whether the tier is worth a user-facing
 * warning (the miner does, block validation does not care).
 *
 * Tier ladder per platform:
 *   Windows:  MEM_LARGE_PAGES (one retry after working-set trim) -> malloc
 *   Linux:    MAP_HUGETLB -> mmap + madvise(MADV_HUGEPAGE) (THP) -> mmap
 *   FreeBSD:  mmap + MAP_ALIGNED_SUPER (transparent superpages) -> mmap
 *   others:   mmap -> malloc (no huge-page mechanism exposed) */
static int allocate_hugepage(size_t size, void **hp)
{
#if defined(_MSC_VER) || defined(__MINGW32__)
    /* Large pages need the SeLockMemory privilege ("Lock pages in memory")
     * and physically contiguous memory, which fragments away with uptime.
     * No THP equivalent on Windows, so the only fallback is malloc. */
    const SIZE_T lp_min = GetLargePageMinimum();
    if (lp_min != 0 && SetLockPagesPrivilege(GetCurrentProcess(), TRUE))
    {
        /* VirtualAlloc rejects large-page requests that are not a multiple
         * of the large-page size, so round up (mmap does the same rounding
         * for hugetlb on Linux). Costs at most one extra large page for the
         * salt and the 1 MB legacy pad. */
        const SIZE_T lp_size = (size + lp_min - 1) & ~(lp_min - 1);
        *hp = VirtualAlloc(NULL, lp_size, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (*hp == NULL) {
            /* Contiguous memory fragments with uptime; trimming our own
             * working set nudges the memory manager to free contiguous runs
             * and one retry rescues a good share of borderline failures
             * (same technique as XMRig). Only worth it while the privilege
             * is held - without it large pages can never succeed. */
            SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
            *hp = VirtualAlloc(NULL, lp_size, MEM_LARGE_PAGES | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        if (*hp != NULL)
            return CN_PAGES_HUGE;
    }
    *hp = malloc(size);
    return CN_PAGES_MALLOC;
#elif defined(__FreeBSD__)
    /* No hugetlb pool on FreeBSD; superpages are transparent. The aligned
     * mapping plus a full prefault lets the VM promote it to superpages. */
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_ALIGNED_SUPER, -1, 0);
    if (*hp != MAP_FAILED) {
        memset(*hp, 0, size);
        return CN_PAGES_THP;
    }
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (*hp != MAP_FAILED)
        return CN_PAGES_PLAIN_MMAP;
    *hp = malloc(size);
    return CN_PAGES_MALLOC;
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (*hp != MAP_FAILED)
        return CN_PAGES_PLAIN_MMAP;
    *hp = malloc(size);
    return CN_PAGES_MALLOC;
#else
    /* MAP_POPULATE faults the huge pages in now instead of one by one
     * during the first hash. */
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE, -1, 0);
    if (*hp != MAP_FAILED)
        return CN_PAGES_HUGE;
    /* No hugetlb pool reserved (vm.nr_hugepages). Take regular pages and
     * hint transparent huge pages; with THP enabled the prefault typically
     * lands the region on 2 MB pages right away, which is most of what the
     * v13 pointer chase wants. */
    *hp = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*hp != MAP_FAILED) {
        int thp = -1;
#ifdef MADV_HUGEPAGE
        thp = madvise(*hp, size, MADV_HUGEPAGE);
#endif
        memset(*hp, 0, size);
#ifdef __linux__
        /* madvise accepted the hint but that is not a promise of huge pages;
         * if THP is off system-wide we are on 4 KB pages, so report plain
         * mmap and let the miner warn instead of claiming a tier we did not
         * get. */
        if (thp == 0 && !thp_hint_effective())
            return CN_PAGES_PLAIN_MMAP;
#endif
        return (thp == 0) ? CN_PAGES_THP : CN_PAGES_PLAIN_MMAP;
    }
    *hp = malloc(size);
    return CN_PAGES_MALLOC;
#endif
}

#if !defined(_MSC_VER) && !defined(__MINGW32__) && defined(__linux__)
/* munmap length must be a multiple of the huge page size for hugetlb
 * mappings; the kernel rounds up at mmap time but does not tell us, so
 * read the default size (Hugepagesize in /proc/meminfo) once. */
static size_t default_hugepage_size(void)
{
    static unsigned long kb = 0;
    if (kb == 0)
    {
        char line[128];
        FILE *f = fopen("/proc/meminfo", "r");
        if (f != NULL)
        {
            while (fgets(line, sizeof(line), f) && sscanf(line, "Hugepagesize: %lu kB", &kb) != 1)
                ;
            fclose(f);
        }
        if (kb == 0)
            kb = 2048;
    }
    return (size_t)kb * 1024;
}
#endif

static void free_hugepage(void *hp, size_t size, int page_tier)
{
    if (page_tier) {
#if defined(_MSC_VER) || defined(__MINGW32__)
        VirtualFree(hp, 0, MEM_RELEASE);
#else
#if defined(__linux__)
        if (page_tier == CN_PAGES_HUGE)
        {
            const size_t hps = default_hugepage_size();
            size = (size + hps - 1) & ~(hps - 1);
        }
#endif
        munmap(hp, size);
#endif
    } else {
        free(hp);
    }
}

/* Allocate a PoW buffer on first use. Contexts are also created for work that
 * never hashes a block (the wallet KDF, key encryption) and a node past HF14
 * never touches the v6 pad, so none of these are worth carrying up front. The
 * context is per-thread, so there is no race to guard. Failure leaves the
 * pointer NULL and returns 0; the caller decides how loudly to die. */
static int cn_buffer_ensure(uint8_t **buf, int *tier, size_t size)
{
    if (*buf == NULL)
        *tier = allocate_hugepage(size, (void **)buf);
    return *buf != NULL;
}

static int cn_pads_ensure(cn_hash_context_t *ctx, int legacy, int v6)
{
    if (legacy && !cn_buffer_ensure(&ctx->scratchpad, &ctx->scratchpad_is_mapped, CN_SCRATCHPAD_MEMORY))
        return 0;
    if (v6 && !cn_buffer_ensure(&ctx->cna_scratchpad, &ctx->cna_scratchpad_is_mapped, CN_SCRATCHPAD_MEMORY_V13))
        return 0;
    return 1;
}

static void cn_pads_require(cn_hash_context_t *ctx, int legacy, int v6)
{
    if (!cn_pads_ensure(ctx, legacy, v6)) {
        /* hashing cannot proceed, and a wrong hash would be worse than a
         * crash; a failed pad allocation means the process is out of memory */
        fprintf(stderr, "failed to allocate a CryptoNight scratchpad\n");
        abort();
    }
}

cn_hash_context_t *cn_hash_context_create(void)
{
    // calloc so pointer fields start NULL; a failed alloc can't leave
    // cn_hash_context_free freeing an uninitialized pointer.
    cn_hash_context_t *ctx = (cn_hash_context_t *)calloc(1, sizeof(cn_hash_context_t));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->oaes_ctx = oaes_alloc();
    if (ctx->oaes_ctx == NULL) {
        free(ctx);
        return NULL;
    }
    /* the PoW pads are allocated on first use (cn_pads_ensure); calloc above
     * leaves their pointers NULL. Only the salt is carried up front, because
     * the block-hash callers fill it before they call in. */
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

    if (context->cna_scratchpad != NULL) {
        free_hugepage(context->cna_scratchpad, CN_SCRATCHPAD_MEMORY_V13, context->cna_scratchpad_is_mapped);
        context->cna_scratchpad = NULL;
    }

    if (context->salt != NULL) {
        free_hugepage(context->salt, CN_SALT_MEMORY, context->salt_is_mapped);
        context->salt = NULL;
    }

    free(context);
}

/* Separate from cn_slow_hash_self_test: that one gates startup and is gated on
 * hardware AES, and neither fits a prototype that has nothing to do with AES.
 * Catches a build whose floating point diverges, which would fork rather than
 * fail to compile.
 *
 * Returns 1 on success, inverting cn_slow_hash_v15_selftest, to match
 * cn_slow_hash_self_test's convention.
 *
 * WHEN v15 SHIPS: make this fatal and move the hw-vs-sw comparison into
 * cn_slow_hash_self_test beside v14's. */
int cn_fp_stage_self_test(void)
{
    return cn_slow_hash_v15_selftest() == 0 ? 1 : 0;
}

/* v8 known-answer vectors, generated from the shipped implementation.
 * salt and random_values are zeroed before each case so the vector
 * depends only on (input, iters, blk, xx, yy). */
static const struct { uint16_t xx, yy; uint32_t iters; unsigned char want[32]; } cn_v14_kat[] = {
    { 4, 4, 0, {0x23,0xe8,0x63,0x37,0xd6,0x56,0x3f,0x83,0x9a,0xac,0x60,0xb6,0x64,0x74,0x8a,0x33,0xb0,0x24,0xf2,0x8c,0x08,0x5f,0xf9,0xb8,0xc9,0xa5,0xf6,0x38,0x37,0xb8,0xed,0x45} },
    { 4, 5, 1, {0x3e,0x01,0xa5,0xc5,0xf1,0x3b,0x2e,0x83,0x6b,0xcc,0x21,0x13,0xd4,0x68,0x7d,0x91,0xe8,0xc0,0xb3,0x6b,0x4d,0xea,0x74,0xa7,0xd9,0xa9,0xbc,0xcd,0x09,0xee,0x57,0xc2} },
    { 5, 4, 17, {0xc3,0xb7,0x06,0x5e,0xc7,0xad,0xec,0xd6,0x90,0x54,0xd4,0xf8,0x41,0x88,0x9d,0xea,0xb4,0xc8,0xe4,0xdd,0x09,0x4e,0xc9,0x6a,0x95,0xd0,0x90,0x9e,0x7f,0xe0,0x26,0x35} },
    { 6, 6, 64, {0x23,0x15,0x6a,0x57,0xad,0x07,0x7f,0xc5,0xbf,0xde,0xa2,0x35,0x7d,0xb1,0x20,0x3c,0x0f,0x9c,0x99,0x8e,0x79,0x19,0x63,0xce,0xa1,0x9a,0x98,0x4b,0x57,0x35,0x44,0x92} },
    { 8, 8, 63, {0x94,0x5f,0x9f,0x1d,0x48,0x96,0x59,0x17,0x84,0xe8,0x2b,0x33,0xe8,0xef,0x10,0x35,0xce,0x1c,0xe9,0x3a,0x9c,0xdb,0x6c,0xaf,0x8e,0xcb,0xb2,0x8d,0xb4,0x42,0x6c,0x19} },
    { 7, 5, 7, {0xc7,0xc5,0x87,0x4c,0xa0,0xe2,0xa5,0xca,0x71,0xd5,0x96,0x49,0xe6,0x8c,0xb7,0xfa,0xcf,0xf4,0xe6,0xa3,0x62,0x4d,0x97,0x20,0x21,0x79,0x91,0xef,0xb7,0x53,0xbf,0x8c} },
};

/* Fixed salt and fixed draws, so the chain entry's self-test compares the two
 * AES arms rather than the callback. draw_out is NULL when it is called just to
 * fill a salt buffer. */
static void cn_selftest_salt(void *user, const unsigned char seed[32], char *salt_out, cn_v8_draw_t *draw_out)
{
    size_t i;
    (void)user;
    (void)seed;
    for (i = 0; i < CN_SALT_MEMORY; i++)
        salt_out[i] = (char)(i * 31u + 7u);
    if (draw_out != NULL)
    {
        draw_out->xx = 3;
        draw_out->yy = 3;
        draw_out->iters = 64;
    }
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

    /* every case below calls the _hw/_sw entry points directly, so the lazy
     * allocation in the dispatchers does not run for them. A failed allocation
     * says nothing about HW versus SW agreement, so skip the test the same way
     * a failed context allocation does above rather than refusing to start. */
    if (!cn_pads_ensure(ctx, 1, 1)) {
        cn_hash_context_free(ctx);
        return 1;
    }

    /* variant 1 reads a tweak at data+35 as a 64 bit word, so anything
     * shorter than 43 bytes reads past the end of it. Monero refuses short
     * input outright; here the fixed test vector just has to be long enough. */
    static const char input[] = "nerva-cn-slow-hash hardware versus software self test vector";
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

    /* v14 (CNA v8). The two arms are separate copies whose r2 aliases a
     * different register on purpose, so a slip between them is invisible to
     * review and would split the chain along the AES-NI line. xx/yy run to 3 so
     * the inner loop runs more than once and actually varies the selector. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v14_hw(ctx, input, sizeof(input) - 1, hw, 64, 8, 3, 3);
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v14_sw(ctx, input, sizeof(input) - 1, sw, 64, 8, 3, 3);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    /* The chain entry, which is the one consensus uses and the one nothing
     * else can reach: HF14 is not active, so no daemon calls it in anger yet.
     * It shares cn_v8_core with the call above, but the callback hook sits
     * between the fill and the salt, so an arm that mishandled it would be
     * invisible to every check that does not go through it. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14_chain_hw(ctx, input, sizeof(input) - 1, hw, 8, cn_selftest_salt, NULL);
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_slow_hash_v14_chain_sw(ctx, input, sizeof(input) - 1, sw, 8, cn_selftest_salt, NULL);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    /* and it must agree with the caller-supplied-salt entry given the same
     * salt and the same draws, which is what stops the two from drifting */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    cn_selftest_salt(NULL, NULL, ctx->salt, NULL);
    cn_slow_hash_v14_hw(ctx, input, sizeof(input) - 1, sw, 64, 8, 3, 3);
    if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;

    /* Known-answer vectors. HW == SW cannot catch a change that moves both
     * arms together, which is what editing a shared macro like salt_pad_v8
     * does, and neither can the v14-against-v11 check below. These pin what
     * v8 computes so an unintended change to it fails the build's own
     * self-test rather than the chain. Regenerate them only when the
     * algorithm is meant to change, and say so in the commit. */
    {
        static const char kat_in[] = "nerva cna v8 known-answer vector";
        size_t ki;
        for (ki = 0; ki < sizeof(cn_v14_kat) / sizeof(cn_v14_kat[0]); ki++)
        {
            memset(&ctx->random_values, 0, sizeof(ctx->random_values));
            memset(ctx->salt, 0, CN_SALT_MEMORY);
            cn_slow_hash_v14(ctx, kat_in, sizeof(kat_in) - 1, hw,
                             cn_v14_kat[ki].iters, CN_V8_INIT_SIZE_BLK,
                             cn_v14_kat[ki].xx, cn_v14_kat[ki].yy);
            if (memcmp(hw, cn_v14_kat[ki].want, HASH_SIZE) != 0) ok = 0;
        }
    }

    /* v14 must also differ from v11 on the same inputs, which catches a build
     * where the variant silently failed to take effect (stale macro, bad copy,
     * an arm that picked up salt_pad). The HW/SW check above would still pass
     * in all of those. */
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));
    memset(ctx->salt, 0, CN_SALT_MEMORY);
    cn_slow_hash_v11_hw(ctx, input, sizeof(input) - 1, sw, 64, 8, 3, 3);
    if (memcmp(hw, sw, HASH_SIZE) == 0) ok = 0;

    /* v13: 8 MB scratchpad + VM. seed is a fixed 32-byte value; salt and
     * random_values reset so both paths see identical inputs. */
    {
        static const uint8_t seed[32] = {0};
        memset(&ctx->random_values, 0, sizeof(ctx->random_values));
        memset(ctx->salt, 0, CN_SALT_MEMORY);
        cn_slow_hash_v13_hw(ctx, input, sizeof(input) - 1, hw, seed);
        memset(&ctx->random_values, 0, sizeof(ctx->random_values));
        memset(ctx->salt, 0, CN_SALT_MEMORY);
        cn_slow_hash_v13_sw(ctx, input, sizeof(input) - 1, sw, seed);
        if (memcmp(hw, sw, HASH_SIZE) != 0) ok = 0;
    }


    cn_hash_context_free(ctx);
    return ok;
#endif
}
