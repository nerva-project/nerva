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

/* PLAN-v8 Phase 6 B2: the chain salt is fetched from inside the hash, seeded
 * from the AES fill's final chain state, so a device cannot produce salts
 * without first running the whole 1 MB fill.
 *
 * Nothing exercises that path at runtime today: HF14 is not active, so the
 * daemon never calls cn_slow_hash_v14_chain, and cn_slow_hash_self_test only
 * covers the NULL-callback entry. Without this check the consensus path would
 * ship having never run.
 *
 * The load-bearing property is B2's whole point and it is the one a refactor
 * would silently break: THE SEED MUST BE THE FILL'S OUTPUT, NOT THE BLOB'S
 * HASH. If someone "simplifies" it back to keccak(blob), every test that only
 * compares hashes still passes, because the hash is self-consistent either
 * way. Case 2 is what catches that: the seed has to move when init_size_blk
 * moves, since blk changes how the fill chains but cannot change keccak(blob).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "hash-ops.h"

void cn_slow_hash_v14_chain(cn_hash_context_t *, const void *, size_t, char *,
                            uint8_t, cn_v8_salt_fn, void *);
void cn_slow_hash_v14(cn_hash_context_t *, const void *, size_t, char *,
                      size_t, uint8_t, uint16_t, uint16_t);

static int failures = 0;
#define CHECK(cond, msg)                                        \
    do {                                                        \
        if (!(cond)) { printf("  FAIL: %s\n", (msg)); failures++; } \
        else         { printf("  ok:   %s\n", (msg)); }          \
    } while (0)

struct probe {
    unsigned char seed[32];
    int calls;
    cn_v8_draw_t give;
};

/* Records the seed it was handed, then supplies a fixed salt and fixed draws,
 * so the only thing that can move the hash is the seed itself. */
static void probe_fn(void *user, const unsigned char seed[32], char *salt_out, cn_v8_draw_t *draw)
{
    struct probe *p = (struct probe *)user;
    memcpy(p->seed, seed, 32);
    p->calls++;
    for (size_t i = 0; i < CN_SALT_MEMORY; i++)
        salt_out[i] = (char)(i * 31u + 7u);
    *draw = p->give;
}

int main(void)
{
    static const char blob_a[] = "nerva v8 chain-entry check, blob A";
    static const char blob_b[] = "nerva v8 chain-entry check, blob B";
    cn_hash_context_t *ctx = cn_hash_context_create();
    char h1[32], h2[32];
    struct probe p1, p2;

    if (!ctx) { printf("context alloc failed\n"); return 1; }
    memset(&ctx->random_values, 0, sizeof(ctx->random_values));

    printf("v8 chain entry (hardware AES: %s)\n\n",
           cn_hardware_aes_supported() ? "yes" : "no, software path");

    /* 1. deterministic: same blob, same callback, same hash */
    memset(&p1, 0, sizeof p1); p1.give.xx = 6; p1.give.yy = 5; p1.give.iters = 17;
    memset(&p2, 0, sizeof p2); p2.give = p1.give;
    cn_slow_hash_v14_chain(ctx, blob_a, sizeof(blob_a) - 1, h1, CN_V8_INIT_SIZE_BLK, probe_fn, &p1);
    cn_slow_hash_v14_chain(ctx, blob_a, sizeof(blob_a) - 1, h2, CN_V8_INIT_SIZE_BLK, probe_fn, &p2);
    CHECK(p1.calls == 1, "the callback runs exactly once per hash");
    CHECK(memcmp(h1, h2, 32) == 0, "same blob and same salt give the same hash");
    CHECK(memcmp(p1.seed, p2.seed, 32) == 0, "same blob gives the same seed");

    /* 2. THE PROPERTY B2 EXISTS FOR: the seed is the fill's output.
     * blk changes how the fill chains, so it must move the seed. keccak(blob)
     * would not move, which is exactly the regression to catch. */
    memset(&p2, 0, sizeof p2); p2.give = p1.give;
    cn_slow_hash_v14_chain(ctx, blob_a, sizeof(blob_a) - 1, h2, 2, probe_fn, &p2);
    CHECK(memcmp(p1.seed, p2.seed, 32) != 0,
          "the seed moves with init_size_blk, so it is the fill, not keccak(blob)");

    /* 3. the seed still depends on the blob */
    memset(&p2, 0, sizeof p2); p2.give = p1.give;
    cn_slow_hash_v14_chain(ctx, blob_b, sizeof(blob_b) - 1, h2, CN_V8_INIT_SIZE_BLK, probe_fn, &p2);
    CHECK(memcmp(p1.seed, p2.seed, 32) != 0, "a different blob gives a different seed");
    CHECK(memcmp(h1, h2, 32) != 0, "a different blob gives a different hash");

    /* 4. the draws the callback returns are the ones the hash uses: changing
     * them must change the hash with everything else held fixed */
    memset(&p2, 0, sizeof p2); p2.give = p1.give; p2.give.xx = 7;
    cn_slow_hash_v14_chain(ctx, blob_a, sizeof(blob_a) - 1, h2, CN_V8_INIT_SIZE_BLK, probe_fn, &p2);
    CHECK(memcmp(h1, h2, 32) != 0, "xx returned by the callback reaches the hash");

    memset(&p2, 0, sizeof p2); p2.give = p1.give; p2.give.iters = 18;
    cn_slow_hash_v14_chain(ctx, blob_a, sizeof(blob_a) - 1, h2, CN_V8_INIT_SIZE_BLK, probe_fn, &p2);
    CHECK(memcmp(h1, h2, 32) != 0, "iters returned by the callback reaches the hash");

    /* 5. a NULL callback leaves the caller's salt and parameters alone, which
     * is what every benchmark and the self-test rely on */
    for (size_t i = 0; i < CN_SALT_MEMORY; i++)
        ctx->salt[i] = (char)(i * 31u + 7u);
    cn_slow_hash_v14(ctx, blob_a, sizeof(blob_a) - 1, h2, 17, CN_V8_INIT_SIZE_BLK, 6, 5);
    CHECK(memcmp(h1, h2, 32) == 0,
          "NULL callback with the same salt and draws matches the chain entry");

    cn_hash_context_free(ctx);
    printf("\n%s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
