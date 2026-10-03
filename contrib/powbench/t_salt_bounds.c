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

/* Can salt_pad_v8 read past the salt at any pad size?
 *
 * This is the failure mode the Phase 3 stride derivation exists to prevent,
 * and it is silent: an out-of-bounds read of a heap buffer usually returns
 * neighbouring memory rather than crashing, so the hash would simply be wrong
 * in a way no functional test notices, on some machines and not others.
 *
 * Sampling nonces cannot establish absence. But the inputs that drive the two
 * salt indices are small enough to enumerate completely:
 *
 *   temp_1    uint16_t, 65536 values
 *   offset_1  (d % 64) + 1, so 1..64
 *
 * and everything else is derived. So this walks the entire input space for
 * each candidate pad size and checks both places salt is indexed:
 *
 *   1. the 32-byte write, salt[offset_1 .. offset_1 + 31] where
 *      offset_1 = temp_1 * ((d % 3) + 1)
 *   2. the sweep, which steps salt once per loop iteration, so the highest
 *      index is (number of iterations - 1)
 *
 * 16.7M cases of integer arithmetic, no hashing, so it runs instantly and the
 * result is a proof over the input domain rather than evidence from a sample.
 *
 * Build:
 *   gcc -O2 -I src -I src/crypto -I contrib/epee/include \
 *       contrib/powbench/t_salt_bounds.c -o t_salt_bounds
 */

#include <stdio.h>
#include <stdint.h>

#include "hash-ops.h"

/* the derivation under test, from slow-hash.h */
#define SALT_STEP(pad)  ((pad) / CN_SALT_MEMORY)
#define STRIDE_MOD(pad) (129 - SALT_STEP(pad))

static int check_pad(uint64_t pad, const char *name)
{
    const uint32_t step = (uint32_t)SALT_STEP(pad);
    const uint32_t mod  = (uint32_t)STRIDE_MOD(pad);
    uint32_t worst_sweep = 0, worst_write = 0;
    uint32_t o1, t1;
    int bad = 0;

    if (mod == 0 || step == 0) {
        printf("  %-5s  INVALID: step %u, mod %u\n", name, step, mod);
        return 1;
    }

    /* 1. the 32-byte salt write. offset_1 here is temp_1 * ((d % 3) + 1),
     *    so the multiplier is 1, 2 or 3. */
    for (t1 = 0; t1 < 65536u; t1++) {
        uint32_t m;
        for (m = 1; m <= 3; m++) {
            const uint32_t top = t1 * m + 31u;
            if (top > worst_write) worst_write = top;
        }
    }
    if (worst_write >= (uint32_t)CN_SALT_MEMORY) bad++;

    /* 2. the sweep. j runs offset_1, offset_1+offset_2, ... while j < pad, and
     *    salt is stepped once per iteration, so the highest index touched is
     *    iterations - 1. */
    for (o1 = 1; o1 <= 64u; o1++) {
        for (t1 = 0; t1 < 65536u; t1++) {
            const uint32_t o2 = ((t1 * o1) % mod) + step;
            /* iterations of: for (j = o1; j < pad; j += o2) */
            const uint64_t iters = (pad > o1) ? ((pad - o1 + o2 - 1) / o2) : 0;
            const uint64_t top   = iters ? iters - 1 : 0;
            if (top > worst_sweep) worst_sweep = (uint32_t)top;
            if (top >= (uint64_t)CN_SALT_MEMORY) bad++;
        }
    }

    printf("  %-5s step %3u  mod %3u   max write idx %6u   max sweep idx %6u   %s\n",
           name, step, mod, worst_write, worst_sweep,
           bad ? "OUT OF BOUNDS" : "in bounds");
    return bad;
}

int main(void)
{
    int bad = 0;

    printf("salt_pad_v8 bounds, exhaustive over temp_1 (65536) x offset_1 (64)\n");
    printf("salt is %u bytes, so every index must be <= %u\n\n",
           (unsigned)CN_SALT_MEMORY, (unsigned)CN_SALT_MEMORY - 1);

    bad += check_pad(1024ull*1024,  "1 MB");
    bad += check_pad(2048ull*1024,  "2 MB");
    bad += check_pad(4096ull*1024,  "4 MB");
    bad += check_pad(8192ull*1024,  "8 MB");

    /* The shipped v5 stride, for contrast: fixed at (% 125) + 4 whatever the
     * pad, which is why anything above 1 MB overruns and why v5pad.inc has to
     * wrap the index to benchmark it at all. */
    {
        uint64_t pad = 4096ull*1024;
        uint32_t o2min = 4, iters = (uint32_t)((pad + o2min - 1) / o2min);
        printf("\n  for contrast, v5's fixed stride at 4 MB: min stride %u\n", o2min);
        printf("  gives up to %u sweep steps against a %u-byte salt: %s\n",
               iters, (unsigned)CN_SALT_MEMORY,
               iters > (uint32_t)CN_SALT_MEMORY ? "OUT OF BOUNDS, as expected" : "in bounds");
    }

    printf("\n%s\n", bad == 0
           ? "PASS: no pad in the sweep can index the salt out of bounds"
           : "FAIL: a pad in the sweep reads past the salt");
    return bad == 0 ? 0 : 1;
}
