/* Prove a change to src/crypto did not change any consensus hash.
 *
 * Two gates, both already in the tree and neither normally reachable without
 * starting a daemon:
 *
 *   cn_slow_hash_known_answer_test   fixed vectors for v10, v11, v13 and v14.
 *                                    This is the one that matters: it pins the
 *                                    hashes that live heights were validated
 *                                    against, so it fails if an edit moved any
 *                                    of them, including an edit that moved the
 *                                    hardware and software arms together.
 *
 *   cn_slow_hash_self_test           hardware AES against software AES. Catches
 *                                    an arm that diverged from the other, which
 *                                    the vectors alone would not if both moved.
 *
 * Run this after any edit to slow-hash.h, slow-hash.c, slow-hash-impl.h,
 * slow-hash-v8-impl.h or the AES helpers, and before committing one. It takes a
 * few seconds and it is the difference between "this change is inert" as an
 * assertion and as a fact.
 *
 * It was written while porting the streaming-store switch (PLAN-v8-PHASE7 A6),
 * whose whole safety argument is that it compiles to the memcpy it replaces
 * when the switch is off. That argument is worth nothing unverified.
 *
 * Exit status is 0 only if both pass, so it can gate a script.
 *
 * Build: sh contrib/powbench/build-kat.sh
 */

#include <stdio.h>
#include <cpuid.h>

#include "hash-ops.h"

/* slow-hash.c calls this and the real one is in a C++ TU that is not linked
 * here. Same answer, so the dispatcher picks the same arm it would in the
 * daemon; without it the link fails rather than quietly running software AES. */
int crypto_has_aesni(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(0, &a, &b, &c, &d) || a == 0) return 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return 0;
    return (c & (1u << 25)) != 0;
}

int main(void)
{
    int kat, st;

    /* Which arm ran is part of the result: a pass on the software arm alone
     * says nothing about the hardware one that every miner uses. */
    printf("hardware AES dispatch: %s\n",
           cn_hardware_aes_supported() ? "yes" : "NO, software arm only");

    kat = cn_slow_hash_known_answer_test();
    printf("known-answer vectors (v10, v11, v13, v14): %s\n", kat ? "PASS" : "FAIL");

    st = cn_slow_hash_self_test();
    printf("hardware AES against software AES:         %s\n", st ? "PASS" : "FAIL");

    if (!kat)
        printf("\n  A known-answer failure means a consensus hash moved.\n"
               "  Do not commit. The vectors name the failing one on stderr.\n");
    else if (!st)
        printf("\n  The vectors pass but the two arms disagree, so one arm\n"
               "  drifted. Mining and verification would split.\n");

    return (kat && st) ? 0 : 1;
}
