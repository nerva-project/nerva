/* v8 at 1 MB with salt_pad_v8 removed: candidate D1 in PLAN-v8-PHASE8.
 *
 * THIS IS A DIFFERENT HASH, deliberately. The sweeps are 21.1% of a nonce by
 * the eager profile and are provably not hard, so D1 proposes deleting them and
 * spending the budget on the chain fill instead. v8 has never validated a
 * block, so the question is open.
 *
 * Compiled beside the real v8 rather than replacing it, so the two can be costed
 * against each other in one process on one machine, which is the only honest way
 * to compare them (measurement rule 6).
 *
 * The symbol is cn_slow_hash_v14_ns1. CN_V8_NO_SWEEP is read by
 * slow-hash-v8-impl.h; everything else is the standard resize scaffolding, so
 * the pad, the stride and the salt behave exactly as the shipped build's do. */
#define CN_V8_NO_SWEEP 1
#define V5PAD_TAG   ns1
#define V5PAD_BYTES (1024 * 1024)
#include "v5pad.inc"
