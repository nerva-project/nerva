/* v8 at 1 MB with salt_pad_v8's pad sweep removed but its extra hash kept:
 * the middle option in PLAN-v8-PHASE8 D1.
 *
 * The pad sweep is provably not hard (A1b reorders it bit-identically) and is
 * the bulk of the cost. The extra hash is cheap and is the only thing forcing a
 * specialised implementation to carry blake, groestl, jh and skein alongside
 * AES, which is an area cost rather than a time cost.
 *
 * THIS IS A DIFFERENT HASH, deliberately. Symbol is cn_slow_hash_v14_np1. */
#define CN_V8_NO_PADXOR 1
#define V5PAD_TAG   np1
#define V5PAD_BYTES (1024 * 1024)
#include "v5pad.inc"
