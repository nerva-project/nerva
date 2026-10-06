/* CNA v8 without salt_pad_v8, software-AES arm. PLAN-v8-PHASE8 candidate D1.
 *
 * A copy of src/crypto/slow-hash-v8-sw.c with CN_V8_NO_SWEEP defined and the
 * symbols renamed, so the variant links beside the shipped v8 and the two can
 * be compared in one process.
 *
 * It lives here and not in src/crypto because it is not a candidate for the
 * daemon build: nothing should be able to reach it by setting a define. When
 * D1 is decided, this file is deleted and the change is made in the real
 * translation units instead.
 *
 * Why a real translation unit rather than the v5pad.inc scaffolding that the
 * cost measurement used: v5pad.inc refuses a software-AES build by design,
 * because v5's pad indexing has its own power-of-two assumption on that path.
 * The hardware arm against the software arm is exactly the gate D1 needs, so
 * the variant needs a pair of units that can be built both ways.
 */

#include "hash-ops.h"

#undef CN_SCRATCHPAD_MEMORY
#define CN_SCRATCHPAD_MEMORY CN_SCRATCHPAD_MEMORY_V8

#define CN_V8_NO_SWEEP 1

#define cn_slow_hash_v14 cn_slow_hash_v14ns_sw
#define cn_slow_hash_v14_chain cn_slow_hash_v14ns_chain_sw
#define CN_V8_EMIT_CHAIN 1

#define CN_FORCE_SOFTWARE_AES 1

#include "slow-hash.h"
#include "slow-hash-v8-impl.h"
