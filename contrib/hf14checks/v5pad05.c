/* v5 at 512 KB, below the smallest size Phase 3 ever measured. PLAN-v8-PHASE7 C1
   reopens the pad decision downward; this is the leading candidate, because its
   derived stride modulus is 127, a prime larger than the largest offset_1, so
   unlike 125 at 1 MB it never degenerates. See v5pad.inc for what a resized pad
   requires. */
#define V5PAD_TAG   p05
#define V5PAD_BYTES (512 * 1024)
#include "v5pad.inc"
