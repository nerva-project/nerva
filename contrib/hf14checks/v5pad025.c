/* v5 at 256 KB, the floor: the pad must be a whole multiple of CN_SALT_MEMORY
   or the sweep reads past the salt, and 256 KB is that multiple at 1. Measured
   for completeness rather than as a candidate, since its stride modulus is 128
   and half of all draws then land on a reduced stride set. PLAN-v8-PHASE7 C1.1. */
#define V5PAD_TAG   p025
#define V5PAD_BYTES (256 * 1024)
#include "v5pad.inc"
