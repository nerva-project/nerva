/* v5 at 1.25 MB. See v5pad.inc for what a resized pad requires. */
#define V5PAD_TAG   p1_25
#define V5PAD_BYTES (1280 * 1024)
#define V5PAD_MOD   1   /* (1280 * 1024) / 16 is not a power of two */
#include "v5pad.inc"
