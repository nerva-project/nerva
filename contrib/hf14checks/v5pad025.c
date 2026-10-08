/* v5 and v8 at 256 KB, the floor: the pad must be a whole multiple of
   CN_SALT_MEMORY, and 256 KB is that multiple at 1. */
#define V5PAD_TAG   p025
#define V5PAD_BYTES (256 * 1024)
#include "v5pad.inc"
