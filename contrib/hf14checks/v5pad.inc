/* Template for a second compilation of v5 (cn_slow_hash_v11) at a different
   scratchpad size, so pad size can be varied without touching consensus code.
   This is a separate translation unit with renamed symbols, the same pattern
   slow-hash-sw.c and slow-hash-hw.c already use. The shipped 1 MB v11 is
   linked in unchanged alongside these and is the reference row in the bench.

   Each includer defines, before including this file:
     V5PAD_TAG    identifier suffix for the renamed symbols, e.g. p2
     V5PAD_BYTES  scratchpad size in bytes
     V5PAD_MOD    optional. Index the pad with % instead of &, so a size whose
                  block count is not a power of two still addresses all of it.

   THREE PAD-SIZE ASSUMPTIONS IN THE SHIPPED CODE HAVE TO BE LIFTED HERE. None
   is a live bug at the shipped 1 MB; each holds only because of that one size.

     randomize_scratchpad_256k  steps salt[x++] once per 4 pad bytes, and
     salt_pad                   steps salt[x++] once per offset_2 pad bytes,
                                where offset_2 is at least 4. Both stay in
                                bounds only because a 1 MB pad yields at most
                                1048576 / 4 = 262144 steps, which is exactly
                                CN_SALT_MEMORY. Any larger pad reads past the
                                salt. Wrapped below, which is what v13 already
                                does for its own 8 MB pad.

                                The wrap is an AND, not a compare and branch.
                                CN_SALT_MEMORY is 262144, a power of two, so
                                x & (CN_SALT_MEMORY - 1) wraps for free and is
                                a provable no-op at 1 MB, where x never reaches
                                the mask. Written as a branch instead, it cost
                                29% against the shipped build, because these
                                are the innermost loops of the whole hash and
                                run on the order of a million times per nonce.
                                The bench control row exists to catch exactly
                                that kind of self-inflicted difference.

     state_index                masks with (pad / 16 - 1), which addresses the
                                whole pad only when pad / 16 is a power of two.
                                At 1.25 or 1.5 MB the mask would quietly
                                confine every access to the low 1 MB, making
                                the larger pad look free. V5PAD_MOD replaces
                                the mask with a modulo by a compile-time
                                constant, which gcc lowers to a multiply-high
                                and a shift. Verified in the disassembly: the
                                masked builds carry and $0xffff0 / $0x1ffff0 /
                                $0x3ffff0 / $0x7ffff0, exactly (blocks - 1) << 4
                                for 1/2/4/8 MB, while the modulo builds carry
                                no mask and instead the division magic for
                                81920 = 5 << 14 and 98304 = 3 << 15. */

#include "crypto/hash-ops.h"

#if !defined(V5PAD_TAG) || !defined(V5PAD_BYTES)
#error "V5PAD_TAG and V5PAD_BYTES must be defined before including v5pad.inc"
#endif

#define V5PAD_CAT2(a, b) a##b
#define V5PAD_CAT(a, b) V5PAD_CAT2(a, b)

#undef CN_SCRATCHPAD_MEMORY
#define CN_SCRATCHPAD_MEMORY V5PAD_BYTES

/* expand_key and finalize_hash walk the pad in init_size_byte blocks, which is
   32, 64 or 128 depending on the per-nonce init_size_blk. A pad that is not a
   multiple of 128 leaves a tail that no AES fill ever writes, so the hash
   would read whatever the allocator left there. */
_Static_assert(CN_SCRATCHPAD_MEMORY % 128 == 0, "pad must be a multiple of 128");

/* the free wrap below depends on this */
_Static_assert((CN_SALT_MEMORY & (CN_SALT_MEMORY - 1)) == 0,
               "CN_SALT_MEMORY must be a power of two");

#define cn_slow_hash      V5PAD_CAT(cn_slow_hash_, V5PAD_TAG)
#define cn_slow_hash_v7_8 V5PAD_CAT(cn_slow_hash_v7_8_, V5PAD_TAG)
#define cn_slow_hash_v9   V5PAD_CAT(cn_slow_hash_v9_, V5PAD_TAG)
#define cn_slow_hash_v10  V5PAD_CAT(cn_slow_hash_v10_, V5PAD_TAG)
#define cn_slow_hash_v11  V5PAD_CAT(cn_slow_hash_v11_, V5PAD_TAG)
#define cn_slow_hash_v13  V5PAD_CAT(cn_slow_hash_v13_, V5PAD_TAG)
#define cn_slow_hash_v14  V5PAD_CAT(cn_slow_hash_v14_, V5PAD_TAG)

#include "crypto/slow-hash.h"

#if defined(CN_USE_SOFTWARE_AES)
/* The software path indexes the pad through e2i, which masks with (count - 1)
   and carries the same power-of-two assumption as state_index. Rather than
   patch a path the bench never exercises, refuse to build it. */
#error "compile v5pad units with -maes: the software AES path has its own pad-size assumption"
#endif

#define V5PAD_BLOCKS (CN_SCRATCHPAD_MEMORY / AES_BLOCK_SIZE)
#define V5PAD_SALT_WRAP(i) ((i) & (uint32_t)(CN_SALT_MEMORY - 1))

#if defined(V5PAD_MOD)
#undef state_index
#define state_index(x) \
    (((*((uint64_t *)(x)) >> 4) % (uint64_t)V5PAD_BLOCKS) << 4)
#else
_Static_assert((V5PAD_BLOCKS & (V5PAD_BLOCKS - 1)) == 0,
               "without V5PAD_MOD the pad block count must be a power of two");
#endif

#undef randomize_scratchpad_256k
#define randomize_scratchpad_256k(r, salt, scratchpad)          \
    uint32_t x = 0;                                             \
    for (uint32_t i = 0; i < CN_SCRATCHPAD_MEMORY; i += 4)      \
        scratchpad[i] ^= salt[V5PAD_SALT_WRAP(x++)];            \
    randomize_scratchpad(r, scratchpad);

#undef salt_pad
#define salt_pad(salt, salt_hash, a, b, c, d)                   \
    extra_hashes[a % 3](salt, 200, salt_hash);                  \
    temp_1 = (uint16_t)(iters ^ (b ^ c));                       \
    offset_1 = temp_1 * ((d % 3) + 1);                          \
    for (j = 0; j < 32; j++)                                    \
        (salt)[offset_1 + j] ^= (salt_hash)[j];                 \
    x = 0;                                                      \
    offset_1 = (d % 64) + 1;                                    \
    offset_2 = ((temp_1 * offset_1) % 125) + 4;                 \
    for (j = offset_1; j < CN_SCRATCHPAD_MEMORY; j += offset_2) \
        hp_state[j] ^= (salt)[V5PAD_SALT_WRAP(x++)];

/* CNA v8's salt_pad needs the same wrap for the same reason. Without this the
 * v14 compilations would keep the unwrapped macro from slow-hash.h and read
 * past the salt at any pad above 1 MB: the sweep steps the salt once per
 * offset_2 pad bytes, and offset_2's minimum of 4 is what makes 1 MB consume
 * exactly CN_SALT_MEMORY and no more. At 4 MB it would index four times that.
 *
 * Only the selector differs from the macro above, `a & 3` against `a % 3`,
 * which is the whole of CNA v8 and the thing these rows exist to measure. */
#undef salt_pad_v8
#define salt_pad_v8(salt, salt_hash, a, b, c, d)                \
    extra_hashes[a & 3](salt, 200, salt_hash);                  \
    temp_1 = (uint16_t)(iters ^ (b ^ c));                       \
    offset_1 = temp_1 * ((d % 3) + 1);                          \
    for (j = 0; j < 32; j++)                                    \
        (salt)[offset_1 + j] ^= (salt_hash)[j];                 \
    x = 0;                                                      \
    offset_1 = (d % 64) + 1;                                    \
    offset_2 = ((temp_1 * offset_1) % 125) + 4;                 \
    for (j = offset_1; j < CN_SCRATCHPAD_MEMORY; j += offset_2) \
        hp_state[j] ^= (salt)[V5PAD_SALT_WRAP(x++)];

#include "crypto/slow-hash-impl.h"
