/* This program gives the optimized implementation of stream cipher HC-128 for 32-bit platform

   The docuement of HC-128 is available at
   1) Hongjun Wu. ``The Stream Cipher HC-128.'' New Stream Cipher Designs -- The eSTREAM Finalists, LNCS 4986, pp. 39-47, Springer-Verlag, 2008.
   2) eSTREAM website:  http://www.ecrypt.eu.org/stream/hcp3.html

   -----------------------------------------
   Performance:

   Microprocessor: Intel CORE 2 processor (Core 2 Duo Mobile P9400 2.53GHz)
   Operating System: 32-bit Debian 5.0 (Linux kernel 2.6.26-2-686)
   Speed of encrypting long message:
   1) 2.1 cycle/byte   compiler: Intel C++ compiler 11.1   compilation option: icc -O2
   2) 3.9 cycles/byte  compiler: gcc 4.3.2                 compilation option: gcc -O3

   Microprocessor: Intel CORE 2 processor (Core 2 Quad Q6600 2.4GHz)
   Operating System: 32-bit Windows Vista Business
   Speed of encrypting long message:
   3) 2.2 cycles/byte  compiler: Intel C++ compiler 11.1    compilation option: icl /O2
   4) 3.4 cycles/byte  compiler: Microsoft Visual C++ 2008  compilation option: release

   ------------------------------------------
   In this simplified optimization program, loop unrolling is applied to the description of HC-128 directly.
   16 steps are executed in each loop.

   ------------------------------------------
   Written by: Hongjun Wu
*/

#ifndef _HC128_H_
#define _HC128_H_

#include <stdint.h>
#include <stddef.h>   /* size_t, used by HC128_U32 below */

typedef unsigned char hc_byte;

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGN16(x) x __attribute__((aligned(16)))
#else
#define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

typedef struct
{
    DATA_ALIGN16(uint32_t P[512]);
    DATA_ALIGN16(uint32_t Q[512]);
    DATA_ALIGN16(uint32_t keystream[16]); /*16 32-bit keystream words*/
    uint32_t counter1024;                 /*counter1024 = i mod 1024 */
} HC128_State;

/* initialization of the cipher, the key and iv are used to update the state */
void HC128_Init(HC128_State *state, hc_byte *key, hc_byte *iv);

void HC128_NextKeys(HC128_State *state);

/* Generate a random number in the range [0, max) */
/* static: a plain C99 `inline` in a header emits no external definition, so
 * any C TU built without inlining (-O0) fails to link */
static inline uint32_t HC128_U32(HC128_State *state, size_t *key_idx, uint32_t max)
{
    uint32_t mask = (uint32_t)0xFFFFFFFFU;
    --max;
    mask >>= __builtin_clz(max | 1);
    uint32_t r;
    do
    {
        if (*key_idx > 15)
        {
            HC128_NextKeys(state);
            *key_idx = 0;
        }
        r = state->keystream[(*key_idx)++] & mask;
    } while (r > max);
    return r;
}

/* encrypt a message
   three inputs to this function: cipher state, message, the message length in bytes
   one output:  ciphertext
*/
void HC128_EncryptMessage(HC128_State *state, hc_byte *message, hc_byte *ciphertext, uint64_t msglength);

/* this function encrypts a message,
   there are four inputs to this function: a 128-bit key, a 128-bit iv, a message, the message length in bytes
   one output from this function: ciphertext
*/
void HC128(hc_byte *key, hc_byte *iv, hc_byte *message, hc_byte *ciphertext, uint64_t msglength);

#endif /* _HC128_H_ */