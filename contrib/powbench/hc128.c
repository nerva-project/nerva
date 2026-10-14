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
   Last Modified: December 15, 2009
*/

#include <string.h>

#include "hc128.h"

/*this function right rotates a 32-bit word x by n positions*/
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/*the h1 function in HC-128*/
#define h1(x, y)                               \
    {                                          \
        a = (hc_byte)(x);                      \
        c = (hc_byte)((x) >> 16);              \
        (y) = state->Q[a] + state->Q[256 + c]; \
    }

/*the h2 function in HC-128*/
#define h2(x, y)                               \
    {                                          \
        a = (hc_byte)(x);                      \
        c = (hc_byte)((x) >> 16);              \
        (y) = state->P[a] + state->P[256 + c]; \
    }

/*one step of HC-128, update P and generate 32 bits keystream*/
#define step_P(m0, m511, m3, m10, m12, s) \
    {                                     \
        tem0 = ROTR32((m511), 23);        \
        tem1 = ROTR32((m3), 10);          \
        tem2 = ROTR32((m10), 8);          \
        (m0) += tem2 + (tem0 ^ tem1);     \
        h1((m12), tem3);                  \
        (s) = tem3 ^ (m0);                \
    }

/*one step of HC-128, update Q and generate 32 bits keystream*/
#define step_Q(m0, m511, m3, m10, m12, s) \
    {                                     \
        tem0 = ROTL32((m511), 23);        \
        tem1 = ROTL32((m3), 10);          \
        tem2 = ROTL32((m10), 8);          \
        (m0) += tem2 + (tem0 ^ tem1);     \
        h2((m12), tem3);                  \
        (s) = tem3 ^ (m0);                \
    }

/* this function computes 16 steps of HC-128
   the state is updated,
   16 32-bit keystream words are generated and stored in the array state->keystream
*/
void HC128_NextKeys(HC128_State *state)
{
    uint32_t tem0, tem1, tem2, tem3;
    hc_byte a, c;
    uint32_t cc, dd, ee;

    cc = state->counter1024 & 0x1ff;
    dd = (cc + 16) & 0x1ff;
    ee = (cc - 16) & 0x1ff;

    if (state->counter1024 < 512)
    {
        step_P(state->P[cc + 0], state->P[cc + 1], state->P[ee + 13], state->P[ee + 6], state->P[ee + 4], state->keystream[0]);
        step_P(state->P[cc + 1], state->P[cc + 2], state->P[ee + 14], state->P[ee + 7], state->P[ee + 5], state->keystream[1]);
        step_P(state->P[cc + 2], state->P[cc + 3], state->P[ee + 15], state->P[ee + 8], state->P[ee + 6], state->keystream[2]);
        step_P(state->P[cc + 3], state->P[cc + 4], state->P[cc + 0], state->P[ee + 9], state->P[ee + 7], state->keystream[3]);
        step_P(state->P[cc + 4], state->P[cc + 5], state->P[cc + 1], state->P[ee + 10], state->P[ee + 8], state->keystream[4]);
        step_P(state->P[cc + 5], state->P[cc + 6], state->P[cc + 2], state->P[ee + 11], state->P[ee + 9], state->keystream[5]);
        step_P(state->P[cc + 6], state->P[cc + 7], state->P[cc + 3], state->P[ee + 12], state->P[ee + 10], state->keystream[6]);
        step_P(state->P[cc + 7], state->P[cc + 8], state->P[cc + 4], state->P[ee + 13], state->P[ee + 11], state->keystream[7]);
        step_P(state->P[cc + 8], state->P[cc + 9], state->P[cc + 5], state->P[ee + 14], state->P[ee + 12], state->keystream[8]);
        step_P(state->P[cc + 9], state->P[cc + 10], state->P[cc + 6], state->P[ee + 15], state->P[ee + 13], state->keystream[9]);
        step_P(state->P[cc + 10], state->P[cc + 11], state->P[cc + 7], state->P[cc + 0], state->P[ee + 14], state->keystream[10]);
        step_P(state->P[cc + 11], state->P[cc + 12], state->P[cc + 8], state->P[cc + 1], state->P[ee + 15], state->keystream[11]);
        step_P(state->P[cc + 12], state->P[cc + 13], state->P[cc + 9], state->P[cc + 2], state->P[cc + 0], state->keystream[12]);
        step_P(state->P[cc + 13], state->P[cc + 14], state->P[cc + 10], state->P[cc + 3], state->P[cc + 1], state->keystream[13]);
        step_P(state->P[cc + 14], state->P[cc + 15], state->P[cc + 11], state->P[cc + 4], state->P[cc + 2], state->keystream[14]);
        step_P(state->P[cc + 15], state->P[dd + 0], state->P[cc + 12], state->P[cc + 5], state->P[cc + 3], state->keystream[15]);
    }
    else
    {
        step_Q(state->Q[cc + 0], state->Q[cc + 1], state->Q[ee + 13], state->Q[ee + 6], state->Q[ee + 4], state->keystream[0]);
        step_Q(state->Q[cc + 1], state->Q[cc + 2], state->Q[ee + 14], state->Q[ee + 7], state->Q[ee + 5], state->keystream[1]);
        step_Q(state->Q[cc + 2], state->Q[cc + 3], state->Q[ee + 15], state->Q[ee + 8], state->Q[ee + 6], state->keystream[2]);
        step_Q(state->Q[cc + 3], state->Q[cc + 4], state->Q[cc + 0], state->Q[ee + 9], state->Q[ee + 7], state->keystream[3]);
        step_Q(state->Q[cc + 4], state->Q[cc + 5], state->Q[cc + 1], state->Q[ee + 10], state->Q[ee + 8], state->keystream[4]);
        step_Q(state->Q[cc + 5], state->Q[cc + 6], state->Q[cc + 2], state->Q[ee + 11], state->Q[ee + 9], state->keystream[5]);
        step_Q(state->Q[cc + 6], state->Q[cc + 7], state->Q[cc + 3], state->Q[ee + 12], state->Q[ee + 10], state->keystream[6]);
        step_Q(state->Q[cc + 7], state->Q[cc + 8], state->Q[cc + 4], state->Q[ee + 13], state->Q[ee + 11], state->keystream[7]);
        step_Q(state->Q[cc + 8], state->Q[cc + 9], state->Q[cc + 5], state->Q[ee + 14], state->Q[ee + 12], state->keystream[8]);
        step_Q(state->Q[cc + 9], state->Q[cc + 10], state->Q[cc + 6], state->Q[ee + 15], state->Q[ee + 13], state->keystream[9]);
        step_Q(state->Q[cc + 10], state->Q[cc + 11], state->Q[cc + 7], state->Q[cc + 0], state->Q[ee + 14], state->keystream[10]);
        step_Q(state->Q[cc + 11], state->Q[cc + 12], state->Q[cc + 8], state->Q[cc + 1], state->Q[ee + 15], state->keystream[11]);
        step_Q(state->Q[cc + 12], state->Q[cc + 13], state->Q[cc + 9], state->Q[cc + 2], state->Q[cc + 0], state->keystream[12]);
        step_Q(state->Q[cc + 13], state->Q[cc + 14], state->Q[cc + 10], state->Q[cc + 3], state->Q[cc + 1], state->keystream[13]);
        step_Q(state->Q[cc + 14], state->Q[cc + 15], state->Q[cc + 11], state->Q[cc + 4], state->Q[cc + 2], state->keystream[14]);
        step_Q(state->Q[cc + 15], state->Q[dd + 0], state->Q[cc + 12], state->Q[cc + 5], state->Q[cc + 3], state->keystream[15]);
    }
    state->counter1024 = (state->counter1024 + 16) & 0x3ff;
}

/*The following defines the initialization functions*/

/*the functions used for expanding the key and iv*/
#define f1(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >> 3))
#define f2(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))
#define f(a, b, c, d) (f2((a)) + b + f1((c)) + d)

/*update one element in table P*/
#define update_P(m0, m511, m3, m10, m12) \
    {                                    \
        tem0 = ROTR32((m511), 23);       \
        tem1 = ROTR32((m3), 10);         \
        tem2 = ROTR32((m10), 8);         \
        (m0) += tem2 + (tem0 ^ tem1);    \
        h1((m12), tem3);                 \
        (m0) = tem3 ^ (m0);              \
    }

/*update one element in table Q*/
#define update_Q(m0, m511, m3, m10, m12) \
    {                                    \
        tem0 = ROTL32((m511), 23);       \
        tem1 = ROTL32((m3), 10);         \
        tem2 = ROTL32((m10), 8);         \
        (m0) += tem2 + (tem0 ^ tem1);    \
        h2((m12), tem3);                 \
        (m0) = tem3 ^ (m0);              \
    }

/*update the state for 16 steps, without generating keystream*/
static void UpdateSixteenSteps(HC128_State *state)
{
    uint32_t tem0, tem1, tem2, tem3;
    hc_byte a, c;
    uint32_t cc, dd, ee;

    cc = state->counter1024 & 0x1ff;
    dd = (cc + 16) & 0x1ff;
    ee = (cc - 16) & 0x1ff;

    if (state->counter1024 < 512)
    {
        update_P(state->P[cc + 0], state->P[cc + 1], state->P[ee + 13], state->P[ee + 6], state->P[ee + 4]);
        update_P(state->P[cc + 1], state->P[cc + 2], state->P[ee + 14], state->P[ee + 7], state->P[ee + 5]);
        update_P(state->P[cc + 2], state->P[cc + 3], state->P[ee + 15], state->P[ee + 8], state->P[ee + 6]);
        update_P(state->P[cc + 3], state->P[cc + 4], state->P[cc + 0], state->P[ee + 9], state->P[ee + 7]);
        update_P(state->P[cc + 4], state->P[cc + 5], state->P[cc + 1], state->P[ee + 10], state->P[ee + 8]);
        update_P(state->P[cc + 5], state->P[cc + 6], state->P[cc + 2], state->P[ee + 11], state->P[ee + 9]);
        update_P(state->P[cc + 6], state->P[cc + 7], state->P[cc + 3], state->P[ee + 12], state->P[ee + 10]);
        update_P(state->P[cc + 7], state->P[cc + 8], state->P[cc + 4], state->P[ee + 13], state->P[ee + 11]);
        update_P(state->P[cc + 8], state->P[cc + 9], state->P[cc + 5], state->P[ee + 14], state->P[ee + 12]);
        update_P(state->P[cc + 9], state->P[cc + 10], state->P[cc + 6], state->P[ee + 15], state->P[ee + 13]);
        update_P(state->P[cc + 10], state->P[cc + 11], state->P[cc + 7], state->P[cc + 0], state->P[ee + 14]);
        update_P(state->P[cc + 11], state->P[cc + 12], state->P[cc + 8], state->P[cc + 1], state->P[ee + 15]);
        update_P(state->P[cc + 12], state->P[cc + 13], state->P[cc + 9], state->P[cc + 2], state->P[cc + 0]);
        update_P(state->P[cc + 13], state->P[cc + 14], state->P[cc + 10], state->P[cc + 3], state->P[cc + 1]);
        update_P(state->P[cc + 14], state->P[cc + 15], state->P[cc + 11], state->P[cc + 4], state->P[cc + 2]);
        update_P(state->P[cc + 15], state->P[dd + 0], state->P[cc + 12], state->P[cc + 5], state->P[cc + 3]);
    }
    else
    {
        update_Q(state->Q[cc + 0], state->Q[cc + 1], state->Q[ee + 13], state->Q[ee + 6], state->Q[ee + 4]);
        update_Q(state->Q[cc + 1], state->Q[cc + 2], state->Q[ee + 14], state->Q[ee + 7], state->Q[ee + 5]);
        update_Q(state->Q[cc + 2], state->Q[cc + 3], state->Q[ee + 15], state->Q[ee + 8], state->Q[ee + 6]);
        update_Q(state->Q[cc + 3], state->Q[cc + 4], state->Q[cc + 0], state->Q[ee + 9], state->Q[ee + 7]);
        update_Q(state->Q[cc + 4], state->Q[cc + 5], state->Q[cc + 1], state->Q[ee + 10], state->Q[ee + 8]);
        update_Q(state->Q[cc + 5], state->Q[cc + 6], state->Q[cc + 2], state->Q[ee + 11], state->Q[ee + 9]);
        update_Q(state->Q[cc + 6], state->Q[cc + 7], state->Q[cc + 3], state->Q[ee + 12], state->Q[ee + 10]);
        update_Q(state->Q[cc + 7], state->Q[cc + 8], state->Q[cc + 4], state->Q[ee + 13], state->Q[ee + 11]);
        update_Q(state->Q[cc + 8], state->Q[cc + 9], state->Q[cc + 5], state->Q[ee + 14], state->Q[ee + 12]);
        update_Q(state->Q[cc + 9], state->Q[cc + 10], state->Q[cc + 6], state->Q[ee + 15], state->Q[ee + 13]);
        update_Q(state->Q[cc + 10], state->Q[cc + 11], state->Q[cc + 7], state->Q[cc + 0], state->Q[ee + 14]);
        update_Q(state->Q[cc + 11], state->Q[cc + 12], state->Q[cc + 8], state->Q[cc + 1], state->Q[ee + 15]);
        update_Q(state->Q[cc + 12], state->Q[cc + 13], state->Q[cc + 9], state->Q[cc + 2], state->Q[cc + 0]);
        update_Q(state->Q[cc + 13], state->Q[cc + 14], state->Q[cc + 10], state->Q[cc + 3], state->Q[cc + 1]);
        update_Q(state->Q[cc + 14], state->Q[cc + 15], state->Q[cc + 11], state->Q[cc + 4], state->Q[cc + 2]);
        update_Q(state->Q[cc + 15], state->Q[dd + 0], state->Q[cc + 12], state->Q[cc + 5], state->Q[cc + 3]);
    }
    state->counter1024 = (state->counter1024 + 16) & 0x3ff;
}

/*initialization of the cipher, the key and iv are used to update the state*/
void HC128_Init(HC128_State *state, hc_byte *key, hc_byte *iv)
{
    uint32_t i;

    /*expand the key and iv into P and Q*/
    // TODO: Endianness
    for (i = 0; i < 4; i++)
    {
        state->P[i] = ((uint32_t *)key)[i];
        state->P[i + 4] = ((uint32_t *)key)[i];
    }
    for (i = 0; i < 4; i++)
    {
        state->P[i + 8] = ((uint32_t *)iv)[i];
        state->P[i + 12] = ((uint32_t *)iv)[i];
    }

    for (i = 16; i < 256 + 16; i++)
        state->P[i] = f(state->P[i - 2], state->P[i - 7], state->P[i - 15], state->P[i - 16]) + i; /*generate W[16] ... W[256+16-1] */
    for (i = 0; i < 16; i++)
        state->P[i] = state->P[i + 256];
    for (i = 16; i < 512; i++)
        state->P[i] = f(state->P[i - 2], state->P[i - 7], state->P[i - 15], state->P[i - 16]) + 256 + i; /*generate W[256+16] ... W[256+512-1] */

    for (i = 0; i < 16; i++)
        state->Q[i] = state->P[512 - 16 + i];
    for (i = 16; i < 32; i++)
        state->Q[i] = f(state->Q[i - 2], state->Q[i - 7], state->Q[i - 15], state->Q[i - 16]) + 256 + 512 + (i - 16); /*generate W[256+512] ... W[256+512+16-1]*/
    for (i = 0; i < 16; i++)
        state->Q[i] = state->Q[i + 16];
    for (i = 16; i < 512; i++)
        state->Q[i] = f(state->Q[i - 2], state->Q[i - 7], state->Q[i - 15], state->Q[i - 16]) + 768 + i; /*generate W[256+512+16] ... W[256+512+512-1]*/

    /*initialize counter1024*/
    state->counter1024 = 0;

    /*run the cipher 1024 steps without generating keystream*/
    for (i = 0; i < 64; i++)
        UpdateSixteenSteps(state);
}

/* encrypt a message
   three inputs to this function: cipher state, message, the message length in bytes
   one output:  ciphertext
*/
void HC128_EncryptMessage(HC128_State *state, hc_byte *message, hc_byte *ciphertext, uint64_t msglength)
{
    uint64_t i;
    uint32_t j;

    /*encrypt a message, each time 64 bytes are encrypted*/
    for (i = 0; (i + 64) <= msglength; i += 64, message += 64, ciphertext += 64)
    {
        /*generate 16 32-bit keystream and store it in state.keystream*/
        HC128_NextKeys(state);
        /*encrypt 64 bytes of the message*/
        for (j = 0; j < 16; j++)
            ((uint32_t *)ciphertext)[j] = ((uint32_t *)message)[j] ^ state->keystream[j];
    }

    /*encrypt the last message block if the message length is not multiple of 64 bytes*/
    if ((msglength & 0x3f) != 0)
    {
        HC128_NextKeys(state);
        for (j = 0; j < (msglength & 0x3f); j++)
        {
            *(ciphertext + j) = *(message + j) ^ *(((hc_byte *)state->keystream) + j);
        }
    }
}

/* this function encrypts a message,
   there are four inputs to this function: a 128-bit key, a 128-bit iv, a message, the message length in bytes
   one output from this function: ciphertext
*/
void HC128(hc_byte *key, hc_byte *iv, hc_byte *message, hc_byte *ciphertext, uint64_t msglength)
{
    HC128_State state;

    /*initializing the state*/
    HC128_Init(&state, key, iv);

    /*encrypt a message*/
    HC128_EncryptMessage(&state, message, ciphertext, msglength);
}