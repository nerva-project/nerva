// Copyright (c) 2018-2024, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project

#ifndef _RANDOM_NUMBERS_
#define _RANDOM_NUMBERS_

#include <stdint.h>
#include <limits>

#ifndef RDATA_ALIGN16
    #if defined(_MSC_VER)
        #define RDATA_ALIGN16 __declspec(align(16))
    #else
        #define RDATA_ALIGN16 __attribute__ ((aligned(16)))
    #endif
#endif

namespace angrywasp
{
    class mersenne_twister
    {
        private:

            static const uint32_t N = 624;
            static const uint32_t M = 397;
            static const uint32_t MATRIX_A = 0x9908b0df;
            static const uint32_t UPPER_MASK = 0x80000000;
            static const uint32_t LOWER_MASK = 0x7fffffff; 
            static const uint32_t TEMPERING_MASK_B = 0x9d2c5680;
            static const uint32_t TEMPERING_MASK_C = 0xefc60000;

            const uint32_t mag01[2] = { 0x0, MATRIX_A };
            
            uint32_t mt[N] = { 0 };
            uint16_t mti = 0;

        public:

            mersenne_twister(uint32_t seed)
            {
                set_seed(seed);
            }

            void set_seed(uint32_t seed)
            {
                mt[0] = seed & 0xffffffff;
                for (mti = 1; mti < N; mti++)
                    mt[mti] = (69069 * mt[mti - 1]) & 0xffffffff;
            }

            uint32_t generate_uint()
            {
                uint32_t y;

                if (mti >= N)
                {
                    uint32_t kk;

                    for (kk = 0; kk < N - M; kk++)
                    {
                        y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1];
                    }

                    for (; kk < N - 1; kk++)
                    {
                        y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                        mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1];
                    }

                    y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
                    mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1];

                    mti = 0;
                }

                y = mt[mti++];
                y ^= (y >> 11);
                y ^= (y << 7) & TEMPERING_MASK_B;
                y ^= (y << 15) & TEMPERING_MASK_C;
                y ^= (y >> 18);

                return y;
            }

            uint32_t next(uint32_t min, uint32_t max)
            {
                uint32_t r = generate_uint();
                double div = (double)(0xffffffff) / (double)(max - min);
                return (r / div) + min;
            }

            std::array<uint32_t, 36864> generate_v4_sequence(uint32_t seed, uint32_t height)
            {
              std::array<uint32_t, 36864> reval;
              size_t oIndex = 0;
              uint32_t y, r;
              for(size_t i = 0; i < 2048; ++i)
              {
                {
                  uint32_t kk;
                  for (kk = 0; kk < 27; kk++)
                  {
                      y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
                      mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1];
                  }
                  mti = 0;
                }

                reval[oIndex++] = next(1, (uint32_t)(height - 1));

                for(uint8_t j = 0; j < 4; ++j)
                {
                  r = next(6, (uint32_t)(height - 6));
                  reval[oIndex++] = next(r - 5, r + 5);
                  reval[oIndex++] = next(r - 5, r + 5);
                  
                  r = next(6, (uint32_t)(height - 6));
                  reval[oIndex++] = next(r - 5, r + 5);
                  reval[oIndex++] = next(r - 5, r + 5);
                }

                reval[oIndex++] = next(1, (uint32_t)(height - 1));
                set_seed(seed ^ generate_uint());
              }
              return reval;
            }
    };

    class xoshiro256
    {
        // Based on the xoshiro256** random number generater
        // Copyright 2018 David Blackman and Sebastiano Vigna (vigna@acm.org)
        // http://xoshiro.di.unimi.it/

        private:

            union d64
            {
                uint64_t i;
                double d;
            };

            inline double to_double(uint64_t x)
            {
                union d64 u = { .i = UINT64_C(0x3FF) << 52 | x >> 12 };
                return u.d - 1.0;
            }

        public:

            inline uint64_t rotl64(const uint64_t x, int k)
            {
                return (x << k) | (x >> (64 - k));
            }

            inline uint32_t rotl32(const uint32_t x, int k)
            {
                return (x << k) | (x >> (32 - k));
            }
            
            inline uint64_t u64(uint64_t* state)
            {
                const uint64_t result = rotl64(state[1] * 5, 7) * 9;
                const uint64_t t = state[1] << 17;

                state[2] ^= state[0];
                state[3] ^= state[1];
                state[1] ^= state[2];
                state[0] ^= state[3];

                state[2] ^= t;
                state[3] = rotl64(state[3], 45);

                return result;
            }

            uint32_t u32(uint64_t* state)
            {
                uint64_t r = u64(state);
                double dbl = to_double(r);
                double div = 1.0 / (double)((uint32_t)-1);
                return (dbl / div);
            }

            uint32_t u32(uint64_t* state, uint32_t min, uint32_t max)
            {
                uint64_t r = u64(state);
                double dbl = to_double(r);
                double div = 1.0 / (double)(max - min);
                return (dbl / div) + (double)min;
            }
    };
};

#endif
