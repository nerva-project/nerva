/* Known-answer vectors for get_cna_v6_data, generated independently of it.
 *
 * WHY. Nothing pinned the chain fill's output (review of 2026-10-07, open item
 * 2), and RESEED-PREREG adds a v14-only reseed interval to code that live v13
 * consensus also runs. The daemon now checks both of its loops against these
 * vectors at startup (cna_v6_data_known_answer_test in db_lmdb.cpp).
 *
 * This file is the other half of that check, so it must not share code with
 * the daemon's loops: it is the serial form transcribed from
 * t_v8_fill.cpp's fill_serial and the daemon's cna_v6_data_reference, with
 * the reseed interval added as RESEED-PREREG specifies. The synthetic cache
 * and the digest are defined identically on both sides; everything between
 * them is written twice.
 *
 * Digest: cn_fast_hash over the 256 KB fill followed by the 64 bytes of
 * keystream one HC128_NextKeys later, so the cipher state the fill leaves
 * behind is pinned too (v14 draws xx, yy and iters from it).
 *
 *   sh contrib/powbench/build-fill-kat.sh && ./t_fill_kat
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vector>

#include "hc128.h"
extern "C" void cn_fast_hash(const void *data, size_t length, char *hash);

#pragma pack(push, 1)
struct ent { uint8_t hash[32]; uint64_t timestamp, diff_lo, coins; };
#pragma pack(pop)

/* Must match cna_v6_data_kat_cache in db_lmdb.cpp. */
static const uint64_t KAT_HEIGHT = 120000;
static const uint64_t KAT_WINDOW = 100000;   /* CNA_V6_WINDOW_BLOCKS_V13 */

static uint64_t splitmix(uint64_t &s)
{
    uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void build_cache(std::vector<ent> &c)
{
    uint64_t s = 0x4e65727661ULL;   /* "Nerva" */
    c.resize(KAT_HEIGHT);
    for (uint64_t i = 0; i < KAT_HEIGHT; i++) {
        for (int w = 0; w < 4; w++) {
            const uint64_t z = splitmix(s);
            for (int b = 0; b < 8; b++) c[i].hash[w * 8 + b] = (uint8_t)(z >> (8 * b));
        }
        c[i].timestamp = splitmix(s);
        c[i].diff_lo   = splitmix(s);
        c[i].coins     = splitmix(s);
    }
}

static void fill(const std::vector<ent> &C, HC128_State *rng, unsigned char *out,
                 uint32_t odds, uint32_t reseed_blocks)
{
    const uint64_t height = KAT_HEIGHT;
    const uint64_t wsz = height > KAT_WINDOW ? KAT_WINDOW : height;
    const uint64_t wbase = height - wsz;
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;

    auto pick = [&]() -> uint64_t {
        if (HC128_U32(rng, &ki, 256) < odds) return HC128_U32(rng, &ki, (uint32_t)height);
        return wbase + HC128_U32(rng, &ki, (uint32_t)wsz);
    };
    auto block = [&]() {
        HC128_NextKeys(rng);
        for (int k = 0; k < 16; k++) {
            memcpy(msg,      C[pick()].hash, 32);
            memcpy(msg + 32, &C[pick()].timestamp, 8);
            memcpy(msg + 40, &C[pick()].diff_lo,   8);
            memcpy(msg + 48, &C[pick()].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        if (((count / 16) % reseed_blocks) == 0) {
            unsigned char *iv  = optr - 512  + HC128_U32(rng, &ki, 512 - 16);
            unsigned char *key = optr - 1024 + HC128_U32(rng, &ki, 512 - 16);
            HC128_Init(rng, key, iv);
        }
    };

    while (count < 2048) block();
    for (int r = 0; r < 4; r++)
        memcpy(msg, optr - 131072 + HC128_U32(rng, &ki, 131072u - 16u), 16);
    HC128_EncryptMessage(rng, msg, optr, 64);
    HC128_Init(rng, optr, optr + 16);
    while (count < 4096) block();
}

int main()
{
    std::vector<ent> C;
    build_cache(C);

    static const struct { const char *name; uint32_t odds, reseed; } cases[] = {
        { "v13", 13u, 1u },
        { "v14", 256u, 16u },
    };
    for (const auto &cs : cases) {
        std::vector<unsigned char> buf(262144 + 64);
        unsigned char seed[32];
        char h[32];
        HC128_State rng;
        for (int i = 0; i < 32; i++) seed[i] = (unsigned char)(i * 7 + 3);
        HC128_Init(&rng, seed, seed + 16);
        HC128_NextKeys(&rng);
        fill(C, &rng, buf.data(), cs.odds, cs.reseed);
        HC128_NextKeys(&rng);
        memcpy(buf.data() + 262144, rng.keystream, 64);
        cn_fast_hash(buf.data(), buf.size(), h);
        printf("%s odds %u reseed %u: ", cs.name, cs.odds, cs.reseed);
        for (int i = 0; i < 32; i++) printf("0x%02x%s", (unsigned char)h[i], i < 31 ? "," : "\n");
    }
    return 0;
}
