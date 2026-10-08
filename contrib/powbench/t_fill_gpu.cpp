/* The whole v14 chain fill on a card, against the same fill on the CPU.
 *
 * WHY. DRAW-PREREG.md's C-3. Every "card does everything" figure so far was
 * composed from parts: HC-128 from t_hc128, gather from t_gather, combined by
 * arithmetic (F78, F84). That cannot price a change to the draw, because the
 * one thing the draw changes on a card, warp divergence in the rejection loop,
 * lives in neither part. So this runs the fill itself.
 *
 * WHAT. One work-item computes one complete fill exactly as v14 does:
 * odds 256, a reseed after every 16th block (F85), the midpoint reseed, the
 * 256 KB salt written to global memory, the final keystream folded into the
 * result. HC-128's state is in __local, the placement F78 and F80 found best.
 * The block cache is 4.5M synthetic 56-byte entries in VRAM.
 *
 * Draws: S, the shipped HC128_U32 with its selector and rejection loop; and
 * DRAW-PREREG's B, one keystream word per pick through mul_hi, no selector.
 *
 * THE GATE, before anything is timed: for both draws, the GPU's 256 KB salt and
 * final keystream must equal a CPU serial reference bit for bit, and the CPU
 * run-ahead form that is timed must equal that reference too. Every salt word
 * is stored to global memory, so no part of the fill is dead (F79, F80).
 *
 *   t_fill_gpu [seconds]
 *
 * Build: sh contrib/powbench/build-fill-gpu.sh
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <vector>
#include <string>

#include "clmin.h"
#include "hc128.h"

static HMODULE g_dll = NULL;
template <class T> static bool sym(T &fn, const char *name) {
    fn = (T)GetProcAddress(g_dll, name);
    if (!fn) { printf("  OpenCL.dll missing %s\n", name); return false; }
    return true;
}
bool cl_load(CL &cl) {
    g_dll = LoadLibraryA("OpenCL.dll");
    if (!g_dll) return false;
    return sym(cl.GetPlatformIDs,"clGetPlatformIDs") && sym(cl.GetPlatformInfo,"clGetPlatformInfo")
        && sym(cl.GetDeviceIDs,"clGetDeviceIDs") && sym(cl.GetDeviceInfo,"clGetDeviceInfo")
        && sym(cl.CreateContext,"clCreateContext") && sym(cl.CreateCommandQueue,"clCreateCommandQueue")
        && sym(cl.CreateBuffer,"clCreateBuffer") && sym(cl.CreateProgramWithSource,"clCreateProgramWithSource")
        && sym(cl.BuildProgram,"clBuildProgram") && sym(cl.GetProgramBuildInfo,"clGetProgramBuildInfo")
        && sym(cl.CreateKernel,"clCreateKernel") && sym(cl.SetKernelArg,"clSetKernelArg")
        && sym(cl.EnqueueNDRangeKernel,"clEnqueueNDRangeKernel") && sym(cl.Finish,"clFinish")
        && sym(cl.EnqueueWriteBuffer,"clEnqueueWriteBuffer") && sym(cl.EnqueueReadBuffer,"clEnqueueReadBuffer")
        && sym(cl.ReleaseMemObject,"clReleaseMemObject")
        && sym(cl.ReleaseKernel,"clReleaseKernel") && sym(cl.ReleaseProgram,"clReleaseProgram")
        && sym(cl.ReleaseCommandQueue,"clReleaseCommandQueue") && sym(cl.ReleaseContext,"clReleaseContext");
}

#define HEIGHT     4500000u
#define SALT_BYTES 262144
static uint32_t g_reseed_k = 16;   /* argv "k=N"; 16 is v14 as shipped (F85) */
#define RESEED_K g_reseed_k
enum { DRAW_S = 0, DRAW_B = 2 };

#pragma pack(push, 1)
struct blk_ent { uint8_t hash[32]; uint64_t timestamp, diff_lo, coins; };
#pragma pack(pop)
static_assert(sizeof(blk_ent) == 56, "56-byte entries, as db_lmdb.h");

static std::vector<blk_ent> g_cache;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void cache_init(void)
{
    g_cache.resize(HEIGHT);
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    for (uint32_t i = 0; i < HEIGHT; i++) {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        for (int w = 0; w < 4; w++) memcpy(g_cache[i].hash + w * 8, &x, 8), x += 0x632be59bd9b4e019ULL;
        g_cache[i].timestamp = x ^ i;
        g_cache[i].diff_lo   = x + i;
        g_cache[i].coins     = x * 3u;
    }
}

static void seed_for(uint32_t gid, uint32_t r, uint32_t w[8])
{
    uint64_t x = ((uint64_t)gid << 20 ^ r) * 0x9e3779b97f4a7c15ULL + 0xF111ULL;
    for (int i = 0; i < 8; i++) { x = (x ^ (x >> 29)) * 0xbf58476d1ce4e5b9ULL; w[i] = (uint32_t)(x >> 16); }
}

static inline uint32_t hc_word(HC128_State *rng, size_t *ki)
{
    if (*ki > 15) { HC128_NextKeys(rng); *ki = 0; }
    return rng->keystream[(*ki)++];
}

/* "cpu hot" sets this: every pick is computed and then sent to entry 0, so
 * the cipher work is unchanged and the memory cost is removed. */
static bool g_hot = false;
static inline uint64_t pick(HC128_State *rng, size_t *ki, int draw)
{
    uint64_t i_;
    if (draw == DRAW_B) i_ = ((uint64_t)hc_word(rng, ki) * HEIGHT) >> 32;
    else {
        (void)HC128_U32(rng, ki, 256);                   /* selector, odds 256: always taken */
        i_ = HC128_U32(rng, ki, HEIGHT);
    }
    return g_hot ? 0 : i_;
}

/* ---- CPU serial reference: the form the GPU kernel follows ---- */
static uint32_t fill_serial(unsigned char *out, const uint32_t seed[8], int draw)
{
    const blk_ent *C = g_cache.data();
    HC128_State rng;
    HC128_Init(&rng, (unsigned char *)seed, (unsigned char *)(seed + 4));
    HC128_NextKeys(&rng);
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    auto block = [&]() {
        HC128_NextKeys(&rng);
        for (int k = 0; k < 16; k++) {
            memcpy(msg,      C[pick(&rng, &ki, draw)].hash, 32);
            memcpy(msg + 32, &C[pick(&rng, &ki, draw)].timestamp, 8);
            memcpy(msg + 40, &C[pick(&rng, &ki, draw)].diff_lo,   8);
            memcpy(msg + 48, &C[pick(&rng, &ki, draw)].coins,     8);
            memcpy(msg + 56, &count, 8);
            HC128_EncryptMessage(&rng, msg, optr, 64);
            optr += 64;
            count++;
        }
        if (((count / 16) % RESEED_K) == 0) {
            unsigned char *iv  = optr - 512  + HC128_U32(&rng, &ki, 512 - 16);
            unsigned char *key = optr - 1024 + HC128_U32(&rng, &ki, 512 - 16);
            HC128_Init(&rng, key, iv);
        }
    };
    while (count < 2048) block();
    for (int r = 0; r < 4; r++)
        memcpy(msg, optr - 131072 + HC128_U32(&rng, &ki, 131072u - 16u), 16);
    HC128_EncryptMessage(&rng, msg, optr, 64);
    HC128_Init(&rng, optr, optr + 16);
    while (count < 4096) block();
    HC128_NextKeys(&rng);
    uint32_t f = 0;
    for (int j = 0; j < 16; j++) f ^= rng.keystream[j];
    return f;
}

/* ---- CPU run-ahead: what a CPU miner runs, and what is timed ----
 *
 * Plain loops, t_v8_fill's structure. The first version wrapped the block in a
 * lambda capturing everything by reference, called from two loops; every byte
 * store into the salt then forced the captured state back through memory, and
 * the CPU arm ran at 0.66 ms where t_v8_fill's loop, in this same process on
 * this same cache, ran at 0.45. A CPU column has to be the fastest loop a
 * miner would run, so the slow one handicapped the CPU. */
static uint32_t fill_runahead(unsigned char *out, const uint32_t seed[8], int draw)
{
    const blk_ent *C = g_cache.data();
    HC128_State rng;
    HC128_Init(&rng, (unsigned char *)seed, (unsigned char *)(seed + 4));
    HC128_NextKeys(&rng);
    size_t ki = 0;
    unsigned char msg[64];
    unsigned char *optr = out;
    uint64_t count = 0;
    uint64_t idx[16][4];
    uint32_t ks[16][16];

    while (count < 4096)
    {
        HC128_NextKeys(&rng);
        for (size_t k = 0; k < 16; k++)
        {
            for (size_t j = 0; j < 4; j++)
            {
                idx[k][j] = pick(&rng, &ki, draw);
                __builtin_prefetch(&C[idx[k][j]]);
            }
            HC128_NextKeys(&rng);
            memcpy(ks[k], rng.keystream, sizeof(ks[k]));
        }
        for (size_t k = 0; k < 16; k++)
        {
            memcpy(msg,      C[idx[k][0]].hash, 32);
            memcpy(msg + 32, &C[idx[k][1]].timestamp, 8);
            memcpy(msg + 40, &C[idx[k][2]].diff_lo,   8);
            memcpy(msg + 48, &C[idx[k][3]].coins,     8);
            memcpy(msg + 56, &count, 8);
            for (size_t j = 0; j < 16; j++)
            {
                uint32_t w;
                memcpy(&w, msg + j * 4, 4);
                w ^= ks[k][j];
                memcpy(optr + j * 4, &w, 4);
            }
            optr += 64;
            count++;
        }
        if (((count / 16) % RESEED_K) == 0)
        {
            unsigned char *iv  = optr - 512  + HC128_U32(&rng, &ki, 512 - 16);
            unsigned char *key = optr - 1024 + HC128_U32(&rng, &ki, 512 - 16);
            HC128_Init(&rng, key, iv);
        }
        if (count == 2048)
        {
            for (int r = 0; r < 4; r++)
                memcpy(msg, optr - 131072 + HC128_U32(&rng, &ki, 131072u - 16u), 16);
            HC128_EncryptMessage(&rng, msg, optr, 64);
            HC128_Init(&rng, optr, optr + 16);
        }
    }
    HC128_NextKeys(&rng);
    uint32_t f = 0;
    for (int j = 0; j < 16; j++) f ^= rng.keystream[j];
    return f;
}

struct cpu_arg { int draw; uint32_t fills; uint32_t id; uint32_t acc; };
static void *cpu_worker(void *p)
{
    cpu_arg *a = (cpu_arg *)p;
    std::vector<unsigned char> salt(SALT_BYTES);
    uint32_t acc = 0, seed[8];
    for (uint32_t r = 0; r < a->fills; r++) {
        seed_for(a->id + 100000u, r, seed);
        acc ^= fill_runahead(salt.data(), seed, a->draw) ^ salt[r & (SALT_BYTES - 1)];
    }
    a->acc = acc;
    return NULL;
}
static double cpu_fills_per_s(int threads, int draw, double seconds, uint32_t *sink)
{
    uint32_t fills = 8;
    double el = 0.0;
    std::vector<cpu_arg> args(threads);
    std::vector<pthread_t> th(threads);
    for (int pass = 0; pass < 2; pass++) {
        const double t0 = now_s();
        for (int i = 0; i < threads; i++) { args[i] = { draw, fills, (uint32_t)i, 0 };
            pthread_create(&th[i], NULL, cpu_worker, &args[i]); }
        for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
        el = now_s() - t0;
        for (int i = 0; i < threads; i++) *sink ^= args[i].acc;
        if (pass == 0) {
            double n = (double)fills * seconds / (el < 1e-4 ? 1e-4 : el);
            fills = (uint32_t)(n < 8 ? 8 : n);
        }
    }
    return (double)threads * (double)fills / el;
}

/* ---------------- GPU ---------------- */
/* hc_sixteen_l and hc_init_l are t_hc128's __local transcription of
 * src/crypto/hc128.c, which that harness gates against the CPU; copied so this
 * file stands alone, and gated again here as part of the whole fill. */
static const char *K_SRC =
"#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))\n"
"#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))\n"
"#define F1(x) (ROTR32((x),7) ^ ROTR32((x),18) ^ ((x) >> 3))\n"
"#define F2(x) (ROTR32((x),17) ^ ROTR32((x),19) ^ ((x) >> 10))\n"
"#define FF(a,b,c,d) (F2(a) + (b) + F1(c) + (d))\n"
"static void hc_sixteen_l(__local uint *P, __local uint *Q, uint *counter, uint *ks, int emit)\n"
"{\n"
"    const uint cc = *counter & 0x1ff;\n"
"    uint j;\n"
"    if (*counter < 512) {\n"
"        for (j = 0; j < 16; j++) {\n"
"            const uint i0 = (cc + j) & 0x1ff;\n"
"            const uint t0 = ROTR32(P[(cc + j + 1) & 0x1ff], 23);\n"
"            const uint t1 = ROTR32(P[(cc + j - 3) & 0x1ff], 10);\n"
"            const uint t2 = ROTR32(P[(cc + j - 10) & 0x1ff], 8);\n"
"            P[i0] += t2 + (t0 ^ t1);\n"
"            const uint x = P[(cc + j - 12) & 0x1ff];\n"
"            const uint t3 = Q[x & 0xff] + Q[256 + ((x >> 16) & 0xff)];\n"
"            if (emit) ks[j] = t3 ^ P[i0];\n"
"            else      P[i0] = t3 ^ P[i0];\n"
"        }\n"
"    } else {\n"
"        for (j = 0; j < 16; j++) {\n"
"            const uint i0 = (cc + j) & 0x1ff;\n"
"            const uint t0 = ROTL32(Q[(cc + j + 1) & 0x1ff], 23);\n"
"            const uint t1 = ROTL32(Q[(cc + j - 3) & 0x1ff], 10);\n"
"            const uint t2 = ROTL32(Q[(cc + j - 10) & 0x1ff], 8);\n"
"            Q[i0] += t2 + (t0 ^ t1);\n"
"            const uint x = Q[(cc + j - 12) & 0x1ff];\n"
"            const uint t3 = P[x & 0xff] + P[256 + ((x >> 16) & 0xff)];\n"
"            if (emit) ks[j] = t3 ^ Q[i0];\n"
"            else      Q[i0] = t3 ^ Q[i0];\n"
"        }\n"
"    }\n"
"    *counter = (*counter + 16) & 0x3ff;\n"
"}\n"
"static void hc_init_l(__local uint *P, __local uint *Q, uint *counter, const uint *k, const uint *v)\n"
"{\n"
"    uint i;\n"
"    for (i = 0; i < 4; i++) { P[i] = k[i]; P[i + 4] = k[i]; P[i + 8] = v[i]; P[i + 12] = v[i]; }\n"
"    for (i = 16; i < 272; i++) P[i] = FF(P[i-2], P[i-7], P[i-15], P[i-16]) + i;\n"
"    for (i = 0; i < 16; i++)   P[i] = P[i + 256];\n"
"    for (i = 16; i < 512; i++) P[i] = FF(P[i-2], P[i-7], P[i-15], P[i-16]) + 256 + i;\n"
"    for (i = 0; i < 16; i++)   Q[i] = P[512 - 16 + i];\n"
"    for (i = 16; i < 32; i++)  Q[i] = FF(Q[i-2], Q[i-7], Q[i-15], Q[i-16]) + 256 + 512 + (i - 16);\n"
"    for (i = 0; i < 16; i++)   Q[i] = Q[i + 16];\n"
"    for (i = 16; i < 512; i++) Q[i] = FF(Q[i-2], Q[i-7], Q[i-15], Q[i-16]) + 768 + i;\n"
"    *counter = 0;\n"
"    uint dummy[16];\n"
"    for (i = 0; i < 64; i++) hc_sixteen_l(P, Q, counter, dummy, 0);\n"
"}\n"
/* the draw state: the 16-word keystream buffer and the read index survive a
 * reseed, exactly as HC128_State.keystream and rng_key_idx do on the CPU */
"#define NEXTK() hc_sixteen_l(P, Q, &counter, ks, 1)\n"
"static uint hc_u32(__local uint *P, __local uint *Q, uint *counter, uint *ks, uint *ki, uint max)\n"
"{\n"
"    --max;\n"
"    const uint mask = 0xFFFFFFFFu >> clz(max | 1u);\n"
"    uint r;\n"
"    do {\n"
"        if (*ki > 15) { hc_sixteen_l(P, Q, counter, ks, 1); *ki = 0; }\n"
"        r = ks[(*ki)++] & mask;\n"
"    } while (r > max);\n"
"    return r;\n"
"}\n"
"static uint hc_w(__local uint *P, __local uint *Q, uint *counter, uint *ks, uint *ki)\n"
"{\n"
"    if (*ki > 15) { hc_sixteen_l(P, Q, counter, ks, 1); *ki = 0; }\n"
"    return ks[(*ki)++];\n"
"}\n"
"static uint pick(__local uint *P, __local uint *Q, uint *counter, uint *ks, uint *ki, uint draw, uint height)\n"
"{\n"
"    if (draw == 2) return mul_hi(hc_w(P, Q, counter, ks, ki), height);\n"
"    (void)hc_u32(P, Q, counter, ks, ki, 256u);\n"
"    return hc_u32(P, Q, counter, ks, ki, height);\n"
"}\n"
"static uint ld_le(__global const uchar *b, uint off)\n"
"{\n"
"    return (uint)b[off] | ((uint)b[off + 1] << 8) | ((uint)b[off + 2] << 16) | ((uint)b[off + 3] << 24);\n"
"}\n"
"__kernel void fill(__global const uint *cache, const uint height, __global uint *salt_all,\n"
"                   __local uint *scratch, const uint draw, const uint rounds,\n"
"                   __global const uint *seeds, __global uint *out)\n"
"{\n"
"    const uint gid = get_global_id(0);\n"
"    __local uint *P = scratch + get_local_id(0) * 1024;\n"
"    __local uint *Q = P + 512;\n"
"    __global uint *salt = salt_all + (size_t)gid * 65536;\n"
"    __global const uchar *sb = (__global const uchar *)salt;\n"
"    uint ks[16], msg[16], kk[4], vv[4];\n"
"    uint counter = 0, ki, acc = 0, r, i;\n"
"    for (r = 0; r < rounds; r++) {\n"
"        __global const uint *sd = seeds + ((size_t)gid * rounds + r) * 8;\n"
"        for (i = 0; i < 4; i++) { kk[i] = sd[i]; vv[i] = sd[4 + i]; }\n"
"        hc_init_l(P, Q, &counter, kk, vv);\n"
"        NEXTK();\n"
"        ki = 0;\n"
"        uint count = 0, o = 0;\n"
"        for (uint hf = 0; hf < 2; hf++) {\n"
"            const uint stop = hf ? 4096u : 2048u;\n"
"            while (count < stop) {\n"
"                NEXTK();\n"
"                for (uint k = 0; k < 16; k++) {\n"
"                    __global const uint *e0 = cache + (size_t)pick(P, Q, &counter, ks, &ki, draw, height) * 14;\n"
"                    for (i = 0; i < 8; i++) msg[i] = e0[i];\n"
"                    __global const uint *e1 = cache + (size_t)pick(P, Q, &counter, ks, &ki, draw, height) * 14;\n"
"                    msg[8] = e1[8]; msg[9] = e1[9];\n"
"                    __global const uint *e2 = cache + (size_t)pick(P, Q, &counter, ks, &ki, draw, height) * 14;\n"
"                    msg[10] = e2[10]; msg[11] = e2[11];\n"
"                    __global const uint *e3 = cache + (size_t)pick(P, Q, &counter, ks, &ki, draw, height) * 14;\n"
"                    msg[12] = e3[12]; msg[13] = e3[13];\n"
"                    msg[14] = count; msg[15] = 0;\n"
"                    NEXTK();\n"
"                    for (i = 0; i < 16; i++) salt[o / 4 + i] = msg[i] ^ ks[i];\n"
"                    o += 64; count++;\n"
"                }\n"
"                if (((count / 16) % RESEED_K) == 0) {\n"
"                    const uint iv_off  = o - 512  + hc_u32(P, Q, &counter, ks, &ki, 496u);\n"
"                    const uint key_off = o - 1024 + hc_u32(P, Q, &counter, ks, &ki, 496u);\n"
"                    for (i = 0; i < 4; i++) { kk[i] = ld_le(sb, key_off + 4 * i); vv[i] = ld_le(sb, iv_off + 4 * i); }\n"
"                    hc_init_l(P, Q, &counter, kk, vv);\n"
"                }\n"
"            }\n"
"            if (hf == 0) {\n"
"                for (uint q = 0; q < 4; q++) {\n"
"                    const uint off = o - 131072u + hc_u32(P, Q, &counter, ks, &ki, 131072u - 16u);\n"
"                    for (i = 0; i < 4; i++) msg[i] = ld_le(sb, off + 4 * i);\n"
"                }\n"
"                NEXTK();\n"
"                for (i = 0; i < 16; i++) salt[o / 4 + i] = msg[i] ^ ks[i];\n"
"                for (i = 0; i < 4; i++) { kk[i] = salt[o / 4 + i]; vv[i] = salt[o / 4 + 4 + i]; }\n"
"                hc_init_l(P, Q, &counter, kk, vv);\n"
"            }\n"
"        }\n"
"        NEXTK();\n"
"        for (i = 0; i < 16; i++) acc ^= ks[i];\n"
"    }\n"
"    out[gid] = acc;\n"
"}\n"
"/* S-buf: the shipped S draw, computed the way a competent miner would.\n"
" *\n"
" * Under S each lane consumes keystream at its own rate, so in \"fill\" the lanes\n"
" * of a warp reach \"need the next 16-word block\" at different moments and the\n"
" * warp runs HC-128 sixteen steps for each of them in turn. But between two\n"
" * Inits the block sequence is fixed whatever is consumed, so here every lane\n"
" * generates blocks into a small ring at the same pace, in lockstep, and the\n"
" * divergent part is only reading words out of it. A lane that runs dry fills\n"
" * itself on demand, the only divergent generation left. The ring holds blocks\n"
" * [nxt, prod); cur is the current block, kept apart because after an Init the\n"
" * draws still read the old block until the next advance, as on the CPU. */\n"
"#define RB 16\n"
"static void sb_produce(__local uint *P, __local uint *Q, uint *counter, __local uint *ring, uint *prod)\n"
"{\n"
"    uint t[16];\n"
"    hc_sixteen_l(P, Q, counter, t, 1);\n"
"    __local uint *d = ring + ((*prod) % RB) * 16;\n"
"    for (uint i = 0; i < 16; i++) d[i] = t[i];\n"
"    (*prod)++;\n"
"}\n"
"static void sb_advance(__local uint *P, __local uint *Q, uint *counter, __local uint *ring,\n"
"                       uint *prod, uint *nxt, uint *cur)\n"
"{\n"
"    while (*prod <= *nxt) sb_produce(P, Q, counter, ring, prod);\n"
"    __local uint *s = ring + ((*nxt) % RB) * 16;\n"
"    for (uint i = 0; i < 16; i++) cur[i] = s[i];\n"
"    (*nxt)++;\n"
"}\n"
"static uint sb_u32(__local uint *P, __local uint *Q, uint *counter, __local uint *ring,\n"
"                   uint *prod, uint *nxt, uint *cur, uint *ki, uint max)\n"
"{\n"
"    --max;\n"
"    const uint mask = 0xFFFFFFFFu >> clz(max | 1u);\n"
"    uint r;\n"
"    do {\n"
"        if (*ki > 15) { sb_advance(P, Q, counter, ring, prod, nxt, cur); *ki = 0; }\n"
"        r = cur[(*ki)++] & mask;\n"
"    } while (r > max);\n"
"    return r;\n"
"}\n"
"/* S-buf2: sb_u32 without the divergent loop. Test the next eight words at\n"
" * once and take the first accepted one, so every lane does the same work per\n"
" * pick; only the number of words consumed differs. Advances stay lazy, exactly\n"
" * as HC128_U32's \"if (*ki > 15)\" before each read: after consuming m words from\n"
" * position ki, (ki + m - 1) / 16 blocks were entered. */\n"
"static uint sb_peek(__local uint *P, __local uint *Q, uint *counter, __local uint *ring,\n"
"                    uint *prod, uint nxt, const uint *cur, uint t)\n"
"{\n"
"    if (t < 16) return cur[t];\n"
"    const uint b = nxt + ((t - 16) >> 4);\n"
"    while (*prod <= b) sb_produce(P, Q, counter, ring, prod);\n"
"    return ring[(b % RB) * 16 + ((t - 16) & 15)];\n"
"}\n"
"static uint sb_u32_bl(__local uint *P, __local uint *Q, uint *counter, __local uint *ring,\n"
"                      uint *prod, uint *nxt, uint *cur, uint *ki, uint max)\n"
"{\n"
"    --max;\n"
"    const uint mask = 0xFFFFFFFFu >> clz(max | 1u);\n"
"    for (;;) {\n"
"        uint w[8], bits = 0;\n"
"        for (uint j = 0; j < 8; j++) {\n"
"            w[j] = sb_peek(P, Q, counter, ring, prod, *nxt, cur, *ki + j) & mask;\n"
"            bits |= (uint)(w[j] <= max) << j;\n"
"        }\n"
"        const uint m = bits ? (31u - clz(bits & (0u - bits))) + 1u : 8u;\n"
"        const uint adv = (*ki + m - 1) >> 4;\n"
"        for (uint a = 0; a < adv; a++) {\n"
"            __local uint *s = ring + ((*nxt) % RB) * 16;\n"
"            for (uint i = 0; i < 16; i++) cur[i] = s[i];\n"
"            (*nxt)++;\n"
"        }\n"
"        *ki = *ki + m - 16 * adv;\n"
"        if (bits) return w[m - 1];\n"
"    }\n"
"}\n"
"#define SB_ADV() sb_advance(P, Q, &counter, ring, &prod, &nxt, cur)\n"
"#define SB_U32(m) (draw == 4 ? sb_u32_bl(P, Q, &counter, ring, &prod, &nxt, cur, &ki, (m)) : sb_u32(P, Q, &counter, ring, &prod, &nxt, cur, &ki, (m)))\n"
"#define SB_PICK() (SB_U32(256u), SB_U32(height))\n"
"#define SB_PUMP() { if (prod < nxt + RB) sb_produce(P, Q, &counter, ring, &prod); }\n"
"__kernel void fill_buf(__global const uint *cache, const uint height, __global uint *salt_all,\n"
"                       __local uint *scratch, const uint draw, const uint rounds,\n"
"                       __global const uint *seeds, __global uint *out)\n"
"{\n"
"    const uint gid = get_global_id(0);\n"
"    __local uint *P = scratch + get_local_id(0) * (1024 + RB * 16);\n"
"    __local uint *Q = P + 512;\n"
"    __local uint *ring = P + 1024;\n"
"    __global uint *salt = salt_all + (size_t)gid * 65536;\n"
"    __global const uchar *sb = (__global const uchar *)salt;\n"
"    uint cur[16], msg[16], kk[4], vv[4];\n"
"    uint counter = 0, ki, acc = 0, r, i, prod, nxt;\n"
"    for (i = 0; i < 16; i++) cur[i] = 0;\n"
"    for (r = 0; r < rounds; r++) {\n"
"        __global const uint *sd = seeds + ((size_t)gid * rounds + r) * 8;\n"
"        for (i = 0; i < 4; i++) { kk[i] = sd[i]; vv[i] = sd[4 + i]; }\n"
"        hc_init_l(P, Q, &counter, kk, vv); prod = 0; nxt = 0;\n"
"        SB_ADV();\n"
"        ki = 0;\n"
"        uint count = 0, o = 0;\n"
"        for (uint hf = 0; hf < 2; hf++) {\n"
"            const uint stop = hf ? 4096u : 2048u;\n"
"            while (count < stop) {\n"
"                SB_ADV();\n"
"                for (uint k = 0; k < 16; k++) {\n"
"                    __global const uint *e0 = cache + (size_t)SB_PICK() * 14;\n"
"                    for (i = 0; i < 8; i++) msg[i] = e0[i];\n"
"                    __global const uint *e1 = cache + (size_t)SB_PICK() * 14;\n"
"                    msg[8] = e1[8]; msg[9] = e1[9];\n"
"                    __global const uint *e2 = cache + (size_t)SB_PICK() * 14;\n"
"                    msg[10] = e2[10]; msg[11] = e2[11];\n"
"                    __global const uint *e3 = cache + (size_t)SB_PICK() * 14;\n"
"                    msg[12] = e3[12]; msg[13] = e3[13];\n"
"                    msg[14] = count; msg[15] = 0;\n"
"                    SB_ADV();\n"
"                    for (i = 0; i < 16; i++) salt[o / 4 + i] = msg[i] ^ cur[i];\n"
"                    o += 64; count++;\n"
"                    /* 1.75 blocks a message in lockstep, just under the mean\n"
"                     * of about 1.78, so lanes rarely fill the ring */\n"
"                    SB_PUMP();\n"
"                    if ((count & 3u) != 3u) SB_PUMP();\n"
"                }\n"
"                if (((count / 16) % RESEED_K) == 0) {\n"
"                    const uint iv_off  = o - 512  + SB_U32(496u);\n"
"                    const uint key_off = o - 1024 + SB_U32(496u);\n"
"                    for (i = 0; i < 4; i++) { kk[i] = ld_le(sb, key_off + 4 * i); vv[i] = ld_le(sb, iv_off + 4 * i); }\n"
"                    hc_init_l(P, Q, &counter, kk, vv); prod = 0; nxt = 0;\n"
"                }\n"
"            }\n"
"            if (hf == 0) {\n"
"                for (uint q = 0; q < 4; q++) {\n"
"                    const uint off = o - 131072u + SB_U32(131072u - 16u);\n"
"                    for (i = 0; i < 4; i++) msg[i] = ld_le(sb, off + 4 * i);\n"
"                }\n"
"                SB_ADV();\n"
"                for (i = 0; i < 16; i++) salt[o / 4 + i] = msg[i] ^ cur[i];\n"
"                for (i = 0; i < 4; i++) { kk[i] = salt[o / 4 + i]; vv[i] = salt[o / 4 + 4 + i]; }\n"
"                hc_init_l(P, Q, &counter, kk, vv); prod = 0; nxt = 0;\n"
"            }\n"
"        }\n"
"        SB_ADV();\n"
"        for (i = 0; i < 16; i++) acc ^= cur[i];\n"
"    }\n"
"    out[gid] = acc;\n"
"}\n"
;

int main(int argc, char **argv)
{
    double seconds = (argc > 1) ? atof(argv[1]) : 3.0;
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "k=", 2) == 0) {
            const unsigned kk = (unsigned)atoi(argv[i] + 2);
            if (kk >= 1 && 256 % kk == 0) g_reseed_k = kk;
        }
    uint32_t sink = 0;
    const int hw = 32;
    /* draw 3 is S computed by fill_buf: the CPU side treats it as S */
    static const int draws[4] = { DRAW_S, DRAW_B, 3, 4 };
    static const char *const dn[4] = { "S, shipped", "B, mulhi no selector", "S-buf, S kernel buffered",
                                       "S-buf2, buffered branch-free" };

    printf("v14 chain fill, whole, CPU against GPU. k = %u, odds 256, height %u\n",
           RESEED_K, HEIGHT);
    fflush(stdout);
    cache_init();

    /* "cpu": time the CPU arm alone on the calling thread, rdtsc-free, so it
     * can be compared with t_v8_fill's draw arm without threads in the way. */
    if (argc > 2 && strcmp(argv[2], "cpu") == 0) {
        g_hot = (argc > 3 && strcmp(argv[3], "hot") == 0);
        std::vector<unsigned char> salt(SALT_BYTES);
        uint32_t seed[8], acc = 0;
        for (int d = 0; d < 2; d++) {
            for (int pass = 0; pass < 2; pass++) {
                const int n = 2000;
                const double t0 = now_s();
                for (int r = 0; r < n; r++) {
                    seed_for(99, (uint32_t)r, seed);
                    acc ^= (pass ? fill_runahead : fill_serial)(salt.data(), seed, draws[d]);
                }
                printf("  %-22s %-9s %.4f ms/fill\n", dn[d], pass ? "run-ahead" : "serial",
                       (now_s() - t0) * 1000.0 / n);
            }
        }
        printf("  sink %08x\n", acc);
        return 0;
    }

    /* ---- CPU gate: run-ahead == serial, both draws ---- */
    {
        std::vector<unsigned char> a(SALT_BYTES), b(SALT_BYTES);
        uint32_t seed[8];
        for (int d = 0; d < 2; d++) {
            seed_for(7, 0, seed);
            const uint32_t fa = fill_serial(a.data(), seed, draws[d]);
            const uint32_t fb = fill_runahead(b.data(), seed, draws[d]);
            const bool ok = (fa == fb) && memcmp(a.data(), b.data(), SALT_BYTES) == 0;
            printf("  CPU run-ahead against serial, %-22s %s\n", dn[d], ok ? "MATCH" : "MISMATCH");
            if (!ok) return 1;
        }
    }

    CL cl;
    if (!cl_load(cl)) { printf("  OpenCL not available\n"); return 1; }
    cl_uint nplat = 0; cl.GetPlatformIDs(0, NULL, &nplat);
    std::vector<cl_platform_id> plats(nplat ? nplat : 1);
    if (nplat) cl.GetPlatformIDs(nplat, plats.data(), NULL);
    cl_device_id dev = NULL; long long best_score = -1;
    for (cl_uint p = 0; p < nplat; p++) {
        cl_uint nd = 0;
        if (cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 0, NULL, &nd) != CL_SUCCESS || !nd) continue;
        std::vector<cl_device_id> ds(nd);
        cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, nd, ds.data(), NULL);
        for (cl_uint d = 0; d < nd; d++) {
            cl_uint c = 0, uni = 0;
            cl.GetDeviceInfo(ds[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(c), &c, NULL);
            cl.GetDeviceInfo(ds[d], CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof(uni), &uni, NULL);
            const long long score = (uni ? 0LL : 1000000LL) + (long long)c;
            if (score > best_score) { best_score = score; dev = ds[d]; }
        }
    }
    if (!dev) { printf("  no GPU device\n"); return 1; }
    char devname[256] = {0}; cl_ulong gmem = 0, lmem = 0, maxalloc = 0; cl_uint cus = 0; size_t maxwg = 0;
    cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(maxalloc), &maxalloc, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_LOCAL_MEM_SIZE, sizeof(lmem), &lmem, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxwg), &maxwg, NULL);
    printf("  GPU %s, %llu MB, %u CUs, %llu KB local\n", devname,
           (unsigned long long)(gmem / 1048576), cus, (unsigned long long)(lmem / 1024));

    cl_int err = 0;
    cl_context ctx = cl.CreateContext(NULL, 1, &dev, NULL, NULL, &err);
    cl_command_queue q = cl.CreateCommandQueue(ctx, dev, 0, &err);
    size_t sl = strlen(K_SRC);
    cl_program prog = cl.CreateProgramWithSource(ctx, 1, &K_SRC, &sl, &err);
    char bopt[64];
    snprintf(bopt, sizeof(bopt), "-cl-std=CL1.2 -DRESEED_K=%uu", g_reseed_k);
    if (cl.BuildProgram(prog, 1, &dev, bopt, NULL, NULL) != CL_SUCCESS) {
        size_t n = 0; cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &n);
        std::string log(n, 0);
        cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, n, &log[0], NULL);
        printf("  kernel build failed:\n%s\n", log.c_str());
        return 1;
    }
    cl_kernel k = cl.CreateKernel(prog, "fill", &err);
    cl_kernel kb = cl.CreateKernel(prog, "fill_buf", &err);
    if (!kb || err != CL_SUCCESS) { printf("  fill_buf missing\n"); return 1; }
    cl_mem dcache = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, (size_t)HEIGHT * 56, NULL, &err);
    if (err != CL_SUCCESS) { printf("  cache alloc failed\n"); return 1; }
    cl.EnqueueWriteBuffer(q, dcache, 1, 0, (size_t)HEIGHT * 56, g_cache.data(), 0, NULL, NULL);
    const cl_uint height = HEIGHT;

    auto run = [&](size_t gsz, size_t wg, int draw, cl_uint rounds, cl_mem dsalt, cl_mem dseeds,
                   cl_mem dout) -> double {
        cl_uint dr = (cl_uint)draw;
        cl_kernel kk_ = (draw >= 3) ? kb : k;
        const size_t per = (draw >= 3) ? (1024 + 16 * 16) * 4 : 4096;
        cl.SetKernelArg(kk_, 0, sizeof(dcache), &dcache);
        cl.SetKernelArg(kk_, 1, sizeof(height), &height);
        cl.SetKernelArg(kk_, 2, sizeof(dsalt), &dsalt);
        cl.SetKernelArg(kk_, 3, wg * per, NULL);
        cl.SetKernelArg(kk_, 4, sizeof(dr), &dr);
        cl.SetKernelArg(kk_, 5, sizeof(rounds), &rounds);
        cl.SetKernelArg(kk_, 6, sizeof(dseeds), &dseeds);
        cl.SetKernelArg(kk_, 7, sizeof(dout), &dout);
        cl.Finish(q);
        const double t0 = now_s();
        cl_int e = cl.EnqueueNDRangeKernel(q, kk_, 1, NULL, &gsz, &wg, 0, NULL, NULL);
        cl.Finish(q);
        return (e == CL_SUCCESS) ? now_s() - t0 : -1.0;
    };
    auto make_seeds = [&](size_t gsz, cl_uint rounds) -> cl_mem {
        std::vector<uint32_t> s(gsz * rounds * 8);
        for (size_t g = 0; g < gsz; g++)
            for (cl_uint r = 0; r < rounds; r++) seed_for((uint32_t)g, r, &s[(g * rounds + r) * 8]);
        cl_mem m = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, s.size() * 4, NULL, &err);
        cl.EnqueueWriteBuffer(q, m, 1, 0, s.size() * 4, s.data(), 0, NULL, NULL);
        return m;
    };

    /* ---- GPU gate: four work-items, one round, every salt byte and the final
     * keystream fold against fill_serial ---- */
    {
        const size_t gsz = 4, wg = 1;
        cl_mem dsalt = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * SALT_BYTES, NULL, &err);
        cl_mem dout  = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * 4, NULL, &err);
        cl_mem dseeds = make_seeds(gsz, 1);
        std::vector<unsigned char> g(gsz * SALT_BYTES), c(SALT_BYTES);
        std::vector<uint32_t> gf(gsz);
        for (int d = 0; d < 4; d++) {
            if (run(gsz, wg, draws[d], 1, dsalt, dseeds, dout) < 0) { printf("  gate launch failed\n"); return 1; }
            cl.EnqueueReadBuffer(q, dsalt, 1, 0, g.size(), g.data(), 0, NULL, NULL);
            cl.EnqueueReadBuffer(q, dout, 1, 0, gsz * 4, gf.data(), 0, NULL, NULL);
            bool ok = true;
            for (size_t i = 0; i < gsz && ok; i++) {
                uint32_t seed[8];
                seed_for((uint32_t)i, 0, seed);
                const uint32_t cf = fill_serial(c.data(), seed, draws[d]);
                if (cf != gf[i] || memcmp(c.data(), &g[i * SALT_BYTES], SALT_BYTES) != 0) {
                    size_t b = 0;
                    while (b < SALT_BYTES && c[b] == g[i * SALT_BYTES + b]) b++;
                    printf("  GPU gate %s: item %zu differs at byte %zu (fold gpu %08x cpu %08x)\n",
                           dn[d], i, b, gf[i], cf);
                    ok = false;
                }
            }
            printf("  GPU kernel against CPU serial, %-22s %s\n", dn[d], ok ? "MATCH" : "MISMATCH");
            if (!ok) { printf("  refusing to time a kernel that computes something else\n"); return 1; }
        }
        cl.ReleaseMemObject(dsalt); cl.ReleaseMemObject(dout); cl.ReleaseMemObject(dseeds);
    }

    /* ---- timing: S B B S on both sides ---- */
    const size_t wg_cap = (size_t)(lmem / 4096);
    double gpu_best[4] = {0, 0, 0, 0}, cpu_best[4] = {0, 0, 0, 0}, cpu1[4] = {0, 0, 0, 0};
    size_t at_items[4] = {0, 0, 0, 0}, at_wg[4] = {0, 0, 0, 0};
    const int order[8] = {0, 1, 2, 3, 3, 2, 1, 0};
    for (int oi = 0; oi < 8; oi++) {
        const int d = order[oi];
        printf("\n  %s\n", dn[d]);
        const double c32 = cpu_fills_per_s(hw, draws[d], seconds, &sink);
        const double c1  = cpu_fills_per_s(1, draws[d], seconds, &sink);
        if (c32 > cpu_best[d]) cpu_best[d] = c32;
        if (c1 > cpu1[d]) cpu1[d] = c1;
        printf("    CPU %2d threads %10.1f fills/s    1 thread %8.1f fills/s (%.4f ms)\n",
               hw, c32, c1, 1000.0 / c1);
        const size_t groups[] = { 256, 512, 1024, 2048, 4096 };
        for (size_t wg = 2; wg <= wg_cap && wg <= maxwg && wg <= 8; wg *= 2) {
            for (size_t gi = 0; gi < sizeof(groups) / sizeof(groups[0]); gi++) {
                const size_t gsz = wg * groups[gi];
                const size_t sbytes = gsz * (size_t)SALT_BYTES;
                if (sbytes > maxalloc || sbytes + (size_t)HEIGHT * 56 > gmem * 3 / 4) continue;
                cl_mem dsalt = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sbytes, NULL, &err);
                if (err != CL_SUCCESS) continue;
                cl_mem dout = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * 4, NULL, &err);
                cl_uint rounds = 1;
                cl_mem dseeds = make_seeds(gsz, 4);
                double el = run(gsz, wg, draws[d], rounds, dsalt, dseeds, dout);
                /* at most four rounds a launch and about half a second, under a
                 * display GPU's watchdog */
                if (el > 0 && el < 0.12) { rounds = (cl_uint)(0.5 / el); if (rounds > 4) rounds = 4; if (rounds < 1) rounds = 1;
                    el = run(gsz, wg, draws[d], rounds, dsalt, dseeds, dout); }
                if (el > 0) {
                    const double fps = (double)gsz * rounds / el;
                    if (fps > gpu_best[d]) { gpu_best[d] = fps; at_items[d] = gsz; at_wg[d] = wg; }
                    printf("    GPU wg %zu items %6zu rounds %u %10.1f fills/s\n", wg, gsz, rounds, fps);
                }
                std::vector<uint32_t> o(gsz);
                cl.EnqueueReadBuffer(q, dout, 1, 0, gsz * 4, o.data(), 0, NULL, NULL);
                for (size_t i = 0; i < gsz; i++) sink ^= o[i];
                cl.ReleaseMemObject(dseeds); cl.ReleaseMemObject(dout); cl.ReleaseMemObject(dsalt);
            }
        }
        fflush(stdout);
    }

    printf("\n  %-22s %12s %12s %12s %10s\n", "", "CPU fills/s", "GPU fills/s", "CPU better", "1T ms");
    for (int d = 0; d < 4; d++)
        printf("  %-30s %12.1f %12.1f %11.3fx %10.4f   (GPU peak wg %zu, %zu items)\n", dn[d],
               cpu_best[d], gpu_best[d], cpu_best[d] / gpu_best[d], 1000.0 / cpu1[d], at_wg[d], at_items[d]);
    printf("\n  FILLGPU S=%.3fx B=%.3fx Sbuf=%.3fx Sbuf2=%.3fx  (CPU column S's)  GPU B/S %.3fx  Sbuf/S %.3fx  Sbuf2/S %.3fx\n",
           cpu_best[0] / gpu_best[0], cpu_best[1] / gpu_best[1], cpu_best[0] / gpu_best[2], cpu_best[0] / gpu_best[3],
           gpu_best[1] / gpu_best[0], gpu_best[2] / gpu_best[0], gpu_best[3] / gpu_best[0]);
    printf("  sink %08x\n", sink);
    return 0;
}
