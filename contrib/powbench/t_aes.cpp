/* AES throughput, CPU AES-NI against a GPU, with three GPU implementations.
 *
 * WHY. F77 measured B3, the hash core's GPU:CPU ratio, at 64.9x and had to
 * publish it as an UPPER BOUND, because the kernel behind it reads its AES
 * T-table out of __constant memory with sixteen data-dependent indices per
 * round. NVIDIA's constant cache broadcasts efficiently only when a warp's
 * lanes read the same address, so 32 lanes hitting 32 different entries
 * serialise. That is the worst available place for an AES table on a GPU.
 *
 * So the question B3 leaves open is not "is the core a gate" but "how much of
 * the 64.9x is the algorithm and how much is our kernel". That single number
 * decides whether goal 1 rests on the core or on nothing, and it gates the pad
 * question, because a pad pre-registration would otherwise set thresholds
 * against a baseline known to be wrong.
 *
 * This measures the AES on its own rather than operating on the kernel that
 * models consensus, which is the t_hc128 pattern and is far lower risk.
 *
 * METHOD. The CPU arm is vm_aes_fill from vm_ref.h: 8 blocks of 16 bytes, 10
 * _mm_aesenc_si128 rounds each, which is aes_pseudo_round and is what both of
 * v8's full pad passes run. Three GPU arms do the identical computation:
 *
 *   const   te0 in __constant, which is what F77 measured
 *   lds     te0 copied to __local once per work-group
 *   lds4    four pre-rotated tables in __local, so the round has no ROTL32
 *
 * Every arm folds all 32 state words into its output. The first version wrote
 * only s[0] ^ s[31], which depends on blocks 0 and 7 alone; the OpenCL compiler
 * deleted the other six blocks, the GPU did a quarter of the work it was
 * credited with, and the LDS arms read 1.04x against AES-NI where the full
 * computation reads 4.4x. The CPU arm was never affected, since its blocks pass
 * through memory. FINDINGS F79.
 *
 * Every arm is checked against the CPU's AES-NI output bit for bit before it is
 * timed. The S-box is computed here from the GF(2^8) inverse and the affine
 * map rather than copied, so a wrong table cannot silently agree with itself:
 * the CPU side uses the hardware S-box inside AESENC, and the comparison is
 * the test of ours.
 *
 *   t_aes [seconds] [-v]
 *
 * Build: sh contrib/powbench/build-aes.sh
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <vector>
#include <string>

#include "clmin.h"

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

static bool g_verbose = false;

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---------------- the tables, derived rather than copied ---------------- */

static unsigned char SBOX[256];
static unsigned int  TE0[256];
static unsigned int  RKH[40];
static __m128i       RK[10];

static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        unsigned char hi = (unsigned char)(a & 0x80);
        a = (unsigned char)(a << 1);
        if (hi) a ^= 0x1b;
        b = (unsigned char)(b >> 1);
    }
    return p;
}
static unsigned char rotl8(unsigned char x, int n)
{
    return (unsigned char)((x << n) | (x >> (8 - n)));
}
static void build_tables(void)
{
    SBOX[0] = 0x63;
    for (int x = 1; x < 256; x++) {
        unsigned char inv = 0;
        for (int y = 1; y < 256; y++)
            if (gmul((unsigned char)x, (unsigned char)y) == 1) { inv = (unsigned char)y; break; }
        SBOX[x] = (unsigned char)(inv ^ rotl8(inv,1) ^ rotl8(inv,2) ^ rotl8(inv,3) ^ rotl8(inv,4) ^ 0x63);
    }
    for (int i = 0; i < 256; i++) {
        unsigned char sb = SBOX[i];
        unsigned char s2 = (unsigned char)((sb << 1) ^ ((sb >> 7) * 0x1b));
        unsigned char s3 = (unsigned char)(s2 ^ sb);
        TE0[i] = ((unsigned)s2) | ((unsigned)sb << 8) | ((unsigned)sb << 16) | ((unsigned)s3 << 24);
    }
    /* Same schedule main.cpp uses, so figures stay comparable with gpubench. */
    for (int i = 0; i < 40; i++) RKH[i] = 0x9e3779b9u * (unsigned)(i + 1);
    for (int i = 0; i < 10; i++) RK[i] = _mm_loadu_si128((const __m128i *)(RKH + i * 4));
}

/* ---------------- CPU: vm_aes_fill, AES-NI ---------------- */

static void cpu_state(uint32_t gid, uint32_t iters, uint32_t out[32])
{
    __m128i s[8];
    uint32_t seed = gid * 2654435761u + 1u, w[32];
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; w[i] = seed; }
    for (int b = 0; b < 8; b++) s[b] = _mm_loadu_si128((const __m128i *)(w + b * 4));
    for (uint32_t it = 0; it < iters; it++)
        for (int b = 0; b < 8; b++) {
            __m128i t = s[b];
            for (int r = 0; r < 10; r++) t = _mm_aesenc_si128(t, RK[r]);
            s[b] = t;
        }
    for (int b = 0; b < 8; b++) _mm_storeu_si128((__m128i *)(out + b * 4), s[b]);
}

/* The CPU twin of the kernels' OUT_ALL: every word of all eight blocks, so the
 * correctness gate checks every block the GPU is timed on. */
static uint32_t fold_all(const uint32_t st[32])
{
    uint32_t x = 0;
    for (int i = 0; i < 32; i++) x ^= st[i];
    return x;
}

struct cpu_arg { uint32_t iters; uint32_t acc; int id; };
static void *cpu_worker(void *p)
{
    cpu_arg *a = (cpu_arg *)p;
    uint32_t st[32];
    cpu_state((uint32_t)a->id, a->iters, st);
    a->acc = fold_all(st);
    return NULL;
}

/* Returns AES ROUNDS per second: iters * 8 blocks * 10 rounds. */
static double cpu_rounds_per_s(int threads, double seconds, uint32_t *sink)
{
    uint32_t iters = 256;
    double el = 0.0;
    std::vector<cpu_arg> args(threads);
    std::vector<pthread_t> th(threads);
    for (int pass = 0; pass < 2; pass++) {
        const double t0 = now_s();
        for (int i = 0; i < threads; i++) { args[i].iters = iters; args[i].acc = 0; args[i].id = i;
            pthread_create(&th[i], NULL, cpu_worker, &args[i]); }
        for (int i = 0; i < threads; i++) pthread_join(th[i], NULL);
        el = now_s() - t0;
        for (int i = 0; i < threads; i++) *sink ^= args[i].acc;
        if (pass == 0) {
            if (el < 1e-4) el = 1e-4;
            double n = (double)iters * (seconds / el);
            if (n < 64) n = 64;
            if (n > 4e7) n = 4e7;
            iters = (uint32_t)n;
        }
    }
    return (double)threads * (double)iters * 80.0 / el;
}

/* ---------------- GPU ---------------- */

static const char *K_SRC =
"#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))\n"
"\n"
"/* Fold EVERY state word into the output. The eight blocks are independent\n"
" * chains, so an output that reads only s[0] and s[31] leaves blocks 1 to 6\n"
" * dead and the compiler deletes them: the GPU then does a quarter of the AES\n"
" * the rate is divided by. That is what F78's 1.04x measured. FINDINGS F79. */\n"
"#define OUT_ALL(out, gid, s)                                                 \\\n"
"    {   uint acc_ = 0;                                                       \\\n"
"        for (int i_ = 0; i_ < 32; i_++) acc_ ^= s[i_];                       \\\n"
"        out[gid] = acc_; }\n"
"\n"
"#define SEED_STATE(s, gid)                                                   \\\n"
"    {   uint sd = (uint)(gid) * 2654435761u + 1u;                            \\\n"
"        for (int i = 0; i < 32; i++) {                                       \\\n"
"            sd ^= sd << 13; sd ^= sd >> 17; sd ^= sd << 5; s[i] = sd; } }\n"
"\n"
"/* One AES round, table in whatever address space T names. */\n"
"#define RND(T, a0,a1,a2,a3, rk, r)                                           \\\n"
"    {   uint t0 = T[a0 & 0xff] ^ ROTL32(T[(a1>>8)&0xff],8)                   \\\n"
"               ^ ROTL32(T[(a2>>16)&0xff],16) ^ ROTL32(T[(a3>>24)&0xff],24)   \\\n"
"               ^ rk[r*4+0];                                                  \\\n"
"        uint t1 = T[a1 & 0xff] ^ ROTL32(T[(a2>>8)&0xff],8)                   \\\n"
"               ^ ROTL32(T[(a3>>16)&0xff],16) ^ ROTL32(T[(a0>>24)&0xff],24)   \\\n"
"               ^ rk[r*4+1];                                                  \\\n"
"        uint t2 = T[a2 & 0xff] ^ ROTL32(T[(a3>>8)&0xff],8)                   \\\n"
"               ^ ROTL32(T[(a0>>16)&0xff],16) ^ ROTL32(T[(a1>>24)&0xff],24)   \\\n"
"               ^ rk[r*4+2];                                                  \\\n"
"        uint t3 = T[a3 & 0xff] ^ ROTL32(T[(a0>>8)&0xff],8)                   \\\n"
"               ^ ROTL32(T[(a1>>16)&0xff],16) ^ ROTL32(T[(a2>>24)&0xff],24)   \\\n"
"               ^ rk[r*4+3];                                                  \\\n"
"        a0=t0; a1=t1; a2=t2; a3=t3; }\n"
"\n"
"/* Four pre-rotated tables, so the round has no rotates at all. */\n"
"#define RND4(T0,T1,T2,T3, a0,a1,a2,a3, rk, r)                                \\\n"
"    {   uint t0 = T0[a0 & 0xff] ^ T1[(a1>>8)&0xff]                           \\\n"
"               ^ T2[(a2>>16)&0xff] ^ T3[(a3>>24)&0xff] ^ rk[r*4+0];          \\\n"
"        uint t1 = T0[a1 & 0xff] ^ T1[(a2>>8)&0xff]                           \\\n"
"               ^ T2[(a3>>16)&0xff] ^ T3[(a0>>24)&0xff] ^ rk[r*4+1];          \\\n"
"        uint t2 = T0[a2 & 0xff] ^ T1[(a3>>8)&0xff]                           \\\n"
"               ^ T2[(a0>>16)&0xff] ^ T3[(a1>>24)&0xff] ^ rk[r*4+2];          \\\n"
"        uint t3 = T0[a3 & 0xff] ^ T1[(a0>>8)&0xff]                           \\\n"
"               ^ T2[(a1>>16)&0xff] ^ T3[(a2>>24)&0xff] ^ rk[r*4+3];          \\\n"
"        a0=t0; a1=t1; a2=t2; a3=t3; }\n"
"\n"
"/* ARM 1: the table in __constant. This is what F77's B3 measured. */\n"
"__kernel void aes_const(__global uint *out, const uint iters,\n"
"                        __constant uint *te0, __constant uint *rk)\n"
"{\n"
"    const size_t gid = get_global_id(0);\n"
"    uint s[32];\n"
"    SEED_STATE(s, gid)\n"
"    for (uint it = 0; it < iters; it++)\n"
"        for (int b = 0; b < 8; b++) {\n"
"            uint a0=s[b*4+0], a1=s[b*4+1], a2=s[b*4+2], a3=s[b*4+3];\n"
"            for (int r = 0; r < 10; r++) RND(te0, a0,a1,a2,a3, rk, r)\n"
"            s[b*4+0]=a0; s[b*4+1]=a1; s[b*4+2]=a2; s[b*4+3]=a3;\n"
"        }\n"
"    OUT_ALL(out, gid, s)\n"
"}\n"
"\n"
"/* ARM 2: the same table staged into __local once per work-group. */\n"
"__kernel void aes_lds(__global uint *out, const uint iters,\n"
"                      __constant uint *te0, __constant uint *rk,\n"
"                      __local uint *T)\n"
"{\n"
"    const size_t gid = get_global_id(0);\n"
"    const size_t lid = get_local_id(0), lsz = get_local_size(0);\n"
"    for (size_t i = lid; i < 256; i += lsz) T[i] = te0[i];\n"
"    barrier(CLK_LOCAL_MEM_FENCE);\n"
"    uint s[32];\n"
"    SEED_STATE(s, gid)\n"
"    for (uint it = 0; it < iters; it++)\n"
"        for (int b = 0; b < 8; b++) {\n"
"            uint a0=s[b*4+0], a1=s[b*4+1], a2=s[b*4+2], a3=s[b*4+3];\n"
"            for (int r = 0; r < 10; r++) RND(T, a0,a1,a2,a3, rk, r)\n"
"            s[b*4+0]=a0; s[b*4+1]=a1; s[b*4+2]=a2; s[b*4+3]=a3;\n"
"        }\n"
"    OUT_ALL(out, gid, s)\n"
"}\n"
"\n"
"/* ARM 3: four pre-rotated tables in __local, 4 KB, no rotates in the round. */\n"
"__kernel void aes_lds4(__global uint *out, const uint iters,\n"
"                       __constant uint *te0, __constant uint *rk,\n"
"                       __local uint *T)\n"
"{\n"
"    const size_t gid = get_global_id(0);\n"
"    const size_t lid = get_local_id(0), lsz = get_local_size(0);\n"
"    __local uint *T0 = T, *T1 = T + 256, *T2 = T + 512, *T3 = T + 768;\n"
"    for (size_t i = lid; i < 256; i += lsz) {\n"
"        uint v = te0[i];\n"
"        T0[i] = v; T1[i] = ROTL32(v,8); T2[i] = ROTL32(v,16); T3[i] = ROTL32(v,24);\n"
"    }\n"
"    barrier(CLK_LOCAL_MEM_FENCE);\n"
"    uint s[32];\n"
"    SEED_STATE(s, gid)\n"
"    for (uint it = 0; it < iters; it++)\n"
"        for (int b = 0; b < 8; b++) {\n"
"            uint a0=s[b*4+0], a1=s[b*4+1], a2=s[b*4+2], a3=s[b*4+3];\n"
"            for (int r = 0; r < 10; r++) RND4(T0,T1,T2,T3, a0,a1,a2,a3, rk, r)\n"
"            s[b*4+0]=a0; s[b*4+1]=a1; s[b*4+2]=a2; s[b*4+3]=a3;\n"
"        }\n"
"    OUT_ALL(out, gid, s)\n"
"}\n";

struct Arm { const char *name; int local_tbl_uints; };
static const Arm ARMS[] = {
    { "aes_const", 0 },
    { "aes_lds",   256 },
    { "aes_lds4",  1024 },
};
static const int NARM = 3;

int main(int argc, char **argv)
{
    double seconds = 1.5;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) g_verbose = true;
        else seconds = atof(argv[i]);
    }
    uint32_t sink = 0;
    build_tables();

    printf("AES: CPU AES-NI against three GPU table placements.\n");
    printf("Rates are AES ROUNDS/s (8 blocks x 10 rounds per iteration).\n\n");
    fflush(stdout);

    double cpu_best = 0.0;
    printf("  CPU\n    %-10s %14s\n", "threads", "rounds/s");
    {
        const int rows[] = { 1, 30 };
        for (size_t r = 0; r < sizeof(rows)/sizeof(rows[0]); r++) {
            const double v = cpu_rounds_per_s(rows[r], seconds, &sink);
            if (v > cpu_best) cpu_best = v;
            printf("    %-10d %14.3e\n", rows[r], v);
        }
    }
    fflush(stdout);

    printf("\n  GPU\n");
    CL cl;
    if (!cl_load(cl)) { printf("    OpenCL not available\n"); return 0; }
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
    if (!dev) { printf("    no GPU device\n"); return 0; }
    char devname[256] = {0}; cl_uint cus = 0;
    cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
    cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
    printf("    %s, %u CUs\n", devname, cus);

    cl_int err = 0;
    cl_context ctx = cl.CreateContext(NULL, 1, &dev, NULL, NULL, &err);
    cl_command_queue q = cl.CreateCommandQueue(ctx, dev, 0, &err);
    size_t sl = strlen(K_SRC);
    cl_program prog = cl.CreateProgramWithSource(ctx, 1, &K_SRC, &sl, &err);
    if (cl.BuildProgram(prog, 1, &dev, "-cl-std=CL1.2", NULL, NULL) != CL_SUCCESS) {
        size_t n = 0; cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &n);
        std::string log(n, 0);
        cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, n, &log[0], NULL);
        printf("    kernel build failed:\n%s\n", log.c_str());
        return 1;
    }

    cl_mem te_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(TE0), NULL, &err);
    cl_mem rk_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, sizeof(RKH), NULL, &err);
    cl.EnqueueWriteBuffer(q, te_b, CL_TRUE, 0, sizeof(TE0), TE0, 0, NULL, NULL);
    cl.EnqueueWriteBuffer(q, rk_b, CL_TRUE, 0, sizeof(RKH), RKH, 0, NULL, NULL);

    /* Same launch shape for every arm, so the only difference is the table. */
    const size_t LOCAL = 64;
    const size_t items[] = { 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                             131072, 262144, 524288, 1048576 };
    const int NIT = (int)(sizeof(items)/sizeof(items[0]));

    double arm_best[NARM]; size_t arm_peak[NARM];
    for (int a = 0; a < NARM; a++) { arm_best[a] = 0.0; arm_peak[a] = 0; }

    for (int a = 0; a < NARM; a++) {
        cl_kernel k = cl.CreateKernel(prog, ARMS[a].name, &err);
        if (!k || err != CL_SUCCESS) { printf("    %s: kernel missing\n", ARMS[a].name); continue; }

        /* Correctness before timing. A mistranscribed table would most likely
         * be slower, but a fast wrong answer is the failure that would quietly
         * decide this question. 4 work items, 3 iterations, against AES-NI. */
        {
            const size_t vn = 4;
            cl_mem vo = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, vn * 4, NULL, &err);
            cl_uint vi = 3;
            cl.SetKernelArg(k, 0, sizeof(vo), &vo);
            cl.SetKernelArg(k, 1, sizeof(vi), &vi);
            cl.SetKernelArg(k, 2, sizeof(te_b), &te_b);
            cl.SetKernelArg(k, 3, sizeof(rk_b), &rk_b);
            if (ARMS[a].local_tbl_uints)
                cl.SetKernelArg(k, 4, ARMS[a].local_tbl_uints * sizeof(cl_uint), NULL);
            const size_t one = 4, loc = 4;
            cl.EnqueueNDRangeKernel(q, k, 1, NULL, &one, &loc, 0, NULL, NULL);
            cl.Finish(q);
            uint32_t got[4] = {0,0,0,0};
            cl.EnqueueReadBuffer(q, vo, 1, 0, sizeof(got), got, 0, NULL, NULL);
            bool ok = true;
            for (uint32_t g = 0; g < 4; g++) {
                uint32_t st[32]; cpu_state(g, vi, st);
                if (got[g] != fold_all(st)) ok = false;
            }
            printf("    %-10s against AES-NI: %s\n", ARMS[a].name, ok ? "MATCH" : "MISMATCH");
            cl.ReleaseMemObject(vo);
            if (!ok) { printf("    refusing to time a kernel that computes something else\n");
                       cl.ReleaseKernel(k); continue; }
        }

        for (int it = 0; it < NIT; it++) {
            const size_t gsz = items[it];
            cl_mem out = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * 4, NULL, &err);
            if (err != CL_SUCCESS) { cl.ReleaseMemObject(out); continue; }
            cl.SetKernelArg(k, 0, sizeof(out), &out);
            cl.SetKernelArg(k, 2, sizeof(te_b), &te_b);
            cl.SetKernelArg(k, 3, sizeof(rk_b), &rk_b);
            if (ARMS[a].local_tbl_uints)
                cl.SetKernelArg(k, 4, ARMS[a].local_tbl_uints * sizeof(cl_uint), NULL);

            cl_uint iters = 4;
            double el = 0.0;
            const double budget = (seconds < 0.5) ? seconds : 0.5;
            for (int pass = 0; pass < 2; pass++) {
                cl.SetKernelArg(k, 1, sizeof(iters), &iters);
                cl.Finish(q);
                const double t0 = now_s();
                cl.EnqueueNDRangeKernel(q, k, 1, NULL, &gsz, &LOCAL, 0, NULL, NULL);
                cl.Finish(q);
                el = now_s() - t0;
                if (pass == 0) {
                    if (el < 1e-4) el = 1e-4;
                    double n = (double)iters * (budget / el);
                    if (n < 1) n = 1;
                    if (n > 2e5) n = 2e5;
                    iters = (cl_uint)n;
                }
            }
            const double rps = (double)gsz * (double)iters * 80.0 / el;
            if (rps > arm_best[a]) { arm_best[a] = rps; arm_peak[a] = gsz; }
            if (g_verbose) printf("    %-10s %-8zu %14.3e\n", ARMS[a].name, gsz, rps);
            cl.ReleaseMemObject(out);
        }
        printf("    %-10s peak %14.3e  at %zu items%s\n", ARMS[a].name, arm_best[a], arm_peak[a],
               (arm_peak[a] == items[0] || arm_peak[a] == items[NIT-1])
                   ? "   <-- VOID: peak at the end of the range" : "");
        fflush(stdout);
        cl.ReleaseKernel(k);
    }

    printf("\n  %-10s %14s %12s %12s\n", "arm", "rounds/s", "CPU better", "vs const");
    for (int a = 0; a < NARM; a++) {
        if (arm_best[a] <= 0.0) continue;
        printf("    %-10s %14.3e %10.2fx %10.2fx\n", ARMS[a].name, arm_best[a],
               cpu_best / arm_best[a],
               arm_best[0] > 0.0 ? arm_best[a] / arm_best[0] : 0.0);
    }
    printf("\n  sink %x\n", sink);
    return 0;
}
