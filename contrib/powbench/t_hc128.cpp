/* HC-128 throughput, CPU against GPU. The other half of the D5 question.
 *
 * WHY. F60 found the chain fill is 94% HC-128 and two thirds of it HC128_Init.
 * F62 found the fill's random gather is something a GPU does 1.6x to 2.7x
 * BETTER than a CPU. D5 proposes deleting 255 of the 257 reseeds and replacing
 * them with DRAM latency, so it trades HC-128 away for gather.
 *
 * Whether that helps or hurts goal 1 turns on one unmeasured thing: what
 * HC-128 costs a card. The suspicion on record (F60 section 3) is that it is
 * GPU-hostile, because the state is P[512] + Q[512] = **4 KB per instance**
 * and a 32-lane warp would need 128 KB of it, far beyond any shared memory. If
 * that is right, D5 removes the fill's only anti-GPU property.
 *
 * This measures it instead of assuming it.
 *
 * METHOD. Each work item runs rounds of {HC128_Init, then K HC128_NextKeys},
 * with K chosen so the mix matches a real fill: 257 inits and about 10,500
 * NextKeys per fill, so K = 40. The GPU keeps each item's 4 KB state in global
 * memory, which is what a real miner would do; shared memory cannot hold it.
 *
 * The CPU arm links the daemon's own src/crypto/hc128.c, so the reference side
 * is the shipped cipher and not a re-derivation. The kernel is a transcription
 * of that file; `-v` checks the kernel's keystream against the CPU's before
 * timing anything, so a wrong port cannot read as a fast one.
 *
 *   t_hc128 [seconds]
 *
 * Build: sh contrib/powbench/build-hc128.sh
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

/* 257 HC128_Init and ~10,500 HC128_NextKeys per fill, so 40 NextKeys per
 * init is the shipped mix. F60 section 1. */
#define NEXT_PER_SHIPPED 40

/* The mix is now swept rather than fixed, because F64 made it the mechanism
 * rather than a parameter.
 *
 * F64 concluded that the GPU gate is not HC-128's 4 KB state on its own but
 * the fact that the fill re-keys every 16 messages and so never leaves the
 * setup phase, where the published 31 Gbps result lives. That is an inference
 * from what a paper measures, and it has a direct test: if it is right, the
 * GPU's disadvantage must be large at nextper = 0, where every round is a key
 * setup, and small at large nextper, where setup amortises away. If instead
 * the ratio is flat across the sweep, the gate is the state size and reseed
 * count is back to being a tuning dial.
 *
 * The answer decides whether raising the reseed rate buys anything, which is
 * the one lever F67 section 4 priced (1.65x on the fill) without knowing what
 * it purchases. */
static uint32_t g_nextper = NEXT_PER_SHIPPED;
static bool g_verbose = false;   /* -v prints every work-item row */

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

/* ---------------- CPU ---------------- */

struct cpu_arg { uint32_t rounds; uint32_t acc; int id; };

static void *cpu_worker(void *p)
{
    cpu_arg *a = (cpu_arg *)p;
    HC128_State st;
    unsigned char key[16], iv[16];
    uint32_t acc = 0, r, n;
    int i;

    for (i = 0; i < 16; i++) { key[i] = (unsigned char)(a->id * 7 + i); iv[i] = (unsigned char)(i * 3 + 1); }
    for (r = 0; r < a->rounds; r++) {
        key[0] = (unsigned char)r; key[1] = (unsigned char)(r >> 8);
        HC128_Init(&st, key, iv);
        /* Consume a word of the post-init state. Without this, nextper = 0
         * leaves the init's result unread on both arms and either compiler is
         * entitled to delete the thing under test. The GPU arm does the same,
         * so the correctness gate still compares like with like. */
        acc ^= st.P[0];
        for (n = 0; n < g_nextper; n++) { HC128_NextKeys(&st); acc ^= st.keystream[0]; }
    }
    a->acc = acc;
    return NULL;
}

static double cpu_rounds_per_s(int threads, double seconds, uint32_t *sink)
{
    uint32_t rounds = 64;
    double el = 0.0;
    std::vector<cpu_arg> args(threads);
    std::vector<pthread_t> th(threads);
    int i;
    for (int pass = 0; pass < 2; pass++) {
        const double t0 = now_s();
        for (i = 0; i < threads; i++) { args[i].rounds = rounds; args[i].acc = 0; args[i].id = i;
            pthread_create(&th[i], NULL, cpu_worker, &args[i]); }
        for (i = 0; i < threads; i++) pthread_join(th[i], NULL);
        el = now_s() - t0;
        for (i = 0; i < threads; i++) *sink ^= args[i].acc;
        if (pass == 0) {
            if (el < 1e-4) el = 1e-4;
            double nr = (double)rounds * (seconds / el);
            if (nr < 16) nr = 16;
            if (nr > 2e7) nr = 2e7;
            rounds = (uint32_t)nr;
        }
    }
    return (double)threads * (double)rounds / el;
}

/* ---------------- GPU ---------------- */
/* A transcription of src/crypto/hc128.c. The sixteen unrolled step macros
 * there are one regular loop: with cc a multiple of 16, the macro operands
 * m511, m3, m10 and m12 are P[(cc+j+1)&511], P[(cc+j-3)&511],
 * P[(cc+j-10)&511] and P[(cc+j-12)&511]. Updates stay in place and in order,
 * which the sequence depends on. */
static const char *K_SRC =
"#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32-(n))))\n"
"#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))\n"
"#define F1(x) (ROTR32((x),7) ^ ROTR32((x),18) ^ ((x) >> 3))\n"
"#define F2(x) (ROTR32((x),17) ^ ROTR32((x),19) ^ ((x) >> 10))\n"
"#define FF(a,b,c,d) (F2(a) + (b) + F1(c) + (d))\n"
"\n"
"static void hc_sixteen(__global uint *P, __global uint *Q, uint *counter, uint *ks, int emit)\n"
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
"\n"
"static void hc_init(__global uint *P, __global uint *Q, uint *counter,\n"
"                    const uint k0, const uint k1, const uint k2, const uint k3,\n"
"                    const uint v0, const uint v1, const uint v2, const uint v3)\n"
"{\n"
"    uint i;\n"
"    P[0] = k0; P[1] = k1; P[2] = k2; P[3] = k3;\n"
"    P[4] = k0; P[5] = k1; P[6] = k2; P[7] = k3;\n"
"    P[8] = v0; P[9] = v1; P[10] = v2; P[11] = v3;\n"
"    P[12] = v0; P[13] = v1; P[14] = v2; P[15] = v3;\n"
"    for (i = 16; i < 272; i++) P[i] = FF(P[i-2], P[i-7], P[i-15], P[i-16]) + i;\n"
"    for (i = 0; i < 16; i++)   P[i] = P[i + 256];\n"
"    for (i = 16; i < 512; i++) P[i] = FF(P[i-2], P[i-7], P[i-15], P[i-16]) + 256 + i;\n"
"    for (i = 0; i < 16; i++)   Q[i] = P[512 - 16 + i];\n"
"    for (i = 16; i < 32; i++)  Q[i] = FF(Q[i-2], Q[i-7], Q[i-15], Q[i-16]) + 256 + 512 + (i - 16);\n"
"    for (i = 0; i < 16; i++)   Q[i] = Q[i + 16];\n"
"    for (i = 16; i < 512; i++) Q[i] = FF(Q[i-2], Q[i-7], Q[i-15], Q[i-16]) + 768 + i;\n"
"    *counter = 0;\n"
"    uint dummy[16];\n"
"    for (i = 0; i < 64; i++) hc_sixteen(P, Q, counter, dummy, 0);\n"
"}\n"
"\n"
"__kernel void hcbench(__global uint *scratch, const uint rounds, const uint nextper,\n"
"                      __global uint *out)\n"
"{\n"
"    const size_t gid = get_global_id(0);\n"
"    __global uint *P = scratch + gid * 1024;\n"
"    __global uint *Q = P + 512;\n"
"    uint ks[16];\n"
"    uint counter = 0, acc = 0, r, n;\n"
"    for (r = 0; r < rounds; r++) {\n"
"        hc_init(P, Q, &counter, (uint)gid ^ r, 0x11223344u, 0x55667788u, 0x99aabbccu,\n"
"                0x01020304u, 0x05060708u, 0x090a0b0cu, 0x0d0e0f10u);\n"
"        acc ^= P[0];\n"
"        for (n = 0; n < nextper; n++) { hc_sixteen(P, Q, &counter, ks, 1); acc ^= ks[0]; }\n"
"    }\n"
"    out[gid] = acc;\n"
"}\n";

int main(int argc, char **argv)
{
    double seconds = 1.5;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) g_verbose = true;
        else seconds = atof(argv[i]);
    }
    uint32_t sink = 0;
    int hw = 30;

    printf("HC-128 CPU against GPU, swept over the reseed mix. Shipped is %d\n",
           NEXT_PER_SHIPPED);
    printf("NextKeys per Init. Pass -v for the full work-item grid.\n\n");
    fflush(stdout);

    /* The shipped mix runs first AND last. F63 section 4 found this harness
     * family loses 3.8% to heat over a long run, so a sweep that is not
     * bracketed by a repeat of one arm cannot tell a trend from drift. */
    const uint32_t sweep[] = { NEXT_PER_SHIPPED, 0, 10, 160, 640, NEXT_PER_SHIPPED };
    const int NS = (int)(sizeof(sweep)/sizeof(sweep[0]));
    double cpu_r[NS], gpu_r[NS];
    size_t gpu_peak_at[NS];
    for (int s = 0; s < NS; s++) { cpu_r[s] = 0.0; gpu_r[s] = 0.0; gpu_peak_at[s] = 0; }

    printf("  CPU\n");
    printf("    %-10s %-10s %14s %14s %14s\n", "nextper", "threads", "rounds/s", "inits/s", "nextkeys/s");
    for (int s = 0; s < NS; s++) {
        g_nextper = sweep[s];
        const int rows[] = { 1, 30 };
        for (size_t r = 0; r < sizeof(rows)/sizeof(rows[0]); r++) {
            const double rps = cpu_rounds_per_s(rows[r], seconds, &sink);
            if (rps > cpu_r[s]) cpu_r[s] = rps;
            printf("    %-10u %-10d %14.3e %14.3e %14.3e\n", sweep[s], rows[r], rps, rps,
                   rps * (double)sweep[s]);
        }
        fflush(stdout);
    }
    double cpu_best = cpu_r[0];

    printf("\n  GPU\n");
    double gpu_best = 0.0;
    {
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
        char devname[256] = {0}; cl_ulong gmem = 0; cl_uint cus = 0;
        cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
        cl.GetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, NULL);
        cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
        printf("    %s, %llu MB, %u CUs\n", devname, (unsigned long long)(gmem/1048576), cus);

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
            return 0;
        }
        cl_kernel k = cl.CreateKernel(prog, "hcbench", &err);

        /* Correctness before timing. A mistranscribed kernel would most likely
         * be slower, but a fast wrong answer is the one failure that would
         * quietly invert this entry's conclusion, so check it rather than
         * assume it. One work item, two rounds, the same key and iv schedule
         * the kernel uses for gid 0, compared against src/crypto/hc128.c. */
        {
            cl_mem vscr = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, 1024 * sizeof(uint32_t), NULL, &err);
            cl_mem vout = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, 4, NULL, &err);
            cl_uint vr = 2, vn = NEXT_PER_SHIPPED;
            cl.SetKernelArg(k, 0, sizeof(vscr), &vscr);
            cl.SetKernelArg(k, 1, sizeof(vr), &vr);
            cl.SetKernelArg(k, 2, sizeof(vn), &vn);
            cl.SetKernelArg(k, 3, sizeof(vout), &vout);
            size_t one = 1;
            cl.EnqueueNDRangeKernel(q, k, 1, NULL, &one, NULL, 0, NULL, NULL);
            cl.Finish(q);
            uint32_t gpu_acc = 0;
            cl.EnqueueReadBuffer(q, vout, 1, 0, 4, &gpu_acc, 0, NULL, NULL);

            uint32_t cpu_acc = 0;
            for (uint32_t r = 0; r < vr; r++) {
                HC128_State st;
                uint32_t kw[4] = { 0u ^ r, 0x11223344u, 0x55667788u, 0x99aabbccu };
                uint32_t vw[4] = { 0x01020304u, 0x05060708u, 0x090a0b0cu, 0x0d0e0f10u };
                HC128_Init(&st, (unsigned char *)kw, (unsigned char *)vw);
                cpu_acc ^= st.P[0];
                for (uint32_t n = 0; n < vn; n++) { HC128_NextKeys(&st); cpu_acc ^= st.keystream[0]; }
            }
            printf("    kernel against src/crypto/hc128.c: %s (gpu %08x, cpu %08x)\n",
                   gpu_acc == cpu_acc ? "MATCH" : "MISMATCH", gpu_acc, cpu_acc);
            if (gpu_acc != cpu_acc) {
                printf("    refusing to time a kernel that computes something else\n");
                return 1;
            }
            cl.ReleaseMemObject(vout); cl.ReleaseMemObject(vscr);
        }

        printf("    %-10s %-14s %14s %14s %14s\n", "nextper", "work items", "rounds/s", "inits/s", "nextkeys/s");
        if (!g_verbose) printf("    (peaks only; -v for the grid)\n");
        /* 4 KB of state per item, so the scratch is the limit, not occupancy.
         *
         * The array used to start at 1,024. F66 caught the same harness family
         * reporting a peak that sat at the lowest value tested, which means the
         * range was too short and the figure is a floor rather than a
         * measurement, so this starts at 256 and fills in the middle. A peak at
         * either end of this range still voids the row. */
        const size_t items[] = { 256, 512, 1024, 2048, 3072, 4096, 5120, 6144, 8192, 16384, 32768, 131072 };
      for (int s = 0; s < NS; s++) {
        g_nextper = sweep[s];
        for (size_t it = 0; it < sizeof(items)/sizeof(items[0]); it++) {
            const size_t gsz = items[it];
            const size_t scratch_bytes = gsz * 1024 * sizeof(uint32_t);
            if (scratch_bytes > gmem / 2) { printf("    %-14zu (skipped, needs %zu MB)\n", gsz, scratch_bytes/1048576); continue; }
            cl_mem dscr = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, scratch_bytes, NULL, &err);
            if (err != CL_SUCCESS) { printf("    %-14zu (scratch alloc failed)\n", gsz); continue; }
            cl_mem dout = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * 4, NULL, &err);
            cl_uint nextper = g_nextper;
            cl.SetKernelArg(k, 0, sizeof(dscr), &dscr);
            cl.SetKernelArg(k, 2, sizeof(nextper), &nextper);
            cl.SetKernelArg(k, 3, sizeof(dout), &dout);

            cl_uint rounds = 2;
            double el = 0.0;
            const double gpu_seconds = (seconds < 0.5) ? seconds : 0.5;
            for (int pass = 0; pass < 2; pass++) {
                cl.SetKernelArg(k, 1, sizeof(rounds), &rounds);
                cl.Finish(q);
                const double t0 = now_s();
                cl.EnqueueNDRangeKernel(q, k, 1, NULL, &gsz, NULL, 0, NULL, NULL);
                cl.Finish(q);
                el = now_s() - t0;
                if (pass == 0) {
                    if (el < 1e-4) el = 1e-4;
                    double nr = (double)rounds * (gpu_seconds / el);
                    if (nr < 1) nr = 1;
                    if (nr > 1e5) nr = 1e5;
                    rounds = (cl_uint)nr;
                }
            }
            const double rps = (double)gsz * (double)rounds / el;
            if (rps > gpu_r[s]) { gpu_r[s] = rps; gpu_peak_at[s] = gsz; }
            if (g_verbose)
                printf("    %-10u %-14zu %14.3e %14.3e %14.3e\n", sweep[s], gsz, rps, rps,
                          rps * (double)sweep[s]);
            cl.ReleaseMemObject(dout); cl.ReleaseMemObject(dscr);
        }
        printf("    %-10u %-14s %14.3e  at %zu items%s\n", sweep[s], "peak", gpu_r[s],
               gpu_peak_at[s],
               (gpu_peak_at[s] == items[0] ||
                gpu_peak_at[s] == items[sizeof(items)/sizeof(items[0]) - 1])
                   ? "   <-- VOID: peak at the end of the range" : "");
        fflush(stdout);
      }
        gpu_best = gpu_r[0];
    }

    /* The result. Ratios within one machine pairing, which F63 section 3
     * establishes is the only form that transfers. */
    printf("\n  GPU / CPU by reseed mix, and how much disadvantage the reseeds buy\n");
    printf("    %-10s %14s %14s %12s %10s\n", "nextper", "cpu rounds/s", "gpu rounds/s", "GPU is", "vs shipped");
    for (int s = 0; s < NS; s++) {
        if (cpu_r[s] <= 0.0 || gpu_r[s] <= 0.0) continue;
        const double ratio = cpu_r[s] / gpu_r[s];
        const double base  = (cpu_r[0] > 0.0 && gpu_r[0] > 0.0) ? (cpu_r[0] / gpu_r[0]) : 0.0;
        printf("    %-10u %14.3e %14.3e %10.2fx %9.3fx%s\n", sweep[s], cpu_r[s], gpu_r[s],
               ratio, base > 0.0 ? ratio / base : 0.0,
               sweep[s] == NEXT_PER_SHIPPED ? "   (shipped)" : "");
    }
    if (cpu_r[0] > 0.0 && gpu_r[0] > 0.0 && cpu_r[NS-1] > 0.0 && gpu_r[NS-1] > 0.0) {
        const double a = cpu_r[0] / gpu_r[0], b = cpu_r[NS-1] / gpu_r[NS-1];
        const double drift = (a > b ? a / b : b / a) - 1.0;
        printf("\n  drift control, the shipped arm first against last: %.1f%%%s\n",
               drift * 100.0,
               drift > 0.04 ? "   <-- VOID: nothing smaller than this is a signal" : "");
    }
    printf("\n  sink %x\n", sink);
    return 0;
}
