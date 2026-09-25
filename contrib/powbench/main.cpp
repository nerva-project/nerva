#include <windows.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
#include <string>
#include <cpuid.h>
#include <cstdlib>
#include <io.h>
#include "clmin.h"
#include "kernels.cl.h"
#include "cpu_ref.h"

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
        && sym(cl.EnqueueWriteBuffer,"clEnqueueWriteBuffer") && sym(cl.EnqueueReadBuffer,"clEnqueueReadBuffer") && sym(cl.ReleaseMemObject,"clReleaseMemObject")
        && sym(cl.ReleaseKernel,"clReleaseKernel") && sym(cl.ReleaseProgram,"clReleaseProgram")
        && sym(cl.ReleaseCommandQueue,"clReleaseCommandQueue") && sym(cl.ReleaseContext,"clReleaseContext");
}

// v5 is swept across pad size; the rest are fixed points of comparison.
// buf_kb is the per-nonce pad. The chase work (steps, or passes x hops) does
// NOT scale with the pad, matching the real hash, where the AES round count
// comes from the per-nonce parameters and only the sweeps scale with the pad.
struct Variant { const char *name; const char *kernel; size_t buf_kb; unsigned passes; unsigned hops; unsigned steps; int which; };
// Trimmed to 7. PROPOSAL and v7b are gone: v7b was settled long ago (hugely
// GPU-favourable, parked) and PROPOSAL's numbers were never stable enough to
// quote. 1.25 MB is gone because 1 / 1.5 / 2 / 4 / 8 already brackets the
// interesting region and 1.25 sat on top of 1.5.
static Variant VARIANTS[] = {
    { "v5 1MB",     "chase_v5",  1024,    0,    0, 524288, 5 },
    { "v5 1.5MB",   "chase_v5",  1536,    0,    0, 524288, 5 },
    { "v5 2MB",     "chase_v5",  2048,    0,    0, 524288, 5 },
    { "v5 4MB",     "chase_v5",  4096,    0,    0, 524288, 5 },
    { "v5 8MB",     "chase_v5",  8192,    0,    0, 524288, 5 },
    { "v6 HF13",    "chase_v6",  8192,    0,    0, 597688, 6 },
    { "v7 HF14",    "chase_v7", 24576, 3072, 1024,      0, 7 },
};
static const int NV = (int)(sizeof(VARIANTS) / sizeof(VARIANTS[0]));

static double g_gpu[NV];
static size_t g_nonces[NV];
static size_t g_bufs[NV];
static double g_spread[NV], g_cspread[NV];
static const int GPU_REPS = 2;   // best-of; keeps total GPU load near the level that ran fine before
static const int CPU_REPS = 2;   // best-of, see the CPU loop
static double g_cpu[NV], g_ms1[NV], g_ms4[NV];
static double g_vram_frac = 0.50;   // of VRAM; override with argv[1], 0 = skip GPU

static std::string cpu_brand() {
    unsigned r[4]; char buf[49]; memset(buf, 0, sizeof(buf));
    if (!__get_cpuid(0x80000000u, &r[0], &r[1], &r[2], &r[3]) || r[0] < 0x80000004u)
        return "unknown CPU";
    for (unsigned leaf = 0; leaf < 3; leaf++) {
        __get_cpuid(0x80000002u + leaf, &r[0], &r[1], &r[2], &r[3]);
        memcpy(buf + leaf * 16, r, 16);
    }
    std::string s(buf);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    size_t b = s.find_first_not_of(' ');
    return b == std::string::npos ? "unknown CPU" : s.substr(b);
}

// progress on one line, wiped before the table so the screen photographs clean
static bool g_tty = false;
static void progress(const char *side, const char *what, int i, int n) {
    if (!g_tty) return;
    printf("\r  %s  %-12s %2d/%d ...              ", side, what, i, n);
    fflush(stdout);
}
static void progress_clear() { if (g_tty) { printf("\r%74s\r", ""); fflush(stdout); } }

static const unsigned char SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static inline unsigned char xt8(unsigned char x){ return (unsigned char)((x<<1) ^ ((x>>7)*0x1b)); }

int main(int argc, char **argv) {
    if (argc > 1) { double p = atof(argv[1]); if (p >= 0.0 && p <= 95.0) g_vram_frac = p / 100.0; }
    for (int i = 0; i < NV; i++) { g_gpu[i] = 0; g_nonces[i] = 0; g_bufs[i] = 0; g_spread[i] = 1.0; g_cspread[i] = 1.0; g_cpu[i] = 0; g_ms1[i] = 0; }

    CL cl; bool have_gpu = (g_vram_frac > 0.0) && cl_load(cl);
    cl_context ctx = NULL; cl_command_queue q = NULL; cl_program prog = NULL;
    cl_device_id dev = NULL; cl_ulong gmem = 0, maxalloc = 0;
    char devname[256]; char drv[128]; cl_uint cus = 0, mhz = 0;
    memset(devname, 0, sizeof(devname)); memset(drv, 0, sizeof(drv));

    if (have_gpu) {
        cl_uint nplat = 0; cl.GetPlatformIDs(0, NULL, &nplat);
        std::vector<cl_platform_id> plats(nplat ? nplat : 1);
        if (nplat) cl.GetPlatformIDs(nplat, plats.data(), NULL);
        for (cl_uint p = 0; p < nplat && !dev; p++) {
            cl_uint nd = 0;
            if (cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 0, NULL, &nd) != CL_SUCCESS || !nd) continue;
            std::vector<cl_device_id> ds(nd); cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, nd, ds.data(), NULL);
            dev = ds[0];
            cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(maxalloc), &maxalloc, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(mhz), &mhz, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_VERSION, sizeof(drv), drv, NULL);
        }
        if (dev) {
            cl_int err = 0;
            ctx = cl.CreateContext(NULL, 1, &dev, NULL, NULL, &err);
            q = cl.CreateCommandQueue(ctx, dev, 0, &err);
            const char *src = KERNEL_SRC; size_t sl = strlen(src);
            prog = cl.CreateProgramWithSource(ctx, 1, &src, &sl, &err);
            if (cl.BuildProgram(prog, 1, &dev, "-cl-std=CL1.2", NULL, NULL) != CL_SUCCESS) {
                size_t n = 0; cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &n);
                std::string log(n, 0); cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, n, &log[0], NULL);
                printf("Kernel build failed:\n%s\n", log.c_str()); have_gpu = false;
            }
        } else have_gpu = false;
    }

    g_tty = _isatty(_fileno(stdout)) != 0;

    unsigned hw = std::thread::hardware_concurrency(); if (!hw) hw = 4;

    printf("NERVA PoW BENCH   v5 pad sweep vs v6 / v7   identical work both sides\n");
    printf("CPU  %.50s  (%u thr)\n", cpu_brand().c_str(), hw);
    if (have_gpu)
        printf("GPU  %.30s %.1fG VRAM %.1fG alloc %uCU  vram=%d%%\n", devname,
               gmem / 1073741824.0, maxalloc / 1073741824.0, cus, (int)(g_vram_frac * 100.0 + 0.5));
    else
        printf("GPU  none usable, CPU columns only\n");
    printf("\n");

    cl_mem te_buf = NULL, rk_buf = NULL;
    if (have_gpu) {
        unsigned int te0[256];
        for (int i = 0; i < 256; i++) { unsigned char sb = SBOX[i], s2 = xt8(sb), s3 = (unsigned char)(s2 ^ sb);
            te0[i] = ((unsigned)s2) | ((unsigned)sb << 8) | ((unsigned)sb << 16) | ((unsigned)s3 << 24); }
        unsigned int rkh[40]; for (int i = 0; i < 40; i++) rkh[i] = 0x9e3779b9u * (unsigned)(i + 1);
        cl_int e2 = 0;
        te_buf = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(te0), NULL, &e2);
        rk_buf = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(rkh), NULL, &e2);
        cl.EnqueueWriteBuffer(q, te_buf, CL_TRUE, 0, sizeof(te0), te0, 0, NULL, NULL);
        cl.EnqueueWriteBuffer(q, rk_buf, CL_TRUE, 0, sizeof(rkh), rkh, 0, NULL, NULL);
    }

    if (have_gpu) {
        for (int gi = 0; gi < NV; gi++) {
            const Variant &v = VARIANTS[gi];
            progress("GPU", v.name, gi + 1, NV);
            const size_t bytes_per = v.buf_kb * 1024ull;
            const cl_ulong qw = bytes_per / 8;
            size_t budget = (size_t)(gmem * g_vram_frac);
            if (v.which == 9) budget = budget > (300ull<<20) ? budget - (300ull<<20) : budget/2;

            // Spread the pads over up to MAXBUF allocations rather than one.
            // CL_DEVICE_MAX_MEM_ALLOC_SIZE is a per-allocation limit, not a
            // capacity limit: 1 GB on the 4 GB 1050 Ti, 2 GB on the 8 GB 3050.
            // Capping the whole run at it gave those cards 128 and 192 nonces
            // at 8 MB, far too few to fill the device, which made the biggest
            // pads look resistant when the harness was simply starving them.
            const size_t MAXBUF = 4;
            size_t nbuf = 1;
            while (nbuf < MAXBUF && budget / nbuf > (size_t)maxalloc) nbuf++;
            size_t chunk = budget / nbuf;
            if (chunk > (size_t)maxalloc) chunk = (size_t)maxalloc;
            // per_buf is NOT rounded here. Rounding it to a multiple of the
            // work-group size threw away up to 45% of each buffer on the big
            // pads (the 1050 Ti got 64 nonces per buffer out of room for 116),
            // and the fallback for when it rounded to zero left a global size
            // that was not a multiple of lws at all. That made
            // EnqueueNDRangeKernel return CL_INVALID_WORK_GROUP_SIZE, the
            // kernel never ran, and nonces/~0s printed 3.8 MH/s on a 1050 Ti.
            // Round the TOTAL instead, and shrink lws when the total is small.
            size_t per_buf = chunk / bytes_per;
            if (per_buf < 1) continue;

            cl_int err = 0;
            cl_mem bl[MAXBUF] = { NULL, NULL, NULL, NULL };
            size_t got = 0;
            for (size_t b = 0; b < nbuf; b++) {
                bl[b] = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS,
                                        per_buf * bytes_per, NULL, &err);
                if (err != CL_SUCCESS || bl[b] == NULL) { bl[b] = NULL; break; }
                got++;
            }
            if (got == 0) continue;                     // not even one buffer fit
            nbuf = got;                                 // driver refused the rest, use what we have
            for (size_t b = nbuf; b < MAXBUF; b++) bl[b] = bl[0];   // unused slots, never selected
            size_t nonces = nbuf * per_buf;
            size_t lws = 64;
            while (lws > 1 && nonces < lws * 4) lws /= 2;   // want at least 4 groups
            nonces = (nonces / lws) * lws;
            if (nonces < 1) continue;
            // gid < nonces <= nbuf*per_buf, so gid/per_buf stays inside bl[]
            cl_mem out = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, nonces * 8, NULL, &err);
            cl_kernel k = cl.CreateKernel(prog, v.kernel, &err);
            cl_uint a = 0;
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[0]);
            cl.SetKernelArg(k, a++, sizeof(cl_ulong), &qw);
            if (v.which == 9) {
                static cl_mem ds = NULL; static cl_ulong ds_qw = 0;
                if (!ds) { ds_qw = 256ull * 1024 * 1024 / 8;
                    ds = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, ds_qw * 8, NULL, &err); }
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &ds);
                cl.SetKernelArg(k, a++, sizeof(cl_ulong), &ds_qw);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &v.passes);
            }
            else if (v.passes) { cl.SetKernelArg(k, a++, sizeof(cl_uint), &v.passes); cl.SetKernelArg(k, a++, sizeof(cl_uint), &v.hops); }
            else { cl_uint fi = (cl_uint)(bytes_per / 128);
                   cl.SetKernelArg(k, a++, sizeof(cl_uint), &v.steps);
                   cl.SetKernelArg(k, a++, sizeof(cl_uint), &fi); }
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &te_buf);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &rk_buf);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &out);
            // the extra pad buffers go last so the earlier arg indices are unchanged
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[1]);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[2]);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[3]);
            { cl_uint pb = (cl_uint)per_buf; cl.SetKernelArg(k, a++, sizeof(cl_uint), &pb); }
            // Measure REPS times and keep the BEST. A single measurement cannot
            // tell a real effect from driver noise: PROPOSAL on the Vega moved
            // 70% between two runs with only PICK_BUF changed, which cost a
            // manual rerun to diagnose. Best-of-N also discards the first
            // launch, which carries JIT and warm-up. spread is reported so an
            // unstable row announces itself instead of being quoted as fact.
            // Zero the output first. It used to be left uninitialised, so when
            // a launch failed the checksum guard below read whatever garbage
            // was already in VRAM, decided the kernel had run, and published
            // the nonsense figure. Now a failed launch leaves it zero and the
            // row is suppressed.
            {
                std::vector<uint64_t> zeros(nonces, 0);
                cl.EnqueueWriteBuffer(q, out, CL_TRUE, 0, nonces * 8, zeros.data(), 0, NULL, NULL);
            }

            double best = 0.0, worst = 0.0;
            bool launch_ok = true;
            // ONE launch covering the whole range. Splitting it into smaller
            // commands was tried and reverted: an in-order OpenCL queue runs a
            // single kernel at a time, so 64-wide chunks left one compute unit
            // busy and the rest idle, collapsing throughput about 20x. Chunking
            // cannot work here anyway, because keeping enough work-items in
            // flight to fill the device already takes far longer than the TDR
            // watchdog allows. Total GPU load is held down by variant count,
            // GPU_REPS and the VRAM fraction instead.
            for (int rep = 0; rep < GPU_REPS && launch_ok; rep++) {
                const auto t0 = std::chrono::steady_clock::now();
                if (cl.EnqueueNDRangeKernel(q, k, 1, NULL, &nonces, &lws, 0, NULL, NULL) != CL_SUCCESS) {
                    launch_ok = false; break;
                }
                if (cl.Finish(q) != CL_SUCCESS) { launch_ok = false; break; }
                const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                if (secs <= 0.0) continue;
                const double hs = nonces / secs;
                if (hs > best) best = hs;
                if (worst == 0.0 || hs < worst) worst = hs;
            }
            std::vector<uint64_t> res(nonces);
            cl.EnqueueReadBuffer(q, out, CL_TRUE, 0, nonces * 8, res.data(), 0, NULL, NULL);
            uint64_t acc = 0; for (uint64_t x : res) acc ^= x;
            if (launch_ok && acc != 0 && best > 0.0) {
                g_gpu[gi] = best; g_nonces[gi] = nonces; g_bufs[gi] = nbuf;
                g_spread[gi] = (worst > 0.0) ? (best / worst) : 1.0;
            }
            cl.ReleaseKernel(k); cl.ReleaseMemObject(out);
            for (size_t b = 0; b < nbuf; b++) cl.ReleaseMemObject(bl[b]);   // slots >= nbuf alias bl[0]
        }
    }

    // Counts are sized from a measured single nonce so every cell takes about
    // the same wall time. The laptop and the Vega box differ several-fold in
    // speed, and a fixed count tuned on one measures noise on the other.
    for (int ci = 0; ci < NV; ci++) {
        const Variant &v = VARIANTS[ci];
        progress("CPU", v.name, ci + 1, NV);
        const double ms = cpu_one_ms(v.which, v.buf_kb, v.passes, v.hops, v.steps);
        unsigned per = (unsigned)(400.0 / (ms > 0.001 ? ms : 0.001));
        if (per < 1) per = 1;
        if (per > 400) per = 400;
        // Best of CPU_REPS, same reasoning as the GPU side, and it matters more
        // here: a thermally throttling laptop reads slower the longer it runs,
        // which is how the 7700HQ produced a 2 MB pad that looked dearer than
        // a 4 MB one. Best-of-N cannot fix drift ACROSS variants, only within
        // one, so a hot machine still wants a second whole run to compare.
        auto best_of = [&](unsigned threads) {
            double best = 0.0, worst = 0.0;
            for (int rep = 0; rep < CPU_REPS; rep++) {
                const double hs = cpu_bench(v.which, v.buf_kb, v.passes, v.hops, v.steps, threads, per);
                if (hs <= 0.0) continue;
                if (hs > best) best = hs;
                if (worst == 0.0 || hs < worst) worst = hs;
            }
            if (threads == hw && worst > 0.0) g_cspread[ci] = best / worst;
            return best;
        };
        g_cpu[ci] = best_of(hw);
        const double h1 = best_of(1);
        g_ms1[ci] = h1 > 0.0 ? 1000.0 / h1 : 0.0;
        const double h4 = best_of(4);
        g_ms4[ci] = h4 > 0.0 ? 4000.0 / h4 : 0.0;
    }
    progress_clear();

    printf("VARIANT         KB  nonces nb   GPU H/s   CPU%-2u H/s   GPU:CPU    1T ms   4T ms\n", hw);
    printf("------------------------------------------------------------------------------\n");
    for (int i = 0; i < NV; i++) {
        printf("%-11s %6zu", VARIANTS[i].name, VARIANTS[i].buf_kb);
        if (g_gpu[i] > 0.0) printf(" %7zu %2zu %9.1f%s", g_nonces[i], g_bufs[i], g_gpu[i], g_spread[i] > 1.10 ? "!" : " ");
        else                printf(" %7s %2s %9s ", "-", "-", "-");
        printf(" %9.1f%s", g_cpu[i], g_cspread[i] > 1.10 ? "!" : " ");
        if (g_gpu[i] > 0.0) printf(" %7.2fx", g_gpu[i] / g_cpu[i]);
        else                printf(" %8s", "-");
        printf(" %8.2f %7.2f\n", g_ms1[i], g_ms4[i]);
    }
    printf("------------------------------------------------------------------------------\n");
    printf("GPU:CPU is the resistance number, LOWER is better. Best of %d GPU and\n", GPU_REPS);
    printf("%d CPU runs; a \"!\" marks a row that varied over 10%% between runs,\n", CPU_REPS);
    printf("which is noise, not a result. nonces is what the card held: a tiny\n");
    printf("count means VRAM capped it, not the algo. Compare a miner against the\n");
    printf("ALL-THREADS column. Modelled work: ceilings, not real hashrates.\n");

    if (have_gpu) { cl.ReleaseProgram(prog); cl.ReleaseCommandQueue(q); cl.ReleaseContext(ctx); }
    return 0;
}
