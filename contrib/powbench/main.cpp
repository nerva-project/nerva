#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <string>
#include <cpuid.h>
#include <io.h>
#include "clmin.h"
#include "vm_kernels.cl.h"
#include "vm_ref.h"
#include "chain_fill.h"

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

// gen 5/6/7. pad_kb is the main per-nonce working set. v6 runs the VM over the
// pad for CN_VM_ITERATIONS passes; v7 chases a buffer and writes to a separate
// 256 KB pad, with passes = buffer / (8 * hops) exactly as CN_VM_ITERATIONS_V14.
struct Variant { const char *name; int gen; size_t pad_kb; int grp; };

// grp 0 is the default set and answers PLAN-v8's GPU question and nothing
// else: v5 1MB is the control, v8 1MB the baseline, and the two FP rows the
// measurement. Fewer rows means more VRAM and less accumulated heat per row,
// which is what the numbers turn on. grp 1 is the pad sweep plus v6 and v7,
// which Phase 3 already settled (FINDINGS F24, F27, F28) and which v7's
// removal makes dead; pass "all" as the fourth argument to run it anyway.
static const Variant ALL_VARIANTS[] = {
    { "v5 1MB",    5,  1024, 0 },   // control: same GPU work as v8 1MB, separate path
    { "v8 1MB",    8,  1024, 0 },   // baseline the FP rows are divided by
    { "v8+fp rne", 9,  1024, 0 },   // FP stage, rounding fixed at nearest-even
    { "v8+fp",    10,  1024, 0 },   // FP stage as specified, mode from data
    { "v5 1MB end",5,  1024, 0 },   // the control again, AFTER the FP rows
    { "v5 4MB",    5,  4096, 1 },
    { "v5 8MB",    5,  8192, 1 },
    { "v6 1MB",    6,  1024, 1 },
    { "v6 4MB",    6,  4096, 1 },
    { "v6 8MB",    6,  8192, 1 },
    { "v7 24MB",   7, 24576, 1 },
};
static const int MAXV = (int)(sizeof(ALL_VARIANTS) / sizeof(ALL_VARIANTS[0]));
static Variant VARIANTS[MAXV];
static int NV = 0;
static bool g_all = false;          // argv[4] == "all": restore the grp 1 rows

static double g_gpu[MAXV], g_cpu[MAXV], g_ms1[MAXV], g_spread[MAXV], g_cspread[MAXV];
static size_t g_nonces[MAXV], g_bufs[MAXV];
static unsigned g_thr[MAXV];
static double g_alu_full = 0.0, g_alu_only = 0.0;  // v6 8MB: interpreted vs ideal-JIT kernel
static double g_sweep_ratio = 0.0;                 // v5 sweep: naive vs word-coalesced
static bool   g_no_fp64 = false;                   // device has no cl_khr_fp64
// FP round-count multiplier, argv "fpxN". At the real count the stage costs a
// GPU a few tenths of a percent, which is under this harness's own floor (the
// v5/v8 control gap). Running it at 10x puts the cost above the floor on both
// sides, and the cost is linear in the count, so dividing back out gives a
// number the harness can actually resolve. Measured on an RTX 3050: 1x read
// GPU +0.02% CPU +5.6%, 10x read GPU +3.4% CPU +44.3%, and both give the same
// 13x CPU-to-GPU cost ratio. That agreement is what says the 1x reading is a
// resolution limit and not a broken measurement.
static int    g_fp_mult = 1;
static char   g_why[MAXV][72];      // why a GPU row produced nothing
static double g_load = 0.0;         // system CPU busy % before the run

// System-wide CPU busy percentage over a short window.
//
// This exists because a whole set of results was taken on a machine that was
// mining on 12 threads at the time, and nothing in the output said so. The CPU
// column is then measuring the benchmark against a competitor rather than
// against the machine, and it is not recoverable afterwards. So the figure goes
// in the header of every run: a result taken under load is at least labelled as
// one, and cannot be quietly compared against a clean run.
static double sys_busy(int ms)
{
    FILETIME i0, k0, u0, i1, k1, u1;
    if (!GetSystemTimes(&i0, &k0, &u0)) return -1.0;
    Sleep(ms);
    if (!GetSystemTimes(&i1, &k1, &u1)) return -1.0;
    auto d = [](const FILETIME &a, const FILETIME &b) {
        const unsigned long long x = ((unsigned long long)a.dwHighDateTime << 32) | a.dwLowDateTime;
        const unsigned long long y = ((unsigned long long)b.dwHighDateTime << 32) | b.dwLowDateTime;
        return (double)(y - x);
    };
    // kernel time INCLUDES idle time, which is the part everyone gets wrong.
    const double idle = d(i0, i1), kern = d(k0, k1), user = d(u0, u1);
    const double total = kern + user;
    if (total <= 0.0) return -1.0;
    return 100.0 * (total - idle) / total;
}
static int    g_verified[MAXV];        // 1 ok, 0 not run, -1 mismatch
// The FP rows differ from their baseline by about 1% on a GPU, which is the
// same order as run-to-run noise, so both sides take best-of-3 rather than
// best-of-2 and the worst run spread is printed next to the verdict.
static const int GPU_REPS = 3;
static const int CPU_REPS = 5;
static double g_vram_frac = 0.50;   // of VRAM; argv[1], 0 = skip GPU
static double g_cooldown  = 15.0;   // seconds idle between GPU variants; argv[2]
static double g_launch_cap = 25.0;  // max seconds for one kernel launch; argv[3].
                                    // Directly trades freeze-safety against GPU
                                    // occupancy: too low and rows run starved,
                                    // too high and a display GPU trips TDR.
                                    // COMPARE MACHINES AT THE SAME CAP.
                                    // Lets a display-attached card shed heat. A
                                    // Vega FE blower heat-soaks under sustained
                                    // compute and drops the display. Does NOT help
                                    // with TDR, which is per-command duration and
                                    // is what LAUNCH_CAP covers.

static unsigned v6_iters()               { return CN_VM_ITERATIONS; }
static unsigned v7_iters(size_t bytes)   { return (unsigned)(bytes / (8 * CN_V7_HOPS)); }
// gens 8, 9 and 10 are v8: the v5 core with the Phase 2 floating-point stage
// absent, present at fixed nearest-even, and present with data-driven rounding.
// Same pad, same salt residency, same kernel arguments as v5.
static inline bool v5_like(int gen) { return gen == 5 || gen >= 8; }
// -1 no stage, 0 stage at fixed nearest-even, 1 the algorithm as specified
static inline int fp_mode_of(int gen) { return gen < 9 ? -1 : (gen == 9 ? 0 : 1); }

// per-nonce memory beyond the main pad
static size_t side_bytes(int gen) {
    if (v5_like(gen)) return CN_SALT_MEMORY;                              // salt stays resident
    if (gen == 6) return CN_PROGRAM_SIZE * sizeof(cn_ins_t);              // program only
    return CN_PROGRAM_SIZE * sizeof(cn_ins_t) + CN_V7_SEGMENTS * 2
         + CN_V7_HOPS * 8 + CN_V7_PAD_BYTES;                              // prog+segs+vals+pad
}

static std::string cpu_brand() {
    unsigned r[4]; char buf[49]; memset(buf, 0, sizeof(buf));
    if (!__get_cpuid(0x80000000u, &r[0], &r[1], &r[2], &r[3]) || r[0] < 0x80000004u) return "unknown CPU";
    for (unsigned leaf = 0; leaf < 3; leaf++) {
        __get_cpuid(0x80000002u + leaf, &r[0], &r[1], &r[2], &r[3]);
        memcpy(buf + leaf * 16, r, 16);
    }
    std::string s(buf);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    size_t b = s.find_first_not_of(' ');
    return b == std::string::npos ? "unknown CPU" : s.substr(b);
}

static bool g_tty = false;
static void progress(const char *side, const char *what, int i, int n) {
    if (!g_tty) return;
    printf("\r  %s  %-12s %2d/%d ...              ", side, what, i, n);
    fflush(stdout);
}
static void progress_clear() { if (g_tty) { printf("\r%76s\r", ""); fflush(stdout); } }

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

// Shared AES round keys, identical on both sides.
static __m128i g_rk[10];
static unsigned int g_rkh[40];
static void build_keys() {
    for (int i = 0; i < 40; i++) g_rkh[i] = 0x9e3779b9u * (unsigned)(i + 1);
    for (int i = 0; i < 10; i++) g_rk[i] = _mm_loadu_si128((const __m128i *)(g_rkh + i * 4));
}

// ---- CPU side -------------------------------------------------------------
struct HostData {
    std::vector<cn_ins_t> progs;      // nonces * CN_PROGRAM_SIZE
    std::vector<uint16_t> segs;       // nonces * CN_V7_SEGMENTS
    std::vector<uint8_t>  params;     // nonces * 4 (v5)
    std::vector<uint8_t>  salt;       // one shared 256 KB salt
};
static void build_host(HostData &h, size_t nonces) {
    h.progs.resize(nonces * CN_PROGRAM_SIZE);
    h.segs.resize(nonces * CN_V7_SEGMENTS);
    h.params.resize(nonces * 4);
    h.salt.resize(CN_SALT_MEMORY);
    SM64 r{ 0xC0FFEEULL };
    for (size_t i = 0; i < CN_SALT_MEMORY / 8; i++)
        ((uint64_t *)h.salt.data())[i] = r.next();
    for (size_t n = 0; n < nonces; n++) {
        vm_generate_program(&h.progs[n * CN_PROGRAM_SIZE], &h.segs[n * CN_V7_SEGMENTS], (uint64_t)n);
        SM64 p{ (uint64_t)n * 0x2545F4914F6CDD1DULL + 7 };
        h.params[n*4+0] = (uint8_t)p.u32(5);      // xx-4  in [0,4]
        h.params[n*4+1] = (uint8_t)p.u32(5);      // yy-4  in [0,4]
        h.params[n*4+2] = (uint8_t)p.u32(64);     // iters in [0,63]
        h.params[n*4+3] = (uint8_t)p.u32(3);      // init_size_blk selector
    }
}

static uint64_t g_fill_sink = 0;
static uint64_t cpu_one(const Variant &v, uint64_t gid, const HostData &h,
                        uint64_t *pad, uint64_t *side_vals, uint64_t *side_pad,
                        uint64_t *salt_priv, unsigned char *fill_buf)
{
    // Per-nonce chain salt, charged to the CPU ONLY. A GPU rig gets this from
    // its host at ~62 MB/s and under one core; a CPU miner pays it on the same
    // thread that hashes. Omitting it made the CPU column ~4x too fast on v5
    // (26k H/s here against 6.38k measured on the same 7950X). The OUTPUT is
    // discarded because the checksum gate needs both sides to hash identical
    // salts; only the COST is being modelled.
    chain_fill(fill_buf, v.gen, gid);
    g_fill_sink ^= fill_buf[0];

    const uint64_t qw = (uint64_t)v.pad_kb * 1024 / 8;
    if (v5_like(v.gen))
        return vm_v5(pad, qw, &h.params[gid * 4], salt_priv, CN_SALT_MEMORY / 8, g_rk, gid,
                     fp_mode_of(v.gen), (uint32_t)CN_V8_FP_ROUNDS * (uint32_t)g_fp_mult);
    if (v.gen == 6)
        return vm_v6(pad, qw, &h.progs[gid * CN_PROGRAM_SIZE], h.salt.data(), v6_iters(), g_rk, gid);
    return vm_v7(pad, qw, &h.progs[gid * CN_PROGRAM_SIZE], &h.segs[gid * CN_V7_SEGMENTS],
                 side_vals, side_pad, CN_V7_PAD_BYTES / 8,
                 v7_iters(v.pad_kb * 1024), g_rk, gid, h.salt.data());
}

static double cpu_bench(const Variant &v, const HostData &h, unsigned threads,
                        unsigned per, size_t gid_mod)
{
    const size_t padb = v.pad_kb * 1024;
    const int total = (int)(threads * per);
    std::atomic<uint64_t> sink(0);
    std::atomic<unsigned> ready(0);
    std::atomic<bool> go(false);
    std::atomic<int> remaining(total);
    auto worker = [&](unsigned t) {
        std::vector<uint64_t> pad(padb / 8);
        std::vector<uint64_t> vals(v.gen == 7 ? CN_V7_HOPS : 1);
        std::vector<uint64_t> spad(v.gen == 7 ? CN_V7_PAD_BYTES / 8 : 1);
        std::vector<uint64_t> salt(v5_like(v.gen) ? CN_SALT_MEMORY / 8 : 1);
        std::vector<unsigned char> fillb(SALT_BYTES);
        if (v5_like(v.gen)) memcpy(salt.data(), h.salt.data(), CN_SALT_MEMORY);
        uint64_t acc = 0;
        acc ^= cpu_one(v, t % gid_mod, h, pad.data(), vals.data(), spad.data(), salt.data(), fillb.data());
        ready++;
        while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
        unsigned i = 0;
        while (remaining.fetch_sub(1, std::memory_order_relaxed) > 0)
            acc ^= cpu_one(v, (t * 977 + (++i)) % gid_mod, h, pad.data(), vals.data(), spad.data(), salt.data(), fillb.data());
        sink ^= acc;
    };
    std::vector<std::thread> ts;
    for (unsigned t = 0; t < threads; t++) ts.emplace_back(worker, t);
    while (ready.load() < threads) std::this_thread::yield();
    const auto t0 = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto &t : ts) t.join();
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (sink.load() == 1) printf("");
    return secs > 0.0 ? total / secs : 0.0;
}

int main(int argc, char **argv) {
    if (argc > 1) { double p = atof(argv[1]); if (p >= 0.0 && p <= 95.0) g_vram_frac = p / 100.0; }
    if (argc > 2) { double c = atof(argv[2]); if (c >= 0.0 && c <= 120.0) g_cooldown = c; }
    if (argc > 3) { double L = atof(argv[3]); if (L >= 1.0 && L <= 600.0) g_launch_cap = L; }
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "all") == 0) g_all = true;
        else if (strncmp(argv[i], "fpx", 3) == 0) {
            const int mlt = atoi(argv[i] + 3);
            if (mlt >= 1 && mlt <= 100) g_fp_mult = mlt;
        }
    }
    for (int i = 0; i < MAXV; i++)
        if (ALL_VARIANTS[i].grp == 0 || g_all) VARIANTS[NV++] = ALL_VARIANTS[i];
    for (int i = 0; i < NV; i++) {
        g_gpu[i]=0; g_cpu[i]=0; g_ms1[i]=0; g_spread[i]=1.0; g_cspread[i]=1.0;
        g_nonces[i]=0; g_bufs[i]=0; g_verified[i]=0;
    }
    build_keys();
    chain_cache_init();

    CL cl; bool have_gpu = (g_vram_frac > 0.0) && cl_load(cl);
    cl_context ctx = NULL; cl_command_queue q = NULL; cl_program prog = NULL;
    cl_device_id dev = NULL; cl_ulong gmem = 0, maxalloc = 0;
    char devname[256]; char drv[128]; cl_uint cus = 0, mhz = 0;
    memset(devname, 0, sizeof(devname)); memset(drv, 0, sizeof(drv));

    if (have_gpu) {
        cl_uint nplat = 0; cl.GetPlatformIDs(0, NULL, &nplat);
        std::vector<cl_platform_id> plats(nplat ? nplat : 1);
        if (nplat) cl.GetPlatformIDs(nplat, plats.data(), NULL);
        // Pick the device with the most compute units, not simply the first.
        // On a Ryzen desktop the first GPU is usually the integrated one.
        // Prefer a DISCRETE GPU, then the most compute units among those.
        // Ranking purely by compute units compares incomparable things: an
        // Intel HD 630 reports 24 EUs and a GTX 1050 Ti reports 6 SMs, so the
        // old heuristic picked the integrated chip and benchmarked it instead
        // of the discrete card. CL_DEVICE_HOST_UNIFIED_MEMORY is true exactly
        // for integrated parts, which is the distinction that matters.
        long long best_score = -1;
        for (cl_uint p = 0; p < nplat; p++) {
            cl_uint nd = 0;
            if (cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 0, NULL, &nd) != CL_SUCCESS || !nd) continue;
            std::vector<cl_device_id> ds(nd); cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, nd, ds.data(), NULL);
            for (cl_uint d = 0; d < nd; d++) {
                cl_uint c = 0; cl.GetDeviceInfo(ds[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(c), &c, NULL);
                cl_uint uni = 0; cl.GetDeviceInfo(ds[d], CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof(uni), &uni, NULL);
                const long long score = (uni ? 0LL : 1000000LL) + (long long)c;
                if (score > best_score) { best_score = score; dev = ds[d]; }
            }
        }
        if (dev) {
            cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(maxalloc), &maxalloc, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(mhz), &mhz, NULL);
            cl.GetDeviceInfo(dev, CL_DEVICE_VERSION, sizeof(drv), drv, NULL);
            cl_int err = 0;
            ctx = cl.CreateContext(NULL, 1, &dev, NULL, NULL, &err);
            q = cl.CreateCommandQueue(ctx, dev, 0, &err);
            const char *src = VM_KERNEL_SRC; size_t sl = strlen(src);
            prog = cl.CreateProgramWithSource(ctx, 1, &src, &sl, &err);
            if (cl.BuildProgram(prog, 1, &dev, "-cl-std=CL1.2", NULL, NULL) != CL_SUCCESS) {
                size_t n = 0; cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, NULL, &n);
                std::string log(n, 0); cl.GetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, n, &log[0], NULL);
                printf("Kernel build failed:\n%s\n", log.c_str()); have_gpu = false;
            }
        } else have_gpu = false;
    }

    g_load = sys_busy(500);
    g_tty = _isatty(_fileno(stdout)) != 0;
    unsigned hw = std::thread::hardware_concurrency(); if (!hw) hw = 4;

    printf("NERVA PoW BENCH   real VM cores, same work both sides\n");
    printf("CPU  %.50s  (%u thr)\n", cpu_brand().c_str(), hw);
    if (g_load >= 0.0) {
        printf("LOAD %.0f%% CPU busy before the run%s\n", g_load,
               g_load > 8.0 ? "   <-- STOP MINERS AND CLOSE THE BROWSER" : "");
        if (g_load > 8.0)
            printf("     the CPU columns measure this machine against whatever else is\n"
                   "     running on it, so they are not comparable with a clean run\n");
    }
    if (have_gpu)
        printf("GPU  %.28s %.1fG/%.1fG %uCU  vram=%d%% cap=%.0fs cool=%.0fs\n", devname,
               gmem / 1073741824.0, maxalloc / 1073741824.0, cus,
               (int)(g_vram_frac * 100.0 + 0.5), g_launch_cap, g_cooldown);
    else
        printf("GPU  none usable, CPU columns only\n");
    if (g_fp_mult != 1)
        printf("     fpx%d: FP stage at %d rounds, %dx the real count\n",
               g_fp_mult, CN_V8_FP_ROUNDS * g_fp_mult, g_fp_mult);
    printf("\n");

    cl_mem te_buf = NULL, rk_buf = NULL;
    if (have_gpu) {
        unsigned int te0[256];
        for (int i = 0; i < 256; i++) { unsigned char sb = SBOX[i], s2 = xt8(sb), s3 = (unsigned char)(s2 ^ sb);
            te0[i] = ((unsigned)s2) | ((unsigned)sb << 8) | ((unsigned)sb << 16) | ((unsigned)s3 << 24); }
        cl_int e2 = 0;
        te_buf = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(te0), NULL, &e2);
        rk_buf = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(g_rkh), NULL, &e2);
        cl.EnqueueWriteBuffer(q, te_buf, CL_TRUE, 0, sizeof(te0), te0, 0, NULL, NULL);
        cl.EnqueueWriteBuffer(q, rk_buf, CL_TRUE, 0, sizeof(g_rkh), g_rkh, 0, NULL, NULL);
    }

    HostData host;
    std::vector<uint64_t> gpu_out;

    // Records why a GPU row produced nothing. Silence here cost a whole RX 580
    // run: every row printed a dash and the output said nothing about why.
    #define WHY(...) snprintf(g_why[gi], sizeof(g_why[gi]), __VA_ARGS__)
    if (have_gpu) {
        for (int gi = 0; gi < NV; gi++) {
            const Variant &v = VARIANTS[gi];
            progress("GPU", v.name, gi + 1, NV);
            const size_t padb = v.pad_kb * 1024ull;
            const cl_ulong qw = padb / 8;
            const size_t sideb = side_bytes(v.gen);
            size_t budget = (size_t)(gmem * g_vram_frac);

            // Cap the nonce count by TOTAL per-nonce memory, not just the pad.
            // v5 keeps a 256 KB salt resident per nonce and v7 needs a 256 KB
            // pad plus 8 KB of chased values, so budgeting on the pad alone
            // would oversubscribe VRAM, which is exactly what made the Vega
            // read 7x slow above 55%.
            size_t cap_nonces = budget / (padb + sideb);
            if (cap_nonces < 1) { WHY("VRAM too small for even one nonce"); continue; }

            const size_t MAXBUF = 4;
            size_t nbuf = 1;
            size_t padbudget = cap_nonces * padb;
            while (nbuf < MAXBUF && padbudget / nbuf > (size_t)maxalloc) nbuf++;
            size_t chunk = padbudget / nbuf;
            if (chunk > (size_t)maxalloc) chunk = (size_t)maxalloc;
            size_t per_buf = chunk / padb;
            if (per_buf < 1) { WHY("no pad fits in one allocation"); continue; }

            cl_int err = 0;
            cl_mem bl[MAXBUF] = { NULL, NULL, NULL, NULL };
            size_t got = 0;
            for (size_t b = 0; b < nbuf; b++) {
                bl[b] = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, per_buf * padb, NULL, &err);
                if (err != CL_SUCCESS || bl[b] == NULL) { bl[b] = NULL; break; }
                got++;
            }
            if (got == 0) { WHY("VRAM allocation refused by the driver"); continue; }
            nbuf = got;
            for (size_t b = nbuf; b < MAXBUF; b++) bl[b] = bl[0];
            size_t nonces = nbuf * per_buf;
            if (nonces > cap_nonces) nonces = cap_nonces;
            size_t lws = 64;
            while (lws > 1 && nonces < lws * 4) lws /= 2;
            nonces = (nonces / lws) * lws;
            if (nonces < 1) { WHY("fewer nonces than one work group");
                              for (size_t b=0;b<nbuf;b++) cl.ReleaseMemObject(bl[b]); continue; }

            if (host.progs.size() < nonces * CN_PROGRAM_SIZE) build_host(host, nonces);

            cl_mem out = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, nonces * 8, NULL, &err);
            cl_mem progs_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, nonces * CN_PROGRAM_SIZE * sizeof(cn_ins_t), NULL, &err);
            cl.EnqueueWriteBuffer(q, progs_b, CL_TRUE, 0, nonces * CN_PROGRAM_SIZE * sizeof(cn_ins_t), host.progs.data(), 0, NULL, NULL);
            cl_mem salt_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, CN_SALT_MEMORY, NULL, &err);
            cl.EnqueueWriteBuffer(q, salt_b, CL_TRUE, 0, CN_SALT_MEMORY, host.salt.data(), 0, NULL, NULL);
            cl_mem segs_b = NULL, vals_b = NULL, spad_b = NULL, params_b = NULL, salts_b = NULL;
            if (v.gen == 7) {
                segs_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, nonces * CN_V7_SEGMENTS * 2, NULL, &err);
                cl.EnqueueWriteBuffer(q, segs_b, CL_TRUE, 0, nonces * CN_V7_SEGMENTS * 2, host.segs.data(), 0, NULL, NULL);
                vals_b = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, nonces * CN_V7_HOPS * 8, NULL, &err);
                spad_b = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, nonces * (size_t)CN_V7_PAD_BYTES, NULL, &err);
            }
            if (v5_like(v.gen)) {
                params_b = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, nonces * 4, NULL, &err);
                cl.EnqueueWriteBuffer(q, params_b, CL_TRUE, 0, nonces * 4, host.params.data(), 0, NULL, NULL);
                salts_b = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, nonces * (size_t)CN_SALT_MEMORY, NULL, &err);
            }
            if (err != CL_SUCCESS) {
                WHY("side buffer creation failed, CL %d", (int)err);
                if (out) cl.ReleaseMemObject(out);
                for (size_t b=0;b<nbuf;b++) cl.ReleaseMemObject(bl[b]);
                continue;
            }

            const char *kname = v.gen == 5 ? "cna_v5"
                              : v.gen == 6 ? "cna_v6"
                              : v.gen == 7 ? "cna_v7"
                              : v.gen == 8 ? "cna_v8"
                              : v.gen == 9 ? "cna_v8_fp_rne" : "cna_v8_fp";
            cl_kernel k = cl.CreateKernel(prog, kname, &err);
            // A device without cl_khr_fp64 builds the rest of the program fine and
            // simply has no FP kernels, so the row is skipped rather than the run
            // being lost. g_missing records it for the footnote.
            if (!k || err != CL_SUCCESS) {
                WHY("kernel %s missing%s", kname,
                    v.gen >= 9 ? " (no cl_khr_fp64?)" : "");
                if (v.gen >= 9) g_no_fp64 = true;
                cl.ReleaseMemObject(out); cl.ReleaseMemObject(progs_b);
                cl.ReleaseMemObject(salt_b);
                if (params_b) cl.ReleaseMemObject(params_b);
                if (salts_b) cl.ReleaseMemObject(salts_b);
                for (size_t b = 0; b < nbuf; b++) cl.ReleaseMemObject(bl[b]);
                continue;
            }
            cl_uint a = 0;
            cl_uint prog_size = CN_PROGRAM_SIZE;
            cl_uint iters = v.gen == 6 ? v6_iters() : v.gen == 7 ? v7_iters(padb) : 0;
            cl_uint hops = CN_V7_HOPS, segments = CN_V7_SEGMENTS;
            cl_uint pad_qw = CN_V7_PAD_BYTES / 8;
            cl_uint salt_qw = CN_SALT_MEMORY / 8;
            cl_uint pb = (cl_uint)per_buf;
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[0]);
            cl.SetKernelArg(k, a++, sizeof(cl_ulong), &qw);
            if (v5_like(v.gen)) {
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &params_b);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &salts_b);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &salt_qw);
            } else if (v.gen == 6) {
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &progs_b);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &prog_size);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &iters);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &salt_b);
            } else {
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &progs_b);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &prog_size);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &iters);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &segs_b);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &salt_b);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &vals_b);
                cl.SetKernelArg(k, a++, sizeof(cl_mem), &spad_b);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &hops);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &segments);
                cl.SetKernelArg(k, a++, sizeof(cl_uint), &pad_qw);
            }
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &te_buf);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &rk_buf);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &out);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[1]);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[2]);
            cl.SetKernelArg(k, a++, sizeof(cl_mem), &bl[3]);
            cl.SetKernelArg(k, a++, sizeof(cl_uint), &pb);
            const cl_uint fp_rounds = (cl_uint)CN_V8_FP_ROUNDS * (cl_uint)g_fp_mult;
            if (v.gen >= 8) cl.SetKernelArg(k, a++, sizeof(cl_uint), &fp_rounds);

            // Zero the output so a failed launch cannot pass the guard below.
            { std::vector<uint64_t> z(nonces, 0);
              cl.EnqueueWriteBuffer(q, out, CL_TRUE, 0, nonces * 8, z.data(), 0, NULL, NULL); }

            // Sweep the nonce count SMALLEST FIRST, and refuse any launch
            // projected to run longer than LAUNCH_CAP.
            //
            // Largest-first froze a Vega box mid-run: fan spun up, monitor
            // went blank. A single launch of v5 at 8 MB takes ~93 s at 50%
            // VRAM here, because v5 does ~30 full-pad sweeps per nonce at
            // BYTE stride, which on a GPU means non-coalesced byte
            // read-modify-writes. Windows kills any GPU command over ~2 s
            // (TDR), and on a display-attached card the driver reset takes
            // the desktop with it. Chunking cannot help: an in-order queue
            // runs one kernel at a time, so short chunks starve the device
            // (tried and reverted earlier in this harness).
            //
            // So: start small, measure, extrapolate, and only go larger if
            // the projection fits under the cap. A row that gets capped
            // reports the largest count the card could safely run, which is
            // an honest statement of what it managed rather than a hang.
            // A TINY PROBE FIRST, then the ramp. LAUNCH_CAP cannot protect the
            // first launch, because the projection needs a rate from a completed
            // one, and the first launch is exactly where a card with a 2 s display
            // watchdog dies: nmax/4 is already several seconds on a mid-range card.
            // An RX 580 produced no rows at all this way, and the run after it could
            // not create a context, which is what a driver reset looks like.
            //
            // The probe is timed only to seed the projection and is never reported:
            // a launch that small is starved, and its rate is not the card's rate.
            const double LAUNCH_CAP = g_launch_cap;
            const size_t nmax = nonces;
            size_t cands[4] = { lws * 8, nmax / 4, nmax / 2, nmax };
            double best = 0.0, worst = 0.0;
            bool ok = true;
            size_t best_n = 0;
            double rate = 0.0;                 // nonces/sec from the previous launch
            cl_int lerr = CL_SUCCESS;
            size_t last_ok = 0;                // largest launch that completed
            for (int c = 0; c < 4 && ok; c++) {
                size_t n = (cands[c] / lws) * lws;
                if (n < lws || n > nmax) continue;
                if (c > 0 && rate > 0.0 && (double)n / rate > LAUNCH_CAP) break;
                const auto t0 = std::chrono::steady_clock::now();
                lerr = cl.EnqueueNDRangeKernel(q, k, 1, NULL, &n, &lws, 0, NULL, NULL);
                if (lerr != CL_SUCCESS) { ok = false; break; }
                lerr = cl.Finish(q);
                if (lerr != CL_SUCCESS) { ok = false; break; }
                const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                if (secs <= 0.0) continue;
                rate = n / secs;
                last_ok = n;
                if (c > 0 && rate > best) { best = rate; best_n = n; }
            }
            if (!ok)
                WHY("ramp failed after %zu nonces ok, CL %d (watchdog?)",
                    last_ok, (int)lerr);
            else if (best_n == 0)
                WHY("every launch projected over the %.0fs cap", LAUNCH_CAP);
            if (best_n == 0) ok = false;
            best = 0.0;
            for (int rep = 0; rep < GPU_REPS && ok; rep++) {
                const auto t0 = std::chrono::steady_clock::now();
                lerr = cl.EnqueueNDRangeKernel(q, k, 1, NULL, &best_n, &lws, 0, NULL, NULL);
                if (lerr != CL_SUCCESS) {
                    WHY("timed rep %d of %zu failed, CL %d (watchdog?)", rep + 1,
                        best_n, (int)lerr);
                    ok = false; break;
                }
                lerr = cl.Finish(q);
                if (lerr != CL_SUCCESS) {
                    WHY("timed rep %d of %zu did not finish, CL %d (watchdog?)", rep + 1,
                        best_n, (int)lerr);
                    ok = false; break;
                }
                const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                if (secs <= 0.0) continue;
                const double hs = best_n / secs;
                if (hs > best) best = hs;
                if (worst == 0.0 || hs < worst) worst = hs;
            }
            nonces = best_n;
            gpu_out.assign(nonces, 0);
            const cl_int rerr = cl.EnqueueReadBuffer(q, out, CL_TRUE, 0, nonces * 8,
                                                     gpu_out.data(), 0, NULL, NULL);
            size_t unwritten = 0;
            for (uint64_t x : gpu_out) if (x == 0) unwritten++;
            const double sp = (worst > 0.0) ? (best / worst) : 1.0;
            if (ok && rerr != CL_SUCCESS)
                WHY("could not read results back, CL %d", (int)rerr);
            else if (ok && unwritten > 0)
                WHY("%zu of %zu nonces unwritten, kernel claimed %.0f n/s", unwritten,
                    nonces, best);
            else if (ok && best <= 0.0)
                WHY("every timed launch returned a zero duration");
            if (ok && unwritten == 0 && best > 0.0) {
                g_gpu[gi] = best; g_nonces[gi] = nonces; g_bufs[gi] = nbuf; g_spread[gi] = sp;

                // CHECKSUM GATE. Recompute a sample of nonces on the CPU and
                // compare. The GPU kernel and the C reference are two hand
                // written copies of the same algorithm; without this there is
                // nothing stopping them drifting, and a drifted pair produces a
                // confident wrong ratio. A row that fails is reported as such,
                // never as a number.
                progress("VERIFY", v.name, gi + 1, NV);
                std::vector<uint64_t> pad(padb / 8);
                std::vector<uint64_t> vals(v.gen == 7 ? CN_V7_HOPS : 1);
                std::vector<uint64_t> spadv(v.gen == 7 ? CN_V7_PAD_BYTES / 8 : 1);
                std::vector<uint64_t> saltv(CN_SALT_MEMORY / 8);
                std::vector<unsigned char> fillbv(SALT_BYTES);
                memcpy(saltv.data(), host.salt.data(), CN_SALT_MEMORY);
                int bad = 0;
                const size_t nchk = nonces < 4 ? nonces : 4;
                for (size_t s = 0; s < nchk; s++) {
                    const uint64_t gidv = (uint64_t)(s * (nonces / nchk));
                    if (v5_like(v.gen)) memcpy(saltv.data(), host.salt.data(), CN_SALT_MEMORY);
                    const uint64_t cref = cpu_one(v, gidv, host, pad.data(), vals.data(), spadv.data(), saltv.data(), fillbv.data());
                    if (cref != gpu_out[gidv]) bad++;
                }
                g_verified[gi] = bad ? -1 : 1;
            }
            // Same buffers, same args, same instruction count, but the pad
            // accesses become ALU work. The gap is the memory share, which
            // bounds how much any JIT could ever win here.
            if (v.gen == 6 && v.pad_kb == 8192 && ok && best > 0.0) {
                cl_int ae = 0;
                cl_kernel ka = cl.CreateKernel(prog, "cna_v6_ideal", &ae);
                if (ka && ae == CL_SUCCESS) {
                    cl_uint b = 0;
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &bl[0]);
                    cl.SetKernelArg(ka, b++, sizeof(cl_ulong), &qw);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &progs_b);
                    cl.SetKernelArg(ka, b++, sizeof(cl_uint), &prog_size);
                    cl.SetKernelArg(ka, b++, sizeof(cl_uint), &iters);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &salt_b);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &te_buf);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &rk_buf);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &out);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &bl[1]);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &bl[2]);
                    cl.SetKernelArg(ka, b++, sizeof(cl_mem), &bl[3]);
                    cl.SetKernelArg(ka, b++, sizeof(cl_uint), &pb);
                    double bestalu = 0.0;
                    for (int rep = 0; rep < GPU_REPS; rep++) {
                        const auto ta = std::chrono::steady_clock::now();
                        if (cl.EnqueueNDRangeKernel(q, ka, 1, NULL, &nonces, &lws, 0, NULL, NULL) != CL_SUCCESS) break;
                        if (cl.Finish(q) != CL_SUCCESS) break;
                        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - ta).count();
                        if (s > 0.0) { const double h = nonces / s; if (h > bestalu) bestalu = h; }
                    }
                    if (bestalu > 0.0) { g_alu_full = best; g_alu_only = bestalu; }
                    cl.ReleaseKernel(ka);
                }
            }
            cl.ReleaseKernel(k); cl.ReleaseMemObject(out);
            cl.ReleaseMemObject(progs_b); cl.ReleaseMemObject(salt_b);
            if (segs_b) cl.ReleaseMemObject(segs_b);
            if (vals_b) cl.ReleaseMemObject(vals_b);
            if (spad_b) cl.ReleaseMemObject(spad_b);
            if (params_b) cl.ReleaseMemObject(params_b);
            if (salts_b) cl.ReleaseMemObject(salts_b);
            for (size_t b = 0; b < nbuf; b++) cl.ReleaseMemObject(bl[b]);
            // Cool down before the next variant. A display-attached card under
            // sustained compute heat-soaks and can drop the display; this is the
            // only mitigation short of running it headless. Separate from
            // LAUNCH_CAP, which covers the TDR watchdog (per-command duration).
            if (g_cooldown > 0.0 && gi + 1 < NV) {
                progress("COOL", VARIANTS[gi].name, gi + 1, NV);
                std::this_thread::sleep_for(
                    std::chrono::milliseconds((long long)(g_cooldown * 1000.0)));
            }
        }
    }

    if (host.progs.empty()) build_host(host, 256);
    const size_t gid_mod = host.progs.size() / CN_PROGRAM_SIZE;

    // THE VARIANTS ARE MEASURED INTERLEAVED, not one at a time to completion.
    //
    // The FP stage costs a CPU a few percent of a whole nonce, and a 7950X
    // drifts by more than that over the minutes it takes to finish a row. Run
    // to completion, the baseline and the FP row are measured in different
    // thermal states and the difference between them is mostly drift: that
    // read 2.0% run spread against a 4% effect, which is not a measurement.
    // Interleaving puts every variant in the same few seconds, so drift moves
    // them together and cancels in the ratio. Best-of across rounds then
    // handles scheduling jitter, which interleaving does not help with.
    std::vector<unsigned> per(NV, 1);
    std::vector<double> bw(NV, 0.0);       // worst seen, for the spread

    // Pass 1: calibrate the rep length and pick a thread count per variant.
    // One rep per candidate; the peak matters, not its precision. Pinning this
    // to hardware_concurrency understates the CPU, because the memory-bound
    // variants top out well below all-threads once the pads stop fitting in L3,
    // and an understated CPU inflates GPU:CPU.
    for (int ci = 0; ci < NV; ci++) {
        const Variant &v = VARIANTS[ci];
        progress("CPU thr", v.name, ci + 1, NV);
        const double one = cpu_bench(v, host, 1, 1, gid_mod);
        const double ms = one > 0.0 ? 1000.0 / one : 1000.0;
        // 1000 ms per rep, not 400. A 32-thread memory-bound window that short
        // still has boost and thermal transitions in it, and the FP effect being
        // measured is about 5%: at 400 ms the run spread on these rows reached 19%.
        unsigned pr = (unsigned)(1000.0 / (ms > 0.001 ? ms : 0.001));
        if (pr < 1) pr = 1;
        if (pr > 1000) pr = 1000;
        per[ci] = pr;
        unsigned cand[4] = { hw, hw * 3 / 4, hw / 2, hw / 4 };
        unsigned bestthr = hw; double bestv = 0.0;
        for (int c = 0; c < 4; c++) {
            if (cand[c] < 1) continue;
            const double got = cpu_bench(v, host, cand[c], per[ci], gid_mod);
            if (got > bestv) { bestv = got; bestthr = cand[c]; }
        }
        g_thr[ci] = bestthr;
    }

    // Pass 2: multi-threaded, interleaved, best-of, ORDER REVERSED EVERY OTHER
    // ROUND. Interleaving alone leaves a systematic error: with a fixed order the
    // baseline is always measured before the FP rows within each cycle, so any
    // sawtooth in clocks across a cycle lands on the baseline's side every time
    // and inflates the FP cost. Reversing cancels a monotonic drift to first
    // order. Without it the baseline once read 11351 H/s against a 9900 H/s
    // norm, 19% run spread, and carried the whole verdict with it.
    for (int rep = 0; rep < CPU_REPS; rep++)
        for (int z = 0; z < NV; z++) {
            const int ci = (rep & 1) ? (NV - 1 - z) : z;
            progress("CPU", VARIANTS[ci].name, rep * NV + z + 1, CPU_REPS * NV);
            const double hs = cpu_bench(VARIANTS[ci], host, g_thr[ci], per[ci], gid_mod);
            if (hs <= 0.0) continue;
            if (hs > g_cpu[ci]) g_cpu[ci] = hs;
            if (bw[ci] == 0.0 || hs < bw[ci]) bw[ci] = hs;
        }
    for (int ci = 0; ci < NV; ci++)
        if (bw[ci] > 0.0 && g_cpu[ci] > 0.0) g_cspread[ci] = g_cpu[ci] / bw[ci];

    // Pass 3: single thread, interleaved and reversed the same way.
    std::vector<double> h1(NV, 0.0);
    for (int rep = 0; rep < CPU_REPS; rep++)
        for (int z = 0; z < NV; z++) {
            const int ci = (rep & 1) ? (NV - 1 - z) : z;
            progress("CPU 1T", VARIANTS[ci].name, rep * NV + z + 1, CPU_REPS * NV);
            const double hs = cpu_bench(VARIANTS[ci], host, 1, per[ci], gid_mod);
            if (hs > h1[ci]) h1[ci] = hs;
        }
    for (int ci = 0; ci < NV; ci++)
        g_ms1[ci] = h1[ci] > 0.0 ? 1000.0 / h1[ci] : 0.0;
    progress_clear();

    if (have_gpu) {
        int any = 0;
        for (int i = 0; i < NV; i++) if (g_gpu[i] <= 0.0 && g_why[i][0]) any++;
        if (any) {
            printf("GPU rows with no result:\n");
            for (int i = 0; i < NV; i++)
                if (g_gpu[i] <= 0.0 && g_why[i][0])
                    printf("  %-11s %s\n", VARIANTS[i].name, g_why[i]);
            printf("\n");
        }
    }
    printf("VARIANT       KB  nonces  ok   GPU H/s thr    CPU H/s   GPU:CPU    1T ms\n");
    for (int i = 0; i < NV; i++) {
        printf("%-11s %5zu", VARIANTS[i].name, VARIANTS[i].pad_kb);
        if (g_gpu[i] > 0.0) printf(" %7zu %3s %9.1f%s", g_nonces[i],
                                   g_verified[i] == 1 ? "yes" : "NO", g_gpu[i],
                                   g_spread[i] > 1.10 ? "!" : " ");
        else                printf(" %7s %3s %9s ", "-", "-", "-");
        printf(" %3u %9.1f%s", g_thr[i], g_cpu[i], g_cspread[i] > 1.10 ? "!" : " ");
        if (g_gpu[i] > 0.0 && g_verified[i] == 1) printf(" %7.4fx", g_gpu[i] / g_cpu[i]);
        else                                      printf(" %8s", "-");
        printf(" %8.2f\n", g_ms1[i]);
    }

    // ---- the Phase 2 FP question ----------------------------------------
    // What the floating-point stage costs each side, as a multiple of the v8
    // baseline. The modelling caveats that limit the absolute GPU:CPU column
    // (extra_hash replaced by mix64, chain salt charged only to the CPU) cancel
    // in these ratios, because numerator and denominator differ by the stage and
    // by nothing else. That is why this block is worth more than the column.
    {
        int ib = -1, ir = -1, im = -1, ic = -1, ic2 = -1;
        for (int i = 0; i < NV; i++) {
            if (VARIANTS[i].gen == 8)  ib = i;
            if (VARIANTS[i].gen == 9)  ir = i;
            if (VARIANTS[i].gen == 10) im = i;
            if (VARIANTS[i].gen == 5 && VARIANTS[i].pad_kb == 1024) {
                if (ic < 0) ic = i; else ic2 = i;
            }
        }
        // Divide the measured cost back down to one round count. Linear in the
        // count on both sides, checked at 1x and 10x.
        auto cost = [&](const double *arr, int i) {
            if (!(ib >= 0 && i >= 0 && arr[i] > 0.0 && arr[ib] > 0.0)) return 0.0;
            return 1.0 + (arr[ib] / arr[i] - 1.0) / (double)g_fp_mult;
        };
        auto fmt = [](char *b, double x) {
            if (x > 0.0) snprintf(b, 12, "%6.3fx", x); else snprintf(b, 12, "%7s", "-");
        };
        char c1[12], c2[12], c3[12], c4[12];
        fmt(c1, cost(g_gpu, ir)); fmt(c2, cost(g_cpu, ir));
        fmt(c3, cost(g_gpu, im)); fmt(c4, cost(g_cpu, im));
        printf("FP cost x v8 base   rne GPU %s CPU %s | modes GPU %s CPU %s%s\n",
               c1, c2, c3, c4, g_fp_mult != 1 ? "  (scaled back from fpx)" : "");
        if (ib >= 0 && im >= 0 && g_gpu[ib] > 0.0 && g_gpu[im] > 0.0 &&
            g_cpu[ib] > 0.0 && g_cpu[im] > 0.0 && g_verified[ib] == 1 && g_verified[im] == 1) {
            const double r0 = g_gpu[ib] / g_cpu[ib];
            const double r1 = r0 * cost(g_cpu, im) / cost(g_gpu, im);
            // r1 == r0 * cpu_cost / gpu_cost, both being multipliers on a rate.
            //
            // The CPU cost has to be the stage as a share of a WHOLE nonce, chain
            // fill included, and the harness charges that fill per nonce because
            // consensus does: get_block_longhash_v14 seeds HC128 from the blob hash
            // and the blob carries the nonce, so get_cna_v6_data runs on every nonce
            // for miner and verifier alike. F34's +14.5 to +18.2% is the stage
            // against cn_slow_hash alone, which is the right number for verify cost
            // and the wrong denominator here. An earlier version of this line used it
            // and overstated the effect about threefold.
            //
            // The worst run spread over these rows goes beside the verdict, because
            // the GPU effect is around 1% and so is the noise.
            double sg = 0.0, sc = 0.0;
            const int fprows[3] = { ib, ir, im };
            for (int z = 0; z < 3; z++) {
                const int j = fprows[z];
                if (j < 0) continue;
                if (g_spread[j]  > 1.0 + sg) sg = g_spread[j]  - 1.0;
                if (g_cspread[j] > 1.0 + sc) sc = g_cspread[j] - 1.0;
            }
            printf("GPU:CPU %.4fx -> %.4fx, FP %s by %.0f%%   spread GPU %.1f%% CPU %.1f%%\n",
                   r0, r1, r1 < r0 ? "HELPS" : "HURTS",
                   100.0 * (r1 > r0 ? r1 - r0 : r0 - r1) / r0, 100.0 * sg, 100.0 * sc);
            // The GPU rows are NOT interleaved (each needs its own buffers), so the
            // within-row spread above understates their real uncertainty: v8 and
            // v8+fp are measured a minute apart. v5 1MB and v8 1MB are identical GPU
            // work, so the gap between them IS that cross-row reproducibility,
            // measured rather than assumed. The FP effect has to clear it to mean
            // anything, and on the GPU the two are within about a factor of two.
            // THREE rows of identical GPU work, one before the FP rows and one
            // after, so the floor brackets them instead of leading them. Measured
            // only between the first two, the control read 0.02% on a run whose FP
            // rows were visibly noise, because drift that accumulates by rows 3 and
            // 4 cannot show up in a comparison of rows 1 and 2.
            double ctl = 0.0;
            const int ctls[3] = { ic, ib, ic2 };
            for (int x = 0; x < 3; x++)
                for (int y = x + 1; y < 3; y++) {
                    const int u = ctls[x], w = ctls[y];
                    if (u < 0 || w < 0 || g_gpu[u] <= 0.0 || g_gpu[w] <= 0.0) continue;
                    const double d = (g_gpu[u] > g_gpu[w] ? g_gpu[u] - g_gpu[w]
                                                          : g_gpu[w] - g_gpu[u]) / g_gpu[w];
                    if (d > ctl) ctl = d;
                }
            // Scaled by fp_mult exactly as the costs above are, or the two are not
            // comparable: at fpx10 a raw 4.0% FP gap against a raw 1.1% drift floor
            // printed as "1.004x" against "1.14%" and read as though the effect were
            // under the floor, when it is 3.5x above it.
            if (ctl > 0.0)
                printf("control: %.3f%% drift between rows of identical GPU work, one\n"
                       "         after the FP rows. Same scale as the costs above\n",
                       100.0 * ctl / (double)g_fp_mult);
        }
        if (g_no_fp64)
            printf("no cl_khr_fp64 here, so the FP rows could not run.\n");
    }
    // ---- v5 sweep bound -------------------------------------------------
    // How much an optimising GPU miner could gain on v5's salt_pad sweeps,
    // the only part of v5 with no loop-carried dependency and therefore the
    // only part anyone can restructure. Both kernels apply identical XORs;
    // sweep_vec just folds every hit inside an 8-byte word into one load and
    // store instead of doing a byte read-modify-write per hit.
    if (have_gpu && g_all) {
        cl_int se = 0;
        const size_t sp_bytes = 8ull * 1024 * 1024;
        const size_t sp_n = 64;
        const cl_uint sp_sweeps = 4;
        cl_mem spads = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_HOST_NO_ACCESS, sp_n * sp_bytes, NULL, &se);
        cl_mem ssalt = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, CN_SALT_MEMORY, NULL, &se);
        cl_mem sout  = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, sp_n * 8, NULL, &se);
        if (se == CL_SUCCESS && spads && ssalt && sout) {
            std::vector<unsigned char> sb(CN_SALT_MEMORY);
            SM64 rr{ 0xBEEFULL };
            for (size_t i = 0; i < CN_SALT_MEMORY / 8; i++) ((uint64_t *)sb.data())[i] = rr.next();
            cl.EnqueueWriteBuffer(q, ssalt, CL_TRUE, 0, CN_SALT_MEMORY, sb.data(), 0, NULL, NULL);
            const cl_ulong pb2 = sp_bytes;
            double tn = 0.0, tv = 0.0;
            const char *kn[2] = { "sweep_naive", "sweep_vec" };
            for (int which = 0; which < 2; which++) {
                cl_kernel ks = cl.CreateKernel(prog, kn[which], &se);
                if (!ks || se != CL_SUCCESS) break;
                cl_uint z = 0;
                cl.SetKernelArg(ks, z++, sizeof(cl_mem), &spads);
                cl.SetKernelArg(ks, z++, sizeof(cl_ulong), &pb2);
                cl.SetKernelArg(ks, z++, sizeof(cl_mem), &ssalt);
                cl.SetKernelArg(ks, z++, sizeof(cl_uint), &sp_sweeps);
                cl.SetKernelArg(ks, z++, sizeof(cl_mem), &sout);
                size_t gsz = sp_n, lsz = 64;
                double bestt = 1e30;
                for (int rep = 0; rep < 2; rep++) {
                    const auto t0 = std::chrono::steady_clock::now();
                    if (cl.EnqueueNDRangeKernel(q, ks, 1, NULL, &gsz, &lsz, 0, NULL, NULL) != CL_SUCCESS) break;
                    if (cl.Finish(q) != CL_SUCCESS) break;
                    const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                    if (s > 0.0 && s < bestt) bestt = s;
                }
                if (bestt < 1e29) { if (which == 0) tn = bestt; else tv = bestt; }
                cl.ReleaseKernel(ks);
            }
            if (tn > 0.0 && tv > 0.0) g_sweep_ratio = tn / tv;
        }
        if (spads) cl.ReleaseMemObject(spads);
        if (ssalt) cl.ReleaseMemObject(ssalt);
        if (sout)  cl.ReleaseMemObject(sout);
    }
    if (g_all && (g_sweep_ratio > 0.0 || g_alu_full > 0.0))
        printf("v5 sweep opt %.1fx | JIT ceiling %.2fx (v6/v7 only, v5 has no program)\n",
               g_sweep_ratio > 0.0 ? g_sweep_ratio : 1.0,
               g_alu_full > 0.0 ? g_alu_only / g_alu_full : 1.0);
    printf("ok = GPU matched CPU; on v8+fp that proves OpenCL's software rounding is\n"
           "bit-exact against a real MXCSR. No ok, no ratio. Lower GPU:CPU is better.\n"
           "CPU cost is per whole nonce, chain fill included: that is what a miner\n"
           "pays, since the salt is reseeded from the nonce. v5/v8 1MB are the same\n"
           "GPU work, so a gap there is the port, not the algorithm.\n");

    if (have_gpu) { cl.ReleaseProgram(prog); cl.ReleaseCommandQueue(q); cl.ReleaseContext(ctx); }
    return 0;
}
