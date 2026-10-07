/* Random reads per second into the block cache, CPU against GPU.
 *
 * WHY THIS IS THE QUESTION. PLAN-v8-PHASE8 D5 proposes chaining the fill's
 * reads so each index comes from the bytes at the previous one. The objection
 * recorded against it is that a dependent chain serialises ONE nonce, while an
 * attacker runs thousands at once and hides the latency completely, so the
 * lever might cost the honest CPU more than the attacker.
 *
 * That objection resolves to one number. Each nonce needs 16,384 reads of the
 * block cache whatever the design, so for every device
 *
 *     nonces/s = (random reads/s into the cache) / 16384
 *
 * Latency only matters until a device has enough chains in flight to cover it.
 * After that both sides are bound by the same thing: how many random reads the
 * memory system delivers per second. So the comparison is each device at ITS
 * achievable concurrency, which is what this measures.
 *
 * It also answers the half of B3 that matters most, without needing anyone's
 * opinion on what a card can do: the table is the block cache, the access
 * pattern is the fill's, and both devices run the same dependent chain.
 *
 * TABLE SIZE. 2^22 entries of 56 bytes = 235 MB, against mainnet's 248 MB at
 * height 4.43M. A power of two so the index step is a mask on both devices
 * rather than a 64-bit modulo, which is slow on a GPU and would measure the
 * division instead of the memory.
 *
 * WHAT IT DOES NOT SETTLE. One card is one data point, and an ASIC is not
 * here. The useful output is reads/s per device alongside its memory
 * bandwidth, so another card or a memory technology can be reasoned about from
 * published specs rather than guessed at.
 *
 *   t_gather [seconds]
 *
 * Build: sh contrib/powbench/build-gather.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <vector>
#include <string>

#include <windows.h>
#include "clmin.h"

/* The runtime loader, same as contrib/powbench/main.cpp. Copied rather than
 * shared because main.cpp is one translation unit that also drags in the VM
 * kernels and the chain-fill port, none of which this needs. */
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

/* Table size is a parameter, not a constant. At 2^22 (224 MB) the table is
 * mainnet's block cache today, and a 7950X holds about a third of it in cache,
 * which is a real property of the real system but makes the absolute rate look
 * impossible against DDR5 bandwidth. Sweeping the size separates "what it costs
 * today" from "what it costs once nothing caches", and the second is what a
 * growing chain converges to. */
static uint32_t g_log2_entries = 22;
#define ENTRIES      (1u << g_log2_entries)
#define IDX_MASK     (ENTRIES - 1u)
#define ENTRY_U64    7              /* 56 bytes */
#define READS_PER_NONCE 16384.0

static double now_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static std::vector<uint64_t> g_tab;   /* ENTRIES * ENTRY_U64 */

static void table_init(void)
{
    g_tab.resize((size_t)ENTRIES * ENTRY_U64);
    uint64_t x = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < g_tab.size(); i++) {
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        g_tab[i] = x;
    }
}

/* ---------------- CPU ---------------- */

struct cpu_arg {
    int      chains;        /* dependent chains this thread interleaves */
    uint32_t steps;         /* steps per chain */
    uint64_t acc;
    int      id;
};

static void *cpu_worker(void *p)
{
    cpu_arg *a = (cpu_arg *)p;
    const uint64_t *T = g_tab.data();
    std::vector<uint64_t> cur(a->chains);
    uint64_t acc = 0;
    int c;
    uint32_t s;

    for (c = 0; c < a->chains; c++)
        cur[c] = ((uint64_t)(a->id * 7919 + c) * 2654435761u) & IDX_MASK;

    /* Each chain is strictly serial: the next index comes from the bytes just
     * read. Several chains per thread is the knob that buys memory-level
     * parallelism back, which is exactly what D5 trades away. */
    for (s = 0; s < a->steps; s++)
        for (c = 0; c < a->chains; c++) {
            const uint64_t h = T[cur[c] * ENTRY_U64];
            acc ^= h;
            cur[c] = (h ^ (uint64_t)s) & IDX_MASK;
        }

    a->acc = acc;
    return NULL;
}

static double cpu_reads_per_s(int threads, int chains, double seconds, uint64_t *sink)
{
    /* calibrate the step count so the run lands near the requested duration */
    uint32_t steps = 2000;
    double el = 0.0;
    std::vector<cpu_arg> args(threads);
    std::vector<pthread_t> th(threads);
    int i;

    for (int pass = 0; pass < 2; pass++) {
        const double t0 = now_s();
        for (i = 0; i < threads; i++) {
            args[i].chains = chains; args[i].steps = steps;
            args[i].acc = 0; args[i].id = i;
            pthread_create(&th[i], NULL, cpu_worker, &args[i]);
        }
        for (i = 0; i < threads; i++) pthread_join(th[i], NULL);
        el = now_s() - t0;
        for (i = 0; i < threads; i++) *sink ^= args[i].acc;
        if (pass == 0) {
            if (el < 1e-4) el = 1e-4;
            double want = seconds / el;
            double ns = (double)steps * want;
            if (ns < 1000) ns = 1000;
            if (ns > 4e8) ns = 4e8;
            steps = (uint32_t)ns;
        }
    }
    return (double)threads * (double)chains * (double)steps / el;
}

/* ---------------- GPU ---------------- */

static const char *K_SRC =
"__kernel void gather(__global const ulong *tab, const uint steps, __global ulong *out, const ulong mask)\n"
"{\n"
"    const ulong gid = get_global_id(0);\n"
"    ulong i = (gid * 2654435761UL) & mask;\n"
"    ulong acc = 0;\n"
"    for (uint s = 0; s < steps; s++) {\n"
"        const ulong h = tab[i * 7UL];\n"
"        acc ^= h;\n"
"        i = (h ^ (ulong)s) & mask;\n"
"    }\n"
"    out[gid] = acc;\n"
"}\n";

int main(int argc, char **argv)
{
    const double seconds = (argc > 1) ? atof(argv[1]) : 1.5;
    if (argc > 2) g_log2_entries = (uint32_t)atoi(argv[2]);
    if (g_log2_entries < 16) g_log2_entries = 16;
    if (g_log2_entries > 27) g_log2_entries = 27;
    uint64_t sink = 0;
    int hw = 0;

    printf("random reads into the block cache, CPU against GPU\n");
    printf("table %u entries x 56 B = %.0f MB, dependent chains, mask indexing\n\n",
           ENTRIES, (double)ENTRIES * 56.0 / 1048576.0);
    fflush(stdout);

    table_init();

    /* ---- CPU ---- */
#ifdef _SC_NPROCESSORS_ONLN
    hw = (int)sysconf(_SC_NPROCESSORS_ONLN);
#endif
    if (hw <= 0) hw = 32;
    if (hw > 30) hw = 30;   /* workstation, not a rig */

    printf("  CPU\n");
    printf("    %-24s %14s %14s\n", "config", "reads/s", "nonces/s");
    {
        const struct { int t, c; const char *label; } rows[] = {
            { 1,  1,  "1 thread,  1 chain" },
            { 1,  4,  "1 thread,  4 chains" },
            { hw, 1,  "N threads, 1 chain" },
            { hw, 4,  "N threads, 4 chains" },
            { hw, 16, "N threads, 16 chains" },
        };
        double best = 0.0;
        for (size_t r = 0; r < sizeof(rows)/sizeof(rows[0]); r++) {
            char lbl[64];
            snprintf(lbl, sizeof(lbl), "%s", rows[r].label);
            const double rps = cpu_reads_per_s(rows[r].t, rows[r].c, seconds, &sink);
            if (rps > best) best = rps;
            printf("    %-24s %14.3e %14.0f\n", lbl, rps, rps / READS_PER_NONCE);
        }
        printf("    %-24s %14.3e %14.0f\n", "PEAK", best, best / READS_PER_NONCE);
        printf("    (N = %d, capped at 30 of 32 logical threads)\n", hw);
    }

    /* ---- GPU ---- */
    printf("\n  GPU\n");
    {
        CL cl;
        if (!cl_load(cl)) { printf("    OpenCL not available\n"); return 0; }

        cl_uint nplat = 0; cl.GetPlatformIDs(0, NULL, &nplat);
        std::vector<cl_platform_id> plats(nplat ? nplat : 1);
        if (nplat) cl.GetPlatformIDs(nplat, plats.data(), NULL);
        cl_device_id dev = NULL;
        long long best_score = -1;
        for (cl_uint p = 0; p < nplat; p++) {
            cl_uint nd = 0;
            if (cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, 0, NULL, &nd) != CL_SUCCESS || !nd) continue;
            std::vector<cl_device_id> ds(nd);
            cl.GetDeviceIDs(plats[p], CL_DEVICE_TYPE_GPU, nd, ds.data(), NULL);
            for (cl_uint d = 0; d < nd; d++) {
                cl_uint c = 0, uni = 0;
                cl.GetDeviceInfo(ds[d], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(c), &c, NULL);
                cl.GetDeviceInfo(ds[d], CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof(uni), &uni, NULL);
                /* prefer discrete: an integrated part reports unified memory */
                const long long score = (uni ? 0LL : 1000000LL) + (long long)c;
                if (score > best_score) { best_score = score; dev = ds[d]; }
            }
        }
        if (!dev) { printf("    no GPU device\n"); return 0; }

        char devname[256] = {0};
        cl_ulong gmem = 0; cl_uint cus = 0, mhz = 0;
        cl.GetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(devname), devname, NULL);
        cl.GetDeviceInfo(dev, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(gmem), &gmem, NULL);
        cl.GetDeviceInfo(dev, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(cus), &cus, NULL);
        cl.GetDeviceInfo(dev, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(mhz), &mhz, NULL);
        printf("    %s, %llu MB, %u CUs, %u MHz\n", devname,
               (unsigned long long)(gmem / 1048576), cus, mhz);

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
        cl_kernel k = cl.CreateKernel(prog, "gather", &err);

        const size_t tab_bytes = (size_t)ENTRIES * ENTRY_U64 * 8;
        cl_mem dtab = cl.CreateBuffer(ctx, CL_MEM_READ_ONLY, tab_bytes, NULL, &err);
        if (err != CL_SUCCESS) { printf("    table alloc failed (%d), %zu MB\n", err, tab_bytes/1048576); return 0; }
        cl.EnqueueWriteBuffer(q, dtab, 1, 0, tab_bytes, g_tab.data(), 0, NULL, NULL);

        printf("    %-24s %14s %14s\n", "work items", "reads/s", "nonces/s");
        double best = 0.0;
        /* Keep each launch well under the Windows TDR timeout, which resets
         * the display driver at about 2 s on a display-attached card. The
         * existing gpubench carries a launch cap for the same reason. The
         * measurement is a rate, so a shorter launch costs precision, not
         * validity. */
        const double gpu_seconds = (seconds < 0.5) ? seconds : 0.5;
        const size_t items[] = { 4096, 32768, 131072, 524288, 2097152 };
        for (size_t it = 0; it < sizeof(items)/sizeof(items[0]); it++) {
            const size_t gsz = items[it];
            cl_mem dout = cl.CreateBuffer(ctx, CL_MEM_READ_WRITE, gsz * 8, NULL, &err);
            if (err != CL_SUCCESS) { printf("    out alloc failed at %zu\n", gsz); continue; }
            cl.SetKernelArg(k, 0, sizeof(dtab), &dtab);
            cl.SetKernelArg(k, 2, sizeof(dout), &dout);
            { const cl_ulong m = IDX_MASK; cl.SetKernelArg(k, 3, sizeof(m), &m); }

            /* calibrate, then measure */
            cl_uint steps = 64;
            double el = 0.0;
            for (int pass = 0; pass < 2; pass++) {
                cl.SetKernelArg(k, 1, sizeof(steps), &steps);
                cl.Finish(q);
                const double t0 = now_s();
                cl.EnqueueNDRangeKernel(q, k, 1, NULL, &gsz, NULL, 0, NULL, NULL);
                cl.Finish(q);
                el = now_s() - t0;
                if (pass == 0) {
                    if (el < 1e-4) el = 1e-4;
                    double ns = (double)steps * (gpu_seconds / el);
                    if (ns < 16) ns = 16;
                    if (ns > 2e6) ns = 2e6;
                    steps = (cl_uint)ns;
                }
            }
            const double rps = (double)gsz * (double)steps / el;
            if (rps > best) best = rps;
            printf("    %-24zu %14.3e %14.0f\n", gsz, rps, rps / READS_PER_NONCE);
            cl.ReleaseMemObject(dout);
        }
        printf("    %-24s %14.3e %14.0f\n", "PEAK", best, best / READS_PER_NONCE);
        cl.ReleaseMemObject(dtab);
    }

    printf("\n  sink %llx (ignore; keeps the reads from being optimised away)\n",
           (unsigned long long)sink);
    return 0;
}
