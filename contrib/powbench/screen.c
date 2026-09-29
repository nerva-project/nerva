// Copyright (c) 2026, The Nerva Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/* Cost-uniformity test for the CNA v6 VM, used as a design gate for v8.
 *
 * A PoW is easiest to reason about when every nonce costs the same to hash.
 * Where cost varies, it should at least not be knowable in advance: if the
 * cost of a nonce can be estimated more cheaply than the nonce can be hashed,
 * then the work a hash represents is no longer uniform, and difficulty stops
 * meaning quite what it is assumed to mean.
 *
 * This measures whether that holds for v6. The estimator is the cheapest one
 * available: generate the per-nonce program, walk it with every CN_OP_CBRANCH
 * taken and no registers or memory at all, and count the SP_READ/SP_WRITE
 * instructions the walk lands on.
 *
 * Three properties of the shipped VM make such an estimate possible in
 * principle, all read out of the source rather than assumed:
 *   1. CN_OP_CBRANCH tests regs[dst] & (imm | 1), and cn_vm_generate_program
 *      builds imm from two full 16-bit draws, so the mask carries ~16.5 set
 *      bits and the branch is taken except about once in 2^16.5.
 *   2. cn_vm_execute resets pc and chain on entry, and cn_slow_hash_v13 calls
 *      it CN_VM_ITERATIONS times with one program, so every pass restarts the
 *      same walk from pc 0.
 *   3. cn_vm_execute runs exactly CN_PROGRAM_SIZE steps whatever the branches
 *      do, so the variance is not in how many instructions run, it is in which
 *      instructions those steps land on.
 *
 * What this program measures, rather than argues:
 *   - how many of the 512 program slots the all-taken walk actually reaches
 *   - the distribution of estimated memory ops per pass, and how often it is 0
 *   - the real memory-op count from executing the VM against a real 8 MB pad
 *     with real registers, and how well the estimate tracks it
 *   - whether the 2048 passes of one nonce really do execute the same trace
 *   - the measured CBRANCH taken rate, against the predicted 1 - 2^-16.5
 *
 * The gate for v8: the correlation between estimate and measured cost should
 * be near zero. Run this against any candidate before it ships.
 *
 * The instrumented interpreter is a copy of cn_vm_execute with counters added.
 * A copy can drift from the original and quietly measure the wrong function,
 * so control() runs the real cn_vm_execute and this copy over identical
 * registers and pads and compares both afterwards. If that check fails nothing
 * else here means anything, so it aborts.
 *
 * Build (no nerva build tree needed, the two sources are self-contained):
 *   gcc -O2 -I src -I src/crypto contrib/powbench/screen.c \
 *       src/crypto/cna-vm.c src/crypto/hc128.c -o screen
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "cna-vm.h"
#include "hash-ops.h"

#define PAD_BYTES ((size_t)CN_SCRATCHPAD_MEMORY_V13)

/* ------------------------------------------------------------------ */
/* deterministic seeds, so a rerun reproduces the same numbers          */
/* ------------------------------------------------------------------ */

static uint64_t sm_state;

static uint64_t splitmix64(void)
{
    uint64_t z = (sm_state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static void fill_random(void *dst, size_t bytes)
{
    uint8_t *p = (uint8_t *)dst;
    size_t i = 0;
    while (i < bytes)
    {
        uint64_t v = splitmix64();
        size_t n = bytes - i < 8 ? bytes - i : 8;
        memcpy(p + i, &v, n);
        i += n;
    }
}

/* ------------------------------------------------------------------ */
/* the screen: all branches taken, no registers, no memory             */
/* ------------------------------------------------------------------ */

typedef struct {
    int memops;        /* SP_READ + SP_WRITE among the 512 executed steps */
    int distinct;      /* distinct program slots the walk reaches */
    int cbranches;     /* CBRANCH instructions the walk executes */
} screen_t;

static void screen_program(const cn_vm_program_t *prog, screen_t *out)
{
    const int pc_mask = CN_PROGRAM_SIZE - 1;
    uint8_t seen[CN_PROGRAM_SIZE];
    int pc = 0, step, memops = 0, distinct = 0, cbr = 0;

    memset(seen, 0, sizeof(seen));

    for (step = 0; step < CN_PROGRAM_SIZE; step++)
    {
        const int slot = pc & pc_mask;
        const cn_vm_instruction_t *ins = &prog->instructions[slot];
        int next_pc = pc + 1;

        if (!seen[slot]) { seen[slot] = 1; distinct++; }

        if (ins->op == CN_OP_SP_READ || ins->op == CN_OP_SP_WRITE)
            memops++;

        if (ins->op == CN_OP_CBRANCH)
        {
            /* the screener assumes taken, which is what makes it cheap */
            cbr++;
            next_pc = (pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & pc_mask;
        }

        pc = next_pc;
    }

    out->memops = memops;
    out->distinct = distinct;
    out->cbranches = cbr;
}

/* ------------------------------------------------------------------ */
/* instrumented copy of cn_vm_execute (validated against the real one) */
/* ------------------------------------------------------------------ */

typedef struct {
    long memops;
    long cbranch_seen;
    long cbranch_taken;
} exec_counters_t;

static uint64_t ref_ror64(uint64_t x, uint32_t r)
{
    r &= 63;
    if (r == 0) return x;
    return (x >> r) | (x << (64 - r));
}

/* mix64 is static inside cna-vm.c; this must match it bit for bit, and
 * control() is what proves it does. */
static uint64_t ref_mix64(uint64_t val, uint32_t key_material)
{
    uint64_t k = (uint64_t)key_material * UINT64_C(0x9e3779b97f4a7c15);
    val ^= k;
    val ^= val >> 30;
    val *= UINT64_C(0xbf58476d1ce4e5b9);
    val ^= val >> 27;
    val *= UINT64_C(0x94d049bb133111eb);
    val ^= val >> 31;
    return val;
}

static void traced_execute(const cn_vm_program_t *prog, uint8_t *scratchpad,
                           uint64_t regs[CN_REG_COUNT], exec_counters_t *ctr)
{
    const size_t sp_mask = (size_t)(CN_SCRATCHPAD_MEMORY_V13 - 1) & ~(size_t)7;
    const int    pc_mask = CN_PROGRAM_SIZE - 1;

    int pc = 0;
    uint64_t chain = 0;
    int step;

    for (step = 0; step < CN_PROGRAM_SIZE; step++)
    {
        const cn_vm_instruction_t *ins = &prog->instructions[pc & pc_mask];
        int next_pc = pc + 1;

        const uint8_t dst = ins->dst;
        const uint8_t src = ins->src;

        switch ((cn_vm_opcode_t)ins->op)
        {
        case CN_OP_IADD_RS: regs[dst] += regs[src] << (ins->shift & 3); break;
        case CN_OP_ISUB:    regs[dst] -= regs[src]; break;
        case CN_OP_IMUL:    regs[dst] *= regs[src]; break;
        case CN_OP_IXOR:    regs[dst] ^= regs[src]; break;
        case CN_OP_IROR:    regs[dst] = ref_ror64(regs[dst], (uint32_t)(regs[src] & 63)); break;

        case CN_OP_CBRANCH:
            if (ctr) ctr->cbranch_seen++;
            if (regs[dst] & ((uint64_t)ins->imm | 1))
            {
                if (ctr) ctr->cbranch_taken++;
                next_pc = (pc + (int)((int8_t)ins->shift) + CN_PROGRAM_SIZE) & pc_mask;
            }
            break;

        case CN_OP_SP_READ:
        {
            size_t addr = ((size_t)((uint64_t)regs[src] + (uint64_t)ins->imm + chain)) & sp_mask;
            memcpy(&regs[dst], &scratchpad[addr], sizeof(uint64_t));
            chain = regs[dst];
            if (ctr) ctr->memops++;
            break;
        }

        case CN_OP_SP_WRITE:
        {
            size_t addr = ((size_t)((uint64_t)regs[dst] + (uint64_t)ins->imm + chain)) & sp_mask;
            uint64_t tmp;
            memcpy(&tmp, &scratchpad[addr], sizeof(uint64_t));
            tmp ^= regs[src];
            memcpy(&scratchpad[addr], &tmp, sizeof(uint64_t));
            chain += tmp;
            if (ctr) ctr->memops++;
            break;
        }

        case CN_OP_MIX: regs[dst] = ref_mix64(regs[dst] ^ regs[src], ins->imm); break;

        default: break;
        }

        pc = next_pc;
    }
}

/* ------------------------------------------------------------------ */
/* control: the copy above must be the function that ships             */
/* ------------------------------------------------------------------ */

static uint64_t fnv1a(const uint8_t *p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    size_t i;
    for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

static void control(uint8_t *pad_a, uint8_t *pad_b)
{
    cn_vm_program_t prog;
    uint64_t regs_a[CN_REG_COUNT], regs_b[CN_REG_COUNT];
    uint8_t seed[32];
    int trial, pass;

    for (trial = 0; trial < 8; trial++)
    {
        fill_random(seed, sizeof(seed));
        cn_vm_generate_program(&prog, seed);

        fill_random(pad_a, PAD_BYTES);
        memcpy(pad_b, pad_a, PAD_BYTES);
        fill_random(regs_a, sizeof(regs_a));
        memcpy(regs_b, regs_a, sizeof(regs_a));

        /* several passes, because pass 1 alone would not catch a divergence
         * that only shows once the registers have drifted */
        for (pass = 0; pass < 16; pass++)
        {
            cn_vm_execute(&prog, pad_a, regs_a);
            traced_execute(&prog, pad_b, regs_b, NULL);
        }

        if (memcmp(regs_a, regs_b, sizeof(regs_a)) != 0 ||
            fnv1a(pad_a, PAD_BYTES) != fnv1a(pad_b, PAD_BYTES))
        {
            fprintf(stderr,
                "CONTROL FAILED on trial %d: the instrumented interpreter is not\n"
                "cn_vm_execute. Every number below would be measuring the wrong\n"
                "function, so nothing is reported.\n", trial);
            exit(2);
        }
    }

    printf("control: instrumented interpreter matches cn_vm_execute over 8 programs\n"
           "         x 16 passes (registers and full 8 MB pad identical)\n\n");
}

/* ------------------------------------------------------------------ */

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv)
{
    const int n_static  = argc > 1 ? atoi(argv[1]) : 100000;
    const int n_dynamic = argc > 2 ? atoi(argv[2]) : 200;
    const int passes    = argc > 3 ? atoi(argv[3]) : CN_VM_ITERATIONS;

    uint8_t *pad_a, *pad_b;
    cn_vm_program_t prog;
    uint8_t seed[32];
    int i;

    sm_state = 0x5EEDF00DCAFEBABEull;

    pad_a = (uint8_t *)malloc(PAD_BYTES);
    pad_b = (uint8_t *)malloc(PAD_BYTES);
    if (!pad_a || !pad_b) { fprintf(stderr, "out of memory\n"); return 1; }

    printf("CNA v6 cost-uniformity test\n");
    printf("pad %zu MB, program %d slots, %d steps/pass, %d passes/nonce\n\n",
           PAD_BYTES >> 20, CN_PROGRAM_SIZE, CN_PROGRAM_SIZE, CN_VM_ITERATIONS);

    control(pad_a, pad_b);

    /* ---------- 1. what the cheap estimate sees ---------- */
    {
        int *memops   = (int *)malloc((size_t)n_static * sizeof(int));
        int *distinct = (int *)malloc((size_t)n_static * sizeof(int));
        long zero_memop = 0, total_cbr = 0;
        double sum_m = 0, sum_d = 0;

        for (i = 0; i < n_static; i++)
        {
            screen_t s;
            fill_random(seed, sizeof(seed));
            cn_vm_generate_program(&prog, seed);
            screen_program(&prog, &s);
            memops[i] = s.memops;
            distinct[i] = s.distinct;
            sum_m += s.memops;
            sum_d += s.distinct;
            total_cbr += s.cbranches;
            if (s.memops == 0) zero_memop++;
        }

        qsort(memops, (size_t)n_static, sizeof(int), cmp_int);
        qsort(distinct, (size_t)n_static, sizeof(int), cmp_int);

        printf("1. the cheap estimate, %d programs, no registers and no memory\n", n_static);
        printf("   distinct slots reached : min %d  p50 %d  mean %.1f  p99 %d  max %d  (of %d)\n",
               distinct[0], distinct[n_static/2], sum_d / n_static,
               distinct[(int)(n_static*0.99)], distinct[n_static-1], CN_PROGRAM_SIZE);
        printf("   estimated memops/pass  : min %d  p50 %d  mean %.1f  p99 %d  max %d\n",
               memops[0], memops[n_static/2], sum_m / n_static,
               memops[(int)(n_static*0.99)], memops[n_static-1]);
        printf("   programs with 0 memops : %ld of %d", zero_memop, n_static);
        if (zero_memop) printf("  (1 in %.0f)", (double)n_static / zero_memop);
        printf("\n");
        printf("   CBRANCH steps executed : %.1f per pass\n\n",
               (double)total_cbr / n_static);

        /* How far the distribution's low tail sits below the mean. This is a
         * count of memory operations, not a time: a hash pays its AES fill,
         * its salt XOR and its final pass whatever the program does, so the
         * ratios below bound how uneven the VM's share can be, and are not a
         * throughput figure. Turning them into one needs a timing run on an
         * idle machine. */
        {
            static const double q[] = {0.001, 0.01, 0.05, 0.10, 0.25};
            const double mean_all = sum_m / n_static;
            size_t qi;

            printf("   low tail of the cost distribution (VM memory ops only):\n");
            printf("     cheapest    cutoff    mean memops    vs overall mean\n");
            for (qi = 0; qi < sizeof(q)/sizeof(q[0]); qi++)
            {
                const int k = (int)(n_static * q[qi]);
                double s = 0;
                int j;
                if (k < 1) continue;
                for (j = 0; j < k; j++) s += memops[j];
                s /= k;
                printf("     %7.1f%%    %6d    %10.1f    %8.2fx below\n",
                       q[qi] * 100.0, memops[k-1], s,
                       s > 0 ? mean_all / s : INFINITY);
            }
            printf("\n");
        }

        free(memops);
        free(distinct);
    }

    /* ---------- 2. what the real VM actually costs ---------- */
    {
        double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
        long n_same_trace = 0;
        double worst_pass_spread = 0;

        printf("2. the real VM, %d nonces x %d passes against a live 8 MB pad\n",
               n_dynamic, passes);

        for (i = 0; i < n_dynamic; i++)
        {
            screen_t s;
            uint64_t regs[CN_REG_COUNT];
            long first_pass_memops = -1, min_pass = -1, max_pass = -1;
            double total_memops = 0;
            int p;

            fill_random(seed, sizeof(seed));
            cn_vm_generate_program(&prog, seed);
            screen_program(&prog, &s);

            fill_random(pad_a, PAD_BYTES);
            fill_random(regs, sizeof(regs));

            for (p = 0; p < passes; p++)
            {
                exec_counters_t ctr = {0, 0, 0};
                traced_execute(&prog, pad_a, regs, &ctr);
                total_memops += ctr.memops;
                if (first_pass_memops < 0) first_pass_memops = ctr.memops;
                if (min_pass < 0 || ctr.memops < min_pass) min_pass = ctr.memops;
                if (ctr.memops > max_pass) max_pass = ctr.memops;
            }

            if (min_pass == max_pass) n_same_trace++;
            if (max_pass > 0)
            {
                double spread = (double)(max_pass - min_pass) / (double)max_pass;
                if (spread > worst_pass_spread) worst_pass_spread = spread;
            }

            {
                double x = s.memops;                       /* prediction */
                double y = total_memops / passes;          /* measured mean */
                sx += x; sy += y; sxx += x*x; syy += y*y; sxy += x*y;
            }
        }

        {
            double n = n_dynamic;
            double num = n*sxy - sx*sy;
            double den = sqrt((n*sxx - sx*sx) * (n*syy - sy*sy));
            double r = den > 0 ? num / den : 0.0;

            printf("   nonces whose %d passes all had the same memop count: %ld of %d\n",
                   passes, n_same_trace, n_dynamic);
            printf("   worst within-nonce pass-to-pass spread: %.4f%%\n",
                   worst_pass_spread * 100.0);
            printf("   correlation(estimate, measured cost) r = %.6f\n", r);
            printf("\n   gate: pass condition is r near zero. r = %.4f means per-nonce\n", r);
            printf("   cost is %s from the program alone.\n",
                   fabs(r) > 0.5 ? "substantially predictable" : "not usefully predictable");
        }
    }

    free(pad_a);
    free(pad_b);
    return 0;
}
