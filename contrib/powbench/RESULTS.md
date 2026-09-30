# CryptoNight-Adaptive v5 / v6 / v7: measurements, mistakes, and results

Work done 2026-09-24 to 2026-09-28 to answer three questions before HF14 is
finalised:

1. How does scratchpad size affect verification cost and CPU fairness?
2. How GPU-resistant is each variant, really?
3. Is v7 (the HF14 candidate) better than v6 on those axes?

Everything here is measurement tooling. Nothing under `src/` is touched.

**This document has been rewritten twice as the measurements improved. Earlier
conclusions that are now withdrawn are listed in section 2, with what caused
each error.** The short version of the history: the first harness modelled all
three variants as near-identical memory chases and could not tell them apart;
the second was a faithful port but had several omissions; this is the third.

---

## 1. What is in this branch

### `contrib/hf14checks/` (CPU, real hash functions)

`t_bench_v5v6.cpp` times the **real** `cn_slow_hash_v11` / `_v13` / `_v14` out
of `libcncrypto.a`, plus recompilations of v5 at other pad sizes
(`v5pad.inc` + `v5pad{1,1_25,1_5,2,4,8}.c`). A control row compares the shipped
v11 against the same source recompiled locally; it must read ~1.00x.

### `contrib/powbench/` (GPU vs CPU)

Self-contained OpenCL benchmark: binds `OpenCL.dll` at runtime, builds static,
runs on a machine with no toolchain.

| file | what |
|---|---|
| `vm_kernels.cl.h` | OpenCL ports of the v5/v6/v7 cores, plus two probe kernels |
| `vm_ref.h` | matching C reference |
| `chain_fill.h` | per-nonce chain salt, ported from `get_cna_v5_data`/`_v6_data` |
| `hc128.c/.h` | copied verbatim from `src/crypto` |
| `main.cpp` | driver: allocation, sweeps, checksum gate, table |
| `sizecheck.cpp` | host-only checker for the buffer/work-group sizing maths |

**The checksum gate is the reason to trust any of it.** Every row recomputes a
sample of nonces on the CPU and compares hashes with the GPU. A row that
disagrees is printed without a ratio, because the two sides were not computing
the same thing. It caught several defects that would otherwise have shipped as
confident numbers.

---

## 2. Mistakes, and what each cost

Recorded because every one produced a confident wrong answer first.

### 2.1 The benchmark directory built at `-O0`

`contrib/hf14checks/CMakeLists.txt` set no `CMAKE_BUILD_TYPE`, so CMake passed
no `-O` flag while `libcncrypto.a` is `-O2`. Locally-compiled rows looked ~4x
more expensive. **Produced and then withdrew the claim that v5 at 8 MB costs
26 ms against v6's 6.95.** At matched flags it is 6.72 vs 6.95.

### 2.2 A wrap check in the innermost loop cost 29%

The salt-wrap fix was first a compare-and-branch inside a loop that runs ~1M
times per nonce. `CN_SALT_MEMORY` is a power of two, so the wrap is one AND.

### 2.3 The first GPU harness did not model the algorithms at all

`chase_v5` and `chase_v6` were near-identical dependent walks. v5's
per-iteration AES, v6 and v7's 512-instruction per-nonce VM, the chain fill and
`finalize_hash` were all absent. **Every GPU number from that harness was
meaningless**, including "v7 loses to the GPU at 1.48x" and "v5@8MB equals v6".

### 2.4 `CL_DEVICE_MAX_MEM_ALLOC_SIZE` is per-allocation, not capacity

Capping the run at it gave a 4 GB 1050 Ti 128 nonces at 8 MB. Fixed with
multi-buffer allocation (`PICK_BUF`).

### 2.5 A non-multiple-of-work-group-size launch printed 3.8 MH/s

`clEnqueueNDRangeKernel` returned `CL_INVALID_WORK_GROUP_SIZE`, the kernel never
ran, and nonces divided by ~0 s gave **3,861,386 H/s, GPU:CPU 250,148x**. The
guard missed it because the output buffer was uninitialised.

### 2.6 Chunking kernels to dodge TDR (tried, reverted)

An in-order OpenCL queue runs one kernel at a time, so short chunks left one
compute unit busy and collapsed throughput ~20x.

### 2.7 Aborted kernels printed numbers

An integrated GPU produced 32,167,539 H/s from a TDR-killed kernel. Now every
output slot must be non-zero, CL return codes are checked, and the checksum
gate must pass.

### 2.8 v7 AES-filled 24 MB instead of 256 KB

`cn_slow_hash_v14` AES-fills and salt-XORs only the **256 KB pad**; the 24 MB
buffer gets a cheap splitmix fill. The port AES-filled all 24 MB, ~96x the real
AES work, and since a GPU pays T-tables where a CPU pays AES-NI this dominated.
**v7 read 0.07x; corrected it read 0.33x on the same machine.**

### 2.9 The chain fill was missing entirely

The harness measured `cn_slow_hash` only. The real path also runs
`get_blob_hash`, `HC128_Init` and `get_cna_v5_data`/`_v6_data`, which builds a
256 KB salt from ~16,384 random reads into a ~247 MB block cache plus ~256
HC-128 key setups **per nonce**. Omitting it made the CPU column ~4x too fast
on v5: 26k H/s against 6.38k measured on the same 7950X by the miner.

It is charged to the **CPU only**, because a GPU rig's host supplies it at
~62 MB/s and under one core while a CPU miner pays it on the hashing thread.
It is **ported rather than a measured constant** because its cost is DRAM
latency and HC-128 throughput, both machine-specific.

### 2.10 `salt_pad` indexed words, and `randomize_scratchpad_256k` was absent

`salt_pad` walks `hp_state` as **bytes** with a byte stride; indexing 32-bit
words did a quarter of the work. And v5 runs a full PAD/4 pass after the fill
that was missing. Together, 1.85x.

### 2.11 Two broken attempts to bound JIT headroom

First swapped pad accesses for `mix64` (nine dependent ops), which priced
memory against comparable ALU work and left fetch and dispatch in place. It
reported ceilings of 10x and 20x, both meaningless. Replaced with a kernel
representing what a JIT would emit; see section 5.

### 2.12 Device selection picked integrated GPUs

Ranking by `CL_DEVICE_MAX_COMPUTE_UNITS` compares Intel EUs against NVIDIA SMs.
It picked an Intel HD 630 (24 EUs) over a GTX 1050 Ti (6 SMs), and earlier a
1-CU Raphael iGPU over a discrete Ellesmere. Now prefers discrete via
`CL_DEVICE_HOST_UNIFIED_MEMORY`. **The laptop's GPU column below is Intel HD
630 and needs re-running.**

### 2.13 Measurement hygiene

- Confirm the box is idle. Mainnet mining inflated v7 from 68 to 177 ms.
- Sweep CPU thread counts; pinning to `hardware_concurrency` understated the
  CPU up to 4.5x on memory-bound rows, which inflates GPU:CPU.
- Sweep GPU nonce counts. On the Vega, v6 @1MB read 0.17x at 1984 nonces and
  0.48x at 8128.
- A launch cap is needed on display-attached GPUs, and it starves rows. v7 read
  0.08x at cap 10 and 0.33x at cap 25 on the same box. **Compare machines only
  at the same cap.**

---

## 3. CPU results, real hash functions (7950X, control row 1.01x)

| version | pad KB | mean ms | H/s (1T) | ms per MB |
|---|---|---|---|---|
| v5 1MB ref | 1024 | 0.75 | 1331.1 | 0.75 |
| v5 1MB ctl | 1024 | 0.76 | 1315.8 | 0.76 |
| v5 1.25MB | 1280 | 1.08 | 929.9 | 0.86 |
| v5 1.5MB | 1536 | 1.27 | 788.4 | 0.85 |
| v5 2MB | 2048 | 1.73 | 577.3 | 0.87 |
| v5 4MB | 4096 | 3.32 | 301.2 | 0.83 |
| v5 8MB | 8192 | 6.72 | 148.8 | 0.84 |
| v6 (HF13) | 8192 | 6.95 | 143.9 | 0.87 |
| v7 (HF14) | 24576 | 67.60 | 14.8 | |

Runs agree within 4% except v7, which varied 12.8%; its 24 MB buffer makes it
the most sensitive row to anything else on the machine.

v5 scales **linearly** in pad size (8x pad costs 8.84x). At equal 8 MB pad, v5
and v6 cost the same. With the chain fill added (~1.6 ms v5, ~2.2 ms v6), v5 at
8 MB verifies ~10% cheaper than v6 does today.

---

## 4. Four machines, faithful port

All rows checksum-verified GPU against CPU. `vram=50`, `launch cap=25`.

| | CPU | GPU |
|---|---|---|
| A | Ryzen 9 7950X, 32T | RTX 3050, 8 GB, 20 CU |
| B | Ryzen 7 9700X, 16T | Radeon Ellesmere (RX 480/580), 8 GB, 36 CU |
| C | Ryzen 5 5600X, 12T | Radeon Vega FE, 16 GB, 64 CU |
| D | Intel i7-7700HQ, 8T | **Intel HD 630** (wrong device, see 2.12) |

### GPU:CPU, lower is better

| variant | A | B | C | D* |
|---|---|---|---|---|
| v5 1MB | 0.05x | 0.10x | 0.17x | 0.10x |
| **v5 4MB** | **0.01x** | **0.01x** | **0.02x** | 0.06x |
| v5 8MB | 0.01x | 0.00x | 0.01x | 0.05x |
| v6 1MB | 0.10x | 0.12x | **0.48x** | 0.24x |
| v6 4MB | 0.09x | 0.02x | 0.06x | 0.31x |
| v6 8MB | 0.01x | 0.01x | 0.04x | 0.05x |
| **v7 24MB** | **0.33x** | 0.05x | 0.13x | 0.15x |

### Single-thread ms, and cross-CPU spread

| variant | 7950X | 9700X | 5600X | 7700HQ | spread |
|---|---|---|---|---|---|
| v5 1MB | 2.03 | 1.97 | 2.43 | 3.71 | 1.88x |
| **v6 4MB** | 8.00 | 7.58 | 9.61 | 12.18 | **1.61x** |
| **v5 4MB** | 4.03 | 3.70 | 5.03 | 7.96 | **2.15x** |
| v6 1MB | 3.64 | 3.55 | 6.16 | 9.38 | 2.64x |
| v6 8MB | 10.11 | 9.46 | 11.63 | 27.51 | 2.91x |
| v5 8MB | 6.56 | 5.77 | 8.24 | 21.36 | 3.70x |
| **v7** | 87.88 | 53.66 | 64.84 | 312.44 | **5.82x** |

Four CPUs: Zen 4, Zen 5, Zen 3 and Kaby Lake. The laptop has 6 MB of L3, which
is what makes the large-pad rows diverge.

---

## 5. What the two probe kernels say

**v5 sweep optimisation: 0.5x to 1.0x across four GPUs.** `salt_pad` is the
only part of v5 with no loop-carried dependency, so the only part anyone can
restructure. Coalescing every hit inside an 8-byte word gains **nothing**
(and is slower on AMD): at an average stride of 66 bytes there is usually one
hit per word. v5's GPU column is not hiding a large optimisation.

**JIT ceiling: 1.05x to 1.89x across four GPUs.** Measured against a kernel
representing what a JIT would emit (straight-line, registers in registers, no
instruction fetch, no dispatch). The program is 4 KB and reused 2048 times, so
the fetch is L1-resident and there is little for a JIT to remove. Applies to
v6 and v7 only; v5 has no per-nonce program.

Both bounds were the main uncertainties in earlier versions. Neither is large.

---

## 6. Conclusions

### 6.1 The 4 MB variants are the fairest, and 8 MB and above are not

Cross-CPU spread is **1.61x for v6 4MB and 2.15x for v5 4MB**, against 2.91x
for v6 8MB, 3.70x for v5 8MB and **5.82x for v7**.

This **reverses** the earlier conclusion that a bigger pad buys fairness. That
was drawn from two Ryzen boxes with large L3. The laptop has 6 MB, so pads at
8 MB and above do not fit and it falls off a cliff (27.51 ms on v6 8MB against
9.46 on the 9700X). Pads above the smallest machine's L3 punish exactly the
machines fairness is meant to protect.

### 6.2 v7 is the worst option on two axes and unremarkable on the third

- **Verification**: 87.88 ms against v6 8MB's 10.11 on the same box, and
  312 ms on the laptop. Measured on the real function throughout; this number
  has never moved.
- **Fairness**: 5.82x spread, the worst tested by a wide margin.
- **GPU resistance**: 0.05x to 0.33x. Worse than v6 8MB on every machine, but
  not the worst row overall (v6 @1MB reaches 0.48x on the Vega).

Earlier versions of this document claimed v7 loses outright to a GPU (1.48x,
then 1.33x). Those came from the unfaithful harness. The corrected case against
v7 rests on verification cost and fairness, not on the GPU losing.

### 6.3 v5 at 4 MB is the strongest candidate measured

| | v5 4MB | v6 8MB (current) |
|---|---|---|
| GPU:CPU | 0.01-0.06x | 0.01-0.05x |
| fairness spread | **2.15x** | 2.91x |
| verify, worst machine | **7.96 ms** | 27.51 ms |

Equal on GPU resistance, fairer, and **3.5x cheaper to verify on the weakest
machine**. v6 at 4 MB is fairer still (1.61x) but costs roughly twice as much
to verify as v5 4MB.

Caveat worth keeping in view: v5 has no VM, so its per-nonce variation is four
loop bounds. Its resistance comes from the AES-NI against T-tables asymmetry
rather than program divergence, and that asymmetry disappears the day a GPU
gets competitive AES.

---

## 7. Known gaps

**This document covers v5, v6 and v7 only.** The v8 kernels, the Phase 2
floating-point stage and the GPU measurement that settled it are in
FINDINGS.md F37 to F39, not here. `contrib/powbench/BUILD.txt` describes how to
run the current harness, whose default variant set is the four 1 MB rows rather
than the pad sweep below; pass `all` to reproduce this document.

- ~~**Machine D's GPU column is an Intel HD 630, not the GTX 1050 Ti**~~
  (2.12). **Resolved.** The fixed selector picks the discrete card: machine D
  now reports `GeForce GTX 1050 Ti 4.0G/1.0G 6CU`. See FINDINGS F37.
- **v7's CPU is ~40% above the real function** on machine A (87.88 vs ~69.8)
  and unexplained. It reads *faster* on the slower 5600X, which is impossible,
  so that cell is unreliable. The direction overstates v7's GPU:CPU.
- Rows hitting the launch cap run starved: v5 8MB and v6 8MB at 64 nonces,
  v7 at 32-160 depending on machine. Ordering is sound; magnitudes are floors.
- Residual port approximations, each estimated under 3%: `extra_hashes` inside
  `salt_pad` substituted with `mix64`; per-nonce `cn_vm_generate_program` done
  on the host and reused; Keccak framing and the final `extra_hashes` omitted.
- v6 at 1/2/4 MB and v5 at 2/4/8 MB are exploratory. Real v11 is 1 MB and real
  v13 is 8 MB.
