# CryptoNight-Adaptive v5 / v6 / v7: measurements, mistakes, and results

Work done 2026-09-24 and 2026-09-25 to answer three questions before HF14 is
finalised:

1. How does v5's scratchpad size affect verification cost and CPU fairness?
2. How GPU-resistant is each variant, really?
3. Is v7 (the HF14 candidate) actually better than v6 on those axes?

Everything here is measurement tooling, not consensus code. Nothing under
`src/` is touched by this branch.

---

## 1. What is in this branch

### `contrib/hf14checks/` (CPU, real hash functions)

`t_bench_v5v6.cpp` times the **real** `cn_slow_hash_v11` / `_v13` / `_v14` out
of `libcncrypto.a`, plus recompilations of v5 at other scratchpad sizes.

`v5pad.inc` is the template; `v5pad{1,1_25,1_5,2,4,8}.c` are five lines each.
Each is a separate translation unit with renamed symbols, the same pattern
`slow-hash-sw.c` and `slow-hash-hw.c` already use, so consensus code is
untouched and the shipped 1 MB v11 is linked alongside as the reference row.

**Three pad-size assumptions in the shipped code had to be lifted to build at
any size other than 1 MB.** None is a live bug at the shipped size; each holds
only because of that exact size:

| macro | assumption |
|---|---|
| `randomize_scratchpad_256k` | walks `salt[x++]` once per 4 pad bytes |
| `salt_pad` | walks `salt[x++]` once per `offset_2` pad bytes, `offset_2 >= 4` |
| `state_index` | masks with `(pad/16 - 1)`, needs a power-of-two block count |

The first two stay in bounds only because a 1 MB pad yields at most
1048576/4 = 262144 steps, exactly `CN_SALT_MEMORY`. Anything larger reads past
the salt. The third would silently confine a 1.25 or 1.5 MB pad to its low
1 MB, making the bigger pad look free.

### `contrib/powbench/` (GPU vs CPU)

Self-contained OpenCL benchmark. Binds `OpenCL.dll` at runtime (no SDK), builds
static, runs on a machine with no toolchain. It models the memory-hard core of
each variant with **identical work on both sides**, so `GPU:CPU` is meaningful.
It does not implement Keccak, the AES framing, or the ALU program slices, so
the H/s figures are ceilings, not hashrates.

`sizecheck.cpp` replays the buffer/work-group sizing maths for every machine we
tested plus a stress case. It exists because two real bugs lived in that maths
and could not be reproduced on the development box.

---

## 2. Mistakes we made, and what they cost

These are recorded because every one of them produced a confident wrong answer
first. Anyone re-running this work should check for them.

### 2.1 The benchmark directory built at `-O0` (invalidated a whole conclusion)

`contrib/hf14checks/CMakeLists.txt` set no `CMAKE_BUILD_TYPE`. CMake with no
build type passes **no `-O` flag at all**, so everything built there was `-O0`,
while `libcncrypto.a` is `-O2`. The rows compiled locally looked ~4x more
expensive than the rows linked in.

This produced the claim "v5 at 8 MB costs 26.03 ms against v6's 6.95, so v5's
cheap verification is inseparable from its small pad." **Withdrawn.** At
matched flags it is 6.72 vs 6.95 ms.

Fix: the CMakeLists now defaults to Release, and the pad units carry the exact
flags the main build uses for `slow-hash-hw.c`, read out of its `flags.make`:
`-O2 -DNDEBUG -maes -march=x86-64 -fno-strict-aliasing`. The aliasing flag is
mandatory; slow-hash type-puns the scratchpad.

**The control row exists because of this.** `t_bench_v5v6` measures the shipped
`cn_slow_hash_v11` and the same source recompiled locally at the same 1 MB. It
must read ~1.00x. It caught this bug and the next one. Do not remove it.

### 2.2 A wrap check in the innermost loop cost 29%

The salt-wrap fix that makes a pad larger than 1 MB safe was first written as a
compare-and-branch inside the innermost byte loop of `salt_pad` and
`randomize_scratchpad_256k`. Those loops run on the order of a million times
per nonce. `CN_SALT_MEMORY` is 262144, a power of two, so the wrap is a single
AND and costs nothing. As a branch it cost 29% and broke the control row.

### 2.3 The benchmarks measure `cn_slow_hash` only

The real per-nonce path in `get_block_longhash_v11` / `_v13` also runs
`get_blob_hash`, `HC128_Init`, and `get_cna_v5_data` / `_v6_data`, which builds
a 256 KB salt from the chain: 4096 rounds, 4 random reads each into
`m_block_cache`, plus ~256 `HC128_Init` calls **per nonce**. At height 4.41M
that cache is ~280 MB, so the fill is DRAM-latency bound and grows with the
chain.

Calibrated against the live miner on the 7950X:

| | measured | bench hash core | implied chain fill |
|---|---|---|---|
| v6, 1 thread | 107-111 H/s (9.17 ms) | 6.95 ms | **2.2 ms** |
| v5, 16 threads | 6380 H/s | 0.84 ms/thread | **~1.6 ms** |

Predicted v6 1T = 109 H/s against 107-111 measured; predicted v5 16T ~6400
against 6380 measured. Validated at two independent points.

The fill is 256 KB whatever the pad size, so it is a constant per row. It is
also where the pool resistance lives, and the GPU harness gives the GPU a free
pass on it, so `GPU:CPU` there **overstates** the GPU's advantage.

### 2.4 `CL_DEVICE_MAX_MEM_ALLOC_SIZE` is per-allocation, not capacity

The harness originally put every pad in ONE allocation and capped the run at
`maxalloc`: 1 GB on a 4 GB 1050 Ti, 2 GB on an 8 GB 3050. That gave those cards
192 and 128 nonces at 8 MB, far too few to fill the device, and made whichever
variant had the biggest pad look resistant when the harness was starving it.
A real miner would allocate several buffers, so now the tool does, up to 4,
selected in-kernel by `PICK_BUF`.

### 2.5 A non-multiple-of-work-group-size launch printed 3.8 MH/s

Rounding `per_buf` to a multiple of the work-group size threw away up to 45% of
each buffer, and the fallback for when it rounded to zero left a global size
that was not a multiple of `lws` at all. `clEnqueueNDRangeKernel` returned
`CL_INVALID_WORK_GROUP_SIZE`, the kernel never ran, and dividing nonces by
~0 seconds printed **3,861,386 H/s and a GPU:CPU of 250,148x** on a GTX 1050 Ti.

The `acc != 0` guard should have caught it but did not: the output buffer was
never initialised, so it read stale VRAM.

Fix: round the **total** instead of per-buffer, with an adaptive `lws`; zero
the output buffer before launching; check every CL return code. `sizecheck.cpp`
verifies the maths for all four machines offline.

### 2.6 Chunking kernels to dodge the TDR watchdog (tried, reverted)

Windows kills any GPU command running longer than ~2 s. The Vega ran 11456
nonces of v5 1MB in one 27.8 s command. Splitting it into short chunks was
tried and **reverted**: an in-order OpenCL queue runs one kernel at a time, so
64-wide chunks left one compute unit busy and the rest idle, collapsing
throughput ~20x. Chunking cannot work here anyway, because keeping enough
work-items in flight to fill the device already takes far longer than TDR
allows. Total GPU load is held down by variant count, reps and VRAM fraction
instead.

### 2.7 Aborted kernels still print numbers

On the 9700X's integrated GPU, one run produced 32,167,539 / 123,870,967 /
34,439,461 H/s with `GPU:CPU` up to 276,192x. The next run on the same machine
gave ~100 H/s. The absurd values are a kernel **killed part-way** (TDR reset),
where the finished output slots are populated so the XOR guard passes, `Finish`
still returns `CL_SUCCESS`, and the aborted run's near-zero elapsed time
explodes the rate.

Every bad row carried the `!` instability flag, which is what caught it.
**Known remaining gap:** the tool flags these but does not yet reject them. The
intended fix is to require *every* output slot to be non-zero, not just the
XOR, and to drop any row whose best/worst spread exceeds 2x.

### 2.8 Measurement hygiene

- Confirm the box is idle. Mainnet mining on the dev box inflated v7 from 68 to
  177 ms, and a background build moved the CPU column 30%.
- Thread-scaling clocks must exclude pad allocation and `memset` (barrier), and
  work must come from a shared counter: v5 nonces vary ~2.5x in cost, so with a
  handful of hashes each the unluckiest thread set the elapsed time.
- The 2017 laptop thermally throttles. In one run it read 25.75 ms at 2 MB and
  22.46 ms at 4 MB; a bigger pad cannot be faster. Best-of-N fixes variance
  *within* a variant, not drift *across* them. Run that machine twice.

---

## 3. CPU results, real hash functions (7950X, control row at 1.01x)

AMD Ryzen 9 7950X, 16 cores / 32 threads, 1 MB L2 per core, 64 MB L3 split
32 MB per CCD.

| version | pad KB | mean ms | min | max | H/s (1T) | ms per MB |
|---|---|---|---|---|---|---|
| v5 1MB ref | 1024 | 0.75 | 0.33 | 1.39 | 1331.1 | 0.75 |
| v5 1MB ctl | 1024 | 0.76 | 0.33 | 1.38 | 1315.8 | 0.76 |
| v5 1.25MB | 1280 | 1.08 | 0.59 | 1.58 | 929.9 | 0.86 |
| v5 1.5MB | 1536 | 1.27 | 0.78 | 1.98 | 788.4 | 0.85 |
| v5 2MB | 2048 | 1.73 | 1.09 | 2.65 | 577.3 | 0.87 |
| v5 4MB | 4096 | 3.32 | 1.85 | 5.31 | 301.2 | 0.83 |
| v5 8MB | 8192 | 6.72 | 3.80 | 9.43 | 148.8 | 0.84 |
| v6 (HF13) | 8192 | 6.95 | 6.67 | 8.10 | 143.9 | 0.87 |
| v7 (HF14) | 24576 | 67.60 | 56.97 | 82.70 | 14.8 | |

Two runs agree within 4% on every row **except v7**, which read 59.95 ms in one
run and 67.60 in the other, 12.8% apart. v7's 24 MB buffer makes it by far the
most sensitive row to anything else happening on the machine, so treat its
absolute figures as indicative. The same caveat applies to the v7 1T cell in
section 4.1.

**v5 scales linearly in pad size**, not superlinearly: 8x the pad costs 8.84x,
and ms-per-MB is flat from 1.25 MB up. The dominant cost is `salt_pad` and the
two AES fills, all straight sweeps proportional to pad size.

**At an equal 8 MB pad, v5 and v6 cost the same** (6.72 vs 6.95 ms, 1.03x).

The 1 MB row is the only one below the flat line (0.75 vs ~0.85) because 1 MB
is exactly the per-core L2 on this CPU. That is the likely source of v5's
cross-CPU unfairness: L2-resident on a 1 MB-L2 core, spilling on a smaller one.
Raptor Lake P-cores have 2 MB of L2, so 2 MB does not equalise everyone; 4 MB
does.

### With the chain fill added (fill is pad-independent)

| pad | hash ms | + fill | real total | 1T H/s |
|---|---|---|---|---|
| 1 MB | 0.75 | 1.6 | 2.35 | 426 |
| 1.5 MB | 1.27 | 1.6 | 2.87 | 348 |
| 2 MB | 1.73 | 1.6 | 3.33 | 300 |
| 4 MB | 3.32 | 1.6 | 4.92 | 203 |
| 8 MB | 6.72 | 1.6 | 8.32 | 120 |
| **v6 today** | 6.95 | 2.2 | **9.15** | **109** (measured 107-111) |

**v5 at 8 MB would verify ~10% cheaper than v6 does today**, same pad, because
v6 carries the dearer fill. And pad size is the *minority* of v5's cost at
small pads: at 1 MB the fill is two thirds of the nonce.

---

## 4. GPU results, four machines

All at `vram=50%` unless noted. `!` marks a row that varied over 10% between
reps, i.e. noise. Lower `GPU:CPU` is better; above 1.0 the GPU wins.

### 4.1 Ryzen 9 7950X (32T) + RTX 3050, 8 GB VRAM, 2 GB maxalloc, 20 CU

| variant | KB | nonces | nb | GPU H/s | CPU32 H/s | GPU:CPU | 1T ms | 4T ms |
|---|---|---|---|---|---|---|---|---|
| v5 1MB | 1024 | 4032 | 2 | 800.3 | 7120.2 | 0.11x | 2.37 | 2.37 |
| v5 1.5MB | 1536 | 2688 | 2 | 653.2 | 5905.1 | 0.11x | 3.74 | 4.57 |
| v5 2MB | 2048 | 1984 | 2 | 518.5 | 4814.8 | 0.11x | 4.35 | 4.86 |
| v5 4MB | 4096 | 960 | 2 | 207.4 | 1693.0 | 0.12x | 5.48 | 5.91 |
| v5 8MB | 8192 | 448 | 2 | 55.6 | 573.6 | 0.10x | 6.33 | 11.48 |
| v6 HF13 | 8192 | 448 | 2 | 55.8 | 533.3 | 0.10x | 7.29 | 12.83 |
| **v7 HF14** | 24576 | 160 | 2 | 90.0 | 67.9 | **1.33x** | 66.29* | 251.23 |

\* The v7 1T of 66.29 ms is contaminated and should not be used. It is slower
than the 9700X (43.45) and the 5600X (48.48) on the same test, which a 16-core
Zen 4 will not genuinely be. This box had background load. The GPU:CPU column
is unaffected: it comes from the all-threads measurement.

### 4.2 Ryzen 5 5600X (12T) + Radeon Vega FE (gfx901), 16 GB VRAM, 13.4 GB maxalloc, 64 CU

Two runs at `vram=50%`:

| variant | KB | nonces | GPU H/s | CPU12 H/s | GPU:CPU (A / B) |
|---|---|---|---|---|---|
| v5 1MB | 1024 | 8128 | 3042.1! / 3061.7! | 2028.0 | 1.50x / 1.51x |
| v5 1.5MB | 1536 | 5440 | 2418.8! / 2417.1! | 1851.0 / 1857.1 | 1.31x / 1.30x |
| v5 2MB | 2048 | 4032 | 1871.4! / 1862.6! | 1577.9! / 1722.9 | 1.19x / 1.08x |
| v5 4MB | 4096 | 1984 | 696.2! / 691.3! | 660.7 / 672.1 | 1.05x / 1.03x |
| v5 8MB | 8192 | 960 | 194.1 / 194.2 | 258.1 / 275.7 | 0.75x / 0.70x |
| v6 HF13 | 8192 | 960 | 198.1 / 197.6 | 243.6 / 244.0 | 0.81x / 0.81x |
| **v7 HF14** | 24576 | 320 | 64.5 / 65.7 | 31.9 / 31.8 | **2.02x / 2.07x** |

### 4.3 The VRAM sweep on the Vega, and why 70% was wrong

v5 1MB only, same machine, same binary:

| vram | nonces | GPU H/s | GPU:CPU |
|---|---|---|---|
| 25% | 4032 | 2471.0! | 1.22x |
| 45% | 7360 | 2964.9! | 1.46x |
| 50% | 8128 | 3042.1! | 1.50x |
| 55% | 8960 | 1093.2 | 0.54x |
| 75% | 12224 | 415.7 | 0.21x |

**Seven times slower with more nonces is not a real effect.** Above ~55% the
allocation stops fitting in physical VRAM alongside the display and the driver
starts migrating it. The original Vega column was taken at 70% and was
therefore measured under memory pressure.

This matters because the earlier reading of that column ("a bigger pad makes
the GPU relatively better") was an artefact of oversubscription. At 50%, where
the card is not thrashing, `GPU:CPU` **falls** with pad size, 1.50x at 1 MB to
0.75x at 8 MB.

**Compare machines only at the same `vram=` setting.** The header records it.

### 4.4 Intel i7-7700HQ (8T) + GTX 1050 Ti, 4 GB VRAM, 1 GB maxalloc, 6 CU

Two runs, `vram=50%`. This is the machine multi-buffer rescued: at 8 MB it now
gets 256 nonces on 2 buffers instead of 128 on one.

| variant | KB | nonces | GPU H/s | CPU8 H/s | GPU:CPU (A / B) |
|---|---|---|---|---|---|
| v5 1MB | 1024 | 2048 | 454.3 / 454.7 | 328.9 / 337.5! | 1.38x / 1.35x |
| v5 1.5MB | 1536 | 1344 | 345.1 / 345.4 | 183.0 / 183.3 | 1.89x / 1.88x |
| v5 2MB | 2048 | 1024 | 276.0 / 278.0 | 153.3 / 154.5 | 1.80x / 1.80x |
| v5 4MB | 4096 | 512 | 130.3 / 131.2 | 118.5 / 118.9 | 1.10x / 1.10x |
| v5 8MB | 8192 | 256 | 38.0 / 38.3 | 100.9 / 101.1 | 0.38x / 0.38x |
| v6 HF13 | 8192 | 256 | 38.2 / 38.4 | 98.4 / 99.0 | 0.39x / 0.39x |
| **v7 HF14** | 24576 | 80 | 55.5 / 55.6 | 15.6 / 15.4 | **3.55x / 3.61x** |

### 4.5 Ryzen 7 9700X (16T) + gfx1036 integrated GPU, 1 CU

gfx1036 is the Raphael iGPU: 1 compute unit, "VRAM" is shared system memory.
It is not a gaming card and not the threat model, but it is the machine that
exposed section 2.7. Run 1 produced aborted-kernel garbage (every bad row
flagged `!`); run 2 on the same machine was sane:

| variant | KB | nonces | run 1 GPU H/s | run 2 GPU H/s | run 2 GPU:CPU |
|---|---|---|---|---|---|
| v5 1MB | 1024 | 6208 | 111.5 | 116.8 | 0.03x |
| v5 1.5MB | 1536 | 4096 | 114.9 | 114.9? | 0.03x? |
| v5 2MB | 2048 | 3072 | **32,167,539.3!** | 109.6 | 0.04x |
| v5 4MB | 4096 | 1536 | **123,870,967.7!** | 98.4 | 0.12x |
| v5 8MB | 8192 | 768 | **34,439,461.9!** | 84.8! | 0.25x |
| v6 HF13 | 8192 | 768 | **33,982,300.9!** | 92.8 | 0.30x |
| v7 HF14 | 24576 | 256 | **11,583,710.4!** | (see note) | 0.35x |

Its CPU column is sound and useful: 3864.4 H/s at v5 1MB down to 305.6 at v6,
and it is the source of the 9700X figures used in section 5.2.

Two cells marked `?` are transcription-uncertain. The run-2 1.5 MB GPU value
reads the same 114.9 as run 1, and 114.9 / 3233.5 is 0.04x, not the 0.03x
recorded, so at least one of the three is misread off the photo. One cell of
the v7 row in the run-2 photo was not legible either; its ratio is recorded as
printed. Neither affects any conclusion: this machine's GPU is an iGPU and is
excluded from the resistance comparison.

---

## 5. Conclusions

### 5.1 v7 is the weakest candidate on the axis it was designed for

It loses outright to the GPU on **every** card tested, at every VRAM setting,
across two independent versions of the tool:

| card | GPU:CPU on v7 |
|---|---|
| RTX 3050 | 1.33x |
| Vega FE | 2.02x / 2.07x |
| GTX 1050 Ti | 3.55x / 3.61x |

It is also the most expensive to verify by an order of magnitude on the hash
core alone (67.60 ms against v6's 6.95), about 8x once the chain fill is
included on both sides.

**v7 is not worse on all three axes. It is the best of any variant on CPU
fairness**, with a 1.12x single-thread spread between the 9700X and the 5600X
against v5 1MB's 1.99x and v6's 1.24x (section 5.2). That is almost certainly
because a 24 MB serial chase is pure DRAM latency, and DRAM latency is similar
across CPUs.

An earlier version of this document claimed v7's spread was 2.65x, the worst of
any variant. That was wrong: it was computed from a pre-fix run in which the
5600X's v7 1T read 117.51 ms, against 48.48 / 48.45 ms in the current
best-of-2 runs on the same machine. The old figure was contaminated.

So the case against v7 rests on two axes, not three: it is the worst tested
option for GPU resistance, and the most expensive to verify by a wide margin.
Those are sufficient, but the CPU-fairness argument against it does not hold.

### 5.2 Pad size buys CPU fairness, not GPU resistance

Single-thread cost, 5600X divided by 9700X, from the matched `vram=50%` runs.
The spread narrows monotonically as the pad grows:

| pad | 9700X 1T ms | 5600X 1T ms | spread |
|---|---|---|---|
| v5 1MB | 2.17 | 4.31 | 1.99x |
| v5 1.5MB | 3.32 | 5.30 | 1.60x |
| v5 2MB | 3.99 | 5.83 | 1.46x |
| v5 4MB | 5.16 | 6.73 | 1.30x |
| v5 8MB | 6.02 | 7.47 | **1.24x** |
| v6 | 6.93 | 8.58 | 1.24x |
| v7 | 43.45 | 48.48 | 1.12x |

Whole-machine, 7950X 32T against 5600X 12T (core ratio 2.67x): the big machine
earns 3.51x at v5 1MB, more than its core count justifies, but only 2.22x at
8 MB and 2.19x on v6, less than it justifies. Per thread at 8 MB the 6-core
5600X actually beats the 16-core 7950X by 1.20x, having 2.67 MB of L3 per
thread against 2.0. The big pad inverts the core-count advantage rather than
merely equalising it.

Caveat: Zen 3 against Zen 4, so some of the 1 MB gap is IPC, not core count.
The direction is solid; the exact multiple is not.

GPU resistance from pad size is card-dependent, weaker than assumed, and not
even monotonic on one of the three cards:

| pad | RTX 3050 | Vega FE | GTX 1050 Ti |
|---|---|---|---|
| v5 1MB | 0.11x | 1.50x | 1.38x |
| v5 1.5MB | 0.11x | 1.31x | **1.89x** |
| v5 2MB | 0.11x | 1.19x | 1.80x |
| v5 4MB | 0.12x | 1.05x | 1.10x |
| v5 8MB | 0.10x | 0.75x | 0.38x |

The 3050 is flat: pad size does nothing for it. The Vega falls monotonically.
The 1050 Ti gets **worse** from 1 MB to 1.5 MB before improving, so a modest
pad increase is not reliably an improvement. Only at 4 MB and above do all
three agree that a bigger pad helps.

Where it does help, the resistance rests on VRAM scarcity, and even a 16 GB
Vega runs ~1% occupancy at 8 MB. Every card generation erodes this.

### 5.3 The fairness knob and the verification-cost knob are the same knob

Equalising CPUs requires `threads x pad` to exceed L3, which on a 7950X means
4 MB or more, which costs roughly what v6 costs. There is no pad size that
buys cheap verification *and* CPU fairness.

v7 is the clearest illustration of this, once its corrected figures are used.
It has the fairest CPU profile of anything tested (1.12x spread) *and* the
highest verification cost by a factor of eight. It bought the fairness by
being enormously more expensive, which is the same trade every larger pad
makes, just further along the curve.

### 5.4 The chain fill may be the real pool/GPU resistance

It is ~2.2 ms of v6's 9.15 ms per nonce, needs the ~280 MB block cache
resident, and does ~256 serial HC-128 key setups per nonce. No GPU miner can do
that cheaply. The GPU harness models none of it, so every `GPU:CPU` figure here
is pessimistic in the safe direction. If the pad is not providing GPU
resistance, this is the mechanism that is, and the one worth strengthening.

---

## 6. Known gaps

- Aborted kernels are flagged (`!`) but not yet rejected (section 2.7).
- The 3050 and 1050 Ti columns in section 4 have not been re-taken at matched
  VRAM percentages against the Vega's corrected 50% figures for every pad.
- The chain fill (~1.6 / ~2.2 ms) is inferred from miner calibration, not
  measured directly against the LMDB.
- `t_clsag` in `contrib/hf14checks` does not link (missing `ws2_32`).
- Section 4.5 has two transcription-uncertain cells, marked `?`.
- The 1.25 MB pad exists only in the CPU tool (section 3). The GPU tool was
  trimmed to 1 / 1.5 / 2 / 4 / 8 MB, so section 4 has no 1.25 MB row.
