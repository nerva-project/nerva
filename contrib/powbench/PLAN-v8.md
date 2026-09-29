# CNA v8: plan

A v5-derived PoW for Nerva, aiming to beat the current v6 on all three axes at
once. Every target below comes from measurements in `RESULTS.md`; read that
first, especially section 2 (the mistakes) and section 7 (known gaps).

## Targets, measured against v6 8MB as it ships today

| axis | v6 8MB today | v8 target | why this number |
|---|---|---|---|
| verify, 7950X 1T | 10.11 ms | **< 8 ms** | sync speed was the original complaint |
| verify, i7-7700HQ 1T | 27.51 ms | **< 15 ms** | the weakest machine is what gates fairness |
| cross-CPU spread (4 CPUs) | 2.91x | **< 2.2x** | v5 4MB already reaches 2.15x |
| GPU:CPU, worst of 4 | 0.05x | **<= 0.05x** | do not regress what v6 does well |

If a change cannot hold all four, it does not ship. v7 failed because it was
allowed to trade verification cost away for a benefit that never materialised.

## Starting point

**v5 (`cn_slow_hash_v11`) at a 4 MB pad**, not 1 MB and not 8 MB.

- 1 MB fits in on-die SRAM at useful core counts (~200 MB for an ASIC to match
  one 7950X), so it is the ASIC-friendly size.
- 8 MB punishes small-cache CPUs: the 6 MB-L3 laptop takes 27.51 ms on v6 8MB
  against 9.46 on a 9700X, and can only use 3 of its 8 threads.
- 4 MB measured 2.15x cross-CPU spread and 7.96 ms on the laptop, and forces
  an ASIC to ~680 MB to match one CPU, which is HBM territory.

v5 keeps what it already has and v6 lacks: three data-dependent hash
datapaths, per-sweep variable strides, variable work per nonce (4.7x), and a
variable AES pipeline width. See RESULTS.md section 6.3 and the discussion of
`salt_pad`.

---

## Phase 1: the free change (do first, measure, stop if it costs anything)

**Use all four hash functions in `salt_pad`.**

`src/crypto/slow-hash.h`:
```c
extra_hashes[a % 3](salt, 200, salt_hash);   ->   extra_hashes[a % 4]
```

The table already declares four entries and Skein is never selected. Skein is
Threefish-based, structurally unlike Blake (ARX), Groestl (AES-like) or JH, so
this forces a fourth distinct datapath into any ASIC that cannot be trimmed.

- Cost to CPU: Skein runs at comparable speed to the others, ~30 calls per
  nonce on 200 bytes. Expect under 1% on verification. **Measure it.**
- Cost in silicon: an entire additional hash core.
- Risk: none beyond being a consensus change.

Gate: if verification moves more than 2%, reconsider.

## Phase 2: floating point (the substantive work)

This is the only lever identified that is asymmetric: a CPU runs IEEE-754
double precision at the same rate as integer, it costs **no extra memory** so
it does not hurt small-cache machines, and it barely touches verification. An
ASIC must implement full IEEE-754 with four rounding modes, denormals and NaN
handling, which is large silicon that cannot be simplified without breaking
consensus. It is the biggest single gap between both v5 and v6 and RandomX.

### 2a. Design

v5 has no VM, so there is no instruction stream to add FP opcodes to. Add an
FP stage to the main loop instead, fed from live AES state so it stays
data-dependent:

- Carry 4 double-precision registers alongside the existing integer state.
- Each main-loop iteration: convert part of the AES output to doubles, apply
  add / sub / mul / div / sqrt, fold the result back into the integer state so
  it is load-bearing and cannot be skipped.
- Change the rounding mode from data periodically, RandomX's `CFROUND`. This
  is what defeats a fixed-function FP pipeline.

### 2b. Determinism, which is the real risk

Cross-platform FP determinism is a consensus-critical hazard. A single ULP of
disagreement between x86 and ARM, or between two compilers, forks the chain.
Non-negotiable rules:

1. **Only add, sub, mul, div, sqrt.** All are IEEE-754 exact and correctly
   rounded. No transcendentals, no FMA (contraction changes results), no x87.
2. **SSE2 only on x86**, compiled with `-mfpmath=sse -ffp-contract=off`. Verify
   the generated code contains no `fma`.
3. **Constrain register values** the way RandomX does for its E group: force
   the sign bit to 0 and pin the high exponent bits, so values stay in a
   bounded positive range and denormals, infinities and NaN are unreachable.
4. **Set and restore MXCSR explicitly.** Do not inherit FTZ/DAZ from whatever
   the caller left behind.
5. **Cross-platform test is a merge blocker**: identical hashes on x86-64 and
   ARM64, HW-AES and SW-AES paths, GCC and Clang, debug and release.

If rule 5 cannot be satisfied, phase 2 does not ship. An algorithm that hashes
differently on two machines is worse than no change at all.

### 2c. Measure after

Re-run the four targets. FP should cost near zero on verification. If it
costs more than ~5%, the FP stage is too heavy; reduce the op count per
iteration rather than dropping the phase.

## Phase 3: pad and parameter tuning

Only after phases 1 and 2 are measured.

- Sweep the pad from 2 to 8 MB on all four machines and pick the knee where
  cross-CPU spread and verification both stay inside target.
- Review whether `xx`/`yy` ranges [4,8] and `iters` [0,63] should widen. More
  variance in work per nonce is ASIC-hostile but raises verification variance,
  which matters for block propagation.
- `randomize_scratchpad_256k` and the salt wrap: fix the two latent
  assumptions documented in `contrib/hf14checks/v5pad.inc` before any pad
  other than 1 MB ships. They are not live bugs at 1 MB and are hard bugs at
  any other size.

## Phase 4: plumbing

- `CN_SCRATCHPAD_MEMORY_V8` and a new `cn_slow_hash_v15` (or reuse the v11
  entry point with a size parameter; decide early, it affects the test harness).
- `get_block_longhash_v15` in `cryptonote_tx_utils.cpp`, keeping the existing
  `HC128_Init` + `get_cna_v5_data` chain fill unchanged. **The fill is the
  pool resistance and must not be weakened.**
- Hard-fork table entry, `ASSUME_VALID_HEIGHT` bump, seed-height handling.
- Both HW and SW AES paths (`slow-hash-hw.c`, `slow-hash-sw.c`) must produce
  identical hashes; `cn_slow_hash_self_test` must cover v8.

## Phase 5: validation

- Extend `contrib/hf14checks/t_bench_v5v6.cpp` with v8; the control row must
  stay at ~1.00x.
- Extend `contrib/powbench` with a v8 kernel and C reference. **The checksum
  gate must pass**; a row that does not verify gets no ratio.
- Run all four machines at identical `vram` and `launch cap`.
- Testnet round with the full HF14 test procedure from the runbook.

---

## Open items carried in from RESULTS.md

1. **No GPU number is trustworthy at full occupancy.** Every large-pad row on
   every machine hit the launch cap, because a display-attached GPU trips TDR.
   One card running headless would fix this and would settle the pad question,
   which is currently blocked on measurement rather than on analysis.
2. **v7's CPU figure on the 7950X is 40% above the real function** and reads
   faster on a slower CPU, which is impossible. Unexplained.
3. **The ASIC reasoning is not measured.** It is arithmetic about SRAM density
   and concurrency, anchored to the historical CryptoNight ASIC experience. It
   has not been validated against real hardware and should be weighted as
   engineering estimate, not evidence.
4. **Nerva's CPU miner is itself an interpreter** (`cn_vm_execute`). If v8 ends
   up with a VM-like FP stage, JIT-ing the CPU miner is a cheaper way to widen
   the CPU/GPU gap than another algorithm change.

## What not to do

- Do not add work to the chain fill to buy ASIC resistance. The fill runs
  during verification, so it is a direct sync-speed tax.
- Do not grow the pad past the smallest target machine's L3. That punishes
  exactly the machines fairness is meant to protect.
- Do not ship any phase whose verification cost is not measured on the weakest
  machine in the set, not the fastest.
