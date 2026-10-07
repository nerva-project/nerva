# CNA v8: plan

A v5-derived PoW for Nerva, aiming to beat the current v6 on all three axes at
once.

**Companion documents, all in this directory:**

- [FINDINGS.md](FINDINGS.md) is the evidence. Numbered findings F1 to F41, each
  stating how it was checked and, where it was later shown wrong, what replaced
  it. Nothing enters it from a comment or a commit message alone.
- [RESULTS.md](RESULTS.md) is the v5 / v6 / v7 comparison that set the targets
  below. Section 2 lists the mistakes made along the way and section 7 the known
  gaps.
- [BUILD.txt](BUILD.txt) is how to build and run the benchmark harness.
- [V6-MINER-LOG.md](V6-MINER-LOG.md) is the v6 miner optimization project: what
  a tuned miner actually gets on the live algorithm, measured, and ten lessons
  written to be checked against a proposed v8 change. It is the evidence behind
  Phase 7. The code it describes is on a personal fork and is not proposed here.
- [PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md) is what to change in v8 now that the
  v6 miner project has finished. It supersedes the Phase A list below where the
  two disagree, and it **reopens the pad decision downward**: F24 and F27 swept
  1 to 8 MB and never measured below 1 MB, so the chosen size is the endpoint of
  the sample rather than a bracketed minimum, and every trend in that sample
  points off that end. 512 KB and 256 KB are buildable in the existing harness.

Every target below comes from measurements in [RESULTS.md](RESULTS.md); read
that first.

**Where to start if you only read one thing:** F41 for what the floating-point
stage costs a real miner, F37 for whether it helps against GPUs, and F38 for the
reason those two answers came out the way they did.

## Status

**Phases 1 and 3 to 6 are done. Phase 2, floating point, is built and measured
but not shipped and not decided.**

| phase | state |
|---|---|
| 1, fourth hash function | done, measured on four machines |
| 2, floating point | built and measured, **not shipped**; leaning against |
| 3, pad and parameters | done, pad is 1 MB |
| 4, plumbing | done, `get_block_longhash_v14` live at major_version >= 14 |
| 5, validation | done; the testnet fork round passed on two machines, F49 |
| 6, hardening vs the measured miner | B1, B2, B3 and A1b all landed |
| 7, implementation gap and the pad size | **planned, not started**; see [PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md) |

Phase 6 exists because [0xROOTPLS](https://github.com/0xROOTPLS) built an optimized miner, measured it
at 2.43x the reference and reported it in full. Its breakdown showed that once
the deferrable parts are removed the chain fill is the only irreducible work v8
has.

What v8 is, in one sentence: **v5 with `salt_pad`'s extra-hash selector widened
from three entries to four, at v5's 1 MB pad, using v6's windowed chain fill.**

v7 has been deleted. It was written for this same fork but never released: it
did not perform, HF14 never activated while it existed, so no block was ever
validated with it, and v8 took its slot. There is therefore no new hard fork
version and no second upgrade for users.

HF14 also carries CLSAG, Bulletproofs+ (type 7) and ring size 16. Those are
orthogonal to `get_block_longhash` and untouched by any of this, so the PoW work
could have failed without taking them down.

Everything asserted here about the existing code is recorded, with how it was
checked, in `FINDINGS.md`. Read that before trusting a comment in this tree.

## Targets, and what v8 actually achieved

Set against v6 as it ships. v8 figures are at its 1 MB pad, from `v8bench` on
four machines.

| axis | v6 today | target | **v8 result** |
|---|---|---|---|
| verify, 7950X 1T | 6.95 ms | < 8 ms | **0.77 ms** |
| verify, i7-7700HQ 1T | 27.51 ms | < 15 ms | **1.58 ms** |
| cross-CPU spread, 1T | 2.91x | < 2.2x | **2.39x**, missed |
| cross-CPU spread, nT | not measured | (added) | 11.3x, against 23.8x at 4 MB |
| GPU:CPU, worst of 4 | 0.05x | <= 0.05x | **not measured for v8** |
| cost estimable ahead | r = 0.88-0.95 | r < 0.1 | **not measured for v8** |

Verify cost is met with an order of magnitude to spare, which was the original
complaint and is no longer the constraint anything is traded against.

**The 2.2x spread target is not met and cannot be met by pad tuning**, since
1 MB is already at the favourable end of that curve. Closing it needs work that
adds cost without adding memory, which is what Phase 2 is for. That makes Phase 2
load-bearing rather than optional if the target is firm.

**Two targets are unmeasured for v8.** The GPU ratio needs a powbench kernel.
The cost-predictability gate needs `screen.c` adapted, and since v8 has no VM
the estimator has to be redesigned around v8's cheapest predictor; that choice
is the whole test and deserves review rather than being picked by whoever writes
the patch. Note v8 inherits v5's protection here ([FINDINGS.md](FINDINGS.md) F5): the per-nonce
parameters come from an HC128 state that the chain fill re-seeds from its own
output, so cost cannot be learned without doing the fill.

## Starting point, and where it ended up

Started from **v5 (`cn_slow_hash_v11`)**, intending a 4 MB pad. It ships at
**1 MB**, v5's own size, because the measurements went the other way.

The original reasoning was that 1 MB is "the ASIC-friendly size" and that a
larger pad narrows cross-CPU spread. Neither survived:

- **Fairness is not monotonic in pad size.** Single-threaded, 1/2/4 MB sit
  within noise of each other and 8 MB is far worse. Multi-threaded, which is
  where "1 CPU = 1 vote" actually lives, 1 MB is the clear winner at 11.3x
  spread against 4 MB's 23.8x. A larger pad excludes small-cache machines from
  threading first: the 6 MB-L3 laptop gets no benefit at all from its four cores
  at 4 MB and above.
- **The ASIC argument was never measured.** It was arithmetic about SRAM density,
  linear in pad size by construction, flagged as an estimate in this document's
  own open items, and at this chain's size an ASIC is not a plausible economic
  threat. v5 also ran at 1 MB from HF11 to HF13, about 3.8M blocks, without one
  appearing.
- **The GPU comparison cannot settle it.** It swings 2.8x with nonce count and
  4x with the launch cap, and the large-pad rows ran starved, so they are floors
  compared against an honest small-pad number.

See [FINDINGS.md](FINDINGS.md) F24, F27, F28. The one open question is GPU behaviour at 1 MB at
full occupancy, which no measurement has covered and which is being referred to
someone with the GPU depth to answer it.

## The rule that governs every phase: historical PoW does not change

**No edit may alter the hash any already-mined block was validated against.**

This is not a style preference. It is the single easiest way to break this
chain, and the codebase makes it easy to do by accident:

- `salt_pad` in `src/crypto/slow-hash.h` is expanded by **both**
  `cn_slow_hash_v10` and `cn_slow_hash_v11`, in both the HW and SW arms of
  `slow-hash-impl.h`. `get_block_longhash` routes major_version 10 to v10 and
  11 and 12 to v11. Editing that macro in place rewrites PoW for heights
  341,000 through 4,320,000.
- It would do so **silently for almost everyone**. `ASSUME_VALID_HEIGHT` is
  4,320,000 and `Blockchain::block_needs_pow` skips PoW below it under fast
  sync, so a fast-syncing node never recomputes those hashes. The divergence
  surfaces only with `--fast-block-sync 0`, in FAKECHAIN tests, or for anyone
  auditing the chain from genesis. A consensus break that hides from the
  default sync path is the worst failure mode available here.

So: every algorithm change lands as a **new macro and a new entry point**,
with `cn_slow_hash_v10` and `cn_slow_hash_v11` left byte-identical. The diff
that touches a live function is the one-line dispatcher change at the fork
version, and nothing else.

This has already been close. HF14 appended v7's `seg_hops` generation to
`cn_vm_generate_program`, a function live HF13 consensus calls on mainnet
today. It is correct only because those draws land after the 512-instruction
loop, leaving v6's instructions untouched. Note also that `git diff` reported
it as pure insertion, 255 added and 0 removed, which reads as safe and is not:
an insertion *inside* a live function changes that function. See [FINDINGS.md](FINDINGS.md)
F9.

## The second rule: a nonce's cost must not be knowable in advance

A PoW is easiest to reason about when every nonce costs the same. Where cost
varies, it should at least not be estimable more cheaply than the nonce can be
hashed, or the work a hash represents stops being uniform.

v6 does not hold this. [FINDINGS.md](FINDINGS.md) F6 measures an estimate built from the
program alone, no registers and no memory, that tracks real cost at r = 0.88
to 0.95. Five design rules follow, and they bind every phase below.

1. **Control flow must depend on values loaded from the pad.** v6's
   `CN_OP_CBRANCH` tests `regs[dst] & (imm | 1)` against a mask with ~16.5 set
   bits, so it is taken except about once in 2^16.5. A condition that one-sided
   is not a branch, it is a fixed jump, and the trace becomes a property of the
   program rather than of the data. Use a balanced condition (a single-bit
   test, or a mask with few set bits) on a register that a pad load has
   written.

2. **Do not reset control state between passes.** `cn_vm_execute` sets `pc = 0`
   and `chain = 0` on entry and is called 2048 times with one program, so every
   pass restarts the same walk. Carry them so later passes diverge. Rules 1 and
   2 have to land together: carrying `pc` alone changes nothing while the
   branch stays one-sided.

3. **Derive per-nonce parameters only from state that requires the whole
   prologue.** This is where v5 is already correct, and for a stronger reason
   than statement order. `get_cna_v5_data` re-seeds its own HC128 state from
   bytes it has already written, so the state that yields `xx`, `yy`,
   `init_size_blk` and `iters_divisor` depends on the salt's content. The
   keystream cannot be fast-forwarded; the salt has to be produced, which needs
   the block cache, which needs a full node ([FINDINGS.md](FINDINGS.md) F5). Keep that
   feedback. Contrast v6, whose seed reads only `salt[0..32)`, available after
   about one of 4096 fill iterations (F8).

4. **Prefer constant work per nonce.** v7 gets this right and it is the one
   piece of it worth carrying forward: `seg_hops` sums to exactly `CN_V7_HOPS`
   by construction, so every nonce issues the same number of accesses while the
   rhythm still differs. v5 varies 4.7x through `(xx-1) * yy` in [12, 56], safe
   today only because of rule 3, which makes rule 3 load-bearing rather than
   incidental.

5. **Test it before shipping, on the candidate, not on the argument.**
   `contrib/powbench/screen.c` is the harness. Pass condition is r near zero.

If Phase 2 adds a floating-point stage, rules 1 and 2 apply to it as well. FP
that never feeds control flow is untouched by this; FP-driven branches
reintroduce the problem unless the operands come from pad loads.

## Phase 1: the fourth hash function  [DONE]

**Result: v8 is 0.23% to 0.75% cheaper to verify than v5 across four machines**,
against a prediction of -0.84% made from the hash costs alone before any run.
Skein is the cheapest of the four on 200 bytes (290 ns against Groestl's 1758),
so widening the selector lowers the mean cost per `salt_pad` call. A fourth
structurally distinct datapath, for nothing. [FINDINGS.md](FINDINGS.md) F18.

Two things it took to get a trustworthy number, both recorded in F19: the bench
sampled 60 nonces against a 4.7x work spread with a fixed RNG seed, so a pure
sampling artifact reproduced across runs and looked real; and v5 and v8 had to
be measured interleaved within one pass rather than as consecutive blocks.


**Use all four hash functions in the `salt_pad` extra hash.**

`src/crypto/slow-hash.h:129` currently reads `extra_hashes[a % 3]`, so Skein
is never selected even though the table declares four entries. Skein is
Threefish-based, structurally unlike Blake (ARX), Groestl (AES-like) or JH, so
forcing it into the selection puts a fourth distinct datapath into any ASIC
that cannot be trimmed away.

Skein already ships and is already consensus-live: `finalize_hash` selects it
via `extra_hashes[state.hs.b[0] & 3]`, so roughly a quarter of every v5, v6
and v7 hash already terminates in Skein. Phase 1 adds no new code, no new
dependency and no new endianness surface. That is what makes it cheap.

### 1a. New macro, live macro untouched

Add `salt_pad_v8` next to `salt_pad` in `slow-hash.h`, identical in every line
but the selector:

```c
extra_hashes[a & 3](salt, 200, salt_hash);
```

`& 3` rather than `% 4`: identical on unsigned, and it matches how
`finalize_hash` already selects. Keep the other eight lines byte-identical so
a reviewer diffs one token.

Do **not** parameterise the existing macro and redefine `salt_pad` in terms of
it. It is tidier and it forces a reviewer to prove the live expansion is
unchanged. For a consensus function, prefer the copy.

Free side effect worth recording: `a` is `uint16_t` and 65536 is divisible by
4, so `& 3` is exactly uniform where `% 3` is slightly biased toward Blake.

### 1b. New entry point `cn_slow_hash_v14`

These functions are named for the hard fork that introduces them, not for the
CryptoNight-Adaptive generation, which is why there is no v12 and why CNA v8
becomes `cn_slow_hash_v14`. The name was held by CNA v7, which is deleted
first: it never released, so no chain history refers to it. Copy the `v11` body twice, once per arm, swapping
`salt_pad` for `salt_pad_v8` and changing nothing else. Same signature
(`iters`, `init_size_blk`, `xx`, `yy`).

| file | what |
|---|---|
| `slow-hash-impl.h` (HW arm, SW arm) | the two bodies |
| `slow-hash-hw.c`, `slow-hash-sw.c` | `#define cn_slow_hash_v14 cn_slow_hash_v14_hw` / `_sw` |
| `slow-hash.c` | externs plus the `CN_DISPATCH` wrapper |
| `hash-ops.h`, `hash.h` | declaration and C++ inline |

**The two bodies are not the same body, and the difference is deliberate.**
`slow-hash-impl.h:57` reads `uint16_t *r2 = (uint16_t *)&c;` in the HW arm and
`:354` reads `(uint16_t *)&b;` in the SW arm. That asymmetry looks like a
copy-paste error and is the fix for one: commit `4d87b5f` changed the SW path
to `&b` in April 2019 under the message "Fix for non-AES pathway not syncing",
after it had shipped disagreeing with the HW path for about a month. Copy each
arm from its own arm and do not reconcile them. Reconciling them forks HW from
SW, and only on machines without AES-NI, which is where it will be found late.
See [FINDINGS.md](FINDINGS.md) F3.

**No `get_block_longhash_v14` and no dispatcher change in Phase 1.** This
phase is measurement. The consensus diff stays at zero and the whole phase
reverts with one `git revert`. Wiring it to major_version 14 happens in
Phase 4, once phases 1 to 3 have all been measured.

### 1c. Wire it into the pad-resize machinery

`contrib/hf14checks/v5pad.inc` renames each variant per translation unit. Add
`#define cn_slow_hash_v14 V5PAD_CAT(cn_slow_hash_v14_, V5PAD_TAG)` to that
block and `v5pad1.c` / `v5pad4.c` give v8 at 1 MB and 4 MB for free.

Measure at both. 1 MB isolates the selector change against the shipped
reference. 4 MB is where v8 is intended to live, and the salt wrap in
`v5pad.inc` is live there, so it is a different code path.

### 1d. The measurement

Add three rows to `VS[]` in `contrib/hf14checks/t_bench_v5v6.cpp`: `v8ref`
(dispatcher, `own_pad` 0), `v8ctl` (`cn_slow_hash_v14_p1`, 1 MB) and `v8_4`
(`_p4`, 4 MB). Keep every existing row.

The comparison that decides the gate is **`v5ctl` vs `v8ctl`** and **`v5_4` vs
`v8_4`**: same translation unit, same flags, same pad, one token of
difference. `v5ref` and `v8ref` cross-check that the in-tree build agrees with
the recompile.

Two traps, both of which have already bitten this work:

1. `contrib/hf14checks/CMakeLists.txt` names the resized TUs explicitly in
   `set_source_files_properties`. A new TU that is not in that list builds at
   the directory default, which is `-O0`, and the comparison inverts. This is
   the trap that reversed the conclusion twice.
2. If `v5ref` and `v5ctl` stop agreeing at ~1.00x, nothing below that line
   means anything, v8 rows included.

### 1e. State the prediction before measuring

Expect **neutral to marginally faster**, not slower.

`salt_pad` runs `(xx-1) * yy` times per nonce, so 12 to 56 calls with a mean
near 30. Each call's cost is dominated by its pad sweep, `for (j = offset_1;
j < CN_SCRATCHPAD_MEMORY; j += offset_2)` with `offset_2` in [4,128], meaning
8k to 262k byte-XORs at 1 MB and four times that at 4 MB. One 200-byte extra
hash against that is noise. And the mix moves Groestl, the slowest of the four
on short inputs, from 1/3 of calls to 1/4 while adding Skein at 1/4.

**The gate is self-calibrating, because a fixed 2% is not measurable.** The
bench's runs agree within about 4% (RESULTS.md section 3), so a flat 2%
threshold sits inside its own noise and a pass could not be told from a fail.
Instead, the control pair sets the resolution: `v5ref` and `v5ctl` are the same
source at the same size, so whatever they differ by *is* the harness's noise
floor for that run.

    pass if |v8ctl - v5ctl| <= max(2%, 2 x |v5ref - v5ctl|)

Report both numbers, always. If the control pair differs by more than 4% the
run is too noisy to conclude anything and the machine, not the algorithm, is
what needs attention. Measuring `v5ctl` and `v8ctl` interleaved within one
process rather than as consecutive blocks is what makes the floor small enough
to be useful, since thermal drift then hits both rows equally.

### 1f. HW equals SW

Add a `v14` pair to `cn_slow_hash_self_test` mirroring the existing `v11`
pair, including the `memset(ctx->salt, ...)` between the two calls, since
`salt_pad` writes back into `salt`. `xx/yy = 2,2` keeps it in milliseconds
while still hitting both loop levels. This passing is a precondition for
reporting any number.

### 1g. What Phase 1 cannot tell you

`contrib/powbench` does not model `extra_hashes` at all: the kernel and the C
reference substitute a mix64 chain of equal call count, deliberately. So the
GPU:CPU column is unchanged **by construction, not by measurement**. Record it
as not applicable in RESULTS.md, or the table claims a result it did not
produce. The ASIC argument for Phase 1, a fourth hash core that cannot be
trimmed, stays an engineering estimate under open item 3.

### 1h. Exit criteria

- `v14` HW output equals SW output at 1 MB and 4 MB
- `v8ctl` within the self-calibrating gate above of `v5ctl`, on all four
  machines, gated on the i7-7700HQ and not the 7950X
- control rows still ~1.00x
- RESULTS.md carries the four-machine table, and this section records the
  measured figure, not the predicted one

## Phase 2: floating point  [BUILT AND MEASURED, not shipped, removed from the tree]

**Removed so it does not ship, and preserved at the signed tag
`archive/cna-v8-fp-stage`**, where the stage, its self-test, `t_fp_stage` and
the fp-portability workflow all build and pass. This section describes the code
as it stands at that tag; FINDINGS F29 to F41 are the evidence.

The stage exists as `cn_slow_hash_v15`, wired into nothing. Consensus still
routes HF14 to `cn_slow_hash_v14`. Every question raised against it has been
answered, and the answers do not all point the same way. See "Where this
leaves the decision" at the end of this phase.

### Why, revised

The original justification was ASIC resistance. That is gone: at this chain's
size an ASIC is not a credible economic threat. Two better reasons replace it.

**GPU resistance via FP64 rate limits. MEASURED AND WRONG (F37).** The reasoning
was that consumer GPUs cripple double precision, roughly 1/64 of FP32 on GeForce
and 1/16 on Polaris and Vega, while a CPU runs FP64 at integer speed, making it
the largest hardware asymmetry available that costs no memory.

It does not work, because the kernel is nowhere near FP-limited. Measured on
three cards, the stage costs a GPU 0.4% of a nonce against 4.4% on a CPU, so it
makes GPU resistance slightly *worse*. Hashrate per resident nonce is the same
within 10% across a ten-fold range of compute units, which says the card is
latency-bound and arithmetic added to it is free. This paragraph also had the
Vega FE at 1/2 rate; it is Vega 10, which is 1/16, so the test set never held a
high-FP64 card. That turned out not to matter, which is itself the finding.

So one of the two reasons for this phase is gone. The other still stands.

**Cross-CPU fairness, which v8 measured and missed** at 2.39x against a 2.2x
target. FP adds work without adding memory, so unlike a larger pad it does not
punish small-cache machines. It is the only lever left after Phase 3.

### What RandomX actually does, reviewed against the source

**Read FINDINGS F40 alongside this section.** It answers the question this review
does not: why RandomX has floating point at all, when Monero adopted it (November
2019, block 1978433, never in CryptoNight), and why that precedent does not carry
to a memory-hard loop. FP is 37% of a RandomX program and inseparable from it;
ours is a separable block, which is what F37 and F38 measured the cost of.

Monero vendors `tevador/RandomX`; there is no separate Monero variant. Reviewed
`doc/specs.md`, `src/intrin_portable.h` and `src/common.hpp`.

**The central lesson: RandomX does not normalise platform FP behaviour, it
constrains values so the divergent cases are unreachable.**

    x86:   rx_mxcsr_default = 0x9FC0   // flush to zero, denormals are zero
    ARM64: RANDOMX_DEFAULT_FENV        // default environment, no explicit FTZ/DAZ

Those are different settings on the two platforms, and it is harmless, because
the spec guarantees "no operation results in NaN or a denormal number". The
flags never fire.

**This supersedes what an earlier version of this plan said** ("set and restore
MXCSR explicitly, do not inherit FTZ/DAZ"). That is normalisation thinking: it
requires every platform to agree about denormal handling, forever. Constraint
requires them to agree only about correctly-rounded arithmetic, which IEEE-754
already mandates.

**The constraint, with real constants** (`src/common.hpp`):

    mantissaSize = 52, exponentSize = 11, exponentBias = 1023
    constExponentBits = 0x300      // top three exponent bits forced to 011
    dynamicExponentBits = 4, staticExponentBits = 4

Sign forced to 0, top three exponent bits forced to `011`, which pins the 11-bit
exponent field into [0x300, 0x3FF]: structurally unreachable from 0 (denormal)
and 2047 (infinity, NaN). Four more exponent bits and the low 22 fraction bits
come from per-program masks, varying magnitude without leaving the safe band.

**Three register groups, because the constraints differ:**

| group | role | constraint |
|---|---|---|
| F | additive | abs value stays under ~3.0e+14 |
| E | multiplicative | always positive, masked as above; only group taking div and sqrt |
| A | read-only constants | restricted to [1, 4294967296) |

Only E needs to be positive, because only E is square-rooted.

**Note what that list does NOT exclude: infinity.** `design.md` states "About 2%
(6.85% for RandomX v2) of programs produce at least one `infinity` value".
RandomX constrains group E *memory operands*, so register values may drift
upward, and it forbids NaN and denormals rather than all special values. Our
stage constrains every *result*, so infinity is structurally unreachable here.
Both are deterministic, because IEEE-754 specifies overflow precisely. The point
is that our value-safety argument is stricter than RandomX's and does not
inherit it: `slow-hash-fp.h` says so and `cn_fp_value_scan` proves it on the real
round body. FINDINGS F40.

**Instruction set:** FADD_R/M, FSUB_R/M, FMUL_R, FDIV_M, FSQRT_R, plus FSCAL_R
and FSWAP_R which are bit manipulation rather than arithmetic. Exactly the five
correctly-rounded IEEE-754 operations, nothing else.

**Why the spec never mentions FMA.** The interpreter does one operation per
instruction and stores to a register each time, so a compiler never sees
`a*b+c` as a single expression and contraction cannot happen. That is structural
and more robust than a compiler flag. Do both.

**Rounding changes are deliberately rare.** `CFROUND` rotates a register right
by imm32 and takes 2 bits; in v2 it only applies when bits 2-5 are zero, so
about one time in sixteen. Setting the mode is a register write on x86 and a
libc call on ARM, and in a hot loop that cost is real.

**Int to double conversion is exact by construction:** 8 bytes are read as two
32-bit signed integers, which need only 30 significand bits, so the conversion
needs no rounding and introduces no platform dependence.

### Design constraints for Nerva

v8 has no VM, so RandomX's instruction set cannot be copied directly. The FP
stage goes in v5's main loop instead. What carries over:

1. Only add, sub, mul, div, sqrt.
2. Constrain every FP register write with the group-E mask. Do not rely on
   FTZ/DAZ or on platforms agreeing about denormals.
3. One operation per statement, result stored before the next reads it, so FMA
   contraction is structurally impossible. Set `-ffp-contract=off` as well and
   verify the disassembly.
4. Change rounding mode from data, but rarely, roughly 1 in 16.
5. Convert integers to doubles by a route that needs no rounding.
6. Fold the FP result back into the integer state so it is load-bearing and
   cannot be skipped. Ablate and confirm the hash changes for every nonce; a
   construction can look strong while almost none of its randomness matters.

### The gate

`contrib/powbench/t_fp_determinism.c` tests the primitives under these
constraints and prints four checksums. Build and run on x86-64 and on ARM64
(a Pixel 7a under Termux is available); **all four must match exactly.** It
also carries an FMA-contraction canary that fails on a single machine if the
build flags are wrong.

If the determinism gate cannot be met, Phase 2 does not ship and v8 goes out as
it stands at 2.39x. That is an acceptable outcome, not a failure: v8 already
beats v6 on every measured axis.

### First, whether FP helps fairness at all  [DONE, answered yes]

The fairness argument rests on one sentence: "FP adds work without adding
memory, so unlike a larger pad it does not punish small-cache machines." That is
about memory. It says nothing about whether FP throughput is more or less
uniform across CPUs than memory latency is, and only the second thing decides
whether adding FP moves the spread toward 2.2x or away from it.

`contrib/powbench/t_fp_cost.c` settled it before any consensus code was written.
**The prediction recorded here and in 7c0b8f1 was that FP would spread wider
than 2.44x. It was wrong.** Full results and method in FINDINGS F33.

- **FP spread is 1.22x against the hash's 2.44x.** FP is roughly half as unequal
  as the work it would dilute.
- **FP is more uniform than integer work too**, not merely more uniform than
  memory. The probe's own integer scaffolding spreads 12.2x between a 7950X and
  a Cortex-A55 where FP spreads 2.5x. That is a stronger result than this plan
  claimed.
- **The rounding-mode cost is backwards in the text above and is corrected
  here.** x86 pays 4 to 5 times more than ARM, consistently across all four x86
  machines, because an MXCSR write serialises the pipeline while the ARM FPCR
  write is cheap. Data-driven rounding is the most ARM-favourable component
  measured, not a liability. Keep the 1-in-16 rate; there is no reason to lower
  it and a fairness reason to keep it.
- **The round count from the probe is superseded.** 7,640 was computed from
  `t_fp_cost`, and F34 shows that probe does not predict the stage: it ranks the
  M1 slower than a Pixel X1 where the real stage has the M1 2.4x faster. The
  stage is built and measured now, so the count comes from F34's numbers once
  the last three machines report.

So Phase 2 proceeds, and on a firmer footing than it had: the fairness argument
is now measured rather than assumed, and it is the first lever that reaches the
target at all.

Untested and required before shipping: the multi-threaded picture. Every figure
above is single-thread latency, and SMT siblings share FP units.

### Phase 2 status  [complete; measured on seven machines; ready for a ship decision]

The stage exists (`src/crypto/slow-hash-fp.h`, built as `cn_slow_hash_v15`) and
is not wired into consensus. What it has cleared so far, all in FINDINGS F34:

- **Determinism on the real algorithm**, not the primitives, and on every target
  tested. Seven targets, four instruction sets, five toolchains, both word sizes
  and both byte orders. The floating-point checks pass even on big-endian s390x,
  where the full hash differs for an integer reason that predates this work
  (F36). This was the risk that could have ended the phase, and it is closed.
  `.github/workflows/fp-portability.yml` keeps it closed.
- **Contraction immunity is structural**, verified by building with
  -ffp-contract=off and =fast and getting the same vector, because every FP
  write passes through integer bit manipulation and no a*b+c pattern exists to
  fuse.
- **The fairness target is met.** At 9,600 rounds the cross-CPU spread goes from
  2.388x to **2.201x**, against a target of 2.2x, measured on all seven machines
  with nothing projected. The gate passed everywhere.
- **The mechanism is anti-correlation**, which was not predicted: FP cost runs
  opposite to hash cost across this hardware, so a machine that leads on one
  axis trails on the other. That is why FP reaches a target pad tuning could
  not.

- **The multi-threaded picture holds** (F35). SMT contention is not a factor:
  the 7950X has the most SMT threads in the set and shows no extra cost, and the
  two Zen desktops make the stage *cheaper* under load, at under half its
  single-thread price, because the hash saturates memory bandwidth at high
  thread counts while the stage competes for none. Five of seven machines thread
  better with the stage than without it. Loaded spread narrows from 3.61x to
  3.31x across cooled desktops.

What varies under load is cooling, not architecture: a fanless mini PC, a laptop
and a phone all pay more, because the stage is clock-bound where the hash is
memory-bound. Judged across every machine including the phone the loaded spread
widens, 9.33x to 10.28x, and F35 records both that number and the project's
decision to scope against hardware that will actually mine.

**Phase 2 has no outstanding measurements.** What remains is a decision, not a
test: whether to ship the stage, and if so the fork mechanics of doing so. The
evidence is that it meets the fairness target on the per-core axis, narrows the
loaded axis on cooled hardware, is deterministic across four platforms and two
architectures, is immune to FMA contraction by construction, and costs constant
instruction count per nonce.

### The GPU question  [ANSWERED: the stage makes GPU resistance slightly worse]

**Result: GPU:CPU worsens by 1 to 4% on every card measured.** The stage costs a
GPU 0.4% of a nonce and a CPU 4.4%. Three cards, two vendors, three
architectures; the RX 580 failed to produce output and was not pursued, since it
sits inside the range already covered. FINDINGS F37 has the runs, the method,
the eight measurement errors found on the way, and the caveats.

The two arguments below are kept as written, because the point of recording them
was to see which survived. The first did. The second turned on an estimate that
was wrong by an order of magnitude: emulating directed rounding costs about 4x
per operation, not 10 to 50x, and 4x of work the card is not bound by is still
nothing. Point 3 also did not become the hoped-for compile failure. The kernel
compiles, and it passes the checksum gate, which means software-emulated directed
rounding is bit-exact against a real MXCSR.

The wider lesson is in F38: work added to the hash core is work a specialised
attacker can specialise, and the chain fill is the part they cannot.

What follows is the question as it stood before the measurement, kept for the
record. GPU resistance was half the original justification for adding floating
point and had never been measured. F28 had established that the existing GPU
table could not support strong conclusions, and the harness could not tell the
two arguments apart because it was entirely integer: there was no FP64 anywhere
in `vm_kernels.cl.h`.

**The argument against, from arithmetic.** Consumer GPUs do rate-limit FP64,
1/64 on the RTX 3050 and 1/16 on the RX 580, and the Vega FE is the exception at
1/2. But the GPU is not FP-limited here, it is memory-limited, by roughly three
orders of magnitude. The stage is 9,600 rounds x 5 ops = 48,000 FP64 operations
per nonce; call it 300,000 FMA-equivalents once divide and square root are
counted as the software sequences they are on NVIDIA. An RTX 3050 at about 0.14
FP64 TFLOPS could sustain roughly 440,000 nonces/s of that, against an actual
measured hashrate near 720 H/s (0.05x of the 7950X on v5 at 1 MB). It has about
600x more FP64 capacity than its hashrate can consume, so the stage would cost
it under 1% while costing a CPU 14 to 18%. On that reading FP makes GPU
resistance slightly **worse**, and GPU:CPU drifts from 0.05x toward 0.057x.

This is the same mechanism F35 measured on CPUs: the stage costs *less* under
full thread load on Zen desktops, because the hash saturates memory bandwidth
while the stage competes for none of it. A GPU is that situation in the extreme.

**The argument for, from what OpenCL cannot express.** The stage changes the
rounding mode from data, 600 times per nonce. OpenCL has no way to do that:
round-to-nearest-even is the only mode for arithmetic,
`cl_khr_select_fprounding_mode` was deprecated in OpenCL 1.1 and is not
implemented by current vendors, and only the `convert_*` functions take rounding
suffixes. An OpenCL miner would have to emulate directed rounding in software,
which for add, mul, div and sqrt means error-free transformations at perhaps 10
to 50x per operation. CUDA can express it, through `__dadd_rd`, `__dmul_ru` and
friends, but the mode is per-nonce data and a warp holds 32 nonces, so threads
select different intrinsics and the branch diverges, up to 4x on top of the FP64
rate limit.

That is a far stronger resistance mechanism than the rate limit, and it is the
component measured as cheap on ARM and expensive on x86 (F33). It costs a CPU
one MXCSR write.

**The test that settles it: three kernels, not one.**

1. `cna_v8`: the existing `cna_v5` kernel with `a & 3`, as the baseline
2. `cna_v8_fp_rne`: plus the FP stage at fixed round-to-nearest. Isolates the
   pure arithmetic cost and tests the prediction that it is nearly free
3. `cna_v8_fp`: plus data-driven rounding, as the algorithm specifies

The gap between 2 and 3 is the answer. **If 3 cannot be written in OpenCL at
all, the compile failure is the result**, and a stronger one than any timing.
Comparing the same kernel with and without FP also sidesteps the harness's
modelling caveats, since the extra-hash approximation cancels in the ratio.

**How it was built.** The three kernels are generated from one body in
`vm_kernels.cl.h`, so an FP row cannot drift from the baseline it is divided by,
and `fp_mode` is a compile-time constant at each call site so the unused path is
dead code. The CPU reference is `vm_v5` with an `fp_mode` argument, so all rows
check against one function.

`cna_v8_fp` computes the nearest-even result natively, recovers the exact
residual (2Sum for add and subtract, one `fma` for multiply, divide and square
root) and nudges by one ULP when the mode demands it. Exact for every value this
stage can produce, because the group-E constraint keeps operands in
[2^-255, 2). Written branch-free, because a warp holds nonces with different
modes and a miner would not write the diverging version.

Two things the harness needed before its numbers meant anything. The default set
holds **three rows of identical GPU work** bracketing the FP rows, so the
cross-row floor is measured rather than assumed. And **`fpxN`** runs the stage at
N times its round count and divides the cost back out, because at the real count
the GPU effect sits under that floor. Cost is linear in the count, checked at 1x
and 10x on both sides and independently on a second CPU.

**Where to run it:** the three machines with discrete GPUs. Not the laptop;
RESULTS 2.12 records that column as an Intel HD 630 rather than a discrete card.

### Where this leaves the decision

Against the three things this algorithm is for:

| | effect of the FP stage | evidence |
|---|---|---|
| GPU resistance | slightly worse, 1 to 4% | measured on 3 cards, F37 |
| ASIC resistance | slightly worse, Amdahl bound 1.6x to 1.8x | argued, F38 |
| CPU fairness | better by **2.7%** | measured on the daemon, F41 |
| Sync speed | +0.12 ms per block, about 6 s for a month offline | measured, F39 |
| **Cost to hashrate** | **about 6%, plus or minus 2** | measured on the daemon, F41 |

So the stage helps one of the three things the algorithm is for, and costs about
6% of hashrate to do it. The 2.2x figure was a target to aim at rather than a
requirement.

**The fairness number depends entirely on the denominator, and this is the most
important thing to understand about it.** Measured against `cn_slow_hash` alone
it is an 8% narrowing, 2.388x to 2.201x, which is the right basis for
verification cost and is what F34 reports. But a miner's nonce is the chain fill
plus the hash, and the fill dilutes the stage, so what a miner experiences is
**2.7%**, measured on three machines through the shipped daemon in F41. The
headline number is three times the real one.

The cost side is a new floating-point code path in consensus on a fork with no
successor planned for a long time. The determinism work is thorough: seven
targets, four instruction sets, both byte orders, structural FMA immunity and a
startup self-test. The risk is not zero.

**Recommendation: ship v14, keep v15 on the branch.** The trade is about 6% of
every miner's hashrate for a 2.7% narrowing of the spread, with GPU and ASIC
resistance each moving slightly the wrong way, bought at the price of the first
floating-point code in this chain's consensus on a fork with no successor planned
for a long time.

The measurement is what has value here regardless. It retired the GPU
justification with numbers rather than argument, and F38 generalises why: work
added to the hash core is work a specialised attacker can specialise, while the
chain fill is the part they cannot. That result stands whichever way the decision
goes. If fairness later matters more than it looks now, the stage is built,
tested on seven targets and ready.

**No decision has been made. It is the maintainer's, not a measurement.**

### The three gates this phase set itself  [all answered]

1. **Cross-CPU spread: does 2.39x move toward 2.2x?** Yes, to 2.201x measured on
   nine machine configurations (F34). Against a whole nonce rather than the hash
   alone it is 2.17x to 2.10x, a third of the size but the same direction.
2. **Verify cost.** +14.5 to 18.2% of the hash, which is +0.12 ms per block and
   about 6 seconds on a month-long resync (F39). The headroom was there and this
   does not bind.
3. **The determinism gate, pass/fail.** Passed: seven targets, four instruction
   sets, both byte orders, with FMA contraction made structurally impossible and
   a startup self-test (F29, F30, F34). The OpenCL work added an unplanned check
   on top, since software-emulated directed rounding on three GPUs is bit-exact
   against a real MXCSR (F37).

A fourth question the phase did not set itself, and which changed the picture:
GPU and ASIC resistance both move slightly the wrong way (F37, F38).

## Phase 3: pad and parameter tuning  [DONE]

**Result: 1 MB.** See "Starting point" above and [FINDINGS.md](FINDINGS.md) F24, F27, F28.

The salt stride and pad-init step now derive from `CN_SCRATCHPAD_MEMORY` rather
than being hardcoded, so a future pad change cannot silently read past the salt.
At 1 MB they reduce to the shipped constants, verified by comparing 400 hashes
between the pre- and post-change builds, and `contrib/powbench/t_salt_bounds.c`
proves no out-of-bounds index exhaustively over the whole input space at 1, 2, 4
and 8 MB. The parameter ranges were left alone: widening them widens what a cost
estimate would be worth, and the fifth target governs that.


What was done, and what it settled.

- **The pad was swept at 1, 2, 4 and 8 MB on all four machines, single- and
  multi-threaded.** The single-thread sweep separates only 8 MB; the
  multi-thread one is what decided it. [FINDINGS.md](FINDINGS.md) F24, F27.

- **HF13's reasoning was tested rather than talked past.** HF13 went 4 MB to
  8 MB arguing that 8 MB per thread overflows L3-per-core on nearly every
  machine class, so they all fall back to DRAM latency and even out. Measured,
  that is **true among the desktops** (at 8 MB they amplify 3.5x, 3.6x and 3.4x
  across 16, 8 and 6 cores) and **false once a small machine is included**: the
  6 MB-L3 laptop amplifies 1.0x, so it is excluded rather than equalised. A
  large pad evens out the machines that are already comfortable. Pad size has
  now been argued five times in this project, in both directions (F11).

- **The salt stride is rescaled, not wrapped.** `v5pad.inc` describes the
  salt-index bound as a latent bug holding only at 1 MB; it is a maintained
  invariant. At a 3 MB pad in December 2018 the line read `(% 117) + 12`; back
  at 1 MB it became `(% 125) + 4`. The salt was 262144 bytes in both, and
  `3145728/12` and `1048576/4` are both exactly that. The macro names carry the
  same invariant. So both now derive from the pad, and the AND-wrap stays where
  it belongs, in the benchmark: at 4 MB it makes the salt repeat four times per
  sweep, a different algorithm rather than a resized one. [FINDINGS.md](FINDINGS.md) F4, F22.

- **`state_index` masks with `(pad / 16 - 1)`**, which addresses the whole pad
  only when `pad / 16` is a power of two. Fine at 1 MB; relevant again only if a
  non-power-of-two size is ever considered.

- **`xx`/`yy` and `iters` ranges were left alone.** More variance per nonce is
  ASIC-hostile but it is also the axis the fifth target governs: v5's 4.7x
  spread is acceptable only because the parameters cannot be learned without
  doing the full chain fill (rule 3). Widening them widens what a cost estimate
  would be worth, so any change has to keep that feedback and be re-checked with
  `screen.c`. Narrowing toward constant work per nonce is the safer direction if
  it is ever revisited.

## Phase 4: plumbing  [DONE]

`get_block_longhash_v14` mirrors `get_block_longhash_v11`, with v6's windowed
chain fill (`get_cna_v6_data`) rather than v5's. The window was a sync-speed fix
independent of the v6 algorithm and had to be kept: it biases ~95% of block reads
into the last 100k blocks so per-nonce cost stops growing with chain length,
while the other ~5% still draw from the whole history so pool resistance is
unchanged. The v6 fill re-seeds its HC128 state from its own output exactly as
v5's does, so the property in [FINDINGS.md](FINDINGS.md) F5 carries over.

The dispatcher routes `case 13:` to v6 and `default:` to v8. No hard-fork table
entry was added: v8 inherits HF14.


- `CN_SCRATCHPAD_MEMORY_V15`, a **compile-time constant**, set once by Phase 3.

  Decided against a runtime pad-size parameter. The argument for one was that
  Phase 3 sweeps the pad, but the sweep is a benchmark concern and
  `v5pad.inc` already solves it by compiling the same source at several sizes
  as separate translation units. Paying for that flexibility in shipping code
  means `state_index`'s mask becomes a register rather than an immediate and
  the salt stride's minimum becomes a division rather than a constant, both in
  the innermost loop of the hash. That loop is where the 29% branch-versus-AND
  result came from, and it is the last place to spend anything for
  convenience. One size ships; the bench compiles as many as it likes.
- `get_block_longhash_v14` in `cryptonote_tx_utils.cpp`, keeping the
  `HC128_Init` + `get_cna_v5_data` chain fill unchanged. **The fill is the
  pool resistance and must not be weakened.** v8 uses the v5 fill; the v6
  fill (`get_cna_v6_data`) goes dead along with v7.
- **The reorg trap, which this codebase has already been bitten by once.**
  `context->random_values` is fetched with a pad-size bound and cached by
  height. Around a fork, one context can hash both the old and new version at
  the same height on competing chains, and a stale bound indexes past the pad
  and forks the chain. The comment in `get_block_longhash_v14` documents the
  v13/v14 instance. If v8 runs at a different pad size than v6's 8 MB, it is
  the same trap with different numbers: fetch with v14's own bound on every
  call and invalidate `cached_height`, exactly as v14 does now.
- Dispatcher: point `default:` (major_version >= 14) at
  `get_block_longhash_v14`. This is the only live-code line the whole project
  changes, and it changes no historical height because HF14 has never been
  reached.
- Set the real HF14 height, replacing the 4,500,000 placeholder, once the
  validation gates pass. Leave enough runway for miners and pools to ship v8.
- `ASSUME_VALID_HEIGHT` bump at release, and seed-height handling
  (`CN_SEED_MIN_HEIGHT`) checked against the chosen pad.
- Both HW and SW AES paths must produce identical hashes;
  `cn_slow_hash_self_test` must cover v14.
- **Delete v7** (`cn_slow_hash_v14`, `cn_vm_execute_v7` and the `seg_hops`
  generation, `CN_SCRATCHPAD_MEMORY_V14`, `CN_V7_*`, `get_block_longhash_v14`).
  It is dead once the dispatcher moves, it never validated a mainnet block, and
  removing it is the one case in this codebase where dropping a PoW function
  touches no history. Its removal also takes the `seg_hops` draws back out of
  `cn_vm_generate_program`, which is a function live HF13 consensus calls (F9);
  that alone is worth doing.

  Two constraints. It lands as **its own commit**, separate from adding v8, so
  that the fallback of shipping HF14 on v6 with no PoW change stays one revert
  away. And `get_cna_v6_data` **stays**: it is v6's chain fill and v6 is live on
  mainnet, so only v7's own code goes.

## Phase 5: validation  [DONE, except the contested reorg]

Passed so far:

- `cn_slow_hash_self_test`, covering v8's HW and SW arms, at every build
- daemon starts on mainnet and validates live blocks through the new dispatcher
- every pre-v8 hash body in `slow-hash-impl.h` byte-identical to `master`
  (10 functions, 480 lines), and every pre-v8 `get_block_longhash_*` likewise
- `t_salt_bounds`: no out-of-bounds salt index, exhaustive over the input space
- the stride derivation is a no-op at 1 MB, 400 hashes compared old against new

The testnet round ran on 2026-10-02 and passed; [FINDINGS.md](FINDINGS.md) F49
has the method and the limits. A fresh private net crossed HF14 at height 1000,
a node with an empty database revalidated the chain from genesis, and a second
physical machine on a different microarchitecture reported bit-identical block
hashes. That is the first time `get_block_longhash_v14` validated a real block.

Still outstanding: **a contested reorg across the boundary**, two miners racing
near height 1000 and confirming both nodes converge. That is the case where a
wrong `random_values` bound splits nodes rather than merely producing a wrong
hash, and F49's round did not provoke it.


- Extend `contrib/hf14checks/t_bench_v5v6.cpp` with v8; the control row must
  stay at ~1.00x.
- Extend `contrib/powbench` with a v8 kernel and C reference. **The checksum
  gate must pass**; a row that does not verify gets no ratio.
- Run all four machines at identical `vram` and `launch cap`.
- **Run `contrib/powbench/screen.c` against v8 and require r near zero.** It
  reports v6 at 0.88 to 0.95 today, so it is known to detect the thing it is
  looking for rather than returning zero by construction. Keep its control
  gate, which proves the instrumented interpreter still matches the shipped
  one before printing anything; it caught a wrong `mix64` on its first run and
  refused to report. Adapting it to a v8 with no VM means replacing the
  estimator with the cheapest predictor that v8's structure allows, and the
  choice of estimator is the whole test, so it deserves review rather than
  being picked by whoever writes the patch.
- Reverify historical blocks across the v10, v11 and v13 height ranges. This is
  the direct test of the rule above, and it is a merge blocker. **Owed to a
  mainnet sync from zero on the release candidate**, which is the exhaustive
  form of it: every block through the real consensus path.

  **It only counts with `--fast-block-sync 0`.** The flag defaults on, and at
  `blockchain.cpp`'s `assume_valid` line that makes every block below
  `ASSUME_VALID_HEIGHT` (4,320,000) skip PoW recomputation entirely, with
  quicksync gated the same way. A default sync from zero therefore succeeds
  whether or not this branch perturbed v10, v11 or v13, and proves nothing
  about them. With the flag at 0 both paths are disabled and every proof of
  work is recomputed and checked against its recorded difficulty.

  Popping blocks cannot reach v10 or v11: they are roughly 4 million blocks
  back. `blockchain_import --verify` does not substitute, because it never
  registers `arg_fast_block_sync`, so `m_fast_sync` stays true and it skips the
  same range.
- Testnet round with the full HF14 test procedure from the runbook. Note that
  testnet HF14 is at height 1000 on a fresh net, so a testnet restart exercises
  the fork itself rather than a placeholder.

## Phase 6: hardening against the measured miner  [B1, B2, B3 LANDED; A1b NOT BUILT]

Phases 1 to 5 were designed against reasoning. This phase is designed against a
working optimized miner, built and measured on a 5600G by [0xROOTPLS](https://github.com/0xROOTPLS) and
reported in full: 2.43x the reference miner, with a breakdown of where every
part of it comes from. [FINDINGS.md](FINDINGS.md) F44 to F48 record what was
verified from it.

### The fact that drives this phase

An instrumented copy of the shipped code, over 52,833 nonces, puts v8's cost at:

| part | share |
|---|---|
| chain salt, `get_cna_v6_data` | **59.5%** |
| `salt_pad` sweeps, 30 calls, 964K byte RMW | 17.9% |
| AES fill | 6.5% |
| `randomize_scratchpad_256k_v8` | 6.2% |
| AES finalize | 6.2% |
| extra hashes, 30 calls | 3.2% |
| **CN inner loop** | **0.05%** |

The CryptoNight inner loop, nominally the memory-hard core, is one twentieth of
one percent. That is not a v8 regression: `get_block_longhash_v11` has derived
`iters` the same way since HF11, so it is at most 63 steps against pre-HF7
CryptoNight's 262,144.

Now subtract what an optimized miner removes. The sweeps are deferrable to two
passes (F44). The extra hashes collapse from 30 to about 4 (F45). The fill is
sequential. **What is left that no implementation can avoid is the 234 MB
chain-dependent salt fetch, and nothing else.**

That single fact decides the phase. v8's security is the chain fill. Everything
protecting it matters; everything else is cost.

### B1. Pin `init_size_blk` to 8

`init_size_blk` changes the AES **operation count by zero** and the **time by up
to 2.24x** (F42). It is the largest screenable axis in the algorithm and it buys
nothing.

Pinning it removes that axis and **cuts verify cost by a measured 26.3%**,
0.554 ms against 0.751 ms for the uniform draw, at identical AES work. blk=8 is
the fastest width at every `(xx, yy)`: the column means are 0.997, 0.701 and
0.554 ms for blk 2, 4 and 8. It also removes a cross-machine variance source,
because narrow cores suffer most at blk=2, and cuts the free-fill screening
ceiling from 2.15x to 1.59x by removing the dominant band. And it resolves B2's
circular dependency for free.

7950X, one thread, 51 interleaved rounds, medians, mining and browsers stopped.

Preferred over making it per-block, which would leave some blocks 2.24x slower
to verify than others for no gain.

### B2. Seed the salt's HC-128 from the fill's final AES chain state

Today the salt seed is `keccak(blob)`, which costs nothing, so the 59.5% can be
produced on any device and handed over as 256 KB (F46). Seeding it from the
fill's final chain state means a feeder must run 1 MB of chained AES per
candidate first. A GPU has no AES instruction, so that is ~655K software block
rounds against a few hundred thousand integer ops for the salt itself.

With B1 done this is a pure reorder: fill, seed, salt fetch, rest.
**`get_cna_v6_data` is not touched.** Only the seed handed to it changes. That is
what keeps live HF13 safe, and it is not optional: that function is shared with
`get_block_longhash_v13`, live since 4,320,000.

**Implemented as a callback, not as the `_fill`/`_rest` split the report
proposes.** `init_hash()` declares every local as a macro, `state`, `text`,
`expandedKey`, `a`, `b`, `c` and `tweak1_2`, so a split would have to marshal
all of it across the boundary in both AES arms, which is where a HW/SW
divergence would hide. Instead `cn_slow_hash_v14` takes a `cn_v8_salt_fn` and
calls it between `expand_key()` and `randomize_scratchpad_256k_v8`, in one
stack frame with nothing marshalled.

Two entry points, so the benchmarks and the resized `v5pad.inc` builds keep
compiling untouched, which matters because `contrib/` is not in the daemon
build and breakage there would not be caught:

- `cn_slow_hash_v14(...)` keeps its exact signature and passes NULL.
- `cn_slow_hash_v14_chain(ctx, data, len, hash, blk, salt_fn, user)` is the
  consensus entry and takes **no** `iters`, `xx` or `yy`, because the callback
  supplies them. It is therefore structurally impossible to call the consensus
  path with parameters known before the fill and the fetch have both run.

The blob hash is no longer used to seed the salt and does not need to be:
`expand_key()` opens with `hash_process(&state.hs, data, length)`, so the fill
is already keccak'd from the blob and the seed depends on it transitively. The
nonce's dependency chain is now blob, keccak, 1 MB AES fill, seed, chain salt,
draws, rest of hash, with every link forced.

**Tested by `contrib/hf14checks/t_v8_chain.c` and by `cn_slow_hash_self_test`.**
HF14 is not active, so nothing else reaches the chain entry and without these it
would ship having never run. The load-bearing assertion is that the seed moves
with `init_size_blk`: that is what distinguishes "the fill produced this" from
"`keccak(blob)` produced this", since `blk` changes how the fill chains but
cannot change `keccak(blob)`. A future simplification back to the blob hash
would pass every test that only compares hashes.

**As first built, the seed covered a quarter of the fill (FINDINGS F81).** The
fill is eight independent AES chains and the seed was the first 32 bytes of the
final state, lanes 0 and 1 only; the `init_size_blk` assertion above passed
anyway. The seed now folds all eight lanes, and a chain-entry known-answer
vector pins it.

Stated limits, which are real: it does not stop a device that has AES, so FPGA
and ASIC are unaffected, and it does not stop a GPU computing the whole hash,
which rests on the ordinary argument instead.

### B3. Keep `xx`, `yy` and `iters` per nonce

Do **not** move them to the stable block hash, which the report recommends.
With B2 in place, learning them costs a full fill plus a full salt, so screening
stays at 1.00x and there is nothing left to close. Per-nonce loop bounds also
make a GPU warp run at `max(count)` rather than its own, worth roughly 1.9x on
that portion. Moving them would close a hole B2 already closes and hand that
divergence back to the GPU.

### What this phase deliberately does not do

**Not the sbox on the sweep** (the report's section 3 fix). It costs about +9%
verification and forces 30 real passes over the pad instead of 2, which
penalises small-cache machines and widens the cross-CPU spread. It buys no GPU
or ASIC resistance: 1 MB is trivial SRAM for an ASIC and trivial bandwidth for a
GPU. The sweeps were never a hardness property. Adopt the deferral in the daemon
instead, where it is a 1.18x verification speedup for free.

**Not the per-call hash window** (section 4 fix). It costs about 2.8% of
verification by making 26 redundant extra hashes mandatory, and its benefit,
forcing the whole salt live, is redundant once B2 means the salt cannot leave
the device.

**Not a v14-only fork of `get_cna_v6_data`** for F47's stale-keystream draws.
They affect 256 bytes of a 256 KB salt, are deterministic and chain-dependent,
and no attack follows. Forking the function doubles the consensus-critical
surface permanently for a cosmetic gain. Record it in the fork notes.

### Phase A, no consensus change, do first

1. **Adopt the sweep deferral and extra-hash memoization in the daemon.** Both
   produce bit-identical output, so they are verification speedups, not
   consensus changes: about 1.18x and 1.06x.
2. **Fix the large-pages tier bug.** `cn_page_tier_for_version` sends
   `major_version >= 13` to the 8 MB `cna_scratchpad`, but v8 hashes from the
   1 MB `scratchpad` and the 8 MB buffer is never allocated. Should be `== 13`.
3. **`mdb_reader_check` at LMDB open.** A reader that exits without
   `mdb_env_close` leaks a slot; 126 of them make nervad's own reads fail in a
   way that looks like chain corruption.
4. **Publish the reference-miner optimizations.** A 2.0x implementation gap one
   person holds is a fairness problem; the same 2.0x everyone holds is the
   baseline.

### A1b. Sweep deferral, the implementation plan  [BUILT 2026-10-02]

**Built, measured and verified bit-identical over 1600 vectors.**
[FINDINGS.md](FINDINGS.md) F51 has the result and the two places this plan was
wrong. The headline correction: the gain is set by L2 size, not by the
algorithm, so F44's 1.18x is a 512 KB-L2 machine at a 1 MB pad and the shipped
configuration sees 1.04x on a 7950X and 1.14x on an i7-7700HQ. That asymmetry
is the reason to ship it: it narrows the cross-CPU spread from 2.58x to 2.35x.

The plan as written below is kept because it is what the work was done against.
Non-consensus, output must be bit-identical. F44 has the measurement and the
reasoning. Written down before starting because it is the one piece of Phase 6
most likely to be got wrong on a first attempt, and because a half-finished
version leaves no safe intermediate state to commit.

#### What makes it possible

`salt_pad_v8`'s second loop is `hp_state[j] ^= salt[x++]`. XOR commutes and the
written value never feeds a branch or an address, so the pad after N sweeps is
the pad before them XOR the union of their contributions, in any order. The
sweeps can therefore be recorded and applied once.

The only thing that observes the pad between sweeps is the CN step, and it
touches exactly two 16-byte cells: `pre_aes` at `state_index(a)` and
`post_aes_variant` at `state_index(c)`. At 12 to 56 k/l steps plus at most 63
`iters` steps that is at most ~238 cells per nonce, ~100 typically.

#### Why it cannot be done by editing the shared macros

`pre_aes` and `post_aes_variant` live in `slow-hash.h` and are expanded by
`cn_slow_hash_v10`, `v11` and `v13`, all of which validate mainnet today.
PLAN-v8's standing rule applies: do not edit them in place. **v8 needs private
copies**, the same way `salt_pad_v8` is a copy of `salt_pad` rather than a
parameterisation of it.

Name them `pre_aes_v8` and `post_aes_variant_v8`, put them in `slow-hash.h`
beside `salt_pad_v8`, and have only `slow-hash-v8-impl.h` expand them. The
diff to the shared macros must be zero.

#### The four pieces

1. **The log.** Per nonce, at most 56 entries of `{ uint32_t o, s; }`, the
   sweep's start offset and stride, plus the patch bytes each sweep consumed.
   `salt_pad_v8` stops touching the pad and appends instead.

2. **Reconstruction.** `comp(log, salt, j)` returns the XOR of every logged
   sweep's contribution landing in `[j, j+16)`. For sweep k with start `o` and
   stride `s`, the first index at or after `j` is
   `x = (j <= o) ? 0 : (j - o + s - 1) / s`, and it walks `pos = o + x*s` while
   `pos < j + 16`. Cost is one pass over the log per cell, ~30 entries, ~100
   cells per nonce.

3. **The CN step reads and writes through it.** `pre_aes_v8` loads
   `pad[j] ^ comp(j)`; `post_aes_variant_v8` stores `result ^ comp(j)`. The
   same `comp(j)` value serves both, so compute it once per cell.

4. **Finalise.** Before `finalize_hash`, walk the pad in L1-sized tiles and
   apply every logged sweep to each tile, so the byte traffic happens with the
   tile resident instead of ~30 times over 1 MB.

#### The trap

The salt is **patched in place** by `salt_pad_v8` between sweeps, so sweep k
reads a different salt than sweep k+1. The log must therefore record the salt
bytes each sweep actually consumed, or reconstruct the patch history, not just
`(o, s)`. Getting this wrong produces a hash that is self-consistent and wrong,
which is exactly the failure F44 warns about. The extra-hash memoization
already landed makes the patch sequence easier to reason about, since only the
patch offsets vary, not the digests.

Reconstruction is cheap in practice because the patches cover almost nothing:
~30 patches of 32 bytes is under 1 KB of a 256 KB salt, so a sorted list of
patched ranges answers "does this index need correcting" with a miss nearly
every time. `salt_k[x]` is `salt_final[x]` XOR every patch `p > k` covering `x`.

#### Two corrections to the above, found before building (2026-10-02)

**The sweep sequence is not schedulable.** `r2` aliases `c`:

    uint16_t *r2 = (uint16_t *)&c;
    salt_pad_v8(salt, r2[0], r2[2], r2[4], r2[6]);

`c` is the CN state that `post_aes_variant` has just written from the AES
output, so every sweep's offset and stride depend on the pad at that moment.
Nothing can be precomputed, and the log has to be built as the loop runs. The
deferral is still correct, by induction: reconstructing the logical value at
each read makes `c` identical, so the parameters are identical. But it means
**an error in `comp()` changes the sweep parameters themselves**, so a wrong
implementation does not produce a recognisably corrupt hash, it produces a
different self-consistent one. This is why gate 1 is the known-answer test.

**`VARIANT1_1` is nonlinear and XOR does not commute with it.** It reads byte
11 of the pad cell, indexes a table with bits of it, and writes the byte back.
So the deferral cannot be bolted on as an XOR at each end of the existing
macros. The convention has to be that `hp_state` always holds
`logical ^ comp`, and every read materialises `logical` before anything
nonlinear sees it, with the store re-masking afterwards.

That convention is self-correcting across time and this is the part worth
checking rather than trusting: a cell stored at step `m` holds
`logical_m ^ comp_m`, and a read at step `m' > m` recovers
`logical_m ^ comp_m ^ comp_m'`, which is `logical_m` XOR exactly the sweeps
between `m` and `m'` that hit the cell. That is what the eager version would
have applied. The same identity makes the finalize pass correct: applying the
**full** sweep set to every cell turns `logical_m ^ comp_m` into `logical_N`,
including for cells no CN step ever touched.

#### Gates, in order

1. `cn_slow_hash_known_answer_test` must pass unchanged. It is the whole reason
   this is attempted at all: the edit moves both AES arms together, so HW == SW
   cannot see an error in it.
2. `cn_slow_hash_self_test` still passes, both arms.
3. `contrib/hf14checks/t_v8_chain` still passes.
4. `screen_grid` over all 75 cells, old against new, hashes identical. The KAT
   is six vectors; this is the exhaustive version and should be run once before
   committing even though it is not kept.
5. Measure with `v8bench`, reading the **v8:v5 ratio** rather than the absolute,
   since v5 does not use `salt_pad_v8` and is therefore the control.

#### If it does not work out

It is non-consensus and the algorithm does not depend on it. Dropping it costs
1.18x of verification on a hash that is already 11x cheaper than v6. Do not let
it hold up the testnet round, which is the only thing that has never run.

### Gates before merge, since nothing pre-HF14 may break

Every B item touches only `get_block_longhash_v14` and the v14 hash bodies.
Confirm mechanically:

1. `get_cna_v6_data`, `salt_pad`, `cn_vm_*` and `cn_slow_hash_v5/v10/v11/v13`
   byte-identical to master.
2. Reference vectors for v10, v11 and v13 at fixed heights unchanged.
3. HW and SW arms bit-identical for v14 across the full `(xx, yy)` grid, before
   and after the `_fill`/`_rest` split. That split is where divergence lives.
4. A mainnet resync past 4,320,000 on the built binary.

### The open question, and why it is not in the plan

B2's GPU resistance and v8's existing GPU resistance rest on the **same**
assumption: that AES-NI beats T-table AES. RESULTS.md section 6.3 already warns
that v5-class resistance "disappears the day a GPU gets competitive AES." If
that breaks, B2 breaks with it.

The obvious diversifier is to raise `iters` and restore a real dependent pad
chase, which is latency-bound rather than AES-bound. **It is not recommended
here, because F38 argues against it and the physics probably does too.** A chase
over a 1 MB pad is L2-resident on a CPU and hidden by occupancy on a GPU, which
can keep thousands of nonces resident at 1 MB; and by F38 it adds work to the
specialisable hash core rather than to the chain fill, which loosens the ASIC
bound. The measurement in F48 exists to settle that rather than to justify it.
**It has now run and the answer is no:** 9.4 ns per CN step, so at a 1 MB pad
the chase never leaves L2, and 64K costs +0.67 ms against a pre-registered
+0.5 ms ceiling. Classic CryptoNight depth would be a 2.7x sync tax. Closed.

If more margin is ever wanted, F38 says it has to come from the chain fill. The
cost of that is sync speed, directly, which is why it is not proposed here.

## Open items

1. **GPU behaviour at 1 MB at full occupancy is unmeasured**, and it is the only
   evidence that would justify moving off 1 MB. Every GPU figure swings 2.8x
   with nonce count and 4x with the launch cap, and the large-pad rows ran
   starved. Being referred outward. [FINDINGS.md](FINDINGS.md) F28 records the route to
   measuring it in-house: chunk the **work** rather than the nonces, which
   `main.cpp`'s objection does not rule out.
2. **The cost-predictability gate has not been run against v8.** v6 measures
   r = 0.88 to 0.95 (F6). v8 has no VM, so the estimator must be redesigned.
3. **The ASIC reasoning remains unmeasured** and should not be used as a
   tiebreaker again; it was, twice, and both times the decision it produced was
   later reversed by measurement.
4. **Nerva's CPU miner is itself an interpreter.** If v8 ever gains a VM-like
   stage, JIT-ing the miner is a cheaper way to widen the CPU/GPU gap than
   another algorithm change.
5. ~~Why was RandomX dropped in January 2020?~~ Closed: nobody recalls, and the
   project wants its own algorithm regardless.

## What not to do

- **Do not edit `salt_pad`, `cn_slow_hash_v10` or `cn_slow_hash_v11` in
  place.** See the rule section. Every change is a new macro and a new entry
  point.
- Do not add work to the chain fill to buy ASIC resistance. The fill runs
  during verification, so it is a direct sync-speed tax.
- Do not grow the pad past the smallest target machine's L3, and remember that
  machine is smaller than anything in the test set. A larger pad excludes small
  machines from multi-threading before it constrains large ones.
- Do not settle a pad question with the ASIC arithmetic. It is unmeasured and
  linear in pad size by construction. It was used as a tiebreaker twice here and
  both decisions were later reversed by measurement.
- Do not quote the GPU table as a pad comparison. Its large-pad rows ran starved
  against a launch cap and are floors, not measurements ([FINDINGS.md](FINDINGS.md) F28).
- Do not ship any phase whose verification cost is not measured on the weakest
  machine in the set, not the fastest.
- Do not add a hard-fork version for v8. It inherits HF14, which has never
  activated. Adding one forces users through a second upgrade for no reason.
- Do not let a nonce's cost be estimable ahead of time. This is the fifth
  target and the second rule; it is the one property v6 does not have, and it
  is easy to reintroduce by accident with a one-sided branch or a cheap seed.
- Do not reconcile the HW and SW `r2` difference. It is the fix, not the bug.
- Do not make `salt_pad`'s sweep non-commutative to stop the deferral. It costs
  ~9% of verification, widens the cross-CPU spread and buys no GPU or ASIC
  resistance ([FINDINGS.md](FINDINGS.md) F44).
- Do not move `xx`, `yy` or `iters` to the stable block hash. Phase 6 B2 closes
  screening already, and per-nonce loop bounds are what make a GPU warp run at
  `max(count)` rather than its own.
- Do not trust a comment in `src/crypto` or a figure in a commit message
  without checking the code. Several comments here describe behaviour the
  adjacent code does not have, and [FINDINGS.md](FINDINGS.md) exists because of that.
- Do not change a pad-aware or buffer-aware macro without updating its mirror in
  `contrib/hf14checks/v5pad.inc`, or the benchmark and the daemon diverge
  silently. That happened four times in one session ([FINDINGS.md](FINDINGS.md) F26); prefer
  making the shipped macro general enough that the override can be deleted.
