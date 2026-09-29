# CNA v8: plan

A v5-derived PoW for Nerva, aiming to beat the current v6 on all three axes at
once. Every target below comes from measurements in `RESULTS.md`; read that
first, especially section 2 (the mistakes) and section 7 (known gaps).

## Status

v7 has never activated and never will. Mainnet HF14 sits at the placeholder
height 4,500,000 in `cryptonote_config.h` and the chain is at ~4,420,000, so
no block has ever been hashed with `cn_slow_hash_v14` outside testnet. Two
consequences shape this whole document:

1. **v8 takes the existing HF14 slot.** `get_block_longhash` routes
   `default:` (major_version >= 14) to `get_block_longhash_v14`. v8 replaces
   the body of that one branch. There is no `{15, ...}` hard-fork entry, no
   second fork event, and no user upgrades twice. If v8 fails its gates, the
   fallback is to drop the PoW change and leave HF14 on v6.
2. **HF14 is not only the PoW.** That slot also carries CLSAG, Bulletproofs+
   (type 7 only) and ring size 16. Those are orthogonal to
   `get_block_longhash` and are untouched by everything below. The PoW work
   can fail without taking them down with it.
3. **Cost uniformity is now a fifth target.** In v6, a nonce's cost is
   estimable from its VM program alone, more cheaply than the nonce can be
   hashed, at a measured correlation of 0.88 to 0.95 between estimate and real
   cost. Measured end to end, including what the estimate costs and the chain
   fill, screening alone is worth about **1.3 to 1.4x** throughput at its best
   (FINDINGS.md F6, F6b). That is screening in isolation and not a verdict on
   the larger optimisation work it was reported alongside, which bundles
   several unrelated and legitimate miner improvements that were not tested.
   Worth designing out of v8, since even 1.3x to whoever implements it is a
   fairness problem, but not a reason to slow HF14 down.

Everything this plan asserts about the existing code is recorded, with how it
was checked, in `FINDINGS.md`. Read that before trusting a comment in this
tree: several of them describe behaviour the adjacent code does not have.

## Targets, measured against v6 8MB as it ships today

| axis | v6 8MB today | v8 target | why this number |
|---|---|---|---|
| verify, 7950X 1T | 10.11 ms | **< 8 ms** | sync speed was the original complaint |
| verify, i7-7700HQ 1T | 27.51 ms | **< 15 ms** | the weakest machine is what gates fairness |
| cross-CPU spread (4 CPUs) | 2.91x | **< 2.2x** | v5 4MB already reaches 2.15x |
| GPU:CPU, worst of 4 | 0.05x | **<= 0.05x** | do not regress what v6 does well |
| cost estimable ahead of time | r = 0.88-0.95 | **r < 0.1** | FINDINGS.md F6; gate is `screen.c` |

If a change cannot hold all five, it does not ship. v7 failed because it was
allowed to trade verification cost away for a benefit that never materialised.

The fifth row is the one to keep in view while reading the phases below,
because it constrains the *shape* of v8 rather than its speed, and a
construction can satisfy the other four while failing it outright.

**Which v6 number the first four rows use.** RESULTS.md carries two, measured
differently: 6.95 ms for the shipped function through `hf14checks`, and 10.11
ms for the powbench port, which omits the Keccak framing and the four
finalisation hashes. The table above uses the port's 10.11, because the
cross-machine rows it compares against are also the port. A direct timing of
the shipped `cn_slow_hash_v13` lands at 7.70 ms, agreeing with `hf14checks`.
Keep port against port and function against function; reconcile the two before
these targets are used to accept or reject a candidate (FINDINGS.md F17).

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
an insertion *inside* a live function changes that function. See FINDINGS.md
F9.

## The second rule: a nonce's cost must not be knowable in advance

A PoW is easiest to reason about when every nonce costs the same. Where cost
varies, it should at least not be estimable more cheaply than the nonce can be
hashed, or the work a hash represents stops being uniform.

v6 does not hold this. FINDINGS.md F6 measures an estimate built from the
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
   the block cache, which needs a full node (FINDINGS.md F5). Keep that
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

## Phase 1: the fourth hash function

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

### 1b. New entry point `cn_slow_hash_v15`

Nerva's internal numbering makes CNA v8 into `cn_slow_hash_v15` (v11 = CNA v5,
v13 = v6, v14 = v7). Copy the `v11` body twice, once per arm, swapping
`salt_pad` for `salt_pad_v8` and changing nothing else. Same signature
(`iters`, `init_size_blk`, `xx`, `yy`).

| file | what |
|---|---|
| `slow-hash-impl.h` (HW arm, SW arm) | the two bodies |
| `slow-hash-hw.c`, `slow-hash-sw.c` | `#define cn_slow_hash_v15 cn_slow_hash_v15_hw` / `_sw` |
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
See FINDINGS.md F3.

**No `get_block_longhash_v15` and no dispatcher change in Phase 1.** This
phase is measurement. The consensus diff stays at zero and the whole phase
reverts with one `git revert`. Wiring it to major_version 14 happens in
Phase 4, once phases 1 to 3 have all been measured.

### 1c. Wire it into the pad-resize machinery

`contrib/hf14checks/v5pad.inc` renames each variant per translation unit. Add
`#define cn_slow_hash_v15 V5PAD_CAT(cn_slow_hash_v15_, V5PAD_TAG)` to that
block and `v5pad1.c` / `v5pad4.c` give v8 at 1 MB and 4 MB for free.

Measure at both. 1 MB isolates the selector change against the shipped
reference. 4 MB is where v8 is intended to live, and the salt wrap in
`v5pad.inc` is live there, so it is a different code path.

### 1d. The measurement

Add three rows to `VS[]` in `contrib/hf14checks/t_bench_v5v6.cpp`: `v8ref`
(dispatcher, `own_pad` 0), `v8ctl` (`cn_slow_hash_v15_p1`, 1 MB) and `v8_4`
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

Gate: if verification moves more than 2%, reconsider. If it reads worse than
that, suspect the harness before the algorithm.

### 1f. HW equals SW

Add a `v15` pair to `cn_slow_hash_self_test` mirroring the existing `v11`
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

- `v15` HW output equals SW output at 1 MB and 4 MB
- `v8ctl` within 2% of `v5ctl` on all four machines, gated on the i7-7700HQ
  and not the 7950X
- control rows still ~1.00x
- RESULTS.md carries the four-machine table, and this section records the
  measured figure, not the predicted one

## Phase 2: floating point (the substantive work)

This is the only lever identified that is asymmetric: a CPU runs IEEE-754
double precision at the same rate as integer, it costs **no extra memory** so
it does not hurt small-cache machines, and it barely touches verification. An
ASIC must implement full IEEE-754 with four rounding modes, denormals and NaN
handling, which is large silicon that cannot be simplified without breaking
consensus. It is the biggest single gap between both v5 and v6 and RandomX.

Phase 2 extends `cn_slow_hash_v15` in place. It does not need another entry
point, because v15 has no fork version pointed at it until Phase 4.

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
- If the FP result reaches control flow at all, its operands must come from
  pad loads, per rule 1 above. FP that only feeds the integer state is outside
  that concern entirely, and is the safer default.

"Load-bearing" needs measuring, not asserting. The one v7 lesson worth keeping
is that a construction can look strong while almost none of its randomness
matters: v7's chase drew its address from a fixed five-operation loop, and the
per-nonce program was later found to govern a small fraction of the hash. That
figure comes from a commit message and has not been reproduced here (FINDINGS.md
open question 3), but the failure mode is real and cheap to check: ablate the
FP stage and confirm the hash changes for every nonce, and that removing it
does not leave a shortcut that reproduces the result.

### 2b. Determinism, which is the real risk

Cross-platform FP determinism is a consensus-critical hazard and it is the
largest one in this document. A single ULP of disagreement between x86 and
ARM, or between two compilers, forks the chain. Non-negotiable rules:

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
differently on two machines is worse than no change at all. Failing it is now
cheap: Phase 1 alone can take the HF14 slot and Phase 2 can wait for a later
fork.

### 2c. Measure after

Re-run the four targets. FP should cost near zero on verification. If it
costs more than ~5%, the FP stage is too heavy; reduce the op count per
iteration rather than dropping the phase.

## Phase 3: pad and parameter tuning

Only after phases 1 and 2 are measured.

- Sweep the pad from 2 to 8 MB on all four machines and pick the knee where
  cross-CPU spread and verification both stay inside target.

- **Answer HF13's reasoning rather than passing over it.** Moving to 4 MB
  reverses a deliberate decision. HF13 went 4 MB to 8 MB arguing that 8 MB per
  thread overflows L3-per-core on nearly every machine class, so they all fall
  back to DRAM latency and even out, while 16 or 32 MB would push verify and
  sync past what the sliding-window work protects. This plan wants 4 MB for
  the opposite reason, that 8 MB punishes the 6 MB-L3 laptop. Both cannot be
  right about the same machines. The measured cross-CPU spread decides it, and
  the answer belongs in RESULTS.md next to the numbers. Worth knowing that pad
  size has been argued four times in this project's history, in both
  directions, and reverted twice (FINDINGS.md F11).

- **Rescale the salt stride; do not wrap it.** `contrib/hf14checks/v5pad.inc`
  describes the salt-index bound as a latent bug that holds only at 1 MB. It
  is a maintained invariant. When the pad was briefly 3 MB in December 2018 the
  stride line read `(offset_2 % 117) + 12`, minimum 12; when it was reverted to
  1 MB the line became today's `((temp_1 * offset_1) % 125) + 4`, minimum 4.
  The salt was 262144 bytes in both trees, and `3145728 / 12` and
  `1048576 / 4` are both exactly 262144. Maximum stride is 128 in both. The
  same invariant is in the macro names: `randomize_scratchpad_256k` steps 4
  over 1 MB, which is 262144 salt bytes (FINDINGS.md F4).

  So the AND-wrap that `v5pad.inc` uses is right for a benchmark and wrong for
  consensus: at 4 MB it makes the salt repeat four times per sweep, which is a
  different algorithm with less entropy per pad byte, not a resized one. Do
  what the original author did and rescale the minimum stride with the pad:
  4 MB wants `((temp_1 * offset_1) % 113) + 16`, and
  `randomize_scratchpad_256k` wants a step of 16. Measure both variants rather
  than assume, since they have different costs, but the rescale is what the
  design intends. If a wrap is used anywhere it must be the AND and not a
  compare and branch: as a branch it cost 29%.

- `state_index` masks with `(pad / 16 - 1)`, which addresses the whole pad only
  when `pad / 16` is a power of two. At 4 MB the mask is fine; it is the odd
  sizes that need the modulo. Keep that in mind if the sweep picks a non-power
  of two.

- **Widening `xx`/`yy` and `iters` is now constrained, not just a tradeoff.**
  More variance in work per nonce is ASIC-hostile and raises verification
  variance, which matters for block propagation. But it is also the axis the
  fifth target governs: v5's existing 4.7x spread is acceptable only because
  its parameters cannot be learned without doing the full chain fill first
  (rule 3). Widening the ranges widens what an estimate would be worth, so any
  widening has to keep that feedback intact and be re-checked with `screen.c`.
  Narrowing toward constant work per nonce, v7's `seg_hops` shape, is the
  safer direction and should be considered on its own merits.

## Phase 4: plumbing

- `CN_SCRATCHPAD_MEMORY_V15` at whatever Phase 3 picks, and a decision made
  early on whether v15 is a fixed-size entry point or takes a size parameter,
  because it affects the test harness.
- `get_block_longhash_v15` in `cryptonote_tx_utils.cpp`, keeping the
  `HC128_Init` + `get_cna_v5_data` chain fill unchanged. **The fill is the
  pool resistance and must not be weakened.** v8 uses the v5 fill; the v6
  fill (`get_cna_v6_data`) goes dead along with v7.
- **The reorg trap, which this codebase has already been bitten by once.**
  `context->random_values` is fetched with a pad-size bound and cached by
  height. Around a fork, one context can hash both the old and new version at
  the same height on competing chains, and a stale bound indexes past the pad
  and forks the chain. The comment in `get_block_longhash_v14` documents the
  v13/v14 instance. If v8 runs at a different pad size than v6's 8 MB, it is
  the same trap with different numbers: fetch with v15's own bound on every
  call and invalidate `cached_height`, exactly as v14 does now.
- Dispatcher: point `default:` (major_version >= 14) at
  `get_block_longhash_v15`. This is the only live-code line the whole project
  changes, and it changes no historical height because HF14 has never been
  reached.
- Set the real HF14 height, replacing the 4,500,000 placeholder, once the
  validation gates pass. Leave enough runway for miners and pools to ship v8.
- `ASSUME_VALID_HEIGHT` bump at release, and seed-height handling
  (`CN_SEED_MIN_HEIGHT`) checked against the chosen pad.
- Both HW and SW AES paths must produce identical hashes;
  `cn_slow_hash_self_test` must cover v15.
- Decide whether to delete v7 (`cn_slow_hash_v14`, its `cna-vm.c` paths,
  `CN_SCRATCHPAD_MEMORY_V14`, `get_cna_v6_data`). It is dead once the
  dispatcher moves, and it never validated a mainnet block, so removal is
  clean. Deleting it is the one case in this codebase where dropping a PoW
  function does not touch history.

## Phase 5: validation

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
- Reverify a range of historical blocks with `--fast-block-sync 0` across the
  v10, v11 and v13 height ranges, and confirm the hashes are bit-identical to
  a build from master. This is the direct test of the rule above, and it is a
  merge blocker.
- Testnet round with the full HF14 test procedure from the runbook. Note that
  testnet HF14 is at height 1000 on a fresh net, so a testnet restart exercises
  the fork itself rather than a placeholder.

## Open items carried in from RESULTS.md

1. **No GPU number is trustworthy at full occupancy.** Every large-pad row on
   every machine hit the launch cap, because a display-attached GPU trips TDR.
   One card running headless would fix this and would settle the pad question,
   which is currently blocked on measurement rather than on analysis.
2. **v7's CPU figure on the 7950X is 40% above the real function** and reads
   faster on a slower CPU, which is impossible. Unexplained. Lower priority now
   that v7 is not shipping, but the harness bug it implies may affect v8 rows.
3. **The ASIC reasoning is not measured.** It is arithmetic about SRAM density
   and concurrency, anchored to the historical CryptoNight ASIC experience. It
   has not been validated against real hardware and should be weighted as
   engineering estimate, not evidence.
4. **Nerva's CPU miner is itself an interpreter** (`cn_vm_execute`). If v8 ends
   up with a VM-like FP stage, JIT-ing the CPU miner is a cheaper way to widen
   the CPU/GPU gap than another algorithm change.
5. ~~F6 is measured in operation counts, not time.~~ Measured: the VM is 67%
   of a v6 hash and the cost spread is worth about 1.5x net of screening cost
   (FINDINGS.md F6b). Two further gaps remain: the figure omits the partial
   chain fill a miner still owes per screened nonce, and it is one machine,
   single-threaded.
6. **Nobody has recorded why RandomX was dropped.** It was integrated in June
   2019, worked through to January 2020 and then removed with no stated reason
   (FINDINGS.md F13). This plan measures v8 against RandomX repeatedly, and
   Phase 2 reimplements a piece of it. Worth asking someone who was there
   before that work starts.

## What not to do

- **Do not edit `salt_pad`, `cn_slow_hash_v10` or `cn_slow_hash_v11` in
  place.** See the rule section. Every change is a new macro and a new entry
  point.
- Do not add work to the chain fill to buy ASIC resistance. The fill runs
  during verification, so it is a direct sync-speed tax.
- Do not grow the pad past the smallest target machine's L3. That punishes
  exactly the machines fairness is meant to protect.
- Do not ship any phase whose verification cost is not measured on the weakest
  machine in the set, not the fastest.
- Do not add a hard-fork version for v8. It inherits HF14, which has never
  activated. Adding one forces users through a second upgrade for no reason.
- Do not let a nonce's cost be estimable ahead of time. This is the fifth
  target and the second rule; it is the one property v6 does not have, and it
  is easy to reintroduce by accident with a one-sided branch or a cheap seed.
- Do not reconcile the HW and SW `r2` difference. It is the fix, not the bug.
- Do not trust a comment in `src/crypto` or a figure in a commit message
  without checking the code. Several comments here describe behaviour the
  adjacent code does not have, and FINDINGS.md exists because of that.
