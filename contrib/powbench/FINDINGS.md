# CNA v8: verified findings

A ledger for the v8 effort. `PLAN-v8.md` says what we intend to do and
`RESULTS.md` holds the benchmark tables; this file holds what we have
established about the existing code and why we believe it.

**The rule for this file: nothing goes in that was taken from a comment or a
commit message alone.** Several comments in this tree describe behaviour that
the code next to them does not have, and commit messages carry figures nobody
has reproduced. Every entry below names how it was checked. Entries that rest
on an unreproduced claim live in "Open questions", not here.

## The code

### F1. `salt_pad` is shared by two live consensus functions

`salt_pad` (`src/crypto/slow-hash.h`) is expanded by both `cn_slow_hash_v10`
and `cn_slow_hash_v11`, in both the HW and SW arms of `slow-hash-impl.h`.
`get_block_longhash` routes major_version 10 to v10 and 11 and 12 to v11.
Editing that macro in place rewrites PoW for heights 341,000 to 4,320,000.

*Checked:* read the expansions in `slow-hash-impl.h` and the switch in
`cryptonote_tx_utils.cpp`.

### F2. A historical PoW break would hide from almost every node

`ASSUME_VALID_HEIGHT` is 4,320,000 (`cryptonote_config.h`) and
`Blockchain::block_needs_pow` returns false below it under fast sync. A node
syncing normally never recomputes those hashes, so a change to F1's macro
surfaces only with `--fast-block-sync 0`, in FAKECHAIN, or for someone
auditing from genesis.

*Checked:* read `block_needs_pow` and the config constant.

### F3. The HW and SW paths differ at `r2` on purpose

`slow-hash-impl.h:57` is `uint16_t *r2 = (uint16_t *)&c;` and `:354` is
`uint16_t *r2 = (uint16_t *)&b;`. This looks like a copy-paste error and is
the fix for one: commit `4d87b5f` (2019-04-29, "Fix for non-AES pathway not
syncing") changed the SW path from `&c1` to `&b` to make it agree with the HW
path. It shipped broken for about a month because the SW path is a minority of
machines.

*Consequence:* copying the v11 body to a new entry point means copying two
different bodies. "Tidying" the inconsistency forks HW from SW silently.

*Checked:* both lines in the current tree, plus the diff of `4d87b5f`.

### F4. Pad size and salt stride are coupled, deliberately, and it is not written down

`contrib/hf14checks/v5pad.inc` describes the salt-index bound as a latent bug
that holds only at 1 MB. The history says it is a maintained invariant.

When `5671f9f` (2018-12-15) took the pad to 3 MB, the stride line was
`offset_2 = (offset_2 % 117) + 12`, range [12, 128]. When `d5c97b2`
(2018-12-18, "Revert scratchpad increase. Undesirable results") took it back
to 1 MB, that line became today's `offset_2 = ((temp_1 * offset_1) % 125) + 4`,
range [4, 128]. The salt was `malloc(262144)` in both trees.

    3145728 / 12 = 262144
    1048576 /  4 = 262144

The pad changed 3x and the minimum stride was rescaled 3x to pin worst-case
salt consumption at exactly the salt size. Maximum stride is 128 in both; the
modulus is just `128 - min + 1`. The same invariant is in the macro names:
`randomize_scratchpad_256k` steps 4 over 1 MB, which is 262144 salt bytes;
`randomize_scratchpad_4k` steps 256, which is 4096. The names describe salt
consumed, not pad size.

*Consequence:* wrapping the salt index (what `v5pad.inc` does, correctly, for
a benchmark) makes the salt repeat at a larger pad. That is a different
algorithm, not a resized one. For consensus, rescale the stride instead:
4 MB wants `((temp_1 * offset_1) % 113) + 16` and a step of 16 in
`randomize_scratchpad_256k`.

*Checked:* both diffs, the `malloc(262144)` in the Dec 2018 tree, and the
arithmetic.

### F5. v5's per-nonce parameters cannot be predicted without doing the fill

`get_block_longhash_v11` calls `get_cna_v5_data` first, then `HC128_NextKeys`,
then draws `xx`, `yy`, `init_size_blk` and `iters_divisor` from that state.
The protection is stronger than statement order: `get_cna_v5_data` repeatedly
re-seeds its own RNG from bytes it has already written, `HC128_Init(rng_state,
key, iv)` with `key` and `iv` pointing back into the output buffer, in both its
loops. So the post-fill state depends on the salt's *content*.

A screener cannot fast-forward the keystream to learn the parameters. It has to
produce the salt, which needs the block cache, which needs a full node.

*Consequence:* v5's 4.7x cost variance is safe because of this feedback, not
because of luck. Any v8 change that widens `xx`/`yy` or moves parameter
derivation must preserve it. See F7.

*Checked:* read `get_block_longhash_v11` and `BlockchainLMDB::get_cna_v5_data`.

### F6. In v6, a nonce's cost can be estimated from its program, measured

The cost of hashing a v6 nonce varies, and the variation is estimable ahead of
time from the per-nonce program alone, more cheaply than the nonce can be
hashed. That matters for v8 because it means the work a hash represents is not
uniform. It is a property to design out, not a defect in the current chain's
security: hashes produced this way are still correct hashes.

Three mechanisms, all read in code:

1. `CN_OP_CBRANCH` tests `regs[dst] & ((uint64_t)ins->imm | 1)` and
   `cn_vm_generate_program` builds `imm` as `(hi << 16) | lo` from two full
   `HC128_U32(..., 0x10000)` draws, so the mask carries ~16.5 set bits and the
   branch is taken except about once in 2^16.5.
2. `cn_vm_execute` resets `pc` and `chain` on entry while `cn_slow_hash_v13`
   holds `regs` outside the loop, so every one of the 2048 passes restarts the
   same walk from pc 0.
3. The loop runs exactly `CN_PROGRAM_SIZE` steps whatever the branches do, so
   the variance is not in how many instructions run but in which ones the steps
   land on.

Measured by `contrib/powbench/screen.c` over 200,000 generated programs and
200 nonces executed against a live 8 MB pad for 2048 passes each:

    distinct slots reached : min 1  p50 60  mean 66.7  p99 187  max 325 (of 512)
    estimated memops/pass  : min 0  p50 287  mean 277.3  p99 402  max 486
    programs with 0 memops : 1 in 971
    CBRANCH steps executed : 55.2 per pass
    correlation(estimate, measured cost) r = 0.88 to 0.95

The distribution's low tail sits well below its mean: the cheapest 1% of
programs average 47.7x fewer VM memory operations than the mean, and the
cheapest 0.1% perform none. Those are operation counts, not times; see open
question 1.

*Checked:* `screen.c`, whose instrumented interpreter is proven bit-identical
to `cn_vm_execute` over 8 programs by 16 passes (registers and full 8 MB pad
compared) before any number is printed. That gate caught a wrong `mix64` in the
first run and refused to report.

### F6b. What the spread in F6 is worth in throughput: about 1.5x, not about 10x

F6 counts operations. `contrib/powbench/screen_time.c` measures time, on a
7950X with AES-NI and huge pages confirmed at runtime:

    full cn_slow_hash_v13 : 7.70 ms   (RESULTS.md section 3 says 6.95 for the
                                       same function, so this agrees)
    its 2048 VM passes    : 5.19 ms   (67.4% of the hash)
    everything else       : 2.51 ms   (32.6%, does not vary with the program)

    correlation(estimate, hash time) r = 0.89 to 0.93
    mean hash time, all nonces        : 7.78 ms
    mean hash time, cheapest 1% by est: 4.55 ms   (1.71x faster)

That last column is per accepted nonce and ignores what the estimate costs. At
acceptance q a miner pays 1/q estimates per hash, so the honest figure is
`t_unscreened / ((1/q) * t_estimate + t_accepted)`. One estimate, program
generation plus the walk, takes 10.4 us. That gives:

    accept   1%     5%     10%    25%
    net    1.38x  1.51x  1.41x  1.22x

Two runs of 3000 nonces agree within 0.01x.

**`screen_time.c` omits the chain fill, which is the same mistake RESULTS.md
section 2.9 records the powbench port making.** The real per-nonce path also
runs `get_blob_hash`, `HC128_Init` and `get_cna_v6_data`, about 2.2 ms for v6.
Adding it to both sides, with a rejected nonce owing only the ~1/4096 of the
fill that yields `salt[0..32)` (F8) plus the 10.4 us estimate:

    unscreened          : 2.2 + 7.78          = 9.98 ms/nonce
    screened at 5%      : 20 x 0.0114 + 2.2 + 4.90  = 7.33 ms  -> 1.36x
    screened at 1%      : 100 x 0.0114 + 2.2 + 4.55 = 7.89 ms  -> 1.26x

**So the advantage is about 1.3 to 1.4x, and the 1.5x above is an overstatement
of it.**

*Scope, which matters more than the number.* This measures screening alone,
single-threaded, against an efficient reference build. It is not a measurement
of the reported 8.5 to 13.4x, which describes a fully optimised miner and
bundles work that has nothing to do with screening: K-way nonce interleaving,
a fused pad init, non-temporal stores, large pages, AVX2 HC-128 and Keccak, SMT
pairing. Those are real and multiply with this. Nothing here contradicts them;
they were not tested.

*Consequence:* worth designing out of v8, because even 1.3x to whoever
implements it is a fairness problem, but attribute it correctly. Screening
alone is not an order of magnitude on its own evidence, and the rest of that
document is a separate question that has not been measured.

*Checked:* `screen_time.c`, two runs, with the AES path and page tier printed
in the banner. See F16 for why that banner exists.

### F7. The "identical trace" framing of F6 is false, and F6 holds anyway

Only 78 of 200 nonces had all 2048 passes produce the same memop count, and the
worst within-nonce spread was 92%. The arithmetic explains it: 55.2 CBRANCH
steps per pass at ~2^-16.5 each is ~6e-4 deviation per pass, times 2048 passes
is ~1.2 expected deviations per nonce.

The mean across passes is still stable, which is why r stays at 0.88 to 0.95.

*Consequence:* justify the design rule by the correlation, not by an
identical-trace claim, because that claim is testable and false.

*Checked:* the pass-by-pass counters in `screen.c`.

### F8. v6's seed is available after ~1/4096 of the chain fill

`get_block_longhash_v13` derives its seed as `hash_bytes[i] ^ salt_bytes[i]`
for i in [0,32) and reads nothing else from the salt. `get_cna_v6_data` writes
`optr` forward 64 bytes per inner iteration starting at `out`, so those 32
bytes land in the first of 4096 iterations, at a cost of about four
block-cache reads.

This is what makes F6's estimate cheap enough to matter. Were the seed to
depend on the whole salt, an estimate would owe the full 256 KB fill per nonce
and would cost more than the hash it is trying to avoid, which is the property
v5 has and v6 does not (F5).

*Checked:* read both functions.

### F9. HF14 modified a function that live HF13 consensus calls

On `pow/cna-v8`, `cn_vm_generate_program` runs from line 41 to 112 of
`cna-vm.c`, and lines 93 to 111 generate v7's `seg_hops` from the same
keystream. v6 calls this function on mainnet today. It is safe only because
those draws happen after the 512-instruction loop completes, so v6's
instructions are unchanged. Interleaved, it would have forked mainnet.

A `git diff` of the two branches shows pure insertion (255 added, 0 removed),
which reads as safe and is not sufficient evidence: an insertion *inside* a
live function changes it.

*Checked:* function boundaries via the brace map, and the placement of the
`seg_hops` loop after the instruction loop.

### F10. `salt_pad` has never selected Skein

`extra_hashes[a % 3]` was written that way when the macro was created in
`5671f9f` (2018-12-15) and has not been touched since. The table declares four
entries. Skein is not unreachable in the hash overall: `finalize_hash` selects
it via `extra_hashes[state.hs.b[0] & 3]`, so about a quarter of every v5, v6
and v7 hash already ends in Skein.

*Consequence:* Phase 1 adds no new code, no new dependency and no new
endianness surface, which is what makes it cheap.

*Checked:* the `5671f9f` diff, the current macro, and both `extra_hashes`
declarations.

## The history

### F11. Pad size has been argued four times, in both directions

- 2018-05-01 `b801807`: 2 MB to **64 MB**. Reverted to 1 MB by `ccd231c` the
  same day.
- 2018-12-15 `5671f9f`: 1 MB to 3 MB. Reverted by `d5c97b2` three days later
  as "undesirable results".
- 2026-07: HF13 went 4 MB to 8 MB **deliberately**, arguing that 8 MB per
  thread overflows L3-per-core on nearly every machine class so they all fall
  back to DRAM latency and even out, while 16 or 32 MB would push verify and
  sync past what the sliding-window work protects.
- The 1 MB pad that v5 still uses has been there since the project's third
  algorithm commit.

*Consequence:* PLAN-v8's move back to 4 MB reverses a documented HF13
decision. It may still be right, for laptop fairness, but it has to answer that
argument rather than pass over it.

*Checked:* the diffs; the HF13 rationale is from its commit message and is
therefore an argument, not a measurement.

### F12. Every algorithm change broke a platform

After `8079d37`: two ARM fixes and "Stop writing code at 3am. Derp". After
`b20a00e`: a Mac fix and three days of patches. After `5671f9f`: ARM fixes, a
Windows crash, and `ca5982e` fixing a global rename that turned
`SE_LOCK_MEMORY_NAME` into `SE_LOCK_memory_NAME`, then "Remove code causing
sync issue". No exceptions in the set.

*Checked:* commit list and dates for `src/crypto/slow-hash*`.

### F13. RandomX was integrated and then removed

Merged 2019-06-11 (`161bc26`, forking and hashing on a private testnet), worked
on through `4f5b66a` and `f747a14`, submodule removed 2020-01-17 (`d72b535`).
No commit records why.

*Consequence:* PLAN-v8 repeatedly measures v8 against RandomX. Whatever the
reason was, it is not in the repository.

*Checked:* commit list and dates.

## Phase 1 results

### F18. CNA v8 costs nothing to verify, measured on two machines

`contrib/powbench/v8bench.c`, interleaved pairs (one v5 nonce then one v8 nonce
on identical parameters), 2000 samples at 1 MB and 600 at 4 MB.

Figures below are from the **fixed** harness (F20); the pre-fix run is kept
underneath because one number moved.

| machine | control | v8 vs v5, 1 MB | v8 vs v5, 4 MB | verdict |
|---|---|---|---|---|
| Ryzen 9 7950X (Zen 4) | 0.65% | **-1.00%** | **-0.79%** | PASS |
| Ryzen 7 9700X (Zen 5) | 2.13% | **-0.90%** | **-1.19%** | PASS |
| Ryzen 5 5600X (Zen 3) | 4.55% | **-0.98%** | **-0.85%** | control flagged, see F21 |
| Core i7-7700HQ (Kaby Lake) | 2.85% | **-0.67%** | **-0.54%** | PASS |

Negative is v8 cheaper. Four CPUs across four microarchitectures, and v8 is
cheaper on every one at both pad sizes: 1 MB between -0.67% and -1.00% (mean
-0.89%), 4 MB between -0.54% and -1.19% (mean -0.84%).

Pre-fix, for the record, the 4 MB column read +0.07%, -0.31%, +0.15% and
+0.09%. The 4 MB pair was already interleaved, so the only change was the
per-sample order rotation; that it moved by most of a percentage point says
the old fixed order was biasing in favour of whichever variant ran first.
Trust the fixed numbers.

### F18b. The 4 MB saving does not dilute, and the model says it should

Predicted from hash costs alone: the extra-hash saving is a fixed ~6.6 us per
nonce whatever the pad, so against a 0.75 ms nonce at 1 MB it is about -0.88%,
and against a 3.16 ms nonce at 4 MB it should fall to about **-0.21%**. The
1 MB prediction is almost exact. The 4 MB one is out by 4x: measured -0.84%.

So something makes the swap worth *more* under a larger pad, not less. The
likely mechanism, untested: Groestl carries ~16 KB of lookup tables while
Skein carries none, so under 4 MB of pad pressure Groestl's tables are evicted
more often and it costs more than its standalone 1758 ns suggests. Dropping
its share from a third to a quarter would then save more at 4 MB than at 1 MB,
which is the direction observed.

*Why it matters:* the plan wants v8 at 4 MB, and this says Phase 1 is at least
as valuable there as at 1 MB rather than fading out. Worth confirming before
being relied on, by timing the four hashes again with a 4 MB working set
thrashing cache alongside them.

This agrees with an independent prediction made from the hash costs alone,
before these runs. Measured on 200-byte inputs: blake 765 ns, groestl 1758 ns,
jh 978 ns, **skein 290 ns**. Skein is the cheapest of the four by a wide margin
and Groestl the dearest by six times, so widening the selector from three to
four drops the mean per `salt_pad` call from 1167 ns to 948 ns. Over ~30 calls
that is about -6.6 us on a ~780 us nonce, or **-0.84%** at 1 MB, diluting
toward zero at 4 MB where the pad sweep quadruples but the hash cost does not.
Predicted -0.84%, measured -0.75% and -0.52%.

*Consequence:* Phase 1 adds a fourth structurally distinct hash datapath for no
verification cost, on every machine in the set including the 6 MB-L3 laptop the
fairness argument rests on. The gate is met on the machine that was supposed to
decide it. Phase 1 is done.

### F20. The control check in `v8bench.c` measures the wrong thing

The 5600X run printed "UNUSABLE: the control pair disagrees by more than 4%"
at 5.88%, while its actual v8-against-v5 figures (-0.79% and +0.15%) sit right
on top of the other three machines. The verdict was a false alarm, and the
reason is a design error in the harness, not noise on that box.

`v5ref` and `v5ctl` are measured in **separate passes**, one after the other.
`v5` and `v8` are measured **interleaved**, alternating within a single pass on
identical parameters. So drift, boost behaviour and background load land on the
ref-against-ctl comparison but largely cancel in the v5-against-v8 one. Using
the first as a noise floor for the second therefore overstates the floor, and
scaling the gate to `2 x` it compounds the error.

The evidence that it is drift rather than a real build difference: the same
machine gives a different control figure run to run (7950X 1.46% then 2.21%,
laptop 2.73% then 1.07%). A systematic difference between two builds of the
same source would not move like that.

*Fixed:* `bench_pair` became `bench_group`, taking k variants and interleaving
all of them within each sample on identical parameters. All four 1 MB variants
now go through one pass together, so the control is measured the same way as
the comparison it is the control for. At 1 MB the resized build reads the same
context scratchpad as the shipped one, so no separate pad is needed and the
four genuinely can share the loop. The running order also rotates per sample,
so no variant is always first against a cold pad.

Same machine, same binary otherwise, 7950X:

    control  before 1.46% and 2.21% (two runs)   after 0.65%

*Read the pre-fix numbers with this in mind.* The paired v5-against-v8 figures
in F18 were always sound, since those were interleaved from the start; it was
only the control, and therefore the gate scaled to it, that was inflated. The
5600X row is good data and its UNUSABLE verdict was a false alarm.

One figure did move after the fix: the 4 MB column, on all four machines, from
about zero to about -0.8%. The 4 MB pair was already interleaved, so the only
change was the order rotation, and it moving consistently on every machine
confirms the old fixed order was biasing toward whichever variant ran first.

### F21. After the fix, the control measures something real, so the guard is now wrong in a new way

Post-fix the control is 0.65%, 2.13%, 2.85% and 4.55% across the four machines,
and the 5600X still trips the "UNUSABLE above 4%" guard. But `ref` and `ctl`
are now interleaved, so drift is no longer what that number contains. It is a
**genuine difference between two builds of the same algorithm**, and it varies
by machine rather than by run.

The cause is understood: `ctl` comes from `v5pad.inc`, which wraps the salt
index with `V5PAD_SALT_WRAP`. At 1 MB the wrap is a provable no-op, but it
still costs an AND inside the innermost loop of the hash, which runs on the
order of 10^5 times per `salt_pad` call and ~30 calls per nonce. Narrower cores
pay more for it, which is why the 5600X and the laptop show more than the
7950X.

So the guard now fires on a real, understood, and irrelevant difference. The
comparison that matters is like against like, and both forms agree:

    machine   v8 vs v5 using ref (no wrap)   using ctl (wrap)
    7950X              -0.48%                    -1.00%
    9700X              -0.68%                    -0.90%
    5600X              -0.52%                    -0.98%
    7700HQ             -0.57%                    -0.67%

*To do:* stop scaling the gate by the control and stop failing on it. Report it
as "pad-machinery overhead" rather than "noise floor", keep a fixed gate now
that interleaving handles drift, and fail only when a variant pair disagrees
between its ref and ctl forms, which is the condition that would actually
invalidate a conclusion.

### F19. Interleaving is what made Phase 1 measurable

The first attempt measured v5 and v8 as consecutive blocks at n=60 and reported
v8 **1.7% slower** at 1 MB and 3.2% slower at 4 MB, reproducing to two decimals
across three runs. All of it was an artifact.

`bench_single` in `t_bench_v5v6.cpp` uses a fixed RNG seed, so a small sample
draws the *same* unrepresentative parameter set every run: a sampling
difference looks stable and reads as a real result. With work per nonce varying
about 4.7x, the standard error at n=60 is near 4.5%, so a 2% question is not
answerable at that sample size.

The tell, missed at first, was that the apparent penalty *grew* with pad size.
The extra-hash cost is constant per nonce while the pad sweep quadruples, so
any real effect had to shrink. **A result that contradicts the mechanism is a
reason to distrust the measurement, however well it reproduces.**

Two fixes, both kept: raise n (2000 at 1 MB), and interleave the pair within
one process so drift and boost behaviour hit both variants equally. After
those, the sign flipped and matched the arithmetic.

## Phase 3

### F22. Deriving the salt stride from the pad is not cost-neutral above 1 MB

The Phase 3 change was framed as an out-of-bounds fix. It is also a work
change, and a large one. Measured on the 7950X, control 0.45%:

| pad | v5 ms | v8 ms | v8 vs v5 |
|---|---|---|---|
| 1 MB | 0.8080 | 0.7931 | -1.84% |
| 2 MB | 1.6768 | 1.4039 | -16.27% |
| 4 MB | 3.3681 | 2.5600 | -23.99% |
| 8 MB | 6.5043 | 4.6769 | -28.10% |

Sweep iterations go as pad over stride, and the expectation is dominated by
the small strides. v5 draws `offset_2` uniform in [4,128]; v8 at 4 MB draws
from [16,128]. `E[1/s]` falls from about 0.0288 to 0.0187, so v8 does roughly
35% fewer sweep steps. The sweep is most of the hash, which lands at -24%.

This follows from the invariant rather than from anything new: pinning
worst-case salt consumption at `CN_SALT_MEMORY` means **the salt sweep does
roughly constant work whatever the pad size**. The pad still grows the AES
fill, the finalize pass and the random-access footprint; it no longer grows
the sweep. The author's own 3 MB version had the same property.

### F23. The salt stays fully consumed at every pad size, so chain binding is unchanged

F22 raises an obvious worry: if the sweep touches a smaller fraction of a
larger pad (a quarter of it at 1 MB, a sixteenth at 4 MB), is the chain-derived
salt still binding the whole hash?

It is, and the reason is the pad init rather than the sweep.
`randomize_scratchpad_256k_v8` steps `CN_V8_SALT_STEP`, which is
`pad / CN_SALT_MEMORY`, so it runs exactly `pad / (pad / 262144)` = **262144
iterations at any pad size**, consuming `salt[0 .. 262143]` in full, every
hash, unconditionally. The static assert that the pad divides the salt evenly
is what makes that exact rather than approximate.

So every salt byte is load-bearing at every pad size, and per-nonce chain
dependence (the pool resistance) is identical. What shrinks is only how widely
the *sweep* spreads salt through the pad before the AES main loop diffuses it,
and the main loop's `state_index` access covers the whole pad regardless.

*Consequence:* the pinned-consumption invariant can be kept. It is the
documented historical design, it leaves chain binding intact, and it makes a
larger pad affordable, which is what the cross-CPU fairness argument wants.
The alternative, wrapping the salt so sweep coverage scales, costs the verify
time back and buys repeated salt with less entropy per pad byte.

### F24. The pad decision, measured: 8 MB is disqualified and 2 MB is the fairness optimum

v8 verify cost, single thread, four machines, `contrib/powbench/v8bench.c`.
The laptop is the machine that sets the spread, so its column is the mean of
two agreeing runs; a third, earlier run read 12% high at 4 MB and 4% high at
8 MB and is excluded as thermally suspect.

| pad | 7950X | 9700X | 5600X | 7700HQ | spread |
|---|---|---|---|---|---|
| 1 MB | 0.7627 | 0.6642 | 1.0179 | 1.5827 | 2.38x |
| 2 MB | 1.3565 | 1.2304 | 1.7856 | 2.8052 | 2.28x |
| 4 MB | 2.4331 | 2.2911 | 3.2379 | 5.2069 | **2.27x** |
| 8 MB | 4.5528 | 4.3388 | 6.1236 | **20.3413** | **4.69x** |

Spread is slowest over fastest, and the target is < 2.2x. No pad reaches it.
v6 today is 2.91x, so 2 or 4 MB improves on the shipped algorithm by a useful
margin and 8 MB is far worse than it.

**Fairness is not monotonic in pad size**, which cuts against the plan's
premise that a smaller pad is fairer. There is a minimum around 2 to 4 MB:

- at 1 MB everything is cache-resident on every machine, so what is measured
  is core speed, and cores differ a lot (2.38x)
- from 2 MB the memory system starts to dominate and the machines converge
  (2.28x, 2.27x)
- at 8 MB the 6 MB-L3 laptop exceeds its cache and diverges again (4.69x)

2 MB and 4 MB are a statistical tie. Fairness does not choose between them.

**8 MB is out.** Cost per doubling of the pad, per machine:

| | 1→2 | 2→4 | 4→8 |
|---|---|---|---|
| 7950X | 1.79x | 1.79x | 1.88x |
| 9700X | 1.86x | 1.87x | 1.89x |
| 5600X | 1.75x | 1.81x | 1.89x |
| i7-7700HQ | 1.75x | 2.09x | **3.60x** |

Three machines scale linearly across the whole range. The laptop, with 6 MB of
L3, falls off a cliff between 4 and 8 MB.

*This contradicts HF13's stated reasoning*, which was that 8 MB overflows
L3-per-core on every machine class and therefore evens them out. It does not
even them out. It falls off a cliff on one machine and not the others, which
is the opposite of one box one vote. The plan's instinct to move off 8 MB was
right, and an earlier note in this session suggesting 8 MB might now be
affordable was wrong because it looked only at the 7950X.

*Recommendation:* **4 MB**, because the fairness axis does not separate it from
2 MB and the ASIC axis does: 4 MB forces roughly twice the silicon. The laptop
verifies in 5.21 ms against a 15 ms target, so there is headroom. 1 MB is both
slightly worse on spread and ASIC-friendly in the wrong direction.

*Note on how this recommendation was reached*, because the first two attempts
were wrong. An earlier pass recommended 2 MB on a 0.28x spread advantage, and
a later one recommended 4 MB on a 0.03x one. Both differences were inside the
laptop's run-to-run variance, which is the only machine that sets the spread.
The defensible statement is narrower than either: **8 MB is disqualified, 1 MB
is slightly worse, and 2 versus 4 MB is decided on ASIC grounds because the
measurement cannot separate them.** A ranking that flips when one machine is
re-run is not a ranking.

*Caveats:* this harness excludes the chain fill, which RESULTS.md charges to
the CPU and which is machine-dependent, so the real spread may differ. And no
pad reaches 2.2x, so if that target is firm then pad tuning alone cannot get
there and Phase 2 stops being optional.

### F25. Removing the v8 wrap from v5pad.inc contaminated the 1 MB control

The harness printed SUSPECT on the laptop and the 5600X, at 3.25 and 4.67
points between its two 1 MB comparisons. The check was right and the cause was
a change made earlier in this session.

`v5pad.inc` wraps the salt index so v5, whose stride is hardcoded for 1 MB, can
be benchmarked at larger pads. When v8 became pad-aware its override was
removed, correctly. But v5's remained, so at 1 MB the "ctl" comparison became
**v5 with the wrap against v8 without it**, which is not like for like. The
wrap is a single AND in the innermost loop, which is why narrower cores showed
it most.

Effects, and what survives:

- Phase 1's correct figure is the shipped-build row: **-0.75%, -0.63%, -0.45%,
  -0.70%**. Consistent with F18, so no published conclusion changes.
- The sweep's `v8 vs v5` percentage column is inflated by the same artifact.
  The -24% at 4 MB is mostly the real stride effect (F22 predicts about 35%
  fewer sweep iterations) but not purely that.
- The sweep's absolute `v8 ms` column is unaffected, so F24 stands entirely.

*Fixed:* `V5PAD_SALT_WRAP` is identity at exactly 1 MB, where it was always a
provable no-op, so the control is once more the same code as the shipped
function. Above 1 MB the two legitimately differ, because the wrap is the only
way v5 can run there at all.

*Confirmed.* The overhead the harness reports is what the wrap cost, and
removing it at 1 MB removed essentially all of it:

    machine    before   after
    7950X       0.57%    0.35%
    9700X       2.20%    0.03%
    5600X       4.60%    0.05%
    7700HQ      3.17%    0.13%

SUSPECT no longer fires anywhere, and the two 1 MB comparisons now agree within
0.27 to 0.79 points on every machine. Phase 1 across the four, from the shipped
build: -0.23%, -0.67%, -0.52%, -0.38%.

*Worth keeping in view:* this is the second time a change that was right in
isolation broke something one level up, after HF14's `seg_hops` landing inside
a function live v6 calls (F9). Both were caught by a check rather than by
review.

## Working environment

### F14. The Bash tool cannot build here; use PowerShell

`gcc` under the Bash tool returns rc=1 with **no diagnostics at all** and
produces no output file, even for `int main(void){return 0;}`. The same command
through the PowerShell tool works and prints real errors. A `cmd 2>&1 | head`
pipeline also reports the wrong exit status, so `echo "rc=$?"` after a pipe
reports `head`'s success and hides a failed compile.

Working build line for the standalone harnesses:

    gcc -O2 -I src -I src/crypto -I contrib/epee/include \
        contrib/powbench/screen.c src/crypto/cna-vm.c src/crypto/hc128.c \
        -o screen -lm

(`hash-ops.h` pulls `int-util.h` from `contrib/epee/include`.)

### F16. A hand-built crypto harness silently times software AES

`slow-hash.c` reduces `CN_DISPATCH` to the SW path unless
`SLOW_HASH_HW_AES_BUILT` is defined, and the runtime choice then goes through
`crypto_has_aesni()`, which lives in `crypto.cpp`. A harness compiled by hand
without that define, or one that stubs the symbol to 0, runs the software
body and reports a v6 hash at about **38 ms instead of about 7.7 ms on a
7950X**, a 5x error in the direction that makes fixed costs look dominant.

This happened here, and the first throughput answer it produced (VM = 14.5% of
the hash, screening worth 1.1x) was wrong in a way that looked plausible. What
caught it was the 10.11 ms baseline in RESULTS.md: a number that far off the
record is a reason to stop, not to publish.

`screen_time.c` now prints the AES path and the page tier in its banner. Keep
that. Also note `crypto_has_aesni` has to be supplied to avoid linking the C++
crypto library, and it must do the same CPUID check (leaf 1, ECX bit 25).

Working build line:

    gcc -O2 -maes -march=x86-64 -fno-strict-aliasing -DSLOW_HASH_HW_AES_BUILT=1 \
        -I src -I src/crypto -I contrib/epee/include \
        contrib/powbench/screen_time.c \
        src/crypto/slow-hash.c src/crypto/slow-hash-hw.c src/crypto/slow-hash-sw.c \
        src/crypto/cna-vm.c src/crypto/hc128.c src/crypto/oaes_lib.c \
        src/crypto/aesb.c src/crypto/keccak.c src/crypto/hash.c \
        src/crypto/blake256.c src/crypto/groestl.c src/crypto/jh.c \
        src/crypto/skein.c src/crypto/hash-extra-*.c \
        contrib/epee/src/memwipe.c -o screen_time -lm

### F17. RESULTS.md carries two different v6 numbers, measured differently

Section 3 ("CPU results, real hash functions") reports v6 at 8 MB as 6.95 ms on
the 7950X. Section 4 ("Four machines, faithful port") reports v6 8MB as 10.11
ms on the same CPU. They are not the same measurement: section 3 runs the
shipped function through `hf14checks`, section 4 runs the powbench port, which
deliberately omits the Keccak framing and the four finalisation hashes.

The direct timing in F6b lands at 7.70 ms, agreeing with section 3.

*Consequence:* PLAN-v8's target table is anchored on the 10.11 ms figure, which
is the port and not the function. The targets are still coherent as long as
every row is the port, but any target quoted against the shipped function
should use section 3's number. Worth reconciling before the targets are used
to accept or reject a candidate.

### F15. `hf14checks` inverts its own results if a TU misses its flags

`contrib/hf14checks/CMakeLists.txt` names the resized translation units
explicitly in `set_source_files_properties` with
`-O2;-DNDEBUG;-maes;-march=x86-64;-fno-strict-aliasing`. A new TU left off that
list builds at the directory default, which is `-O0`, and compares against
`libcncrypto.a` built at `-O2`. This has reversed a conclusion twice. The
control row (`v5ref` vs `v5ctl` at ~1.00x) exists to catch it, and if it is not
~1.00x nothing else in the run means anything.

## Open questions

1. ~~The 8.5 to 13.4x throughput claim for F6 is unverified.~~ **Resolved: it
   is about 1.5x.** See F6b.
2. **Why was RandomX dropped in January 2020?** See F13. Worth asking someone
   who was there before Phase 2 reinvents a piece of it.
3. **v7's figures are commit-message claims, not findings.** The "per-nonce
   program only governed 3% of the hash" line and the 1.76x-versus-3.07x GPU
   numbers have not been reproduced. Low priority while v7 is not shipping,
   except that the 3% lesson is the one worth carrying into Phase 2: a
   construction can look strong while almost none of its randomness is
   load-bearing.
4. **No GPU number is trustworthy at full occupancy.** Carried from
   `RESULTS.md`: every large-pad row on every machine hit the launch cap
   because a display-attached GPU trips TDR.

## Reproducing

    # the v6 cost-oracle screen (counts only, unaffected by machine load)
    gcc -O2 -I src -I src/crypto -I contrib/epee/include \
        contrib/powbench/screen.c src/crypto/cna-vm.c src/crypto/hc128.c \
        -o screen -lm
    ./screen 200000 200 2048      # static programs, live nonces, passes each

`screen.c` aborts rather than report if its instrumented interpreter stops
matching `cn_vm_execute`. Keep that gate. It has already caught one error.
