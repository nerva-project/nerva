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

### F24. Single-thread pad measurements: 8 MB is disqualified, 1/2/4 MB are close

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

*This does NOT contradict HF13's reasoning, as an earlier version of this
entry claimed.* HF13 argued that "under full multi-core mining, 8 MB per thread
overflows the L3-per-core budget on nearly every machine class". Everything in
this table is single-threaded, which is the right measure for verification cost
and the wrong one for mining fairness. Both can be true at once, and F27
measures the case HF13 was actually talking about.

*No recommendation from this table alone.* An earlier version recommended 2 MB
on a 0.28x spread advantage, then 4 MB on a 0.03x one. Both differences were
inside the run-to-run variance of the laptop, which is the only machine that
sets the spread, and a ranking that flips when one machine is re-run is not a
ranking. What this table supports is narrower: **8 MB is disqualified; 1, 2 and
4 MB cannot be separated single-threaded.** The decision comes from F27.

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

### F26. `v5pad.inc` shadows consensus macros, and every shadow is a divergence waiting to happen

`contrib/hf14checks/v5pad.inc` rebuilds the hash at a different pad size by
`#undef`-ing and redefining macros from `slow-hash.h`. That is what makes the
pad sweep possible, and it means **the benchmark holds a private copy of parts
of the algorithm**. Whenever the real macro changes, the copy has to change in
the same commit or the two silently compute different things while every number
still looks plausible.

It has happened four times in one session:

1. `salt_pad_v8` was added to `slow-hash.h`, and `v5pad.inc` had no wrap for it,
   so resized v8 rows would have read past the salt (caught before running).
2. v8's stride became pad-aware, and `v5pad.inc` still overrode `salt_pad_v8`
   with the wrap, so the benchmark measured a different algorithm from the
   daemon above 1 MB (F25).
3. v8's wrap override was removed but v5's remained, so the 1 MB control became
   wrapped against unwrapped and overstated v8 by 3 to 5 points on narrow cores
   (F25, caught by the harness's own consistency check).
4. v8 moved to its own translation unit at its own pad size, and `v5pad.inc`
   included only `slow-hash-impl.h`, so the resized v8 builds vanished (a link
   error) and, behind that, v8 read `cna_scratchpad` while the benchmark handed
   it a different buffer through `scratchpad`.

Three of the four would have produced confident wrong numbers rather than a
build failure.

*Rule:* anything in `slow-hash.h` or the impl headers that becomes pad-aware or
buffer-aware has a mirror in `v5pad.inc`. Update both in one commit, and prefer
making the shipped macro general enough that the override can be **deleted**
rather than maintained, as was done for `salt_pad_v8` and `CN_V8_PAD`.

*Guard:* `v8bench` now proves the shipped and recompiled builds compute the same
function, by hashing 24 inputs through both and comparing bytes, before it
times anything. A timing control cannot do this: a cost ratio cannot separate
"different algorithm" from "different memory behaviour", and those need
opposite responses. Output comparison settles it in a fraction of a second and
is the check that would have caught cases 2 and 3 immediately.

### F27. Multi-thread fairness decides the pad, and it chose 1 MB

Everything before this was single-threaded, which measures verification cost.
Mining runs every core at once and the pads compete for a shared L3, so a pad
that fits on one thread may not fit eight times over. That is the case HF13's
argument was about, and it had never been measured.

Peak total H/s, `v8bench` thread scaling, four machines:

| | cores | 1 MB | 2 MB | 4 MB | 8 MB |
|---|---|---|---|---|---|
| 7950X | 16 | 24120 | 12848 | 4553 | 747 |
| 9700X | 8 | 12309 | 6443 | 2396 | 803 |
| 5600X | 6 | 6827 | 3924 | 1452 | 537 |
| i7-7700HQ | 4 | 2132 | 656 | 191 | 49 |
| **spread** | 4.0x | **11.3x** | 19.6x | 23.8x | 16.4x |

The amplification each machine gets from threading, peak over 1T:

| | 1 MB | 2 MB | 4 MB | 8 MB |
|---|---|---|---|---|
| 7950X | 18.6x | 18.0x | 11.5x | 3.5x |
| 9700X | 8.4x | 8.2x | 5.9x | 3.6x |
| 5600X | 7.0x | 7.1x | 4.8x | 3.4x |
| i7-7700HQ | 3.4x | 1.9x | **1.0x** | **1.0x** |

**HF13's effect is real and visible**: at 8 MB the three desktops amplify by
3.5x, 3.6x and 3.4x across 16, 8 and 6 cores. A large pad genuinely does stop
core count mattering.

**But it does not apply to everyone.** The laptop gets 1.0x at both 4 and 8 MB:
with 6 MB of L3 a single 4 MB pad leaves no room for a second thread, so four
cores buy nothing. The cliff does not hit machines evenly, it hits **small
machines first and hardest**. A large pad equalises the machines that are
already comfortable and excludes the one that is not.

The pattern is simply how many threads each machine can fit in L3: at 1 MB the
laptop fits four, at 2 MB two, at 4 MB one, at 8 MB less than one.

*Decision: 1 MB*, the pad v5 has used since HF11.

| | fairness (1T) | fairness (nT) | verify | GPU | ASIC |
|---|---|---|---|---|---|
| 1 MB | 2.39x | **11.3x** | **best** | see F28 | see F28 |
| 4 MB | 2.56x | 23.8x | 3.4x cost | see F28 | see F28 |

Both cleanly measured fairness axes favour it, one decisively, and it is 3.4x
cheaper to verify. The two axes that favour a larger pad could not carry a
decision (F28). Lower-end hardware than the laptop, which is what the fairness
argument is ultimately for, is excluded harder at every step up in pad size.

A secondary benefit: at 1 MB, v8 is v5 with one token changed. For a fork
already carrying CLSAG, Bulletproofs+ and ring size 16, the most conservative
possible PoW change is a virtue.

### F28. Neither argument for a larger pad could carry the decision

**The ASIC argument is unmeasured.** It appears once, in `PLAN-v8.md`, as "1 MB
fits in on-die SRAM at useful core counts (~200 MB for an ASIC to match one
7950X)" against "~680 MB" at 4 MB. `RESULTS.md`, which holds every measurement,
contains no ASIC content at all, and the plan flags it itself: "arithmetic about
SRAM density and concurrency... should be weighted as engineering estimate, not
evidence." It is also **linear in pad size by construction**, being pad times an
assumed concurrency, so it carries no information beyond "4x the pad, 4x the
SRAM" and cannot say whether either figure is prohibitive.

Weak counter-evidence exists that it did not matter: Nerva ran v5 at 1 MB from
HF11 to HF13, about 3.8M blocks, and no ASIC appeared. Coin value affects that
as much as algorithm does, but it is more evidence than the arithmetic. At this
chain's size an ASIC is not a plausible economic threat.

**The GPU comparison cannot support a pad comparison.** The table reads 0.17x
worst-case at 1 MB against 0.06x at 4 MB, which looks like a 3x argument for the
larger pad. RESULTS.md's own caveats undo it:

- the ratio swings **2.8x with nonce count** (v6 at 1 MB: 0.17x at 1984 nonces,
  0.48x at 8128)
- and **4x with the launch cap** (v7: 0.08x at cap 10, 0.33x at cap 25)
- the large-pad rows are the ones that hit the cap and ran starved, so their
  figures are explicitly "floors", while the 1 MB rows were not starved

So the comparison is an honest number against a floor, confounded in exactly the
direction that flatters large pads.

What the GPU data *can* say: on every variant and pad measured, the GPU loses,
0.01x to 0.48x. What it has never covered is **v5 or v8 at 1 MB against a GPU at
full occupancy**, which is the single most relevant number for this choice and
is the open question being referred outward.

*Route to measuring it properly, if wanted:* `main.cpp` states "chunking cannot
help: an in-order queue runs one kernel at a time, so short chunks starve the
device". That rules out chunking the **nonces**, which is what was tried. It does
not rule out chunking the **work**: keep every nonce resident and split the main
loop, leaving the pad, salt and registers in VRAM between launches. Occupancy
stays full while launch duration becomes independent of it, which is how miners
run on display-attached cards under Windows.

## Phase 2

### F29. FP determinism holds between x86-64 and aarch64 under the Phase 2 constraints

`t_fp_determinism.c` exercises the five permitted operations (add, sub, mul,
div, sqrt) under the group-E operand constraint and data-driven rounding, and
prints four checksums of raw bit patterns. All four agree between the x86-64
baseline and a Pixel 7a:

      basic add/sub/mul/div : 8ae92fac4343e627
      sqrt and div          : 0de4d9f1333e87b7
      fma contraction canary: 04c3614dff6aed8c
      data-driven rounding  : d6e736346922def8

The checkpoint that mattered most is the fourth. Rounding mode changed from data
is the most likely place for the two platforms to diverge, because x86 goes
through MXCSR and ARM64 through FPCR, and `fesetround()` is the only part of the
probe that is a libc call rather than an instruction. It agreed bit for bit.

This clears the gate: **an FP stage cannot be ruled out on determinism grounds**,
which is what Phase 2 was blocked on.

*Checked:* built and run on the device, not inferred. `clang -O2
-ffp-contract=off t_fp_determinism.c -o t_fp -lm` under Termux on a Pixel 7a,
banner reporting `arch: aarch64`, `FLT_EVAL_METHOD=0`, 128-bit long double,
against the x86-64 baseline in commit fb5f781. The clang version was not
recorded, which is the one gap in this entry.

### F30. The FMA canary fired on the first ARM run, and that is the real warning

The first Pixel run omitted `-ffp-contract=off`. Three of the four checksums
still matched; the canary did not, reporting contraction on **4674 of 200000
cases** and a checksum of `e718b7f22e56abca` against the baseline's
`04c3614dff6aed8c`. Clang defaults to contraction on and aarch64 has `fmadd`, so
the compiler fused `a*b+c` sites and moved the result.

The canary worked as designed, but the lesson is about what ships rather than
about this probe. **A passing canary means the build flag was set, not that the
risk is absent.** Anyone rebuilding the daemon without `-ffp-contract=off` would
produce a binary that disagrees with the network, and the failure mode is a
chain fork rather than a build error.

The RandomX review already recorded the better answer, and F29 does not
supersede it: the interpreter stores each result before the next operation reads
it, so contraction cannot occur structurally and no flag has to be trusted. If
an FP stage ships, it must be built that way.

*Checked:* observed directly on the device on the first run, before the flag was
added; the second run with the flag produced F29's matching value.

## ARM64

### F31. On ARM, spread worsens monotonically with pad size, which settles the pad question

v8 verify cost, single thread, pinned to one core of each type on a Pixel 7a
(Tensor G2: 2x Cortex-X1 at 2.85 GHz, 2x A78 at 2.35, 4x A55 at 1.80):

| core | 1 MB | 2 MB | 4 MB | 8 MB |
|---|---|---|---|---|
| X1 | 1.6215 | 3.3843 | 7.1943 | 15.8481 |
| A78 | 2.4045 | 4.4923 | 8.3451 | 16.4419 |
| A55 | 7.2288 | 13.3664 | 26.1062 | 69.5758 |

Taking the X1 as the device's figure, because anyone mining pins to the big
cores and nobody runs on an A55 while X1 cores sit idle, and folding it into the
four-machine spread from F:

| pad | x86 only | with the Pixel |
|---|---|---|
| 1 MB | 2.38x | **2.44x** |
| 2 MB | 2.28x | 2.75x |
| 4 MB | 2.27x | 3.14x |
| 8 MB | 4.69x | 4.69x |

At 1 MB the phone lands within 2.4% of the i7-7700HQ (1.6215 against 1.5827) and
barely moves the spread. Every larger pad it moves substantially, and the damage
grows with the pad.

**This reverses the conclusion in F that fairness has a minimum around 2 to 4
MB.** That was measured on four x86 desktops and laptops, every one of them with
a large shared L3, and it is an artifact of that sample. With a phone in the set
the spread worsens monotonically with pad size and 1 MB is the best pad, not the
worst. The 1 MB decision previously rested on the threading argument alone; it
now has direct single-thread evidence.

Two further observations. The A55-to-X1 ratio is roughly flat across pads at
4.46x, 3.95x, 3.63x and 4.39x, so pad size governs how unequal *devices* are
against each other, not how unequal cores are *within* a device. And the gate
passed on all three core types, with 1 MB deltas of +0.08%, -0.15% and -0.34%
against controls of 0.11% to 0.60%, so v8 costs no more than v5 on any ARM core
class measured.

*Checked:* two pinned runs on the device, via `contrib/powbench/pin-runs.sh`,
both self-verified for placement per F32. Reproducibility differs sharply by
core: A78 agreed to 0.01% between runs (2.4045 against 2.4048) and A55 to 0.56%
(7.2288 against 7.2695), but **X1 disagreed by 5.5%** (1.6215 against 1.5370),
with the direction flipping across pads rather than running one way, which makes
it scatter rather than drift and fits the core that boosts hardest and throttles
first. The figure used here is the fully clean 1.6215; the 1.5370 came from a run
reporting `ran on cpu7` against a pin of 6, both X1 cores, so it is probably
sound but carries an asterisk. The X1 being the least reproducible core is worth
remembering, since it is the one the fairness number depends on.

### F32. A pinned run on Android can be moved to another core class mid-measurement

`taskset` verified before the run does not stay true. With the screen allowed to
sleep, a run pinned to cpu4 reported `cpus allowed changed from 4 to 0-5`, then
ran on cpu5, and the following core was skipped because the pin would not take
at all (`allowed: none`). Android rewrites a backgrounded app's cpuset, and the
affinity goes with it.

The failure is silent and produces numbers that look like core-type
measurements. An earlier run pinned to an A55 gave a pad sweep of `1MB=7.2695
2MB=13.2546 4MB=6.9353 8MB=14.3723`: cost falling as the pad quadrupled, because
it began on the A55 and finished on a big core. Its 4 MB and 8 MB figures
matched the X1 run's almost exactly, and its own variant table disagreed with
its 4 MB sweep row by 3.7x, 25.8725 ms against 6.9353. None of that was
reported; it had to be noticed.

v8bench now re-reads the affinity mask after every pad row, compares the running
core against the starting core when the mask names a single CPU, and requires
the sweep to be monotonic. Any of the three prints `*** TAINTED` and exits 2.
`pin-runs.sh` holds a wake lock, treats a tainted block as one bad core rather
than a failed run, and lists what to re-measure.

**Keeping the screen awake was sufficient.** The clean run differs from the
tainted one only in that.

*Checked:* observed on the device across two consecutive runs that differed only
in whether the screen was allowed to sleep. The monotonic check was separately
tested against both real sweeps: it fires on the A55 one and stays quiet on the
X1 one.

### F33. FP is the most uniform work measured, so it narrows the spread rather than widening it

Net cost per iteration, ns, `contrib/powbench/t_fp_cost.c`, serial dependency
chains against an identical control. Phone figures are pinned per core type.

| | 7950X | 9700X | 5600X | 7700HQ | X1 | A78 | A55 |
|---|---|---|---|---|---|---|---|
| add+sub | 1.562 | 1.737 | 1.984 | 2.699 | 1.311 | 1.572 | 2.941 |
| mul | 1.087 | 1.234 | 1.342 | 1.079 | 0.918 | 1.064 | 1.258 |
| div | 2.936 | 3.236 | 3.494 | 3.951 | 4.115 | 4.943 | 11.964 |
| sqrt | 4.340 | 4.763 | 5.004 | 6.227 | 5.473 | 6.628 | 10.891 |
| round | 4.978 | 5.874 | 6.160 | 6.396 | 1.200 | 1.427 | 2.895 |
| **mixed** | **15.131** | **17.075** | **18.143** | **18.533** | **16.592** | **20.164** | **37.896** |
| control | 1.362 | 1.279 | 1.469 | 2.131 | 2.989 | 3.665 | 16.662 |

`add+sub` performs two operations per iteration where the others perform one, so
halve it before comparing it against `mul`. The `mixed` row, which is what the
decision rests on, is unaffected.

**Spread of `mixed` across the machines that can set the CN spread is 1.22x,
against 2.44x for the hash itself (F31).** Taking the X1 as the phone's figure,
since a miner pins to the big cores. FP is roughly half as unequal as the work
it would dilute, so adding it pulls the spread down.

Two rows are worth reading on their own.

**The control.** Plain integer scaffolding, PRNG and bit manipulation, spreads
12.2x between the 7950X and the A55, and 2.2x between the 7950X and the X1. FP
on the same machines spreads 2.5x and 1.1x. **FP is more uniform than integer
work here, not just more uniform than memory work**, which is a stronger claim
than the plan made and was not anticipated by anyone.

**Rounding is inverted from what PLAN-v8 assumed.** The plan says setting the
mode is "a register write on x86 and a libc call on ARM, and in a hot loop that
cost is real", implying ARM pays. Measured, x86 pays 4 to 5 times more, on all
four x86 machines: 4.978, 5.874, 6.160 and 6.396 ns against 1.200 to 2.895 on
ARM. An MXCSR write serialises the x86 pipeline while the ARM FPCR write is
cheap. Data-driven rounding is the single most ARM-favourable component
measured, and it was recorded as a liability.

Also note the two axes rank machines differently: the 7950X is fastest on FP
while the 9700X is fastest on the hash. No machine leads both, which is a
fairness property independent of the spread arithmetic.

**What it costs to reach the 2.2x target.** Treating total cost as the hash plus
k rounds of the mixed stage, k is about **7,640**:

| | hash only | with FP | change |
|---|---|---|---|
| 9700X (fastest) | 0.6642 ms | 0.7947 ms | +19.7% |
| 7950X | 0.7627 | 0.8783 | +15.2% |
| 5600X | 1.0179 | 1.1565 | +13.6% |
| 7700HQ | 1.5827 | 1.7243 | +8.9% |
| Pixel X1 (slowest) | 1.6215 | 1.7483 | +7.8% |

That is the first lever measured that reaches 2.2x; F showed pad tuning cannot.
Worst case is +19.7% verify cost against an order of magnitude of headroom. The
slowest machine changes identity from the phone to the 7700HQ near k = 19,990,
well above where this lands, and the 5600X cannot set either end at any k.

*Checked:* run on all four x86 machines from one static binary and on three
pinned Pixel 7a core types, `-ffp-contract=off` throughout. **This refutes the
prediction recorded in 7c0b8f1**, which was that FP would spread wider than
2.44x because divide and square root vary most between designs. Divide does vary
most, 1.35x between the 7950X and the 7700HQ, but not nearly enough to
outweigh how much more uniform the rest of the mix is than memory access. The
Skylake divider was called "the weakest in the set by a wide margin" and is
1.35x, not the 2x assumed.

*Limits:* k assumes cost is linear in rounds and that the mixed block represents
the shipped stage, which will also fold results into the integer state per
PLAN-v8 item 6 and so carry scaffolding this probe lacks. Treat 7,640 as a
design target to re-measure, not a specification. All figures are single-thread
latency; SMT siblings share FP units, so the multi-threaded picture is untested
and needs its own pass before anything ships.

### F34. The FP stage is bit-identical across architectures, and its real cost is not what the probe predicted

**Determinism, on the algorithm rather than on a probe.** `cn_slow_hash_v14`
and `cn_slow_hash_v15` produce identical output on three platforms spanning two
architectures and three toolchains:

| platform | toolchain | how |
|---|---|---|
| Windows x86-64 | MinGW gcc | by hand |
| Linux x86-64 | gcc | by hand |
| macOS aarch64 (Apple M1) | clang | by hand |
| Android aarch64 (Pixel 7a) | Termux clang | by hand |
| Linux riscv64 | gcc | CI under QEMU |
| Linux armv7 (32-bit) | gcc | CI under QEMU |

    v14 16da28b8ec84c42cd776c908807ac204daf763503b24c396e6b0d6c4b015eba2
    v15 c7d123c1993299cbd07bb8a84cc4bb002e35f3cc1240b95b2e663d22318e5edd

This is what F29 could only claim for the primitives. The FP stage crosses the
architecture boundary inside the real hash, which is the risk that could have
ended Phase 2 outright.

**Four architecture families now, not two.** riscv64 and armv7 were added by
`.github/workflows/fp-portability.yml` running under QEMU, and both pass on the
first attempt: `t_fp_determinism` matches all four x86-64 reference checksums
and `t_fp_stage` produces the same v14 and v15 hashes. riscv64 matters because
it is a third instruction set with a third libc and compiler combination, and
armv7 because it is the 32-bit path nothing else had exercised. Big-endian
remains untested for the full hash, for reasons that are nothing to do with
floating point: see F36.

**Measured cost of the stage**, `contrib/powbench/t_fp_stage.c`, at the shipping
count of 9,600 rounds. Every figure below is measured, none projected:

| | hash 1 MB | FP us | ns/round | hash + stage |
|---|---|---|---|---|
| 9700X | 0.6608 | 121.3 | 12.64 | **0.7821** |
| 7950X | 0.7632 | 111.1 | 11.57 | 0.8743 |
| 5600X | 1.0107 | 138.7 | 14.45 | 1.1494 |
| Apple M1 | 1.3633 | 58.0 | 6.04 | 1.4213 |
| Pixel X1 | 1.5335 | 115.6 | 12.04 | 1.6491 |
| i5-8279U | 1.5638 | 90.1 | 9.39 | 1.6539 |
| 7700HQ | 1.5777 | 144.0 | 15.00 | **1.7217** |
| Pixel A78 | 2.4163 | 138.7 | 14.44 | 2.5550 |
| Pixel A55 | 7.3022 | 322.5 | 33.60 | 7.6247 |

**Cross-CPU spread goes from 2.388x to 2.201x, which meets the 2.2x target.**
The 9700X sets the fast end and the i7-7700HQ the slow end, on both axes. The
gate passed on every machine. Phone figures use the X1, since a miner pins to
the big cores; the A78 and A55 rows are context, not spread inputs.

**The mechanism, which was not predicted: FP cost is anti-correlated with hash
cost.** The 7950X is fastest at hashing and second-slowest at FP; the M1 is
mid-pack at hashing and fastest at FP by 1.9x. A machine that leads on one axis
trails on the other, which is what dilution needs and what no single-axis
workload can provide. This is why FP reaches a target that pad tuning could not
(F).

**Cost is linear in the round count**, checked rather than assumed when the
count moved from 7,680 to 9,600: 7950X 11.70 to 11.57 ns/round, i5-8279U 9.60 to
9.39, Pixel X1 11.77 to 12.04, Pixel A55 35.0 to 33.60. Only the Apple M1
dissented, 4.82 to 6.04, and that machine cannot be pinned, so a longer stage
spends longer exposed to scheduling. Three families agreeing against one
unpinnable outlier is why the arithmetic was trusted.

**F33's probe does not predict this stage and should not be used for the
decision.** The probe called the M1's mixed round 19.186 ns, slower than the
Pixel X1's 16.592; the real stage is 4.82 against 11.77, the opposite ordering.
The probe-to-real ratio is 0.78 on x86 and 0.24 on the M1, so it is a different
answer rather than a constant offset. F33's 1.22x spread, and the 7,640-round
design target computed from it, are superseded by this entry.

*Checked:* built and run on each machine. x86-64 figures come from `-static`
binaries built on the 7950X; aarch64 from local clang builds. The i7-7700HQ was
run three times because it sets the slow end and is thermally limited, and read
143.7, 144.0 and 144.1 us, a 0.3% spread.

*One number in the table is not understood.* The i5-8279U and the i7-7700HQ are
both Skylake-family mobile parts at similar clocks, yet differ 1.60x per round,
9.39 against 15.00. The 7700HQ is not drifting, its three runs agree to 0.3%,
and its hash time is within 3% of the NUC's. A sustained clock held below its
rated turbo would produce exactly this shape, since the hash is memory-bound and
barely notices while the stage is latency-bound and scales with clock. If that
is what it is, its true cost is nearer 12.5 ns/round and the spread is 2.17x
rather than 2.201x. Either reading meets the target, so this is recorded as
unexplained rather than resolved.

*Two estimator lessons, both learned by being caught:*

**The mean is wrong on a machine that migrates.** On the M1 the scheduler moves
work between performance and efficiency cores and macOS offers no affinity call
to stop it. v8bench's mean read -0.59%, meaning the stage appeared free, while
its own min column showed 31 us and a direct measurement showed 37.0 us.

**The mean is wrong on a machine that throttles.** The fanless i5-8279U read
100.4, 65.8 and 73.8 us across three runs. Because the hash is memory-bound
while this stage is a latency-bound dependency chain, throttling slows the stage
and barely touches the hash: across the first two runs the stage moved 35% while
v14 moved 0.7%. Neither effect can make a run faster than its uncontended cost,
so `t_fp_stage` now reports best-of and warns when the mean exceeds it by more
than 25%.

*One retraction.* An earlier version of `t_fp_stage.c` used inputs shorter than
43 bytes, and slow-hash.h's v1 tweak reads `NONCE_POINTER`, which is `data + 35`,
as a uint64_t. All six inputs therefore read past the end of their literals.
Windows and macOS agreed with each other because both laid the literals out the
same way and Linux did not, which presented as v14 producing different hashes on
different platforms. Any cross-platform hash comparison from that build is void,
including a determinism claim recorded before the fix. The test now checks input
length at startup. v8bench was never affected; its blob has always been long
enough and says so in a comment.

### F35. Under full thread load the stage costs less, not more, on properly cooled machines

The concern that prompted this: SMT siblings share FP units, so a stage that is
fair thread-for-thread need not be fair machine-for-machine once every core is
loaded. Peak total H/s at 1 MB, `v8bench` thread scaling:

| | v8 peak | v15 peak | multi cost | single cost | ratio |
|---|---|---|---|---|---|
| 7950X | 14429.0 | 12631.3 | -12.46% | -12.71% | 0.98 |
| 9700X | 13468.9 | 12506.4 | -7.15% | -15.60% | **0.46** |
| 5600X | 6703.4 | 6298.0 | -6.05% | -12.16% | **0.50** |
| Apple M1 | 3999.2 | 3819.8 | -4.49% | -4.26% | 1.05 |
| i5-8279U | 2188.2 | 1968.1 | -10.06% | -7.11% | 1.41 |
| 7700HQ | 2112.2 | 1898.9 | -10.10% | -8.24% | 1.23 |
| Pixel 7a | 1546.9 | 1228.6 | -20.58% | -6.97% | **2.95** |

**SMT contention is not the mechanism.** If it were, the 7950X would show it
worst: it has the most SMT threads in the set, 32 on 16 cores. It shows none.
The two Zen desktops make the stage *cheaper* under load, at less than half its
single-thread price, and thread better with it than without: the 9700X amplifies
9.73x against 9.08x, the 5600X 7.41x against 6.79x. Five of the seven machines
amplify better with the stage than without it.

The reason is the memory wall. At high thread counts the hash saturates memory
bandwidth and its throughput plateaus, so adding compute that touches almost no
memory is close to free. The stage is the only part of the algorithm that does
not compete for bandwidth.

**What varies is cooling, not architecture.** The three machines above 1.0 are a
fanless mini PC, a laptop and a phone. The stage is latency-bound and scales with
clock while the hash is memory-bound and barely notices, so a machine holding a
reduced sustained clock pays disproportionately. That is the same mechanism as
F34's unexplained i5-8279U against i7-7700HQ gap, now visible as a pattern rather
than a single oddity.

**Spread under load, and the scope it is judged against:**

| set | v8 | v15 | |
|---|---|---|---|
| cooled desktops (7950X, 9700X, 5600X, M1) | 3.61x | **3.31x** | narrows |
| every machine except the phone | 6.83x | **6.65x** | narrows |
| every machine | 9.33x | 10.28x | widens |

**Scope decision, and whose it is.** The last row is driven entirely by the
Pixel, whose 2.95x penalty is the outlier in the table. The project's position,
recorded here as a judgement rather than a measurement: a phone is not a mining
target for this chain, miners use desktops or purpose-built rigs, and those have
cooling. Judged against the hardware that will actually mine, the stage narrows
the loaded spread as well as the single-thread one.

The phone row is kept because it is real and because the decision above is a
choice that a later reader is entitled to disagree with. If whole-machine
fairness on thermally limited hardware ever becomes the governing metric, this
is the number that reopens the question.

*Checked:* `v8bench` thread scaling on all seven machines, peak total H/s with
and without the stage measured in the same run so throttling and background load
land on both. Phone run unpinned and under a wake lock, since a thread ladder on
one pinned core measures nothing.

### F36. Big-endian support is nominal: `e2i` is missing its byte swap

`e2i` in `src/crypto/slow-hash.h` reads the scratchpad index straight out of
memory:

    STATIC size_t e2i(const uint8_t *a, size_t count)
    { return (*((uint64_t *)a) / AES_BLOCK_SIZE) & (count - 1); }

There is no `SWAP64LE`. Seven lines below it, `mul` and `sum_half_blocks` both
use it on every load and store. Upstream's version of this line has it.

`SWAP64LE` is `IDENT64` on little-endian and `SWAP64` on big-endian
(`contrib/epee/include/int-util.h`), so on every machine anyone runs this on,
the omission is invisible. On a big-endian machine the same sixteen bytes yield
a different index, so the hash walks a different path through the pad and comes
out different.

**This reaches live consensus, not just the Phase 2 prototype.** The hardware-AES
gate in `slow-hash.h` covers only x86 and aarch64-with-crypto, so every
big-endian target compiles the software path and calls `e2i`. That path is what
`cn_slow_hash_v11` and `cn_slow_hash_v14` run there, which means v5 and v8
already produce different proof-of-work on big-endian than on little-endian.

So the s390x entry in `CMakeLists.txt` buys a build, not a working node. A node
built there would reject the chain. **Big-endian support is nominal.**

Two consequences worth separating.

**For Phase 2:** the FP stage inherits this rather than causing it, and the same
is true of its own `(uint64_t *)` reads of `a` and the pad. "v15 adds
big-endian risk" was wrong as an argument against shipping it; the risk predates
it by every release.

**For a fix, if anyone wants one:** adding `SWAP64LE` to `e2i` is provably a
no-op on little-endian, since the macro is the identity there, so it cannot
change any hash any existing node computes. That makes it safe in a way most
consensus edits are not. It is not done here because it is a consensus file and
the decision is not a measurement. Note also that fixing `e2i` alone would not
be sufficient: the FP stage would need the same treatment, and nothing has
audited the rest of the software path for other unswapped reads.

*Checked:* read the three functions together in `slow-hash.h`; confirmed
`SWAP64LE` resolves to `IDENT64` under `__LITTLE_ENDIAN__` in
`contrib/epee/include/int-util.h`; confirmed the hardware gate at
`slow-hash.h:234` excludes every architecture that is not x86 or
aarch64-with-crypto, so big-endian necessarily takes the `e2i` path; and traced
the line's history to 83ff56d, which introduced it without the swap. The swap
was never present in this file.

*Pinned by CI:* `.github/workflows/fp-portability.yml` runs the FP probes under
QEMU on riscv64, armv7 and s390x. `t_fp_determinism` is a hard gate on all
three, including big-endian, because nothing in it is endian-sensitive.
`t_fp_stage` is expected to fail on s390x and the workflow fails if it ever
starts passing, so a future endianness fix announces itself instead of going
unnoticed.

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
