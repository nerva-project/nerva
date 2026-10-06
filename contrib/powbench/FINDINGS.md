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

    full cn_slow_hash_v13 : 7.70 ms   ([RESULTS.md](RESULTS.md) section 3 says 6.95 for the
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

**`screen_time.c` omits the chain fill, which is the same mistake [RESULTS.md](RESULTS.md)
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
the sweep. The original algorithm author's own 3 MB version (`5671f9f`,
2018) had the same property.

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

**The absolute figures below are stale.** They were taken while `v8bench`
drew `init_size_blk` per nonce, as consensus then did. B1 pinned it, and
`v8bench` now pins it too, which takes the 7950X 1 MB row from 0.7627 to
0.6038 ms. The pad decision this finding reached is unaffected, because every
row moves together and the comparison is between pads at a common blk; only
the absolute costs need re-reading. Re-measure before quoting any number here.

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

*Caveats:* this harness excludes the chain fill, which [RESULTS.md](RESULTS.md) charges to
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

**Reopened downward, 2026-10-05.** This sweep and F24's both start at 1 MB, so
1 MB is the smallest size ever measured and the decision is "the best of what we
tried" rather than a bracketed minimum. Every trend here is monotonic toward
smaller, and the mechanism this finding identifies, how many threads fit in L3,
**has not saturated at 1 MB**: the laptop fits four of its eight threads and
amplifies 3.4x against the 7950X's 18.6x, which is what produces the 11.3x
spread. The salt coupling allows 512 KB and 256 KB, the resize harness builds
them with a three-line change, and 512 KB has strictly better stride entropy
than 1 MB because its derived modulus is 127 rather than 125. The argument
against is that Phase 6 B2's feeder gate is proportional to the fill.
[PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md) C1 has the full case and the five
criteria to decide it against.

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
larger pad. [RESULTS.md](RESULTS.md)'s own caveats undo it:

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

| target | toolchain | how | FP | full hash |
|---|---|---|---|---|
| Windows x86-64 | MinGW gcc | by hand | match | match |
| Linux x86-64 | gcc | by hand | match | match |
| macOS aarch64 (Apple M1) | clang | by hand | match | match |
| Android aarch64 (Pixel 7a) | Termux clang | by hand | match | match |
| Linux armv7, 32-bit | cross gcc | CI, qemu-user | match | match |
| Linux riscv64 | cross gcc | CI, qemu-user | match | match |
| Linux s390x, big-endian | cross gcc | CI, qemu-user | **match** | differs, F36 |

    v14 16da28b8ec84c42cd776c908807ac204daf763503b24c396e6b0d6c4b015eba2
    v15 c7d123c1993299cbd07bb8a84cc4bb002e35f3cc1240b95b2e663d22318e5edd

This is what F29 could only claim for the primitives. The FP stage crosses the
architecture boundary inside the real hash, which is the risk that could have
ended Phase 2 outright.

**The floating-point stage is deterministic on every target tested, including a
big-endian one.** Seven targets, four instruction sets, five toolchains. On
s390x the full hash differs, but every floating-point check passes there: all
four `t_fp_determinism` checksums, the FP reference vector, the value scan, and
the two AES arms. That divergence is `e2i`'s missing byte swap in the integer
path and predates this work by every release (F36).

That is the strongest available form of the claim. The risk that could have
ended Phase 2 was that IEEE-754 double arithmetic would not reproduce across
platforms. It reproduces across two word sizes, four instruction sets and both
byte orders.

armv7 and riscv64 matter most among the additions. armv7 is the 32-bit path
nothing else exercises and the one where `fesetround` reaching the VFP rounding
bits was least certain; riscv64 is a third instruction set with its own libc and
compiler. Both match exactly on all four hashes.

An earlier version of this entry claimed riscv64 and armv7 on the strength of
job status icons in a run still in progress. That was wrong; both are now true
for the right reason.

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

*Denominator, which matters and was not stated here originally.* Every figure in
this entry is against `cn_slow_hash` alone. That is the right basis for verify
cost, and the wrong one for anything a miner pays: `get_block_longhash_v14`
seeds HC128 from the blob hash, which carries the nonce, so `get_cna_v6_data`
runs on every nonce and is roughly 60% of one. Against a whole nonce the stage
costs about 4.4% rather than 14.5 to 18.2%, and the spread narrows from 2.17x to
2.10x rather than 2.39x to 2.20x. Same direction, about a third of the size.
F37 point 2 records where using the wrong one of these overstated a result
threefold.
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

*Since the known-answer vectors landed, that failure is at least legible.*
`cn_slow_hash_known_answer_test` runs unconditionally at startup and goes
through the dispatchers, so on a big-endian machine it fails and nervad refuses
to start saying this build does not compute the same hashes as the network.
Previously such a node started normally and then rejected every block as bad
proof of work, which looks like a network problem rather than a port problem.
The bug is unchanged and still unfixed; only the diagnostic improved.

The fp-portability workflow is unaffected: it cross-builds and runs
`t_fp_determinism.c` under qemu and never starts a daemon, which is why its
s390x row can still expect the full hash to differ.

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

*Confirmed by measurement, not only by reading:* the s390x CI job produces

    v14 ad0cfef2a9dff36aee90b5591ed5be9c87664db8af460efadfa064d67b422fae
    v15 5387071cc6f14f53f64ab3d4d4d3619bdce89a3182b0b4b31588ccb0bfdedd86

against x86-64's `16da28b8...` and `bb62ce91...` for the same input. The
prediction from reading `e2i` was right.

**Everything floating-point passes on big-endian.** All four
`t_fp_determinism` checksums match, the FP reference vector passes, the value
scan finds no denormal or infinity or NaN, and the two AES arms agree. The
divergence is entirely in the integer path. That is worth stating plainly
because it is the opposite of what one would assume from a big-endian failure in
a change that adds floating point.

*Pinned by CI:* the workflow compares the printed hashes against the x86-64
reference, and fails on s390x if they ever start matching, so an endianness fix
announces itself. It did not always: the first version read `t_fp_stage`'s exit
code instead, which cannot answer this question, because all three of that
test's checks are internal and all three pass on big-endian while the hash is
different. It reported that s390x had been fixed. Comparing hashes is the only
thing that tests what this entry is about.

## GPU

### F37. The FP stage costs a GPU 0.4% of a nonce and a CPU 4.4%, so it makes GPU resistance slightly worse

*Three cards, two vendors, three architectures. All runs `50 10 60 fpx10`.*

| CPU | GPU | CU | nonces | GPU H/s | FP cost GPU | FP cost CPU | GPU:CPU | verdict |
|---|---|---|---|---|---|---|---|---|
| 7950X, 32T | RTX 3050 | 20 | 3264 | 511.1 | 1.004x | 1.043x | 0.0433 → 0.0450 | worse 4% |
| 5600X, 12T | Vega FE | 64 | 3264 | 545.8 | 1.006x | 1.038x | 0.1609 → 0.1660 | worse 3% |
| i7-7700HQ, 8T | GTX 1050 Ti | 6 | 1600 | 222.5 | 1.004x | 1.015x | 0.2078 → 0.2101 | worse 1% |
| 9700X, 16T | RX 580 | 36 | n/a | n/a | n/a | 1.048x | n/a | device failed, see below |

**The stage costs a GPU about 0.4% of a nonce and a CPU about 4.4%.** A cost
falling almost entirely on one side moves the ratio toward the other, so GPU
resistance gets slightly worse everywhere it was measured. The arithmetic and
the rounding modes are separable and both are nearly free on the GPU: 0.2% and a
further 0.2%.

**FP64 capability is not the axis.** Hashrate per resident nonce is 0.167 on a
64 CU Vega, 0.157 on a 20 CU RTX 3050 and 0.139 on a 6 CU GTX 1050 Ti: a ten-fold
range of compute units delivers the same throughput per nonce slot within 10%.
v5 runs one work-item per nonce doing ~30 byte-stride scattered read-modify-write
sweeps of a 1 MB pad, which is a chain of dependent memory round trips with no
parallel work inside a nonce for compute units to attack. The card is
latency-bound, and arithmetic added to a latency-bound kernel is free whatever
the FP64 rate. The clinching detail is that the Vega's FP cost came out
*higher* than the 3050's despite far better FP64 hardware, which is backwards
for anything FP64-limited.

*Correction to PLAN-v8:* that document states the Vega FE runs FP64 at 1/2. It
is Vega 10, which is 1/16, the same as the RX 580. So the test set never
contained a high-FP64 card. It does not weaken the conclusion, it changes what
the conclusion rests on: not coverage of the FP64 range, but the measured fact
that FP64 rate does not predict the result.

**PLAN-v8's prediction was right and its counter-argument was wrong by an order
of magnitude.** The plan estimated 0.05x drifting to about 0.057x on
FLOP-capacity grounds; measured, 0.0433x to 0.0450x. The argument the other way
held that OpenCL cannot select a rounding mode, so a miner would emulate
directed rounding at 10 to 50x per operation. The first half is true. The second
is not: error-free transformations cost about 4x, and 4x of work the card is not
bound by is still nothing.

#### Every identified bias runs the same direction

Against the GPU, so its measured FP cost is if anything overstated: 50% of VRAM
and 3264 concurrent nonces where a real miner would use most of the card, and low
occupancy makes added latency harder to hide.

For the GPU, so its real FP share is smaller still: Keccak and the
blake/groestl/jh/skein finalisation are omitted and are branchy work a GPU really
pays; `extra_hash` is replaced by a mix64 chain; the chain salt is modelled as
free to the GPU, which it nearly is at ~0.8 of a host core per card.

The emulation is also close to the best a miner could do. It is branch-free
rather than a switch on the mode, because a warp holds nonces with different
modes. It could save perhaps a quarter by skipping the residual when the mode is
nearest-even, moving 0.4% to about 0.3%. And on NVIDIA an OpenCL miner is not the
relevant threat: **CUDA has native directed rounding** (`__dadd_rd`, `__dmul_ru`
and friends), so a CUDA miner pays nothing for the mode and only the arithmetic,
which is the `rne` row at 0.2%.

So 0.4% is an upper bound and the verdict can only get worse for the stage.

*What the model does not support* is the absolute GPU:CPU figure, which carries
every caveat in F28 and section 7 of [RESULTS.md](RESULTS.md). The ratio change is the claim,
and it holds because numerator and denominator differ by the stage and nothing
else. Note also that the absolute figure is mostly a statement about the CPU it
is paired with: the three GPUs are within 7% of each other while their CPUs
differ threefold, which is the whole spread from 0.043x to 0.208x.

#### Proving the harness can see the effect at all

At the real round count all four rows read the same, which had to be explained
before any of the numbers meant anything. `fpxN` runs the stage at N times its
round count and divides the cost back out:

| | GPU rne | GPU modes | CPU rne | CPU modes | CPU/GPU |
|---|---|---|---|---|---|
| 1x, 9,600 | −0.16% | +0.02% | +1.9% | +5.6% | unresolved |
| 10x, 96,000 | +0.85% | +3.39% | +24.5% | +44.3% | 13x |

Cost is linear in the round count, so the 10x row divided by ten reproduces the
1x row, and the CPU-to-GPU cost ratio is 13x at both scales. The 1x reading is a
resolution limit, not a broken measurement. Confirmed independently on the 9700X,
whose CPU cost reads 1.046x at 1x and 1.048x at 10x.

The floor is measured rather than assumed. Three rows in the default set are
identical GPU work through two separate code paths (`v5 1MB`, `v8 1MB`,
`v5 1MB end`), so the largest gap among them is the harness's own cross-row
reproducibility. On a good run it is 0.026% against an effect of 0.4%.

#### Eight measurement errors found on the way

Worth listing because most of them produced confident wrong numbers rather than
obvious failures, and because six were found only by cross-checking one route
against another.

1. **The verdict was printed inverted.** Both costs divide a rate, so the new
   ratio is `r0 * cpu_cost / gpu_cost`. The first summary line said FP *helped*
   GPU resistance while the table's own column said the opposite.
2. **Wrong denominator on the CPU.** F34's +14.5 to 18.2% is the stage against
   `cn_slow_hash` alone. A miner's nonce is fill plus hash, and
   `get_block_longhash_v14` seeds HC128 from the blob hash, which carries the
   nonce, so `get_cna_v6_data` runs on every nonce. The fill is ~60% of a nonce,
   so the right figure is 4.4%, not 15%. This overstated the effect threefold.
3. **CPU rows measured one at a time to completion**, leaving baseline and FP row
   minutes and several degrees apart. The difference was mostly thermal drift:
   2.0% run spread against a 4% effect. Fixed by interleaving.
4. **Fixed order inside each interleaved cycle**, so the baseline always ran
   first and a sawtooth in clocks landed on its side every time. The baseline
   once read 11,351 H/s against a 9,900 norm, 19% spread. Fixed by reversing the
   order on alternate rounds.
5. **400 ms measurement windows**, too short for 32 threads on a memory-bound
   workload to settle. Raised to 1000 ms.
6. **Background load unmeasured.** A whole set of results was taken on a machine
   mining on 12 threads, and nothing in the output said so. The CPU column was
   depressed ~15%. Every run now prints `LOAD n% CPU busy before the run` and
   warns above 8%, so a contaminated run is self-labelling. The FP *ratio*
   survived it unchanged, 1.046x against 1.044x clean, which is evidence that
   interleaving plus order reversal does what it was added for.
7. **The control led the FP rows instead of bracketing them.** Measured between
   rows 1 and 2, it could not see drift accumulating by rows 3 and 4: it read
   0.02% on a run whose FP rows were visibly noise. A second identical row now
   runs after the FP rows.
8. **The control printed in unscaled units** next to scaled costs. A raw 4.03%
   effect against a raw 1.14% floor printed as "1.004x" against "1.14%" and read
   as though the effect were under the floor when it was 3.5x above it.

#### A second result, from the checksum gate

OpenCL has no rounding-mode control at all, so `cna_v8_fp` computes the
nearest-even result natively, recovers the exact residual (2Sum for add and
subtract, one `fma` for multiply, divide and square root) and nudges by one ULP
when the mode demands it. That is exact for every value this stage can produce,
because the group-E constraint keeps operands in [2^-255, 2) where no sum,
product, quotient or residual can overflow or reach a subnormal.

The row passes the gate against a CPU reference using real `fesetround` on all
three cards, so the software emulation is **bit-exact against a real MXCSR**.
PLAN-v8 hoped this kernel would fail to compile and that the failure would be the
result. It compiles, it is cheap, and directed rounding is not a barrier to an
OpenCL miner.

#### The RX 580, which is a device failure and not a result

Every row on the 9700X box reported `3264 of 3264 nonces unwritten`: the kernel
dispatched with no CL error, the timed repetitions returned, and nothing was
written to the output buffer. The read-back itself is now checked separately and
was not the cause. An earlier run left the OpenCL runtime unable to create a
context at all, which is what a driver reset looks like.

Not pursued, because it cannot change the conclusion: the card sits inside the
range already covered rather than extending it, at 1/16 FP64 like the Vega, and
the three cards that ran agree to within the measurement floor. Its CPU column
is clean and usable (`LOAD 0%`, FP cost 1.048x).

Worth recording for whoever meets it next: the harness now names the reason a
GPU row produced nothing, at every bail-out point. It previously printed a dash
and said nothing, which cost a full diagnostic cycle.

### F38. Work added to the hash core helps the specialised attacker; the chain fill is what does not

The GPU result is one instance of something more general, and it is the most
useful thing to come out of this measurement.

**Put the Amdahl bound on an ASIC.** On a 7950X a whole nonce is 1.54 ms in the
harness while the real `cn_slow_hash_v14` is about 0.65 ms, so
`get_cna_v6_data` is roughly 0.9 ms, about 60% of a nonce. Now suppose an
attacker builds silicon that makes the hash instantaneous:

| | nonce cost | speedup over a commodity CPU |
|---|---|---|
| v14, hash free | 0.90 ms, fill only | **1.6x** |
| v15, hash free | 0.90 ms, fill only | **1.8x** |

A perfect hash ASIC with an infinite budget gets under 2x a desktop. To go past
that it has to accelerate the fill, which is 256 KB per nonce assembled from
scattered reads across a multi-gigabyte database. At any ASIC-scale rate that is
a random-access storage bandwidth problem, which is a server rather than a chip,
and the economics stop being ASIC economics. It is the same mechanism as the
pool resistance: you cannot mine without being a full node, and the requirement
scales linearly with hashrate.

**Note which way v15 moves it: 1.6x to 1.8x, in the attacker's favour**, because
it adds work to the half they can specialise and leaves the half they cannot
untouched.

That is the third appearance of one pattern:

- **GPU** (F37): the stage costs the card 0.4% and the CPU 4.4%, so GPU:CPU worsens
- **ASIC** (here): the stage inflates the hash, which is the specialisable half,
  so the Amdahl bound loosens
- **Thread load** (F35): under full load the stage gets *cheaper* on Zen desktops,
  because the hash saturates memory while the stage competes for none of it

**Work added to the hash core is work a specialised attacker can specialise. The
chain fill is the part they cannot.** Anything bolted onto the hash shifts the
balance toward the attacker, however exotic it looks. This generalises past the
v14-versus-v15 decision and should be applied to any future proposal to
strengthen the hash.

*The honest weak point.* The v6 windowed fill puts ~95% of block reads in the
last 100k blocks specifically so they stay cache-resident, which is what fixed
sync speed. A well-funded attacker gets that cache too and can serve 95% of the
fill from fast memory. What still binds is the ~5% drawn from the whole history:
they must hold the entire database, they just need not read all of it at full
bandwidth. That trade-off is deliberate and is recorded in PLAN-v8 Phase 4.

*Unmeasured.* The 0.9 ms fill figure comes from `chain_fill.h` against a
synthetic 247 MB block cache, not from real `get_cna_v6_data` against LMDB. The
real thing reads a larger database with page-cache misses, so it should be more
expensive and the bound stronger, but that is reasoning rather than measurement.
Timing `get_block_longhash_v14`'s two halves separately in the daemon would
settle it and would also say exactly where sync time goes.

### F39. The FP stage's sync cost is ~0.12 ms per block, which is not what makes a sync slow

Verification does one hash per block, and the stage adds a nearly constant amount
of wall time per hash, because that constancy is the reason it narrows the
cross-CPU spread at all.

| machine | hash | stage share | added per block |
|---|---|---|---|
| 9700X | 0.668 ms | 18.2% | +0.122 ms |
| i7-7700HQ | 1.593 ms | 9.1% | +0.145 ms |

A month offline at one-minute blocks is about 43,000 blocks, so the stage adds
roughly **6 seconds** to that resync. The "+14.5 to 18.2%" figure that Phase 2
has been carrying is 18% of a sub-millisecond operation and reads far more
alarming than it is.

Sync cost is dominated by `get_cna_v6_data`'s scattered reads and by transaction
verification, neither of which any of this touches. On the stated priority of
keeping sync fast, the FP stage is close to a non-issue.

### F40. Monero's floating point is not a precedent for ours: it arrived with RandomX, where FP is 37% of the instruction stream

Researched from primary sources after the GPU result, to answer whether Monero's
use of floating point in consensus supports doing the same here. It does not,
and the reason is the same one F37 and F38 measured.

**Floating point was never in CryptoNight.** Monero ran CryptoNight from 2014 to
November 2019 and its operations are AES, XOR, 64-bit multiply and 64-bit add.
FP arrived with RandomX at the v12 fork, block **1978433**, November 2019
(`src/hardforks/hardforks.cpp`). Nerva forked from Monero v0.12, before any of
this, and carries none of it: the only FP under `src/crypto` is the v15 files
this branch added.

**There is a third position, which neither this plan nor its critics considered.**
CryptoNight v2 (October 2018) used the FPU while keeping FP *out of consensus*.
It computes a 64-bit integer square root with `_mm_sqrt_sd`, a double-precision
hardware instruction, then applies `VARIANT2_INTEGER_MATH_SQRT_FIXUP`, which
corrects by plus or minus one so the result is exactly the integer part.
SChernykh also shipped an integer-only version using a 16 KB table for CPUs with
a slow or absent FPU. So Monero took the FPU's speed and refused its rounding.
If FP hardware is ever wanted here without a new consensus failure class, that is
the shape to copy.

**In RandomX, FP was there on day one.** The repository's initial commit is
2018-10-31 and the initial draft README of the same day already specifies 32
floating point registers, IEEE-754 double precision and exactly ADD, SUB, MUL,
DIV, SQRT. It carries the warning this project rediscovered independently: "The
order of operations must be preserved since floating point math is not
associative." Two days later, "Updated specs: cache, FP rounding". It was never
bolted on.

**Why, from `doc/design.md`.** The goal is *device binding*: "To minimize the
performance advantage of specialized hardware, a proof of work algorithm must
achieve device binding by targeting specific features of existing general-purpose
hardware." The mechanism is section 1.1.3, "The actual program execution should
utilize as many CPU components as possible", listing multi-level caches, the uop
cache, the ALU, **the FPU**, the memory controller and instruction-level
parallelism. An ASIC that omits the FPU saves die area; requiring it forces the
ASIC to build one and stop being cheaper than a CPU.

Section 2.5 is the direct statement: "RandomX uses double precision floating
point operations, which are supported by the majority of CPUs and **require more
complex hardware than single precision**." And on determinism, the same reasoning
this stage uses: "RandomX uses five operations that are guaranteed by the IEEE
754 standard to give correctly rounded results: addition, subtraction,
multiplication, division and square root. All 4 rounding modes defined by the
standard are used."

**Scale is the part that does not transfer.** Counting opcodes in `doc/specs.md`,
FP instructions are **94 of 256, about 37% of a RandomX program**, interleaved
with integer work, branches and memory access, competing for issue slots. Ours is
a separable block of 9,600 rounds appended to an otherwise integer memory-hard
loop.

**So RandomX's floating point works because of what surrounds it, not because FP
is intrinsically hostile to specialised hardware.** RandomX is a random program
execution PoW whose thesis is that an ASIC must replicate a whole CPU. CNA v8 is
a memory-hard loop, which F37 measured as latency-bound: arithmetic added to it
costs a GPU 0.4% of a nonce, and F38's bound moves an ASIC from 1.6x to 1.8x in
the attacker's favour. A separable FP block on a memory-bound loop is something
an attacker amortises. That is what was measured, and this is why.

**Correction to how this plan describes RandomX's value safety.** PLAN-v8's
RandomX review presents their constraint as making the divergent cases
unreachable, which is right, but the set of cases is smaller than assumed:
`design.md` states "About 2% (6.85% for RandomX v2) of programs produce at least
one `infinity` value". RandomX forbids NaN and denormals, **not infinity**,
because it constrains group E *memory operands* while register values may drift
upward. Our stage constrains every *result*, so infinity is structurally
unreachable for us. Both are deterministic, since IEEE-754 specifies overflow
precisely. The point is that our safety argument is **stricter than RandomX's and
does not depend on theirs**, which `slow-hash-fp.h` already says correctly
("checked rather than inherited", proven by `cn_fp_value_scan`).

**What does support the technique generally:** RandomX was audited by four
independent teams between May and August 2019 (Trail of Bits, X41 D-SEC,
Kudelski, QuarksLab) with no critical findings, and FP in consensus has run on
Monero for about seven years across every architecture they ship. The technique
is proven. The question was never whether FP can be made deterministic; it is
whether it buys anything in a design shaped like this one.

*Sources, all primary:* `tevador/RandomX` `doc/design.md` and `doc/specs.md`;
the initial draft README at commit `07a8318`; `monero-project/monero`
`src/hardforks/hardforks.cpp`; monero PR #4218 and `SChernykh/sqrt_v2` for the
CryptoNight v2 square root; docs.getmonero.org for the CryptoNight operation
list.

## Real daemon

### F41. Measured on the shipped miner: the stage costs about 6% of hashrate and buys 2.7% of fairness

Everything before this entry measured the FP stage through a harness. This
measures it through `nervad` itself, mining on an isolated two-node testnet at
fork version 14, with `cn_slow_hash_v15` reached by a local toggle that was
never committed. Three machines, both rounds, `--offline
--fixed-difficulty 100000000` so no block is ever found and the height never
moves.

#### What the stage costs

| machine | 1 thread | peak threads |
|---|---|---|
| 7950X, 16C/32T | 7.6% | 5.1% at 30T |
| 5600X, 6C/12T | 8.0% | 3.7% at 11T |
| i7-7700HQ, 4C/8T | 5.0% | 2.8% at 7T |

**Every machine pays less under full thread load than on one thread.** That is
F35's mechanism, measured through a completely different instrument: the hash
saturates memory bandwidth at high thread counts while the stage competes for
none of it. The laptop pays least in both columns, matching F34, where the
7700HQ's stage is 9.1% of its hash against the 9700X's 18.2%.

#### Cross-CPU fairness, which is the only argument for the stage

| basis | v14 | v15 | narrowing |
|---|---|---|---|
| single thread, three x86 machines | 1.934x | 1.880x | **2.7%** |
| peak threads | 8.782x | 8.572x | 2.4% |

F34 reports 2.388x to 2.201x, an 8% narrowing. That is not wrong: it is measured
against `cn_slow_hash` alone, which is the right basis for verification cost. A
miner's nonce is the chain fill plus the hash, and the fill dilutes the stage, so
**what a miner experiences is about a third of the headline.** Predicted 3.2%
from that reasoning before the test; measured 2.7%.

The peak-thread spread of 8.8x is not a fairness figure. It compares a 16-core
desktop against a 4-core laptop and is dominated by core count.

#### The chain-length series, and why most of it is not usable

The testnet was grown from 724 blocks to 1.96M to see whether chain length
changes the answer, since the chain fill reads a 56-byte cache entry per pick and
that cache is 0.04 MB at 724 blocks and 236 MB at mainnet's height.

| height | cache | order | measured | status |
|---|---|---|---|---|
| 724 | 0.04 MB | v14 first | 7.6% | sound, nothing can warm at 40 KB |
| 103,553 | 5.5 MB | v14 first | 7.9% | low risk |
| 501,472 | 26.8 MB | v14 first | 6.5% | moderate risk |
| 921,051 | 49.2 MB | v14 first | 4.1% | **understated** |
| 1,850,993 | 103.6 MB | v14 first | v15 came out *faster* | **rejected** |
| **1,961,955** | 109.8 MB | **v15, v14, v15** | **6.3%** | **usable** |

**The 1.85M attempt reported v15 as 11.7 to 13.6% faster than v14, which is
impossible**: v15 is v14 plus 9,600 FP rounds on the same code path. Binaries
were verified, not swapped. Running the same binary twice gave 503 and 589 H/s,
**17.1% apart**, against an effect of about 4%. The machine was settling after a
night of mining: a 103 MB block cache to fault in, LMDB pages to pull back, and
the previous daemon's working set being reclaimed.

**Every earlier pair ran v14 first and v15 second**, so a warm-up bias makes v14
look slow and v15 look fast and therefore understates the stage, and the bias
grows with cache size. The reported decline from 7.6% to 4.1% has exactly that
shape.

Re-measured at 1.96M with the order controlled, **v15 to v14 to v15**: 564, 596,
549 H/s at one thread. v14 is above *both* v15 runs at every thread count, and
the sequence is not monotonic in time, so there is no systematic drift. FP cost
6.63% at 1 thread, 8.18% at 8, 4.06% at 16.

**Centre about 6%, and it cannot be pinned tighter than plus or minus 2 points.**
The two v15 runs differ by 2.7 to 4.6%, which is the real run-to-run noise and is
the same order as the effect.

#### Three claims withdrawn

1. **"The cost converges on F37's mainnet estimate of 4.4% as the chain grows."**
   Withdrawn. With the order controlled at twice the height, it returns to about
   6%. Some genuine decline may remain, 7.6% at 724 against 6.3% at 1.96M, but it
   is within the noise.
2. **"The stage costs a constant 0.127 ms per nonce."** True where it was
   checked, and the 8-thread figures at 724 and 103k agree to 0.3%, but the
   apparent fall to 0.068 ms at 921k was the same artefact seen from the other
   side, not a real effect.
3. **The clock-boost hypothesis offered for that fall.** Withdrawn, and the
   frequency measurement proposed to test it is not needed.

#### Unresolved

F37 models a mainnet-shaped nonce and gets 4.4%. This measures a real nonce on a
2M-block testnet and gets about 6%. They differ by more than either error bar,
and a 2M-block chain is still not a 4.4M-block one. Which is right for mainnet is
open. The daemon figure is the more direct measurement; the model is the one
shaped like mainnet.

#### Method notes worth keeping

The GPU harness needed interleaving and order reversal for exactly this reason,
and the same discipline is needed here. For any further run: start and stop a
throwaway daemon first so the LMDB pages are resident, then order **A, B, A**,
and treat the middle reading as usable only if the two outer ones agree.

A `--fixed-difficulty` high enough that no block is ever found is what makes the
reading clean; at difficulty 1 the miner finds a block per hash and the figure
becomes block-template rebuild time.

## Screening and offload

### F42. `init_size_blk` is a third screenable axis, and v8's cost spread is 3.7x in time, not 1.62x

A review of PR #162 modelled v8's per-nonce cost as `P + s*N` with
`N = (xx-1)*yy`, fitted `P = 0.457 ms` and `s = 0.0042 ms` over the `(xx, yy)`
grid, and concluded that the screenable share of a nonce is 9.8%, that the
ceiling for a screener with a free fill is 1.29x, and that screening would pay
only below a 0.15 ms fill.

The correction in that review is right and is most of the answer: the 4.67x
spread in `salt_pad_v8` **calls** is not a 4.67x spread in time, because two
full AES passes over the pad and the 262144-byte randomize sweep are paid by
every nonce. F38 makes the same point from the other direction.

But the fill draws **three** parameters, not two.
[`cryptonote_tx_utils.cpp:746`](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L746)
draws `init_size_blk` from the same post-fill HC-128 state as `xx` and `yy`, two
lines apart, so it is screenable on identical terms. It sits inside `P`.

#### It changes no operation count, and changes the time by up to 2.2x

`aes_pseudo_round` runs `nblocks` blocks of 10 rounds, and `init_hash` calls it
`CN_SCRATCHPAD_MEMORY / (nblocks * 16)` times, so both pad passes perform
`pad/16` AES blocks at any width. `init_size_blk` changes only the width of the
dependency chain and the granularity of the `memcpy` either side of it.

Median ms per hash, 7950X, one thread, shipped `cn_slow_hash_v14`:

| N = (xx-1)*yy | blk=2 | blk=4 | blk=8 | blk2/blk8 |
|---|---|---|---|---|
| 12 (4,4) | 0.782 | 0.487 | 0.349 | 2.24x |
| 18 (4,6) | 0.859 | 0.552 | 0.391 | 2.20x |
| 20 (6,4) | 0.906 | 0.595 | 0.429 | 2.11x |
| 24 (4,8) | 0.932 | 0.646 | 0.474 | 1.97x |
| 28 (8,4) | 0.964 | 0.671 | 0.532 | 1.81x |
| 30 (6,6) | 1.015 | 0.700 | 0.549 | 1.85x |
| 40 (6,8) | 1.077 | 0.800 | 0.678 | 1.59x |
| 42 (8,6) | 1.118 | 0.830 | 0.685 | 1.63x |
| 56 (8,8) | 1.286 | 0.993 | 0.835 | 1.54x |

This is F38's lesson inverted. There, work that looked large in operations was
small in time. Here, an axis that is **identical** in operations is worth up to
2.24x in time. A model fitted on operation counts cannot see it, and a model
fitted on time but binned only on `N` averages it into the floor, which is
presumably what produced the 1.62x and the stable `P`.

#### The grid, and what a screen is worth on it

All 75 reachable cells are equiprobable: `xx` and `yy` uniform on [4,8],
`init_size_blk` uniform on {2,4,8}. `iters` is at most 63 AES rounds against
65536 blocks of pad fill and is ignored here.

|  | review | measured |
|---|---|---|
| spread in time | 1.62x | **3.6 to 3.7x** |
| screenable share of a nonce | 9.8% | **24 to 27%** |
| ceiling with a free fill | 1.29x | **2.12 to 2.17x** |
| break-even fill cost | 0.15 ms | **0.534 ms** |

Break-even is better stated as a ratio, because it is scale free:
**screening pays below `F / E[H]` = 0.71.**

#### It still does not pay, with less margin than claimed

A screener pays the fill on every candidate and the hash only on accepted ones,
`F/p + E[H | accepted]`, against an honest `F + E[H]`.

| fill | `F / E[H]` | best screen |
|---|---|---|
| 0.927 ms, implied by F41's daemon figure | 1.23 | **1.000x** |
| 0.721 ms, the review's synthetic probe | 0.96 | **1.000x** |
| 0.343 ms, the same fill 2.7x faster (F43) | 0.46 | 1.006x |

The verdict is unchanged. The margin is not: against break-even it is
**1.35x to 1.74x**, not the 4.8x the review reported. The range is the
disagreement between the two fill measurements below.

The consequence for review priorities: the prize for breaking the draw ordering
at
[`cryptonote_tx_utils.cpp:741-751`](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L741)
is **about 2.1x**, not 1.29x. That ordering is the entire defence and it is currently
load-bearing commentary. It should be a unit test: same blob hash, two different
salt contents, assert `xx`, `yy`, `init_size_blk` and `iters_divisor` all differ.
A hoist for "clarity", or someone caching `rng_state` across nonces as a mining
optimization, would not fork the chain. It would quietly make v8 screenable.

#### The fill cost, which partly answers open question 7

F41 measured 596 H/s at one thread for v14 on a 1.96M-block testnet, so
1.678 ms per nonce. The grid mean hash here is 0.751 ms on the same machine,
implying a **0.927 ms fill, 55% of a nonce**. The review's synthetic probe got
0.721 of 1.305, also 55%. The absolutes disagree by 29% and the ratio agrees to
a tenth of a point, which is the quantity the economics use.

Treat 0.927 as an **upper bound**: the daemon's hash runs under block-cache
pressure that this probe does not have, so some of that 0.927 is really hash.
A smaller fill means a smaller margin, which is why the range above is quoted
from both ends rather than from the more favourable one. Timing the two halves
inside the daemon would still settle it.

#### Method

75 cells, 51 rounds, one timed call per cell per round, grid order reversed on
alternate rounds, median per cell. Three runs, the third from a separately
compiled binary: means 0.752, 0.751 and 0.757 ms, break-evens 0.5340, 0.5344
and 0.5337, spreads 3.68x, 3.72x and 3.61x. Under 1% apart on everything the
conclusion uses. Mining and browsers stopped for all three, per F35 and F41's
method notes. The probe times the shipped
`cn_slow_hash_v14` and reads the joint distribution off the cells, so no model
is fitted and no third axis can hide in a residual.

### F43. The published v6 miner breaks v6 by screening; v8 removes that, and what is left is fill offload

A document by [0xROOTPLS](https://github.com/0xROOTPLS) describes a v6 miner at 8.5x to 13.4x over the
stock miner, with a GPU hybrid adding a further 74 to 80%. None of its numbers
are reproduced here. Its **structural** claims were checked against the code,
and those are what is used below.

#### The break, and why it is a v6 property

> The program seed is `blob_hash XOR salt[0..32)`, which needs only the first of
> the salt's 2048 sequential iterations.

v6's cost is a property of the VM program, the program seed is readable from the
first 32 bytes of the salt, and those are written by the first of 4096
iterations. The screen therefore costs about **1/2048 of a fill** and resolves a
spread the document gives as 16 MB to 100 MB of DRAM traffic per hash, at
roughly 1% acceptance. Its own progression attributes 319 to 976 H/s to
screening alone, a **3.1x algorithmic break**; the rest of the 13.4x is
engineering.

On v8 the same screen costs a **full fill**. `get_cna_v6_data` reseeds its
HC-128 state 256 times from bytes it has already written, so the keystream
cannot be fast-forwarded, and `xx`, `yy` and `init_size_blk` are drawn only
afterwards. A 55%-of-a-nonce oracle resolving F42's 3.7x spread never pays, at
any fill speed this document demonstrates.

#### What carries into v8, and what dies with the VM

Carries over, and applies to the stock miner equally, so it is implementation
quality rather than a break: K-way nonce interleaving (+23%), fused pad init
(+7%, and worth less at v8's 1 MB pad than at v6's 8 MB), non-temporal stores
(+4%), large pages (+5%), four-way AVX2 Keccak, eight-lane AVX2 HC-128, and the
SMT pairing work. Compounded, roughly **1.4x on the hash**.

The eight-lane HC-128 also takes the chain fill from 4.6M to 1.7M cycles,
**2.7x**, and v8 calls the same `get_cna_v6_data`, so that carries over whole.

Dies with the VM, because v8 has none: trace JIT, JIT-driven virtual pad,
recompute-final, deopt abandonment, and the GPU hybrid. That hybrid hunts
"the ~1 in 950 whose VM never touches the pad" and hashes them with no pad at
all. **v8 has no such nonce**: both AES passes and every `salt_pad_v8` sweep
touch the whole 1 MB pad on every nonce.

Note that the fill speedup and the hash speedup move `F / E[H]` in opposite
directions. Applying the 2.7x without the 1.4x, as the review did, overstates
the screener's position:

| | `F / E[H]` | best screen |
|---|---|---|
| stock | 1.23 | 1.000x |
| fill 2.7x, hash unchanged | 0.46 | 1.006x |
| fill 2.7x, hash 1.4x | 0.64 | **1.000x** |

#### The residual: offloading the fill, which the ordering fix does not touch

The document's last line on the GPU hybrid is the one that matters for v8:

> The 234 MB block cache lives in VRAM and is uploaded incrementally per height.

The chain fill's working set is already on the card, driven by an eight-lane
HC-128 kernel. A GPU can therefore compute v8's fill and hand finished salts to
the CPU. **This is not screening and v8's draw ordering does nothing against
it**: offloading does not need to predict the cost, it pays it elsewhere. At a
55% fill share the uplift is **2.0x to 2.2x** for a GPU-equipped miner, larger
than screening ever bought on v6 and comparable to v8's whole 2.39x cross-CPU
spread.

What limits it is bandwidth, and that appears to be luck rather than design.
`CN_SALT_MEMORY` is 262144 bytes, `salt_pad_v8` sweeps all of it, and the salt
is HC-128 output so it will not compress. The card must ship **256 KB per
nonce**. A 7950X at 32 threads needs about **11 GB/s** at stock hash speed and
**16 GB/s** with the 1.4x above, against roughly 20 GB/s practical on
PCIe 4.0 x16. It fits with little headroom and does not fit on PCIe 3.0 x16.

Those two figures are arithmetic from the salt size and the measured hash cost,
**not measurements**. Nothing here has been built. They are recorded because
they identify a constant as load-bearing that is not documented as such:
**shrinking `CN_SALT_MEMORY` would look like a harmless optimization and would
hand this attack its headroom.** Any future change to it is a GPU-resistance
change, in the same way F38 and `CNA_V6_WINDOW_BLOCKS` are coupled.

#### What would settle it

Pointing the existing fill kernel at v8 and measuring salts per second against
PCIe throughput. [0xROOTPLS](https://github.com/0xROOTPLS) has every component needed and has been
asked directly whether he will try to improve v8's hashrate. That measurement is worth
more than anything in this file, because it would come from the miner that
actually exists, run against the shipped algorithm.

## The measured miner

**Phase 6 of this work exists because of [0xROOTPLS](https://github.com/0xROOTPLS)**, a security
researcher who built optimized miners for CNA v6 and v8, measured them, and
reported the results in full rather than quietly mining with them. The v6 report
documents a screening break worth 3.1x on its own (F43); the v8 report is what
F44 to F48 are checked against. Where this file is adversarial about v8, it is
adversarial because his work made it possible to be.

The findings below come from his v8 report, dated 2026-10-02 and measured on a
Ryzen 5 5600G: reference 2,529 H/s at T=12 against his 6,150 H/s, 2.43x, broken
down as ~2.0x implementation, ~1.18x sweep deferral and ~1.06x extra-hash
memoization. **None of his timings are reproduced here.** Every structural claim
below was re-derived from the code in this tree, and that is what is recorded.

His cost breakdown of the shipped code, from an instrumented copy over 52,833
nonces, is used throughout: salt 59.5%, sweeps 17.9%, AES fill 6.5%, randomize
6.2%, AES finalize 6.2%, extra hashes 3.2%, **CN inner loop 0.05%**.

That last figure is not a v8 regression. `get_block_longhash_v11` has derived
`iters` as `(height + 1) % iters_divisor` with `iters_divisor` in [1,64] since
HF11, so the CryptoNight loop has been at most 63 steps since then, against
pre-HF7's 262,144. **v8's memory hardness is the chain fill, not the pad.**

### F44. The `salt_pad` sweeps can be deferred, so they are not memory-hard work

`salt_pad_v8`'s second loop is:

    for (j = offset_1; j < CN_SCRATCHPAD_MEMORY; j += offset_2)
        hp_state[j] ^= (salt)[x++];

XOR is commutative and the written value never feeds a branch or an address, so
the final pad is the initial pad XOR the union of all ~30 sweeps' contributions,
**in any order**. The sweeps can therefore be recorded and applied once.

The only thing that observes the pad between sweeps is the CN step, and it
touches exactly two cells of 16 bytes: `pre_aes` loads at `state_index(a)` and
`post_aes_variant` loads and stores at `state_index(c)`. At 12 to 56 k/l steps
plus at most 63 `iters` steps that is at most ~238 cells, ~100 typically. Those
are cheap to reconstruct on demand from the sweep log.

Effect: the pad is walked twice per nonce instead of ~32 times, worth ~1.18x.

*Consequence, which matters more than the speed.* The sweeps are 17.9% of a
nonce and read as the memory-hard part of v8. Deferred, they become compute in
L1, and **a small-cache machine stops being penalised by them**. They were never
hardness: a 1 MB pad is trivial SRAM for an ASIC and trivial bandwidth for a
GPU.

*Why the proposed fix is rejected.* Making the sweep non-commutative, for
example `hp_state[j] = sbox[hp_state[j] ^ salt[x++]]`, does force the order. It
also adds a dependent L1 load to 964K byte operations per nonce, about **+9% on
verification** against the 17.9% share, and it forces 30 real passes over the
pad instead of 2, which penalises small-cache machines and therefore widens the
cross-CPU spread. It buys no GPU or ASIC resistance. **Adopt the deferral in the
daemon instead**, where identical output makes it a free verification speedup.

*Checked:* the macro bodies in `slow-hash.h`, and the two `state_index` calls in
`pre_aes` / `post_aes_variant`.

### F45. 26 of every 30 extra hashes are redundant

`salt_pad_v8` opens with `extra_hashes[a & 3](salt, 200, salt_hash)`, always over
`salt[0..200)`. The only thing that can change those bytes is `salt_pad`'s own
32-byte patch at `offset_1 = temp_1 * ((d % 3) + 1)`.

`temp_1` is a `uint16_t` and the multiplier is 1, 2 or 3, so `offset_1` spreads
over [0, 196605] and lands below 200 with probability

    (1/3)(200 + 100 + 67) / 65536 = 0.00187

which over 30 calls is **0.056 times per nonce**. The report's independently
derived figure is 0.057.

So `salt[0..200)` is effectively constant across all 30 calls, there are only
four possible selectors, and a miner computes about 4 distinct extra hashes
instead of 30. Worth ~1.06x.

*What this does not break.* Phase 1's premise survives: an ASIC still needs four
hash cores, because any of the four selectors can appear. What it creates is a
~2.8%-of-nonce gap between an honest miner and an optimized one.

*Why the proposed fix is rejected.* Hashing a different 200-byte window per call
would make all 30 mandatory, costing about 2.8% of verification. Its stated
benefit, forcing the whole 256 KB salt to stay live, is redundant once F46's fix
means the salt cannot leave the device. **Memoized in the daemon instead.**

*Adopted and measured.* `salt_pad_v8` now keeps one digest per selector and
drops all four when a patch lands in `salt[0..200)`. v8bench interleaves v5 and
v8 in one pass and v5 does not use `salt_pad_v8`, so its row is a control for
exactly this change: **v8:v5 moves from -0.96% to -5.80%**, about 4.9 points of
v5's cost. Four runs, two with a browser open and two without, all read -5.74%
to -5.81%; the absolute figures moved 2.7% with the load and the ratio did not,
which is what interleaving against a control is for.

The hash is unchanged, proved by the known-answer vectors on both AES arms.
That is why those vectors were added first: this edit moves both arms together,
so HW == SW could not have caught an error in it.

*Checked:* the macro, and the arithmetic above.

### F46. Independent confirmation of F43: the salt can leave the hashing device

The report reaches F43's conclusion separately and by measurement rather than
estimate. `get_cna_v6_data` depends only on the blob hash and the stable chain,
so it can be produced anywhere and handed over as 256 KB.

| | F43 (ours) | the report |
|---|---|---|
| salt share of a nonce | 55% | **59.5%** |
| uplift from offloading it | 2.0 to 2.2x | **1.95x** over his optimized miner |
| transfer | 256 KB/nonce | 256 KB/nonce, ~1.6 GB/s at 6,150 H/s |

Two independent derivations, different machines, different code. His
break-even for a feeder thread is ~1,050 salts/s and his model reaches ~12 K H/s
with the salt free, about 4.7x stock.

*Consequence:* this is the phase's load-bearing item, because F44 and F45 show
that once the sweeps and extra hashes are optimized away, the chain fill is the
only irreducible work left in the algorithm.

### F47. Independent confirmation of F42, and the four stale-keystream draws

**Screening.** The report measures screening at **1.00x** today, with
`F / E[H] = 1.5`, and states the PR's own note on it is correct. F42 measured
1.000x and 1.23. With a free salt he gets 2.08x at T=1 and 1.67x at T=12 at 1/75
acceptance; F42's free-fill ceiling is 2.12 to 2.17x. The two weaknesses
multiply, which is why F46's fix is what protects F42's conclusion.

**The keystream oddity.** `HC128_Init` ends by running the cipher 1024 steps
"without generating keystream" and never writes `state->keystream`.
`HC128_U32` refills only when `key_idx > 15`. Both `while` loops in
`get_cna_v6_data` open with an explicit `HC128_NextKeys`, so they are safe, **but
the four draws between the loops are not**: they follow an `HC128_Init` with no
intervening refill and read keystream generated under the previous key.

*Severity: cosmetic.* It affects 256 bytes of a 256 KB salt, is deterministic,
and still depends on the chain. No attack follows.

*Why it is not being fixed.* `get_cna_v6_data` is called by
`get_block_longhash_v13` at [cryptonote_tx_utils.cpp:689](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L689),
live since 4,320,000, as well as by v14 at
[:735](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L735). It cannot be
changed in place without breaking resync of every HF13 block. Fixing it for v14
means a permanent second copy of a 60-line consensus function, which is a worse
trade than documenting a 256-byte wart. This is F9's pattern.

*Caution for anyone handing that report to an agent:* its section 12 says the
oddity "has to be fixed before the fork", names no file, and the only candidate
is a function shared with live consensus. The report's own apply list correctly
omits it.

### F48. The `iters` question, and why the expected answer is no

v8's CN loop is 0.05% of a nonce (above). The obvious diversifier for F46's fix,
whose GPU resistance rests on the same AES-NI-beats-T-tables assumption that all
of v8's GPU resistance rests on, is to raise `iters` and restore a real
dependent pad chase, which would be latency-bound rather than AES-bound.

**Two arguments say it will not work, and both should be tested rather than
trusted:**

1. **Occupancy.** A dependent chase is hidden by parallelism across nonces, not
   within one. At a 1 MB pad a GPU can keep thousands of nonces resident, which
   is exactly the mechanism F28 and the v6-to-v7 pad history describe. The chase
   is also L2-resident on a CPU, not DRAM-bound, so it is not obviously
   asymmetric in the CPU's favour at all.
2. **F38.** Work added to the hash core is specialisable; the chain fill is not.
   Raising `iters` raises the specialisable share and loosens the ASIC bound. An
   ASIC with 1 MB of on-die SRAM chases at ~1-2 ns against a CPU's L2 at ~3-4 ns.

So the prior is that raising `iters` makes GPU:CPU **worse**, costs verification
linearly, and helps an ASIC. It is recorded as a measurement rather than a
proposal so that the answer exists in writing before anyone proposes it again,
which per F11 is what happens to pad and parameter questions in this project.

**What settles it**, in order, stopping at the first failure:

1. CPU verify cost against `iters`, single thread on the 7950X. **If 64K costs
   more than about +0.5 ms the sync-speed answer is already no.**
2. Cross-CPU spread at the surviving values on the i7-7700HQ and the 5600X.
3. GPU:CPU at those values on the three cards. The only step that can return a
   yes, and F28's warning applies: chunk the work, not the nonces.

#### Step 1 ran, and the answer is no

`contrib/powbench/t_iters.c`, `xx=yy=6` (the mean, 30 sweeps), blk pinned at 8,
interleaved with the order reversed on alternate rounds, medians. Two runs:

| iters | ms | vs shipped |
|---|---|---|
| 63, as shipped | 0.510 | 1.00x |
| 16384 | 0.651 | 1.28x |
| 65536 | 1.182 | 2.32x |
| 262144, classic CryptoNight depth | 3.029 | 5.94x |

**Marginal cost 9.45 and 9.41 ns per CN step across the two runs**, a slope
stable to under 1% even though the baseline itself moved 10%. A step is two
dependent pad accesses, so that is about 4.7 ns each, which is L2 latency on
this part. **That is F48's first argument made concrete: at a 1 MB pad the
chase never leaves L2 on a CPU, so it is not the DRAM-latency leveller the idea
depends on.**

At 64K the cost is **+0.67 ms and +0.62 ms**, against a pre-registered ceiling
of +0.5 ms. The threshold was written down before the measurement and the
measurement exceeded it, so **steps 2 and 3 do not run**.

For scale, a nonce is hash plus a 0.927 ms chain fill. Classic depth would take
verification from 1.44 ms to 3.91 ms per nonce, a **2.7x sync tax**, to buy a
property the two arguments above say is not there.

#### The supporting arithmetic, which is arithmetic and not measurement

A GPU cannot hold a 1 MB pad in shared memory, so each chase step is a VRAM
round trip, roughly 300 ns against the CPU's 9.4 ns. That looks like a 30x
disadvantage per step and is the intuition the idea rests on. It is wrong for
the usual reason: the GPU runs thousands of nonces concurrently. At a 1 MB pad
an 8 GB card holds ~8192 of them, and the binding limit is its random-access
rate, order 1e9 dependent accesses per second, so roughly 1 step/ns against a
32-thread CPU's 3.4 steps/ns. Comparable, with the CPU ahead by a small factor
that no part of this is confident enough to quote.

So the honest summary is that raising `iters` costs 1.4x to 2.7x of
verification for a GPU effect that is somewhere between slightly favourable and
slightly unfavourable, on top of F38's argument that it loosens the ASIC bound
by growing the specialisable share. **Recorded closed. If anyone proposes it
again, the cost is measured and the burden is on the GPU side of the argument.**
## Testnet

### F49. The testnet fork round: v8 validated real blocks for the first time, on two machines

Run 2026-10-02 at `9390998`. Until this round `get_block_longhash_v14` had never
validated a block anywhere, because HF14 is not active on any live network. Every
earlier gate checked the hash primitive in isolation or checked that pre-v8
consensus was undisturbed. This is the first evidence that the consensus path
around it works.

#### Setup

Fresh private testnet, genesis upward, testnet HF14 at height 1000. Two nodes on
one machine isolated with `--add-exclusive-node` at non-default ports, mined to
height 1048 with 8 threads, then a third node with an empty database, then a
second physical machine. All four ran the same binary, `v0.3.0.0-93909988a`,
verified with `--version` rather than assumed: the version number alone does not
distinguish builds, only the git hash does.

#### Why `--fixed-difficulty 1000` and not 1

A fixed difficulty is needed because a fresh net at real difficulty would take
roughly a day to reach height 1000. The value matters more than it looks.

**At difficulty 1 every hash meets the target.** A node computing a completely
wrong longhash would still accept every block, so the round would pass while
being blind to the one failure it exists to detect. At 1000 the PoW is binding:
a systematically wrong validator rejects about 999 blocks in 1000. The cost is
that the real LWMA difficulty path is not exercised, which is acceptable here
because difficulty is not what this branch changed.

#### Results

- HF14 activates at exactly height 1000 on every node, `enabled=true`
- 998 and 999 are `major_version=13`; 1000, 1001, 1005, 1020 and 1047 are
  `major_version=14`, so everything past the boundary routes through
  `get_block_longhash_v14`
- the two mining nodes held identical block hashes at every height checked
- a third node with an **empty database** revalidated all 1048 blocks from
  genesis in under 25 seconds and matched the top hash exactly. This is the
  first validation of v8 blocks by a node that took no part in producing them
- a **second physical machine**, i7-7700HQ against the 7950X that mined them,
  synced from 0 and reported block 1047 as
  `fc2ed1b074918e50e62a287662218b9ed0648651cf0e77217287835626456a71`,
  identical to the miner's. Same for the top hash and `cumulative difficulty`

The cross-machine result is the one that carries weight. Nodes sharing a CPU, a
binary image and a build agree with each other almost by construction; a
microarchitecture-dependent bug in the hash would pass every single-machine test
here and fail only this one.

#### A corroborating observable, not a measurement

While mining at fixed difficulty, heights 800 to 999 (CNA v6) ran about 4 s per
block. Crossing into v8 the chain produced 12 blocks inside one 5-second poll.
That is consistent with v8 costing roughly an order of magnitude less than v6,
and it is independent of `v8bench`. It is **mining rate under fixed difficulty,
not a verify measurement**, so it corroborates F24's ratio and must not be
quoted as one.

#### What this round does not establish

- real difficulty retargeting across the fork, suppressed by `--fixed-difficulty`
- any transaction behaviour; the chain carried no transactions, so CLSAG and
  Bulletproofs+ at v14 were untouched here and rest on round 3
- a contested reorg across the boundary. Two miners racing near height 1000 is
  still worth provoking, since that is where a wrong `random_values` bound would
  split nodes rather than merely produce a wrong hash
- `--fast-block-sync 0` reverification of the v10, v11 and v13 ranges on mainnet,
  which remains a separate merge blocker

#### A defect this round found, in the branch's own work

`cn_slow_hash_known_answer_test` was called from inside `#if !defined NO_AES` in
`check_aesni`. `NO_AES` drops only the hardware translation units: such a build
still computes consensus hashes through the software path, and it is the build
with the **least** other checking, because there is no hardware arm left for
`cn_slow_hash_self_test` to compare against. The vectors were being skipped
exactly where they were the only remaining check. Moved outside the guard, where
the floating-point self-test already sat for the same reason.

Note the status of that fix honestly: the symbol has no `NO_AES` guard in
`slow-hash.c` and the call is now unconditional, both confirmed by inspection,
but **a `-DNO_AES=ON` build has not been run**. It is an explicit opt-in that
nothing in CI exercises.

### F51. The sweep deferral is built, and its gain is set by L2 size, not by the algorithm

*Built and measured 2026-10-02. Non-consensus: the hash is bit-identical, which
is the only reason it is allowed to exist.* F44 proposed it, PLAN-v8 Phase 6
A1b specifies it, and two of that specification's assumptions were wrong.

#### What the design had to change

**The sweep sequence is not schedulable.** `r2` aliases `c`, the CN state that
`post_aes_variant` has just written from the AES output, so every sweep's
offset and stride depend on the pad at that instant. Nothing precomputes. The
deferral still holds by induction, because reconstructing the logical value at
each read makes `c` identical, but the consequence is sharp: **an error in the
reconstruction changes the sweep parameters themselves**, so a wrong build does
not produce a visibly corrupt hash, it produces a different self-consistent
one.

**`VARIANT1_1` is nonlinear.** It indexes a table with bits of pad byte 11 and
writes the byte back, so XOR does not commute with it and the deferral cannot
be an XOR bolted onto each end of the existing macros. The pad holds
`logical ^ comp` and every read materialises `logical` before anything
nonlinear sees it.

That convention is self-correcting across time, which is what makes it
tractable: a cell stored at step `m` holds `logical_m ^ comp_m`, and a read at
step `m'` recovers it XOR exactly the sweeps between `m` and `m'` that hit the
cell, which is what the eager form would have applied. The same identity makes
the finalize pass correct for cells no CN step ever touched.

#### The mistake that would have made it slower

Reconstructing a historical salt byte by scanning the patch list costs ~56
comparisons per byte, and the finalize pass touches ~476K salt bytes, so a
naive `comp()` is ~26M operations per nonce: **slower than the sweeps it
replaces.** What makes it work is tiling the pad and walking the sweeps in
reverse within each tile, undoing patches as the salt rewinds and redoing them
after. Patch traffic is ~2*npt*32 bytes per tile, about 114K byte-XORs in all,
against 476K of real work.

#### The measurement, and why F44's 1.18x is not the shipped number

A/B on one machine, same conditions, reading v8:v5 because v5 does not use
`salt_pad_v8` and is therefore a control inside the same run.

| pad | v8:v5 eager | v8:v5 deferred | v8 speedup |
|---|---|---|---|
| 1 MB | -5.53% | -9.01% | 1.04x |
| 2 MB | -23.81% | -31.65% | 1.11x |
| 4 MB | -32.57% | -41.07% | 1.14x |
| 8 MB | -37.28% | -47.42% | 1.19x |

The gain rises with pad size, which is the signature of a cache effect. The
7950X has **1 MB of L2 per core**, so at the shipped 1 MB pad the eager sweeps
were already resident and tiling had little to win. The 8 MB row reproduces
F44's 1.18x almost exactly, and F44 was measured on a 5600G with 512 KB of L2
at a 1 MB pad. **The two agree once compared at equal pad-to-L2 ratio.** F44's
figure is not wrong and is not the shipped configuration's figure either.

#### The cross-machine result, which is the reason to ship it

Predicted before measuring: a smaller L2 should gain more, so the i7-7700HQ
(256 KB L2) should show 12 to 18% where the 7950X shows 3.8%. Measured A-B-A on
the laptop: **-4.06%, -15.97%, -4.07%**. The two eager runs differ by 0.01
points, so the gap is not drift, and the v5 control held within 0.4%.

| | eager | deferred |
|---|---|---|
| 1 MB 1T, 7950X | 0.5569 ms | 0.5349 ms (1.04x) |
| 1 MB 1T, i7-7700HQ | 1.4346 ms | 1.2574 ms (1.14x) |
| cross-CPU verify spread, hash core only | 2.58x | **2.35x** |

**Those two rows exclude the chain fill**, because `v8bench` supplies its own
salt and never calls `get_cna_v6_data`, which is ~60% of a real nonce. On real
nonces the spread is 2.23x against 2.13x, so the deferral is worth about half
what this table implies. F52 measured it; read that before quoting these.

Multi-threaded the laptop's 1 MB peak goes 2404.5 to 2840.1 H/s (+18.1%) while
the 7950X is flat (31134.3 to 31082.4), moving that spread 12.9x to 10.9x.

**Worth setting against the floating-point stage** (F41), which costs 6 to 9%
of hashrate, buys 2.7% of spread, makes GPU resistance slightly worse, and is a
consensus change. The deferral narrows the spread several times further, costs
nothing, and changes no hash.

*Two caveats, because this is a verification measurement.* Miners batch nonces,
which changes the cache picture, so the mining magnitude may differ from the
single-nonce figures above; that is unmeasured. And the laptop's multi-thread
tail is thermally noisy, with the peak moving from 4T to 8T between runs, so
the single-thread rows carry more weight than the throughput ones.

#### What was verified, and how

- **1600 digests, eager against deferred, byte-identical.** All 25 `(xx, yy)`
  cells crossed with **every** `iters` value 0 to 63, which is the whole drawn
  parameter space. A one-shot harness compiled twice against the same tree; not
  kept, because the known-answer vectors are the standing guard.
- `cn_slow_hash_known_answer_test` passes. This is the gate that matters:
  **both** AES arms changed together, so the HW-equals-SW self-test structurally
  could not have caught a symmetric error.
- `cn_slow_hash_self_test` passes, which is what covers the software arm: the
  harness dispatches to hardware AES, and HW equals SW equals eager.
- `t_v8_chain` passes, all 9 assertions. **It had never built**: it was
  registered in `24a120b`, but `${NERVA_ROOT}/src/crypto` was never on the
  hf14checks include path, so `#include "hash-ops.h"` could not resolve.
  `git log -S` confirms the path was never there and no artifact exists in the
  tree. A test that cannot build reports nothing and is indistinguishable from
  one that passes. Fixed in the same commit.
- `v8bench`'s own gate, shipped against recompiled on 24 inputs, passes.

### F52. The real cross-machine spread is 2.13x, and every earlier spread figure excluded 60% of a nonce

*Measured 2026-10-02 on a 1,962,207-block testnet chain at fork version 14, one
mining thread, `--offline`, `--fixed-difficulty 100000000` so the miner grinds
instead of churning block templates.*

Every cross-CPU number in this file before now, including F51's fairness
argument and the figure in PR #162, comes from `v8bench`. **`v8bench` hands the
hash a synthetic salt and never calls `get_cna_v6_data`.** The chain fill is
~60% of a real nonce, so those figures are computed from the 40% that excludes
the dominant term.

All four machines, one mining thread, and the multi-thread column at one less
than the machine's thread count:

| CPU | 1T H/s | ms/nonce | vs fastest | max-1 | scaling |
|---|---|---|---|---|---|
| Ryzen 9 7950X, 16c/32t | 756 | 1.323 | 1.00x | 12.77 kH/s @31T | 54% |
| Ryzen 7 9700X, 8c/16t | 737 | 1.357 | 1.03x | 6.35 kH/s @15T | 57% |
| Ryzen 5 5600X, 6c/12t | 587 | 1.704 | 1.29x | 3.53 kH/s @11T | 55% |
| i7-7700HQ, 4c/8t | 348 | 2.874 | **2.17x** | 1.275 kH/s @6T | 61% |

**The whole spread is the laptop.** The three desktops sit within 1.29x of each
other across three Zen generations; Zen 5 and Zen 4 are within 3%.

Scaling efficiency is flat at 54 to 61% across all four, so multi-threading does
not differentially punish the weak machine. That is worth recording because the
4 MB and 8 MB rows in `v8bench` show the opposite, and it is part of why the pad
stayed at 1 MB.

Against the two-machine decomposition:

| | 7950X | i7-7700HQ | spread |
|---|---|---|---|
| hash core, `v8bench` | 0.535 ms | 1.257 ms | 2.35x |
| chain fill, by subtraction | ~0.79 ms | ~1.62 ms | ~2.05x |
| **real nonce, daemon** | **1.323 ms** | **2.874 ms** | **2.17x** |

**The real spread is narrower than the published one**, because the chain fill
is more uniform across machines than the hash core. That is the opposite of the
direction a reviewer would guess, and it is good news: the algorithm is fairer
in practice than the benchmark says.

**Do not call the 2.2x target met on this.** 2.17x clears it by 1.3%, and that
margin is far smaller than the noise on the number underneath it. The same
binary on the same 7950X reads about 760 H/s with the machine quiet and about
670 with a browser open, **a 12% swing**, and in one loaded session the two ends
of an A-B-A came back 10.7% apart under nominally constant conditions. The
denominator of the ratio moves by several times the margin being claimed, so the
third significant figure of 2.17x is noise. Worse, PLAN-v8's
2.2x target and v6's 2.91x were both stated against hash-core figures, and v6
has never been measured this way, so this is not a like-for-like comparison
either. The honest statement is that v8 sits **at** the threshold on a
measurement basis the threshold was not written for.

The 60% share is now confirmed three independent ways: the instrumented profile
at 59.5%, the external review's unscreenable prefix at 63%, and this run's
1.348 ms against `v8bench`'s 0.535 ms.

#### What it does to the deferral's fairness claim

Reconstructing F51 on real nonces, using its own eager hash-core times:

| | eager | deferred |
|---|---|---|
| 7950X | ~1.370 ms | 1.348 ms |
| i7-7700HQ | ~3.052 ms | 2.874 ms |
| real spread | 2.23x | **2.13x** |

So the deferral narrows the real spread by about **4.3%**, not the 8.7% F51
claims from hash-core numbers. It only acts on the 40% of a nonce that is not
the chain fill. The direction is unchanged and it still costs nothing; the
magnitude was overstated by roughly 2x.

#### The caveat on the decomposition

The chain-fill row is a subtraction of two different harnesses, and the external
review's item 4 points out that the daemon's pad is cold where `v8bench`'s is
warm, because the block-cache walk now runs between the AES fill and the pad's
first use. That makes the daemon's hash portion the more expensive one, so the
subtracted fill is an **upper bound** and the true fill is cheaper. The totals
and the 2.13x are measured directly and do not depend on the split.

That also disposes of item 4 in practice: whatever the cold pad costs, it is
already inside the 2.874 ms, and the spread that results is better than what was
being claimed, not worse.

#### Method note worth keeping

`--fixed-difficulty` has to be set **high** here, not low. At the chain's own
difficulty of 3 the miner finds a block almost every hash, so `mining_status`
measures block-template construction rather than hashing. The run above used
100000000, at which no block is found and the reported rate is the hash rate.

**A-B-A is not enough on this measurement, and A-B-B-A is.** An A-B-A comparing
two daemon builds returned its two A runs 10.7% apart, which is larger than any
effect worth looking for, so it could only be discarded; averaging the two A's
against the single B produced a confident `-5.5%` that was pure drift. A-B-B-A
cancels linear drift instead of merely revealing it, because the A's sit at the
outside and the B's in the middle. Discard a warm-up run as well: the first
sample of a session reads high, the machine evidently not yet settled. With
that design the same comparison came back at +0.5% with 1.4% drift across the
A pair, which is the right answer, since the change under test touches only a
failure path.

### F53. External review of the Phase 6 batch, what it found and what was verified

*Second independent review, 2026-10-02, against `bc42c85`. Recorded with the
distinction between what was re-derived here and what is being carried on the
reviewer's word, because that distinction is the point.*

#### Defects found in this branch's own work, all confirmed here before acting

**The sweep log was unbounded, and overflowing it is a stack smash.**
`salt_pad_v8_defer` wrote `cn_v8_swlog[cn_v8_nsw++]` with no guard, and
`nsw = (xx-1)*yy`. Consensus draws `xx, yy` in [4,8] so 56 fits in 64, but
`cn_slow_hash_v14` is exported with unvalidated `uint16_t` and `contrib/`
already calls it, so `xx=yy=100` wants 9900 entries. **Latent rather than live**:
no current caller passes anything above 8.

Fixed by flushing and restarting the log when it fills, rather than clamping or
returning early as suggested, which keeps the hash *correct* at any parameters
instead of merely failing visibly. Verified: at `xx=yy=100`, about 155 mid-hash
flushes, the output is byte-identical to the eager form. The regression set is
now 1615 vectors, the 25x64 grid plus 15 overflow cases.

**A C++ exception could unwind through a C frame.** `v14_fetch_salt` is C++
called from `cn_v8_core`, which is C. Confirmed reachable rather than assumed:
`build_block_cache` does `throw0(DB_ERROR(...))` at `db_lmdb.cpp:2450` and
`get_cna_v6_data` calls it at 2762. Worse than reported: `init_hash()` mallocs
`text` and `finalize_hash()` frees it, so an unwind leaks it as well as being
ABI-dependent. The callback body is now wrapped and the failure becomes a
`false` return from `get_block_longhash_v14`.

**The self-test ignored the seed.** `cn_selftest_salt` took `(void)seed`, so the
two arms' agreement on the AES fill's final chain state, which is consensus
input to HC-128, was inferred from the hashes matching rather than checked. Now
compared directly, with the two capture buffers pre-filled differently so a
callback that never writes fails instead of passing on two zeroed buffers.

Also taken: `comp()`'s O(sweeps x patches) cost is documented at both ends,
including that widening the [4,8] draw range flips the deferral from a win to a
loss **silently**, since it stays bit-identical and no test fails.
`CN_V8_FETCH_SALT` gained its `do/while(0)`.

#### A real defect in `get_cna_v6_data`, which is deliberately not fixed

Two oddities, the first reported by 0xROOTPLS and the second found by the
reviewer, both confirmed here by reading the code:

1. `db_lmdb.cpp:2814` is the last statement of the `while (count < 2048)` body,
   so on loop exit the four `HC128_U32` draws that follow run with no
   `HC128_NextKeys` between. `HC128_Init` does not touch `state->keystream`, so
   those draws read the previous key's block.
2. All four `memcpy` in those lines write to `msg` at offset 0, so three are
   dead stores and 48 of the 64 bytes handed to `HC128_EncryptMessage` are left
   over from the previous iteration. Almost certainly meant to be `msg`,
   `msg+16`, `msg+32`, `msg+48`.

**Neither is being fixed, and "before the fork" would be the wrong call.**
`get_cna_v6_data` is called by `get_block_longhash_v13` at
`cryptonote_tx_utils.cpp:689`, so changing it breaks revalidation of every block
since 4,320,000. Fixing it would mean a v8-private copy, a whole new consensus
surface, to buy back entropy nobody can predict anyway without doing the fill.
Both are deterministic, both arms do them, neither is exploitable. Documented
and left.

#### What is NOT carried over from the review

The reviewer withdrew their earlier "spread is 1.62x" after finding their probe
never reset `ctx->salt` between hashes, so `salt_pad`'s in-place patches
accumulated across 750 hashes and `min-of-N` selected whichever accumulated
state produced large strides. Their corrected figures are a 3.2x screening
margin and a 1.71x ceiling against an attacker with both fills free.

**Those are their numbers, not reproduced here.** F42's measured figures stand
as this file's own. The two agree in direction and both say screening does not
pay, which is the conclusion that matters; the magnitudes have not been
reconciled and should not be quoted as ours. Their 50-80 ms estimate for the
startup KAT is likewise unmeasured here.

#### A second round, and a defect the first fix created

The reviewer re-tested the flush-restart over 192 hashes at `xx`/`yy` in
{9,12,17,20}, sweep counts 72 to 380 so the 64-entry log restarts 1 to 6 times
per hash, both AES arms, and found it identical to the eager form. They then
found a defect the exception fix had introduced.

**Wrapping the callback gave `false` a new meaning, and the callers were never
told.** Before it, `get_block_longhash_v14` returned false only at the
`height < CN_SEED_MIN_HEIGHT` check, which happens before anything writes `res`,
so false always meant "res untouched" and the two callers that ignore the return
were safe by accident. After it, a salt-fetch failure lets the hash run to
completion, write a meaningless `res`, and return false.

Confirmed here rather than taken: `blockchain.cpp:1749` and `:3596` ignore the
return, run `check_hash` on the garbage, and set `bvc.m_bad_pow`, which feeds
`drop_connection_with_score(context, P2P_IP_FAILS_BEFORE_BLOCK, ...)` at three
sites in `cryptonote_protocol_handler.inl`. **A transient local LMDB error would
have rejected a valid block and banned the peer that sent it.** Local fault,
remote penalty. `blockchain.cpp:4398` does check the return, but its re-hash
path goes to 3596, so the careful caller fed the careless one.

Also confirmed: the salt buffer comes from `allocate_hugepage` and is never
zeroed, so the failure path read 256 KB of uninitialized heap in
`randomize_scratchpad_256k_v8`. Benign in effect, undefined in fact.

Fixed in three places: the catch zeroes the salt, `get_block_longhash_v14`
stamps `res` with 0xff before returning false so anything that ignores the bool
still fails closed, and both careless callers now treat false as *could not
verify*, setting `m_verifivation_failed` without `m_bad_pow`.

**The lesson is about the shape of the mistake, not the code.** The exception
wrap was reasoned carefully at the point of the throw, down to the ABI and the
leaked `text` buffer. What was never asked is what `false` had previously
*meant* to the people receiving it. Changing a return value's meaning is an
interface change, and this one looked like a local bug fix.

#### The pattern worth extracting

That salt-reset bug is the **third** time in this effort a confident wrong
number came from a harness diverging from the thing it measured: the `-O0` build
trap that reversed the pad conclusion twice, `v8bench` still drawing
`init_size_blk` after B1 pinned it, and now a probe that never reset the salt.
All three were caught by a control row or an A/B, none by reading the code.
F52 is a fourth instance of the same family, found the same way.

## The pad, measured below 1 MB

### F54. The pad was never measured below 1 MB, and now it has been: it stays at 1 MB

*Measured 2026-10-06 on a Ryzen 9 7950X and an i7-7700HQ, both quiet, three
back-to-back runs each, median. Decided against criteria fixed in
[PAD-DECISION-PREREG.md](PAD-DECISION-PREREG.md) before any number existed.*

F24 and F27 swept 1, 2, 4 and 8 MB. **Nothing below 1 MB was ever measured**, so
the shipped size was the smallest point in the sample rather than a bracketed
minimum, and every trend in that sample pointed off the bottom end: multi-thread
spread 11.3x at 1 MB against 19.6x at 2 MB, and F31's ARM spread worsening
monotonically with size. That is the condition under which an optimum usually
lies outside the range, so the sweep was extended down to the floor.

The floor is **256 KB**: the pad must be a whole multiple of `CN_SALT_MEMORY` or
the sweep reads past the salt, and a power of two or `state_index`'s mask
confines every access to a prefix. 768 KB satisfies the first and fails the
second, and would need `V5PAD_MOD`, timing it through a multiply-high rather
than a mask and making it incomparable with every other row.

Peak total H/s, median of three, `v8bench` with the resized `v5pad` units:

| pad | 7950X @30T | i7-7700HQ @8T | spread | vs 1 MB |
|---|---|---|---|---|
| 256 KB | 63400.5 | 6658.9 | 9.521x | -12.07% |
| 512 KB | 52022.9 | 5338.4 | 9.745x | -10.01% |
| **1 MB** | **30775.1** | **2842.0** | **10.829x** | **0.00%** |
| 2 MB | 18777.4 | 1396.4 | 13.447x | +24.18% |
| 4 MB | 8777.1 | 604.0 | 14.532x | +34.20% |
| 8 MB | 1629.7 | 282.1 | 5.777x | -46.65% |

**C-1 required a 20% improvement in multi-thread spread at 512 KB and got
10.01%.** C-2 also failed, see F55. Both criteria with data pointed the same
way, so **the pad stays at 1 MB**.

#### The three-run rule is what produced the right answer

A single earlier laptop run gave 2476.6 H/s at 1 MB, **13% below all three of
the back-to-back runs**, which agree with each other to 1.5%. Computed against
that one reading, C-1 came out at 18.78% and looked like a near miss worth
arguing about. It was an outlier, and a slightly softer threshold would have
shipped a consensus change on it.

The pre-registration's value was not the threshold. It was fixing the stopping
rule, three runs and a median, **before** the first result made a fourth run
tempting.

#### Predictions, scored

Stated in the pre-registration before measuring.

| # | prediction | result |
|---|---|---|
| 1 | 7950X gains 1.5x to 1.8x at 512 KB | **1.690x, correct** |
| 2 | laptop gains 2.0x to 2.8x, above the 7950X | 1.878x: out-gains the desktop, **below the band** |
| 3 | spread falls to 7x to 9x at 512 KB | 9.745x, **wrong** |
| 4 | laptop's peak thread count moves up | it never moved, **wrong** |
| 5 | single-thread spread stays 2.2x to 2.5x | 2.38x, **correct** |

The mechanism in prediction 2 is real and is half the claimed size. The laptop
does gain more than the desktop from a smaller pad, because the desktop already
fits all 32 threads in L3 and has no occupancy to recover. It simply does not
gain enough to clear the bar.

Prediction 4 is the instructive miss. The argument was that the laptop fits four
of its eight threads at 1 MB and all eight at 512 KB. It peaks at 8T at **every**
pad size including 8 MB, where its working set is eleven times its L3, so there
was never a thread-count cliff to climb. The gain is contention relief at a fixed
thread count: amplification goes 3.65x to 4.33x. The conclusion survived; the
explanation given for it did not.

That also puts a question mark on F27's amplification column, which showed this
laptop at 1.0x for 4 and 8 MB. It cannot reproduce that today, and the
`tcounts[6]` overflow fixed on 2026-10-06 (below) affected 8-CPU machines too.

#### A harness bug found while sizing the run

`v8bench.c` declared `unsigned tcounts[6]` while both writers were bounded at
`ntc < 12`. The default ladder produces eight entries on a 32-thread machine
(1,2,4,8,14,16,24,32) and seven on an 8-thread one, so **both machines in the
set wrote past the end of that array**. Now `tcounts[12]`. Any earlier
default-ladder result from either machine came from a binary that smashed its
own stack.

#### Independent corroboration, from the GPU side, obtained after the fact

Bento-Box was asked on 2026-10-06 whether lowering the pad below 1 MB would give
a GPU an advantage, **after** these measurements were taken and deliberately not
before, so the pre-registered run was made blind to the answer. The reply, in
summary and as opinion rather than measurement:

> Yes, monotonically, and roughly in proportion to how much you shrink it.
> 1, the salt does not shrink with the pad. 2, it shrinks the AES, which is the
> only part GPUs are bad at. 3, the sweet stride range collapses toward 1.
> 4, cache residency: the limiter for a CryptoNight-adjacent GPU kernel is how
> many nonces stay resident, not VRAM, so a 32 MB Infinity Cache holds 32 nonces
> at 1 MB and 128 at 256 KB, and at 256 KB it is inside FPGA block-RAM
> territory. Going up is not the answer either; Monero settled at 2 MB.

Three of those four were already in PLAN-v8-PHASE7 C1.3 as the argument against
shrinking: the salt's invariance is F23, the AES fill being the anti-GPU gate is
Phase 6 B2, and resident-nonce count was flagged there as the unmeasured risk
that B3 exists to settle. Point 3 is sharper than what was written: the analysis
there covered the stride **modulus** degenerating, and the point being made is
about the stride **minimum**, `CN_V8_SALT_STEP`, falling to 2 at 512 KB and 1 at
256 KB. The cost side of that is measured, see F55's note on v8 crossing v5.

The FPGA observation is new and is not in any document here. Every
specialisation argument in this tree is about ASIC SRAM; 256 KB fitting in FPGA
block RAM is a nearer-term threat and a cheaper one to realise.

**This is recorded as corroborating opinion, not as evidence.** Nothing in this
file enters from a comment alone, and the verdict above rests on C-1 and C-2.
Its value is that an argument from GPU internals and a measurement of CPU
fairness, made independently, point the same way.

### F55. Streaming stores never pay on v8 at any pad size, and over-subscription ratio is not the governing variable

*Measured 2026-10-06 on a 7950X, quiet, `t_v8_nt.c`, 4 s a point, three runs at
30 threads and one each at 8 and 16. Zero digest mismatches at any point.*

V6-MINER-LOG lesson 9 proposed that the streaming-store attack switches on above
some over-subscription ratio "well above 1.3x", from two points on two machines,
and recommended stating the pad as a ratio to L3 per thread. That is now tested
across six pad sizes and three thread counts, 21 points spanning **0.06x to
3.87x**.

Streaming stores lose, in percent, negative meaning the attack does not pay:

| pad | 30T | 16T | 8T |
|---|---|---|---|
| 256 KB | -30.7% | -49.0% | -52.4% |
| 512 KB | -39.2% | -59.0% | -62.6% |
| 1 MB | -42.5% | -60.7% | -62.8% |
| 2 MB | -48.9% | -61.8% | -63.9% |
| 4 MB | -66.8% | -65.4% | -66.3% |
| 8 MB | -67.3% | -70.0% | -68.3% |

**The sign never flips.** The attack does not switch on anywhere in the
reachable range, including at 3.87x, which is the ratio at which lesson 9
records v13 paying +22%.

#### The ratio is not the variable

Running three thread counts was the point: the same ratio is reached by
different (threads, pad) pairs, and if the ratio governs they must agree.

```
~1.05x:  (30T, 2MB) -48.9%   (16T, 4MB) -65.4%   (8T, 8MB) -68.3%
```

Three points at one ratio, **19.8 percentage points apart**. The two inputs act
independently and in opposite directions:

- **more threads at a fixed pad makes streaming less bad**: 1 MB reads -62.8% at
  8T, -60.7% at 16T, -42.5% at 30T. This is lesson 9's mechanism working as
  described: pressure from sibling threads evicts the pad anyway, so streaming's
  eviction becomes free.
- **a bigger pad at fixed threads makes streaming worse**: -30.7% at 256 KB to
  -67.3% at 8 MB. This is the opposite of what lessons 9 and 10 imply.

The mechanism, from the measured cycle counts: streaming's cost is that it
evicts the pad, and the passes immediately after the fill must refetch it. That
penalty is **linear in pad size and the nonce is not**. Cycles per MB of pad fall
from 7.99M at 256 KB to 3.57M at 2 MB, so the penalty grows faster than the
quantity it is a fraction of.

**So lesson 9's rule, state the pad as a ratio to L3 per thread, is not
supported and should not be used.** The ratio collapses two variables that do
not move together. The honest statement is that thread count, not pad size, is
what moves this attack toward viability, and on this machine 30 threads is the
cap and it never arrives.

#### What this did to the pad decision

C-2 was pre-registered as: at 512 KB the streaming arm must lose by **at least
as much** as at 1 MB, and a smaller loss "would be the opposite of what C1.2
claims and would need explaining before anything else proceeds."

Measured: **512 KB loses 39.2%, 1 MB loses 42.5%.** C-2 fails. Shrinking the pad
shrinks the eviction penalty faster than it shrinks the nonce, so a smaller pad
moves this attack slightly toward viability. A 39% loss is not a risk in
absolute terms, but the direction is against shrinking, it was not anticipated,
and **PLAN-v8-PHASE7 C1.2's claim that shrinking roughly doubles the attack
margin is wrong in sign**.

#### Note on v8 crossing v5 below 1 MB

In the single-thread sweep, v8 is cheaper than v5 at every size at or above
1 MB (-8.3% at 1 MB, -46.5% at 8 MB, consistent with F22) and **more expensive
below it**: +7.2% at 512 KB and +51.6% at 256 KB. The crossover sits between
512 KB and 1 MB.

The cause is the stride coupling running backwards. v8's `offset_2` floor is
`CN_V8_SALT_STEP`, which falls to 2 and then 1 while v5's stays hardcoded at 4,
so v8 does more sweep steps rather than fewer. E[1/s] predicts a 1.47x sweep
penalty at 256 KB and the row measures 1.52x. v5 is the control rather than a
candidate, so this does not disqualify anything by itself, but it does mean the
sweep work does not shrink with the pad as fast as the fill does.

#### Harness note

`t_v8_nt.c` prints a **split-half check**, the same ratio recomputed from the
first and second halves of each point's own window, which is what says whether
the window was long enough. The halves converge to within 0.4 points at 1.5 s;
the fork's version ran a fixed 20 s a point chosen by guess, roughly 13x longer
than needed.

The 8 MB row at 30T flags UNSTABLE in all six runs, with the first half near
-64% and the second near -70% every time. That is a reproducible **within-window
trend**, not run-to-run instability: the full-window figure repeats to 0.3
points. The UNSTABLE label conflates those two and should distinguish them.

### F56. v8's four extra hashes reach the digest only through the pad sweep, so the hash diversity is not separable from the thing that costs 22%

*Measured 2026-10-06 on a 7950X with `t_v8_sweep.c`, three variants compiled
side by side at a 1 MB pad, A-B-C-C-B-A per group of six nonces with one draw
feeding all six. This is a property of v8 as it stands, independent of whether
PLAN-v8-PHASE8's D1 is adopted.*

`salt_pad_v8` does two separable-looking jobs per call: it hashes `salt[0..200)`
with one of blake, groestl, jh or skein and patches 32 bytes of the salt with
the result, then it XORs salt across the pad at a data-dependent stride. The
`& 3` selector that reaches all four, rather than v5's `% 3` that never reached
Skein (F10), **is v8's defining difference from v5**.

The obvious design move was to drop the expensive half and keep the cheap one:
the pad XOR is 17.9% of a nonce by the eager profile and is provably not hard
(F51 reorders 30 sweeps into two passes bit-identically), while the extra hash
is 3.2% and is the only thing forcing a specialised implementation to carry four
more hash cores than AES and keccak. That is an area argument, and F38's rule is
about time, so the rule does not settle it.

**The move does not exist.** Three variants, one thread:

| | cycles/nonce | core | nonce | digest FNV-1a |
|---|---|---|---|---|
| v8 as it stands | 2,414,385 | baseline | baseline | `4cf5b55ca66f6f21` |
| pad sweep removed, extra hash kept | 1,122,383 | +115.1% | +21.7% | `84be284becf1ae99` |
| whole `salt_pad_v8` gone | 1,104,258 | +118.6% | +22.0% | `84be284becf1ae99` |

**The last two digests are identical**, so everything that differs between them
is dead code: with the pad XOR gone, the extra hash and its salt patch still run,
still cost cycles and influence nothing.

#### Why, and it is structural rather than a bug

`randomize_scratchpad_256k_v8` consumes `salt[0 .. 262143]` in full **before**
the main loop (F23). After that the only thing that reads the salt again is
`salt_pad_v8` itself: its extra hash reads `salt[0..200)` and its patch writes 32
bytes back. That is a closed loop feeding nothing unless the pad XOR carries it
into the pad, which is what the main loop then reads through `state_index`. Sever
the XOR and the loop is severed with it.

So the four extra hashes are load-bearing **only** in the presence of the sweep,
and the `& 3` widening that makes v8 v8 is load-bearing only in the same sense.

#### Consequences

- **D1 is binary.** There is no cheap way to keep hash-function diversity for
  ASIC area while dropping the pad sweep. Keeping it would mean rewiring the
  extra hash into something that is actually read, which is a new construction
  rather than a trim, and would need its own justification.
- **The 22% is a floor, not a point estimate.** It is the measured core saving
  scaled by F52's 40.5% core share, and F52 states its fill figure is an upper
  bound because the daemon's pad is cold where `v8bench`'s is warm. A colder pad
  means a larger core share and a larger saving.
- The saving is flat across thread counts: 21.7% at 1 thread, 22.1% at 16,
  22.1% at 30, so it is not a cache artefact.

#### Two harness bugs on the way here, both of which hid the result

Recorded because both are the same family and the family is common.

1. **A XOR accumulator over an A-B-B-A pattern cancels itself.** Each arm hashes
   twice per group from a restored salt, so the digests are identical and the
   accumulator goes to zero. It read 0 of 256 bits on both arms, which looks
   like a broken hash and is a broken check. Replaced with FNV-1a, which does
   not cancel.
2. **Comparing every arm only against the baseline misses arms agreeing with
   each other**, which was the entire finding. It now compares every pair.

Neither invented a result; both concealed one. That is the better direction to
fail in, but the only reason this was caught at all is that two timings looked
implausibly close and the digests were checked on a hunch.

### F57. The chain fill is 56% of a v8 nonce, the run-ahead is worth 6% not 27%, and the same function costs 1.6x more under v13 than under v14

*Measured 2026-10-06 on a 7950X, machine quiet, in the daemon with HF14
temporarily lowered to 4,400,000 so v14 was actually active, 30 threads, over
1,005,568 nonces. Figures are invariant-TSC ticks, not core cycles; every ratio
and share below is therefore valid, and none of them converts to seconds without
the TSC frequency.*

PLAN-v8-PHASE7's A1 proposed porting the fork's run-ahead rewrite of
`get_cna_v6_data`, predicting roughly +27% on a v8 nonce from a 1.57x fill
speedup at a 59.5% fill share. **Both inputs were wrong and they were wrong in
opposite directions.**

#### What was measured

```
v14 active, 30 threads, 1,005,568 nonces
  whole nonce                11,274,230
  chain fill, reference loop  6,819,499
  chain fill, run-ahead       6,142,082   1.110x
  hash core, by subtraction   4,793,440
```

| | removes | speedup | fill share | ASIC bound |
|---|---|---|---|---|
| v8 with the reference fill | | | 58.7% | 1.70x |
| v8 with the run-ahead, **A1** | **5.8%** | **1.062x** | 56.2% | 1.78x |
| and with D1's sweeps removed | 23.9% | 1.313x | 73.8% | 1.36x |

**The port is bit-identical**, which it must be because `get_cna_v6_data` is
shared with live v13: `NERVA_SALT_SELFCHECK` computed both loops and compared
all 256 KB plus the final cipher state, 64 of 64, against the real chain at
height 4,424,751, with zero disagreements.

Internal consistency: 11,782 H/s times 30 threads times 11,274,230 ticks gives
4.43 GHz per thread against the part's 4.5 GHz base, which is what invariant TSC
should read. Two independent timers and the reported hashrate agree.

#### The finding that generalises: the fill's cost depends on the algorithm around it

The same function, measured in two versions of the daemon on the same machine
against the same database:

| | fill, reference | fill, run-ahead | run-ahead is worth |
|---|---|---|---|
| under v13, 30 threads | 11,114,446 | 7,767,445 | 1.431x |
| under v14, 30 threads | 6,819,499 | 6,142,082 | **1.110x** |

**The chain fill costs 1.63x more under v13 than under v14, and the
optimisation is worth 1.29x more there.** The cause is the pad: v13 holds 8 MB
per thread, which at 30 threads is 240 MB against 64 MB of L3, so the fill's
block-cache reads miss constantly and there is a great deal of memory latency
for a run-ahead to hide. v14's 1 MB pad leaves the fill already fast and little
left to recover.

So a figure for this function does not transfer between versions **even though
it is literally the same code**. That is lesson 5 in its sharpest form so far,
and it is what produced the two errors below.

#### Two corrections to this project's own numbers

**The 59.5% fill share was right and the 68% that briefly replaced it was
wrong.** The 68% came from composing a fill measured under v13 with a core
measured in a harness, and inherited v13's inflated fill cost. The real share is
56.2% with the run-ahead and 58.7% without, which is where the original
instrumented profile always had it. Everything scaled by that number in
PLAN-v8-PHASE8 stands.

**A1's prediction of +27% was wrong by more than 4x.** The honest reading is
that the prediction was stated before measuring, per Phase 1e's discipline, which
is the only reason the miss is visible at all.

#### The cold-pad question, closed

F52 notes that its own fill figure is an upper bound because the daemon's pad
goes cold during the chain-cache walk while `v8bench`'s stays warm. That caveat
was bounded here at anywhere from 1% to 20% of a nonce, which is too wide to
leave underneath the share that scales every projection in Phase 8.

Measured: the harness core at 30 threads is 4,640,763 ticks and the daemon core
is 4,793,440, so **the cold-pad penalty is +3.3%.** The bound was honest and
nearly useless; the measurement cost one build and is now a number.

#### A void run, and why the obvious design was the broken one

The first attempt ran A-B-B-A as **four separate daemon processes**, one per arm.
It came back with its two A arms 25.1% apart against a 2% tolerance, after
discarding the first window of each to remove cold-cache bias. Void.

The cause is structural rather than noise: between-process variation on a 5 GB
database swamps an effect of this size, and the arms drifted in different
directions within their own runs (one trending down 17%, another up 20%).

The fix was to **interleave the arms per call inside one process** against one
block cache, selected by `NERVA_SALT_AB`, which is what `t_v8_nt.c` already does
across threads. The interleaved run was stable to 0.5% across six checkpoints
immediately. Both arms produce identical output, so alternating them is
invisible to consensus and only the timing differs.

Also recorded: the reported figure was a **cumulative** mean, which is not
comparable across runs that reached different call counts, because a shorter run
carries proportionally more cold-cache calls. Per-window figures are the ones to
read.

#### Measurement-only changes, not committed

HF14 was lowered from 4,500,000 to 4,400,000 so v14 would be active on a chain
copy whose tip was 4,424,751. **The daemon then popped the chain back to exactly
4,400,000**, since the blocks above it had been mined under v13 rules, which
truncated the database copy. That is worth knowing before anyone repeats this: it
writes to the copy and the copy is not reusable for v13 work afterwards. The fork
height was restored immediately and a nonce timer added to
`get_block_longhash_v14` for this run was reverted, being scaffolding in a
consensus-critical file.

#### What it means for the plan

A1 is still worth doing: it is bit-identical, it is verified, and it speeds
verification and sync for everyone. But at 1.062x on v8 it is **a quarter of the
size of D1**, it does not justify the position it was given in the running order,
and it slightly loosens the ASIC bound it was partly meant to pay for, from 1.70x
to 1.78x, exactly as F38 predicts for anything that accelerates the half an
attacker cannot specialise.

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
caught it was the 10.11 ms baseline in [RESULTS.md](RESULTS.md): a number that far off the
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

### F17. [RESULTS.md](RESULTS.md) carries two different v6 numbers, measured differently

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

### F58. The two v8 arms agree across the whole consensus domain, and D1 collapses the three per-nonce draws into a single step count

Two results from the first D1 correctness gate. The first is the gate passing.
The second was not being looked for and changes what D1 is.

`contrib/powbench/t_v8_grid.c`, built by `build-v8-grid.sh`. The D1 candidate is
a real pair of translation units, `contrib/powbench/v8ns-hw.c` and `v8ns-sw.c`,
rather than the `v5pad.inc` scaffolding the cost measurement used, because
`v5pad.inc` refuses a software-AES build by design and the software arm is the
whole point here.

#### 1. The gap that was there before D1

`cn_slow_hash_self_test` compares v8's hardware and software arms at exactly one
point, `(xx, yy, iters) = (3, 3, 64)`. Consensus draws `xx` and `yy` from
`[4, 8]` and `iters` from `[0, 63]`
([cryptonote_tx_utils.cpp:752](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L752)),
so the one point the arms were ever compared on is **outside the range the chain
asks for**. That is a gap in v8 as it stands today and has nothing to do with
D1.

It matters because the two arms are separate copies of the core, not one body
behind a macro, and they differ in source on purpose: `r2` aliases `&c` in the
hardware arm and `&b` in the software arm. A disagreement there splits mining
from verification on exactly the platforms that have no hardware AES and so
would never notice.

#### 2. The gate, and it passes

All six checks pass on the 7950X. 1600 in-domain cases is the full `5 x 5 x 64`
product, not a sample, with the input, the salt and `random_values` varied per
case from splitmix64 rather than left zeroed.

| check | result |
|---|---|
| v8 shipped, hw == sw over 1600 consensus draws | PASS |
| v8 no-sweep, hw == sw over the same 1600 | PASS |
| no-sweep differs from shipped on all 1600 | PASS |
| chain entry, both variants, 64 pairs, hash and the 32-byte fill seed | PASS |
| out-of-domain `(xx, yy)` including `xx = 1` and `yy = 1`, 64 pairs | PASS |

    v8 shipped   hw 09accdf062ccd318  sw 09accdf062ccd318
    v8 no-sweep  hw 09d34831c25f506c  sw 09d34831c25f506c

FNV-1a over all 1600 digests per arm, so another machine can be compared against
this run in one line rather than case by case.

**Repeated on the i7-7700HQ, Kaby Lake against Zen 4: all six checks PASS and
all four digests are bit-identical to the run above.** That is the stronger
result. Per machine the test shows the two arms agreeing with each other; across
machines it shows both arms agreeing with both arms on a different
microarchitecture, over 1600 cases, for the shipped hash and the candidate
alike. The software arm exists for machines unlike the one it is usually
developed on, so a second microarchitecture is where the check earns its keep.

#### 3. What was not being looked for: after D1 the loop nest is decorative

With `CN_V8_NO_SWEEP`, the outer loop body, the inner loop body and the `iters`
loop body are **the same three statements**. `xx`, `yy` and `iters` then appear
nowhere else in the core: the only other reader of `iters` was
`temp_1 = iters ^ (b ^ c)` inside `salt_pad_v8`, and the only reader of `r2` was
the sweep. So the whole main loop reduces to

    steps = (xx - 1) * yy + iters,  which lies in [12, 119]

and nothing can distinguish two draws with the same total.

Checked rather than read off the source, because it decides whether the daemon
should keep drawing three numbers. Two equivalence groups, every row sharing one
input, salt and `random_values`:

| group | rows | no-sweep | shipped v8 |
|---|---|---|---|
| 12 steps | (4,4,0) (1,1,12) (1,8,12) (2,4,8) (3,6,0) | all identical | all different |
| 119 steps | (8,8,63) (1,1,119) (5,8,87) (4,5,104) | all identical | all different |

The shipped hash separates them, which is what `salt_pad_v8` reading `xx`, `yy`
and `iters` individually buys. The candidate does not.

**119 is not a coincidence.** It is the same 119 as the fixed cap on
unpredictable pad writes in lesson 10 and PLAN-v8-PHASE8 P4, arrived at from the
other direction.

#### 4. Two consequences for D1, one in each direction

**In favour: D1 deletes the only place the two arms touch different state.**
`r2` is the sole asymmetry between the hardware and software cores, and the
sweep is its sole consumer. After D1 the initializer is dead and the arms can no
longer diverge in that particular way, which is the failure mode that would show
up only on machines without AES-NI and only in the field.

**Against, and this is not in PLAN-v8-PHASE8: the sweep is a second source of
GPU warp divergence, and D1 removes it.** The sweep's inner loop runs
`1 MB / offset_2` times with `offset_2 = ((temp_1 * offset_1) % 125) + 4`, so
its length spans 8,192 to 262,144 iterations, a 32x range, drawn fresh per
sweep from data. A 32-lane warp runs at the maximum over its lanes.

Modelled, not measured, and recorded as modelled:

| divergence source | mean | E[max of 32] | penalty | survives D1 |
|---|---|---|---|---|
| step count, `(xx-1)*yy + iters` | 46 | ~88 | **1.9x** | yes, unchanged |
| sweep length, summed over ~30 sweeps | 906K | ~1.33M | **~1.5x** | **no** |

So P6's 1.9x term is untouched, which is the one the design actually leans on,
and D1 gives up a smaller second term on a smaller share of the work. The
arithmetic is a normal approximation to a sum of 30 draws of `1/U[4,128]` and
should be treated as an order of magnitude. It is here because the cost existed
and was not named, not because it is settled.

#### 5. The core cost, re-measured with absolute time

`t_v8_sweep` now calibrates the invariant TSC against the wall clock and reports
ms/nonce as well as cycles, because cycles compare arms on one machine and
cannot compare one machine against another. That conversion is what the
cross-machine spread gate needs.

7950X, one thread, 10 s, TSC 4.491 GHz nominal against a 4.5 GHz base:

| arm | cycles/nonce | ms/nonce | core | nonce |
|---|---|---|---|---|
| v8 as it stands | 2,433,678 | 0.5418 | baseline | baseline |
| pad sweep removed | 1,125,235 | 0.2505 | +116.3% | +21.8% |
| whole `salt_pad` gone | 1,106,369 | 0.2463 | +120.0% | +22.1% |

0.5418 ms against F52's 0.535 ms for the same thing, so the harness and the
daemon agree to 1.3%. The two candidate arms still produce identical digests,
which is F56 reproducing rather than a new result.

#### 6. The cross-machine spread: the core widens 13%, the real nonce widens 1%

Same binary on the i7-7700HQ, the machine that sets the spread in F52 and F54.
One thread, 10 s, TSC 2.808 GHz nominal against a 2.8 GHz base.

| arm | 7950X ms | 7700HQ ms |
|---|---|---|
| v8 as it stands | 0.5418 | 1.4189 |
| pad sweep removed | 0.2505 | 0.7529 |
| whole `salt_pad` gone | 0.2463 | 0.7293 |

**The laptop gains less from D1 than the desktop does**: 1.946x against 2.200x
within each run, which is the drift-robust figure since the arms are
interleaved A-B-C-C-B-A.

The mechanism, and it is the same shape as F52's:

| part of a nonce | spread, slowest over fastest |
|---|---|
| chain fill, F52 by subtraction | **2.05x**, most uniform |
| the sweeps, this run | 2.33x |
| the rest of the hash core | **2.96x**, least uniform |

**The sweeps are the more uniform half of the core.** D1 removes a term sitting
below the weighted mean of what is left, so the spread of the whole has to rise.

Rebased on F52's core times rather than this run's, because the laptop read
12.9% high today while the 7950X agreed to 1.3%, and F52 already records that
machine throwing a 12% hot run. Today's contribution is the in-run ratios; the
absolutes stay F52's.

| | now | after D1 |
|---|---|---|
| hash core, 7950X | 0.535 ms | 0.243 ms |
| hash core, 7700HQ | 1.257 ms | 0.646 ms |
| core spread | 2.35x | **2.66x**, widens 13% |
| real nonce, 7950X | 1.325 ms | 1.033 ms |
| real nonce, 7700HQ | 2.877 ms | 2.266 ms |
| **real nonce spread** | **2.17x** | **2.19x**, widens 1.0% |

**The gate does not block D1, and it does not support it either.** 1.0% is far
inside the 12% session noise F52 documents for this very measurement. What it
does kill is any claim that D1 improves fairness: the direction is the wrong
one, and the reason it does not matter is that the core is 40% of a nonce and
the fill does not change.

*Caveat with a known direction.* F52's chain fill is a subtraction and so an
upper bound, which means the true core share is larger and D1's effect on the
spread is larger than 1.0%. The bound at zero fill is the core spread, 2.66x.

*Method note.* `t_v8_sweep`'s FNV digests are **not** comparable between
machines: the harness snapshots whatever the allocator left in `ctx->salt` after
the warm-up, so `salt0` differs per run. The 7950X read `505fb8502dc9038d` and
the laptop `5f89632b67de8cc5` for the same two arms, which is expected rather
than a divergence. The cross-machine digest comparison belongs to `t_v8_grid`,
whose salt comes from splitmix64 and is deterministic.

### F15. `hf14checks` inverts its own results if a TU misses its flags

`contrib/hf14checks/CMakeLists.txt` names the resized translation units
explicitly in `set_source_files_properties` with
`-O2;-DNDEBUG;-maes;-march=x86-64;-fno-strict-aliasing`. A new TU left off that
list builds at the directory default, which is `-O0`, and compares against
`libcncrypto.a` built at `-O2`. This has reversed a conclusion twice. The
control row (`v5ref` vs `v5ctl` at ~1.00x) exists to catch it, and if it is not
~1.00x nothing else in the run means anything.

### F50. Running a local multi-node testnet on Windows: two traps

Both cost time during F49 and neither is in the runbook.

**The daemon exits instantly if you redirect its stdout.** `Start-Process` with
`-RedirectStandardOutput` leaves stdin at EOF and the daemon takes that as a
shutdown request: `I EOF on stdin, exiting`, before it even opens the database.
It looks exactly like a crash on startup. Launch it detached with
`-WindowStyle Hidden` and **no redirection**, then read
`<data-dir>\testnet\nerva.log`, which has everything anyway. This affects any
build, not just this branch.

**Testnet allows only one inbound connection per host**, so a third node on
loopback is refused. From `net_node.inl`:

```c
// for testing networks we allow more than 1 connection
const size_t max_connections = m_nettype == cryptonote::STAGENET ? 3 : 1;
```

The comment says "testing networks" but only STAGENET is exempt, so TESTNET
inherits the mainnet limit. The symptom is misleading: TCP connects fine and the
dialing node logs `COMMAND_HANDSHAKE invoke failed. (-3,
LEVIN_ERROR_CONNECTION_DESTROYED)` in a loop, which reads like a protocol or
version mismatch rather than a refusal. The limit is **per host**, so nodes on
other machines are unaffected; it only bites multiple nodes on 127.0.0.1.

**Fixed here**, as `MAINNET ? 1 : 3`. This is not a policy change: `cc02066`,
which introduced the cap in January 2020, is titled "Only allow multiple
connections from the same IP on testing networks" and exempted stagenet alone,
so the code never matched its own stated intent. Mainnet behaviour is untouched,
and there the cap is doing real work: it is what stops one host taking several
of a node's inbound slots. The one visible production effect, that two nodes
behind a single public IP cannot both hold an inbound connection from the same
remote peer, is the intended anti-Sybil behaviour and is unchanged.

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
4. **How far does the FP cost really fall with chain length?** F41 measured
   about 6% at 1.96M blocks with the order controlled, where F37's model of a
   mainnet-shaped nonce says 4.4%. They differ by more than either error bar and
   a 2M-block chain is not a 4.4M-block one. Resolving it needs either a much
   longer testnet or the daemon-side split timing in F38's open question.
5. **No GPU number is trustworthy at full occupancy.** Carried from
   `RESULTS.md`: every large-pad row on every machine hit the launch cap
   because a display-attached GPU trips TDR. Still true of the large-pad
   rows, which are now off by default. It does not affect F37, whose rows
   are all 1 MB, all ran their full nonce count, and are compared against a
   measured cross-row floor rather than against each other in isolation.
6. **Why the RX 580 dispatches without writing output.** F37. Not pursued,
   because it cannot change that conclusion, but it is unexplained and the
   next person to meet it should know it is a known device failure and not
   a property of the kernel.
7. **The real cost of `get_cna_v6_data` against LMDB is unmeasured.** F38
   puts the ASIC bound at 1.6x using a modelled fill; the real one should
   be more expensive and the bound stronger. F42 narrows this by
   subtraction, 0.927 ms as an upper bound against the harness's 0.721 ms,
   but timing `get_block_longhash_v14`'s two halves in the daemon is still
   what settles it, and would also say exactly where sync time goes.
8. **Whether a GPU can feed v8's chain fill to a CPU.** F43, confirmed
   independently by F46 at 1.95x. The limit is PCIe bandwidth at 256 KB of
   salt per nonce. Neither side has been built; PLAN-v8 Phase 6 B2 is the
   proposed fix.
9. ~~**Does raising `iters` help or hurt?**~~ **Closed, it hurts.** F48.
   Step 1 measured +0.67 ms at 64K against a pre-registered +0.5 ms ceiling,
   and the 9.4 ns/step slope shows the chase stays in L2 at a 1 MB pad.
   Steps 2 and 3 were not run.

## Reproducing

    # the v6 cost-oracle screen (counts only, unaffected by machine load)
    gcc -O2 -I src -I src/crypto -I contrib/epee/include \
        contrib/powbench/screen.c src/crypto/cna-vm.c src/crypto/hc128.c \
        -o screen -lm
    ./screen 200000 200 2048      # static programs, live nonces, passes each

    # F42's screening grid: all 75 (xx, yy, init_size_blk) cells of v8, timed.
    # Same flags and sources as build-v8bench.sh, because it times the same
    # shipped hash; -DSLOW_HASH_HW_AES_BUILT=1 and -maes are not optional and
    # the numbers are about 5x slow without them.
    gcc -O2 -maes -march=x86-64 -fno-strict-aliasing -ffp-contract=off \
        -DSLOW_HASH_HW_AES_BUILT=1 -I contrib/powbench/noboost \
        -I src -I src/crypto -I contrib/epee/include \
        contrib/powbench/screen_grid.c \
        src/crypto/slow-hash.c src/crypto/slow-hash-hw.c \
        src/crypto/slow-hash-sw.c src/crypto/slow-hash-v8-hw.c \
        src/crypto/slow-hash-v8-sw.c src/crypto/slow-hash-v8fp-hw.c \
        src/crypto/slow-hash-v8fp-sw.c src/crypto/cna-vm.c \
        src/crypto/hc128.c src/crypto/oaes_lib.c src/crypto/aesb.c \
        src/crypto/keccak.c src/crypto/hash.c src/crypto/blake256.c \
        src/crypto/groestl.c src/crypto/jh.c src/crypto/skein.c \
        src/crypto/hash-extra-blake.c src/crypto/hash-extra-groestl.c \
        src/crypto/hash-extra-jh.c src/crypto/hash-extra-skein.c \
        contrib/epee/src/memwipe.c -pthread -o screen_grid -lm
    ./screen_grid 51 0.927        # rounds, chain fill cost in ms

    # regenerate the known-answer vectors in cn_slow_hash_known_answer_test.
    # Same source list as screen_grid above, swapping in t_gen_kat.c. Paste the
    # output over the tables in slow-hash.c. ONLY do this when the algorithm is
    # meant to change, and say so in the commit: the whole point of the vectors
    # is that regenerating them is a deliberate act.
    #
    # The v10/v11/v13 tables were generated from master, so regenerating them
    # from a branch that touches those algorithms would hide exactly what they
    # exist to catch. Generate those from master, in a worktree if need be.
    gcc ... contrib/powbench/t_gen_kat.c <same sources> -o t_gen_kat
    ./t_gen_kat

Stop mining and close browsers before running it. F41's method notes apply
unchanged: a contaminated run of this probe reads as a cell effect.

`screen.c` aborts rather than report if its instrumented interpreter stops
matching `cn_vm_execute`. Keep that gate. It has already caught one error.
