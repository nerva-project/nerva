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
*Corrected 2026-10-07, F71: it needs the block cache, which is 237 MB of
derived data and NOT a full node. The screening conclusion is unaffected.*

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

**The floating-point stage was removed from the tree so it does not ship, and
is preserved at the signed tag `archive/cna-v8-fp-stage`.** At that tag the
stage (`cn_slow_hash_v15`, `slow-hash-fp.h`, `slow-hash-v8fp-{hw,sw}.c`), its
startup self-test, `t_fp_stage` and the fp-portability CI workflow all build
and pass. Everything below is unchanged and still describes that code. The
primitive-level probes `t_fp_determinism.c` and `t_fp_cost.c` need nothing from
`src/` and stay in the tree, as do the GPU harness's FP kernels behind F37.

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
pool resistance: you cannot mine without holding the block cache, and the
requirement scales linearly with hashrate. *Corrected 2026-10-07, F71: that is
237 MB of derived data, not a full node, so a thin client is possible.*

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

*Fixed 2026-10-07, and it was wider than this entry found.* v11 had the same
gap, at `(xx, yy) = (2, 2)` against its own drawn `[4, 8]`
([cryptonote_tx_utils.cpp:893](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L893)),
and both v10 and v11 passed an `iters` of 64 that no caller can produce, since
both derive it as a modulus by at most 64. **v11 is a live algorithm**, so the
gap was not confined to the unreleased one. v14 now takes both ends of its
domain, 12 steps at `(4, 4, 0)` and 119 at `(8, 8, 63)`, the second running
`salt_pad_v8` 56 times against the old point's 6.

Inert with respect to consensus, and checked rather than asserted: `t_kat`
passes both gates on Zen 4 and on the i7-7700HQ, with `hardware AES dispatch:
yes` on both so the comparison actually ran. The known-answer vectors are
untouched, and they are what would catch a change that moved both arms
together. Worth noting that a self-test failure is **fatal** at startup
([util.cpp:827](../../src/common/util.cpp#L827) refuses to start), so pointing
the test at new draws is a change that has to be run on more than one
microarchitecture before it ships, not reasoned about.

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

### F59. The AES-NI asymmetry is 4.9x to 8.0x and is a property of the CPU rather than of v8; D1 doubles it; the gate is the pad fill

RESULTS.md 6.3 has carried this sentence since before v8 existed:

> its resistance comes from the AES-NI against T-tables asymmetry rather than
> program divergence, and that asymmetry disappears the day a GPU gets
> competitive AES

PLAN-v8-PHASE8 P3 is built on it, D2's value is argued from it, and D1 is
argued safe because it leaves it alone. **It has never had a number.** This puts
one on it, for the half a CPU can answer.

`contrib/powbench/t_v8_aes.c`, built by `build-v8-aes.sh`. Both arms are already
in the tree and F58 proved them bit-identical over the whole consensus domain,
so this is one hash run twice with a single implementation choice changed.

7950X, one thread, 12 s, arms interleaved A-B-C-D-D-C-B-A within one process.

| | AES-NI | T-table | core | whole nonce |
|---|---|---|---|---|
| v8 as it stands | 0.555 ms | 4.41 ms | **7.96x** | **3.82x** |
| v8 without the sweeps | 0.251 ms | 4.07 ms | **16.2x** | **7.15x** |

**Read section 6 before quoting any of these.** The i7-7700HQ returns roughly
half of each, and the reason it does is the most useful thing in this entry.

The whole-nonce column holds the chain fill at 59.5% of a nonce and the same
cost in both arms, since it is a database gather that touches no AES. Dividing
a core ratio by 0.405 would be the wrong arithmetic and is the obvious mistake
to make here.

#### 1. D1 does not leave the AES gate alone, it doubles it

P3 says to cut the sweeps and not the AES, and treats D1 as neutral on goal 1.
It is better than neutral. The sweeps cost 0.303 ms with AES-NI and 0.341 ms
with T-tables, near enough the same, because they are a strided XOR over the pad
and use no AES at all. Removing AES-neutral work raises the share of what is
left that is AES, so the ratio doubles.

Whether that converts into GPU resistance depends on whether a card runs the
strided pad XOR better or worse than it runs T-table AES, which is the B3
question and is not settled here. But on the one axis P3 names, D1's direction
is favourable rather than neutral, and that is a point in its favour that the
design pass did not have.

#### 2. The asymmetry is two numbers, not one

Measured on the no-sweep core, where F58's collapse makes step count a single
clean knob:

| | AES-NI | T-table | ratio |
|---|---|---|---|
| once per nonce, the AES pad fill and the finalize | 0.2511 ms | 4.0705 ms | **16.2x** |
| per main-loop step | 10.7 ns | 26.4 ns | **2.48x** |

Both stable to 1% across two runs. The reason they differ nearly sevenfold is
structural: the pad fill is back-to-back AES on 8 blocks at a time and nothing
else, so losing the instruction costs nearly all of it, while a main-loop step
is one `aesenc` wrapped around a random 16-byte read from a 1 MB pad and is
memory bound, so the AES is a small part of each step.

**Two consequences, neither of them the expected one.**

P3's anti-GPU gate is **the pad fill**, not the chained main loop, and **pad
size is what sets it**. That ties the AES gate directly to the decision F54
closed, and it means the 1 MB pad is doing more work in this design than the
pad decision credited it with.

Phase 6 B2's feeder gate, the fill a device must run before it can know which
blocks to read, is therefore the **16x** part and not the 2.5x part. That is
better for B2 than the plan claimed, and it is the first independent support
B2 has had.

#### 3. 119 CryptoNight steps cost nothing

Across the whole consensus range, 12 steps against 119, the core moved
`-0.72%`, `+2.09%`, `+0.77%` and `-0.1%` on four runs: the noise floor, with no
consistent sign. The CryptoNight main loop is not a cost at a 1 MB pad.

Third independent confirmation, after the instrumented profile's 0.05% inner
loop and F48's ceiling test, and the first one that reached it by varying the
step count directly.

#### 4. What this is not

**It is not a GPU number.** The software arm is a CPU with good caches doing
table lookups out of L1. A card pays differently: shared-memory bank conflicts
rather than L1 hits, and thousands of lanes to hide latency with. This is the
floor of the structural penalty, not an estimate of a card's.

**It is not the AES share of a nonce.** The software arm replaces AES
everywhere, so the ratio mixes the fill, the main loop and the finalize.

**It is not large on its own.** F37 measured GPU:CPU at 0.01 to 0.06x on v5 and
v6, so cards are 20 to 100x worse than CPUs there. An 8x AES asymmetry is one
contributor to that, not the whole of it, and reading it as the whole would
overstate what the AES is doing.

#### 5. A model that failed, kept because the failure is the finding

The first version fitted a **single** pure-AES penalty `k` to the once-per-nonce
cost and solved `icept_hw = A + N`, `icept_sw = kA + N` for the AES share. It
returned an AES share of **227%**, and **-127%** on the next run.

The cause is section 2: there is no single `k`. The pad fill and the main loop
use AES in ways whose penalties differ by nearly sevenfold, so one ratio cannot
stand for both. The two regimes are now reported as measured rather than
modelled, and the solve is gone.

Worth recording for the same reason lesson 5 exists. The absurd numbers were a
gift; a plausible wrong one would have been believed. The first attempt also
tried to read the per-step slope off the in-domain pair, 12 against 119, where
section 3 shows the signal is zero, which is why the slope is now taken at 2,000
against 20,000 where it dominates.

#### 6. The asymmetry is roughly halved on the i7-7700HQ, and the reason matters more than the number

Two runs on the laptop, agreeing to 2% on every cell. Desktop figures beside
them.

| T-table over AES-NI | 7950X | 7700HQ |
|---|---|---|
| v8 core | 7.96x | **4.85x** |
| v8 no-sweep core | 16.19x | **8.38x** |
| pad fill and finalize | 15.95x | **8.13x** |
| per main-loop step | 2.36x | **1.82x** |
| v8, whole nonce | 3.82x | **2.56x** |

**Nearly a factor of two on every row.** The mechanism is visible in the same
data, by reading it the other way: what each path costs on one machine against
the other.

| cross-machine, laptop over desktop | |
|---|---|
| no-sweep core, **AES-NI** | **2.95x** |
| no-sweep core, **T-table** | **1.53x** |
| pad fill, AES-NI | 2.97x |
| pad fill, T-table | 1.51x |
| per step, AES-NI | 1.96x |
| per step, T-table | 1.52x |

**The T-table path is twice as uniform across machines as the AES-NI path is.**
Table lookups out of L1 scale with ordinary integer and cache performance, which
differs by about half between these two CPUs. The AES units differ by about
three, because Zen 4 retires roughly twice the `aesenc` per clock that Kaby Lake
does and is clocked higher on top of that.

**So the asymmetry is not a constant of the algorithm. It is the quality of the
CPU's AES unit, measured against a table lookup.** That is a sharper and less
comfortable statement than RESULTS.md 6.3's, which frames the risk entirely as
a card acquiring better AES. The other half of the risk is a network of CPUs
with weaker AES, and it needs nothing to happen.

**The honest figure for the gate is the low end, not the high one.** The gate
has to hold for the network as it is, not for the best machine in it, and this
project already treats the laptop as the machine that sets the spread. So v8's
AES gate is worth **4.9x on the core and 2.6x on a whole nonce**, and the 8.0x
and 3.8x in the header are what it is worth on a Zen 4.

**What survives unchanged.** Both conclusions in section 2 hold on the laptop:
the pad fill is 8.13x against the main loop's 1.82x, so the gate is still the
pad fill and pad size still sets it. And D1 still roughly doubles the asymmetry,
by 1.73x here against 2.03x on the desktop.

*Prediction, stated before the run and half wrong.* The expectation recorded was
that the ratios would come in lower on the laptop, with the per-step number the
one to watch, possibly falling toward 1.5x. The direction was right and the
per-step number did fall, to 1.82x. But the pad fill was described as the stable
algorithmic property, and it halved along with everything else. The part
predicted to move moved least, proportionally, and the part described as fixed
moved most.

### F60. The chain fill is not memory bound. It is 94% HC-128, and two thirds of it is key setup

F38 names one assumption as the honest weak point of the whole design, and
PLAN-v8-PHASE8 repeats it under "what would make this whole direction wrong":

> The pool resistance and the ASIC bound are the same argument, and both assume
> random-access database bandwidth is the binding constraint. A 236 MB working
> set is not large.

**It was never tested, and it is false.**

`contrib/powbench/t_v8_fill.cpp`, built by `build-v8-fill.sh`. Four arms over one
loop body, differing only in which index a pick returns. The cipher work is
identical in all four by construction: the selector draw happens whether or not
its branch is taken, and the hot arm computes a real index and discards it, so
no arm consumes a different amount of keystream than any other.

7950X, height 4,500,000, a 240 MB cache and a 5.3 MB window, as mainnet is.

| arm | ms/fill | vs floor |
|---|---|---|
| shipped, 13 of 256 full history | 0.7441 | 1.06x |
| window only, odds forced to 0 | 0.7201 | 1.03x |
| **one hot entry, memory removed** | **0.7019** | **1.00x** |
| all full history, odds forced to 256 | 0.9026 | 1.29x |

#### 1. Where the 0.744 ms goes

| | ms | share |
|---|---|---|
| **`HC128_Init`, 257 reseeds per nonce** | **0.5006** | **67.3%** |
| `HC128_NextKeys`, ~10,500 of them | 0.1642 | 22.1% |
| **memory, all 16,384 reads** | **0.0422** | **5.7%** |
| the XOR, the copies, the loop | 0.0371 | 5.0% |

The accounting closes to 0.1%, which is the main reason to believe it.

**The fill is a stream cipher being re-keyed 257 times per nonce.** The loop
reseeds every 16 messages, 256 times, plus once at the midpoint, and
`HC128_Init` runs the full P and Q expansion before it yields a usable word:
1.95 us, about 8,750 cycles, each time.

#### 2. Why this is not an artifact

**The HC-128 is byte-identical to the daemon's.** `diff contrib/powbench/hc128.c
src/crypto/hc128.c` is empty, so the floor is the real cipher and not a slow
copy of it.

**It agrees with the daemon by an independent route.** F52 put the 7950X fill at
~0.79 ms by subtracting two harnesses. This is a direct port and reads 0.744 ms,
within 6%, having been built from the source rather than from that number.

**The harness is not blind to memory.** Sweeping the chain height moves the
memory term exactly as it should, which is the control that makes a small
reading meaningful rather than suspicious:

| height | cache | memory share | all-history arm |
|---|---|---|---|
| 1,000,000 | 53 MB | 3.3% | 1.05x |
| 4,500,000 | 240 MB | 5.7 to 7.8% | 1.21 to 1.29x |
| 16,000,000 | 854 MB | 7.9% | 1.26x |
| 40,000,000 | 2,136 MB | 10.8% | 1.63x |

**Each read costs 12.2 ns** in the all-history arm, far under DRAM latency,
because the run-ahead issues 64 prefetches before touching any of them. The
memory-level parallelism is already extracted, by us, in A1. There is very
little left for an attacker to win, and that is the point: this is the residual
after the best optimisation we know, not an artifact of a lazy loop.

*Corrected by F82: about 40% of the all-history arm's increment is extra
HC-128 work from rejection sampling, not memory, because the hot arm draws at
the shipped odds. Memory at 100% full history is about 10% of the fill.*

**Even at 100% full-history draws the memory is 17 to 29% of the fill.** So D3,
raising `CNA_V6_FULL_HISTORY_ODDS`, cannot repair this. Its ceiling is too low
to matter, and that is now measured rather than assumed.

#### 3. What breaks, and what does not

**Pool resistance survives, and it survives for a reason worth being explicit
about.** It is a *correctness* requirement, not a cost one. A miner cannot
produce the right salt without the chain, however cheap the reads turn out to
be, so cheap reads do not let a pool hand out work. The feeder attack, where the
pool ships the 256 KB itself, is bounded by bandwidth and is unaffected by any
of this (F43, F46).

**The ASIC bound does not survive as stated.** Every such figure in this project
is `1 / (fill share)` on the premise that the fill is the part nobody can
specialise. Against this measurement:

| assumption | bound |
|---|---|
| the hash core is free, the fill is not | 1.78x, the plan's figure |
| the hash core **and HC-128** are free | **31x** |

The truth is between them and depends entirely on what HC-128 costs in silicon.
A 1024-word state updated by adds, XORs and rotates, re-keyed on a fixed
schedule, is close to the friendliest thing in this algorithm to put in
hardware, and the two thirds that is key setup is the most regular part of it.
**This is now the sharpest open question in the project**, and it is a better
question for Bento-Box than the one already sent.

*ANSWERED 2026-10-07, F65, and the guess in the paragraph above was right.* The
expansion half of the key setup is SHA-256's message schedule (F64) and prices
at **about 500,000x cheaper** in current silicon than in `hc128.c`. **It is the
31x row, not the 1.78x row**, and no outside opinion was needed. The sentence
"the truth is between them" is withdrawn: the truth is at the top of the range.
The consequence is in F65 section 3, and it is that this table's two rows are
really one question asked of two different machines.

**Against GPUs it may still be fine, for a reason nobody wrote down.** The
HC-128 state is `P[512] + Q[512]`, **4 KB per instance**. A 32-lane warp needs
128 KB of it, far beyond any shared memory, so on a card it has to live in
global memory with a per-lane access pattern. HC-128 is ASIC-friendly and
GPU-hostile at the same time, and the two pull in opposite directions. That
asymmetry is unmeasured and is the second question worth asking.

*Measured, F62, and then corrected, F64.* The asymmetry is real: 12.1x against a
GPU while being near-free in an ASIC. But the mechanism named here, the 4 KB
state, is only half of it. F64 section 2 shows the published GPU work reaches
**31 Gbps on HC-128** given 32,768 parallel streams, so the state size alone
does not stop a card. What stops it here is that **our fill re-keys 257 times a
nonce and never amortises a key setup**, which is the regime that paper never
enters. The 4 KB makes a setup expensive; the reseed count is what prevents it
being paid once.

#### 4. What F38's rule should say instead

> Work added to the hash core is work a specialised attacker can specialise.
> The chain fill is the part they cannot.

The second sentence is wrong, and the error is a conflation. **The fill does two
separate jobs: it costs time, and it binds the nonce to the chain.** The rule
assumes the cost is what provides the binding. It is not. The binding comes from
needing the right 16,384 blocks to get the right answer, and is intact and
cheap. The cost is a stream cipher, and is specialisable.

Everything built on "raise the fill's share" therefore needs rereading. Raising
the fill's share raises the share of HC-128, not the share of anything an
attacker struggles with. **D1 is a clean example**: it takes the fill from 56%
to 74% of a nonce, which the plan scores as tightening the ASIC bound from 1.70x
to 1.36x, but on this measurement it mostly raises the share of a stream cipher.

#### 5. A candidate that falls out of it, with its cost stated

If the fill should be memory bound, the lever is visible: **257 reseeds cost
67% of it**. Fewer reseeds would make the fill both cheaper to verify and more
memory bound, improving goals 1 and 4 together, which is the shape P1 asks for.

**But the reseeds are doing real work and it is not cost.** Each one keys
HC-128 from the output buffer, which depends on blocks already read, so a
reseed is a point where the attacker must have finished reading before it can
continue. 257 reseeds are 257 serialisation points against the data. Remove
them and the whole 256 KB of keystream depends only on the nonce, so it can be
produced before a single block is touched.

So this is a real trade and not a free win: **reseed count buys precomputation
resistance and sells both verification speed and memory-boundedness.**

The next three sections measure it, and the trade turns out to be avoidable:
the property the reseeds provide can be bought in a currency that is not a
stream cipher.

#### 6. Can it be improved? Yes, and the two levers are measured

Both on the 7950X, same harness.

**Lever 1, the reseed interval.** 257 reseeds are two thirds of the fill, so the
sweep says what they cost. It does not say what they are worth.

| reseed every | reseeds | ms/fill | vs shipped |
|---|---|---|---|
| 16 messages, shipped | 256 | 0.709 | 1.00x |
| 32 | 128 | 0.449 | 0.63x |
| 64 | 64 | 0.291 | 0.41x |
| 256 | 16 | 0.210 | 0.30x |
| once | 1 | **0.189** | **0.27x** |

**Lever 2, dependent reads.** Memory is 4 to 6% because A1's run-ahead issues 64
prefetches at a time, so each read costs 12.2 ns against a DRAM latency near
100. Chaining the reads, each index derived from the bytes at the previous one,
removes that parallelism by construction. Memory only, no cipher, best of 20:

| chains | ms | ns/read |
|---|---|---|
| 1, fully serial | 1.682 | **102.6** |
| 2 | 0.830 | 50.6 |
| 4 | 0.414 | 25.3 |
| 8 | 0.223 | 13.6 |
| 16 | 0.124 | 7.6 |
| 64 | 0.117 | 7.1 |

102.6 ns at one chain is DRAM latency, which is the check that the probe is
measuring what it claims. 7.1 ns at 64 chains is roughly where the shipped fill
already sits, which is the other end of the same check.

#### 7. The two levers are the same lever

**The reseed exists to make the index stream depend on data already fetched.**
It keys HC-128 from the output buffer, so an attacker cannot know which blocks
they need before reading the previous sixteen messages. That is a real property
and it is why the reseeds cannot simply be deleted.

**A dependent read chain provides exactly that property, directly.** Index `n+1`
comes from the bytes at index `n`. Today there is one dependency barrier per 64
reads; four parallel chains give one per 4 reads, which is **16x more
serialisation against the data**, not less.

So the chain subsumes the reseed's security function and pays for it in DRAM
latency instead of key setup. One is inherent and the other is the single most
ASIC-friendly thing in the algorithm.

Dropping to one reseed and adding a dependent chain, against today's 1.323 ms
nonce with its 0.744 ms fill:

| chains | fill | nonce | vs today | memory share of a nonce | ASIC bound |
|---|---|---|---|---|---|
| shipped | 0.744 | 1.323 | 1.00x | **2.2%** | **45.6x** |
| 1 | 1.870 | 2.449 | 1.85x | 68.6% | 1.5x |
| 2 | 1.019 | 1.598 | 1.21x | 51.9% | 1.9x |
| **4** | **0.603** | **1.182** | **0.89x** | **35.0%** | **2.9x** |
| 8 | 0.412 | 0.991 | 0.75x | 22.5% | 4.4x |

**At four chains the nonce is cheaper than it is today and the ASIC bound
improves roughly sixteenfold.** Verification gets faster, which is goal 4, while
the irreducible share goes from 2.2% to 35%. With D1 as well the nonce is
0.865 ms and the bound 2.1x.

That is the first candidate in this project that improves goals 1 and 4 together
by a large margin rather than a few percent, and it does so by **removing** code
rather than adding any.

#### 8. What is wrong with this, stated now

**The biggest one: latency is what a CPU pays and throughput is what an attacker
pays.** A dependent chain serialises one nonce. A device with thousands of
nonces in flight hides that latency completely and is then bound by random-read
throughput, not by the 102.6 ns. A CPU miner with 30 threads is already near its
own limit for outstanding misses, so it does *not* hide it as well. **The lever
may therefore cost the honest CPU more than it costs the attacker**, which is
the exact failure mode F38's rule exists to catch, arriving from a new
direction. What decides it is random-read throughput per dollar on GPU and ASIC
memory against CPU memory, and that is unmeasured.

This does not make the change wrong. Today's cost is HC-128 key setup, which is
unambiguously cheap in silicon; DRAM traffic is at worst ambiguous. Trading an
known-bad cost for an uncertain one, while getting faster verification, is still
the right direction. But it is not the slam dunk the table above looks like, and
the table should not be quoted without this paragraph.

**It needs a v14-only fill.** `get_cna_v6_data` has validated every block since
4,320,000, so this forks it permanently and doubles the consensus-critical
surface. PLAN-v8-PHASE8 D2 declines that cost for a smaller gain and is right
to; the gain here is much larger, but the cost is the same and it is forever.

**It conflicts with the window, but less than this document first said.**
*Corrected by F61:* measured in the daemon against real blocks, drawing from
full history costs **1.30x on the fill, +0.311 ms per block**, which is about
34 seconds across every block above the assume-valid height. The window is not
load-bearing for sync speed at today's chain length. The paragraph below stands
as the mechanism; its weight does not.

The 102.6 ns assumes every read is drawn over
the whole 240 MB. The shipped distribution puts 95% in a 5.3 MB window that is
cache-resident by design, and a chain through that window would be fast and
would buy nothing. Getting the latency means drawing from full history, which is
what the window was introduced to avoid. The window exists for sync speed, and
the table above shows sync speed improving anyway, so the two may be reconcilable
rather than opposed, but it is a deliberate reversal of an earlier decision and
should be argued rather than slipped in.

**The cost grows with chain length** and nobody has decided whether that is
wanted. The height sweep in section 2 shows the all-history arm going from 1.05x
to 1.63x between 1M and 40M blocks. Difficulty absorbs it, but verification
grows too.

### F61. The 100,000-block window is worth 1.30x on the fill, measured in the daemon against real blocks

F60 section 6 put the fill's full-history penalty at 1.13x from a standalone
harness and noted that a harness cannot see the rest of the daemon competing for
cache. This is the same question asked in the daemon, verifying real mainnet
blocks.

**Method.** `NERVA_SALT_ODDS_AB` in `get_cna_v6_data` runs **two shadow fills**
per block, identical code, differing only in `CNA_V6_FULL_HISTORY_ODDS`, both
written to a scratch buffer and discarded. Both arms are shadows rather than one
shadow against the real fill, so the comparison cannot pick up a difference in
anything else, and the order alternates per call so drift cancels. The real fill
runs from the real cipher state and leaves the real state behind, so the chain
validates normally with the switch on.

Verified non-invasive: `NERVA_SALT_SELFCHECK` passed **64 of 64** with zero
digest or cipher-state disagreements during the run.

7950X, 4,000 blocks popped from the tip and re-verified from the network, chain
at 4,430,890, cache 248 MB, machine otherwise idle.

| | cycles/block | ms at 4.491 GHz |
|---|---|---|
| windowed, 13 of 256 | 4,629,700 | 1.031 |
| all full history | 6,024,460 | 1.341 |
| **ratio** | **1.3013** | **+0.311 ms** |

Stable to 0.1% across 1024, 2048 and 3072 samples: 1.3027, 1.3009, 1.3013.

#### What it changes

**The harness understated it by about 15%, as predicted, and no more.** 1.13x
standalone against 1.30x in the daemon. There is a real system-level component
from validation competing for cache, and it is small. The daemon's windowed fill
also costs 1.03 ms against the harness's 0.73 ms, which is the same effect seen
on the absolute figure.

**Drawing from full history is affordable.** Above the assume-valid height it is
+0.311 ms on about 110,000 blocks, roughly 34 seconds of extra sync, and for a
node at the tip it is 0.311 ms per minute. **The window is not load-bearing for
sync speed at today's chain length.** That removes the scaling objection raised
against D5 in PLAN-v8-PHASE8, though D5 still depends on the dependent-chain
cost and on the unanswered throughput question.

#### A correction to F60, and it is mine

F60 section 8 and the D5 entry said the window was protecting against something
large and unidentified, on the grounds that the fill's own penalty was ~2% of
the 3.7x cliff in the April 2026 sync logs. **That compared two different
things.**

The April 2026 measurement predates the window by two months: it is
`get_cna_v5_data` with uniform full-history reads, and its 3.7x is **the same
fill getting slower as the block cache outgrew L3**. It is not windowed against
full-history, which is what this entry measures. There was never an unexplained
gap; there was a mismatched comparison.

#### The operational lesson, which cost more than the measurement did

**`MGINFO` is invisible at Nerva's default log level.** The daemon's categories
are

    *:ERROR,net:FATAL,net.http:FATAL,net.p2p:FATAL,net.cn:FATAL,user:INFO,
    verify:FATAL,stacktrace:INFO,logging:INFO,msgwriter:INFO

`MGINFO` logs to `global`, which is covered by `*:ERROR`, so it is dropped.
`--log-level 0`, `1` and `2` all leave that list unchanged. The sync progress
lines that *are* visible come through `msgwriter`, which is why the log looks
healthy while every instrumented switch reports nothing.

**Run any measurement switch with `--log-level "global:INFO"`.** This applies to
`NERVA_SALT_AB` (F57) and `NERVA_SALT_SELFCHECK` as much as to this one; F57 was
taken on the mining path, so the sync path had never exposed it.

The failure mode is nasty because it is indistinguishable from the code never
running. Hours went into chasing why `get_cna_v6_data` was "never called",
including instrumenting `block_needs_pow` and `add_new_block`, when PoW had been
running on every block the whole time. The probes that finally showed it
(`needs_pow=1 precomputed=0`) only printed once the category was set, which is
the same lesson arriving twice in one session.

*Second-order lesson:* `pop_blocks` followed by a re-sync **does** re-verify PoW
in full, through `add_new_block` to `handle_block_to_main_chain`, with
`precomputed=0`. That was doubted during the above and the doubt was unfounded.
It is a sound way to force verification of real blocks on demand.

### F62. A GPU beats a CPU at the fill's memory access and loses 12x at its cipher, so D5 would trade the fill's only anti-GPU property away

PLAN-v8-PHASE8 D5 proposes chaining the fill's reads and deleting 255 of the 257
reseeds. The objection on record was that a dependent chain serialises one nonce
while an attacker runs thousands, so it might cost the honest CPU more than the
attacker. That was waiting on an outside opinion. It did not need one.

The objection reduces to two rates, because every device needs 16,384 random
reads and 257 inits plus ~10,500 keystream blocks per nonce whatever the design.
Both are measured here on the same machine, against an **RTX 3050** and a
**7950X capped at 30 threads**.

`contrib/powbench/t_gather.cpp` and `t_hc128.cpp`, both using the existing
`clmin.h` runtime loader, so no OpenCL SDK is needed.

#### 1. Random gather: the GPU wins

| table | CPU peak reads/s | GPU peak reads/s | GPU / CPU |
|---|---|---|---|
| 224 MB, mainnet today | 2.42e9 | 3.97e9 | **1.64x** |
| 896 MB | 1.39e9 | 2.45e9 | 1.77x |
| 3.5 GB, nothing caches | 8.70e8 | 2.38e9 | **2.73x** |

The gap widens as the chain grows, because the CPU loses its cache and the GPU
has little to lose. At 3.5 GB the absolutes check out as fractions of peak
bandwidth: 56 GB/s for the CPU against DDR5's ~83, and 76 GB/s for the card
against its ~224. At that size the GPU curve is **flat across every work-item
count**, which is the signature of a bandwidth-bound measurement and the check
that the number is real.

*At 224 MB the CPU rate implies 150 GB/s, which exceeds DDR5 dual-channel.* That
is not an error: a 7950X holds roughly a third of a 224 MB table in its 96 MB of
cache. It is a true property of the chain today and it is why the sweep matters.

*Corrected 2026-10-07, F66.* **The work-item sweep behind this table was too
short and these GPU figures are floors.** At 224 MB the peak sat at 4,096 items,
the lowest tested, so the curve was still rising below the range; the sentence
above about it being "flat across every work-item count" is true at 3.5 GB and
false here. Extending the sweep to 256 items puts **224 MB at 1.98x rather than
1.64x**. The composed whole-fill figure in section 3 moves only from 10.5x to
10.4x, because gather is small beside HC-128, so every conclusion below stands.
F66 also measures the sizes this table never reached: at **window size a card is
5.65x to 6.91x better**, which is the regime 94.9% of the fill's reads are
actually in.

#### 2. HC-128: the GPU loses, badly

| | CPU (30 threads) | GPU (8,192 items) | GPU / CPU |
|---|---|---|---|
| rounds/s, 1 init + 40 NextKeys | 6.310e6 | 5.215e5 | **0.083x** |

**The CPU is 12.1x faster.** The cause is the one F60 section 3 guessed at: the
state is `P[512] + Q[512]`, **4 KB per instance**, so a 32-lane warp would need
128 KB and cannot use shared memory at all. The kernel keeps each item's state
in global memory, which is what a miner would have to do.

*Corrected 2026-10-07, F64 section 2.* The number reproduces, at 12.4x on a
re-run with the same work-item sweep. **The stated cause is incomplete and the
missing half is the more important one.** Published work gets HC-128 to 31 Gbps
on a card with 32,768 parallel streams, so the 4 KB state is not by itself
disqualifying. It is disqualifying *here* because this fill re-keys every 16
messages and so pays a full `HC128_Init` for 76% of its work, where that paper
amortises the setup away over a long message. **The gate is the reseed
frequency**; the state size is what makes each reseed cost something. Also note
12.4x is an upper bound: this kernel is a verified transcription, not an
optimised one.

Two checks that this is a real number and not a bad port:

- **The kernel agrees with `src/crypto/hc128.c` bit for bit** before any timing
  runs, and refuses to report if it does not.
- The CPU arm independently reproduces F60's decomposition: 2.57 us per round
  here against F60's 1.95 us per init plus 40 x 15.6 ns, from a different
  harness.

#### 3. What the fill is actually made of, as a defence

Combining, per fill (257 rounds of HC-128 and 16,384 reads):

| | CPU | GPU | ratio |
|---|---|---|---|
| HC-128 portion | 40.7 us | 492.9 us | 12.1x worse |
| gather portion | 6.8 us | 4.1 us | 1.64x better |
| **whole fill** | **47.5 us** | **497.0 us** | **10.5x worse** |

**So the chain fill is a strong anti-GPU gate, and the mechanism is HC-128, not
memory.** F38's rule said the fill is the part an attacker cannot specialise and
attributed that to random-access database bandwidth. The conclusion was right
and the reason was wrong: memory is the half a card is *better* at.

That also makes HC-128 a **stronger** GPU gate than the AES. F59 put the
AES-NI against T-tables asymmetry at 4.9x to 8.0x; this is 12.1x.

#### 4. D5 is a regression on goal 1, quantified

D5 removes the inits, which are 76% of a round, and adds dependent gather.
Both halves of what it trades are now measured:

| | CPU fill | GPU fill | GPU disadvantage |
|---|---|---|---|
| today | 0.744 ms | 8.50 ms | **11.4x** |
| after D5, 4 chains | 0.603 ms | 2.54 ms | **4.2x** |

**D5 cuts the fill's GPU disadvantage by 2.7x.** Carrying it to a whole nonce
with F59's AES penalty gives roughly 9x today against 5x after, so D5 costs
about **1.8x of v8's GPU resistance** to buy a cheaper nonce and a tighter ASIC
bound.

That is a real trade rather than the free win the plan describes, and it points
the opposite way to PLAN-v8-PHASE8's framing. **D5 should not be built as
specified.**

#### 5. What this does not settle

One card, and a low-end one. An RTX 4090 has about 4.5x this card's bandwidth,
which would widen section 1's gather gap and narrow nothing in section 2, since
HC-128 is bound by per-lane state rather than bandwidth. A better GPU programmer
might beat my kernel; 4 KB per lane is a hard constraint, not an implementation
detail, but a factor of two or three there would still leave the card far
behind.

The whole-nonce figures in section 4 carry F59's AES penalty, which is a CPU
T-table proxy rather than a measured GPU number. The fill figures do not depend
on it.

An ASIC is not here and is not implied: HC-128's 4 KB is nothing in silicon, so
section 2's gate is specific to GPUs. F60's ASIC bound stands unchanged.

### F63. v8's own pad curve is 2x, not the 8.7x first measured, and three ways a GPU bench lies

F62 established that a GPU is better than a CPU at the fill's gather and 12.1x
worse at HC-128. The obvious follow-up was pad size, since a bigger pad means
fewer nonces resident on a card. **Every number this entry first produced was
wrong, in the favourable direction, and the corrections are more useful than the
result.**

`contrib/powbench/main.cpp` gained `v8 2MB` and `v8 4MB` rows. **v8's pad curve
had never been measured**; PLAN-v8-PHASE8's argument for growing the pad was
carried over from v5's curve in RESULTS.md, and v8's turns out to be much
flatter.

#### 1. The result

Vega FE, 5600X host, `vram=90 cap=60`, the only run where the 4 MB row was not
starved. Within-machine, which is the only transferable form (see section 3):

| pad | GPU slowdown | CPU slowdown | **pad's value** |
|---|---|---|---|
| 1 MB | 1.0x | 1.0x | baseline |
| 2 MB | 2.33x | 1.59x | **1.46x** |
| 4 MB | 6.45x | 3.30x | **1.96x** |

2 MB reproduces across every run and both vendors at **1.40x to 1.53x**. 4 MB is
**1.96x**, and it costs 2.4x verification: 1.92 ms to 4.62 ms single-threaded.

**Pad size is not the dominant GPU lever.** It is worth about 2x at 4 MB, which
is comparable to the other dials and smaller than this project believed when it
reopened the question.

#### 2. What the first numbers said, and why they were wrong

| run | card | 4 MB reads as |
|---|---|---|
| RTX 3050, `vram=50 cap=25` | 8 GB | 8.70x |
| RTX 3050, `vram=90 cap=25` | 8 GB | 5.14x |
| Vega FE, `vram=50 cap=25` | 16 GB | 8.65x |
| **Vega FE, `vram=90 cap=60`** | 16 GB | **1.96x** |

The 8.7x was reproduced on two unrelated GPUs, which felt like confirmation and
was not: both were hitting the same wall. **The 4 MB row was starved by the
launch cap**, running 448 nonces against a 25 s ceiling. Given 60 s it ran 1,728
nonces and its rate went 19.5 to 75.3 H/s, a factor of 3.9 that came from
nothing but being allowed to run.

RESULTS.md section 7 already warned that capped rows are starved and that
"magnitudes are floors". That warning was read and then not applied.

#### 3. Three ways this harness misleads, all hit in one session

**The launch cap starves exactly the rows under test.** The cap is per launch
and exists so a display-attached card does not trip the driver timeout. A
bigger pad makes each nonce slower, so the batch that fits the cap shrinks, so
occupancy collapses, so the GPU looks worse *because the pad is bigger*. That is
the measurement arguing for its own hypothesis. **Divide nonces by GPU H/s: if
it is near the cap, the row is a floor and not a measurement.**

**Absolute GPU:CPU is a property of the pairing, not the algorithm.** v8 at 1 MB
reads 0.0525x on a 7950X with an RTX 3050 and 0.1455x on a 5600X with a Vega,
3x apart for identical code. Only the within-machine ratio of slowdowns
transfers, because there the hardware cancels. **Every cross-machine comparison
of the raw column in this file and in RESULTS.md is suspect**, including the
claim this entry started from, that v8 is 4x less GPU-resistant than live v13.
*That claim is withdrawn as unestablished.* It may be true; this data cannot
show it.

**The CPU side silently changes thread count with pad size.** The harness chose
12 threads at 1 MB, 9 at 4 MB and 3 at 8 MB on the Vega, because pad x threads
has to fit L3. On the 3050 the same 4 MB row ran at 16 threads in one run and 24
in the next, and 24 threads gave *half* the throughput of 16 while per-thread
cost was identical. Since GPU:CPU divides by that figure, **every large-pad row
understates the CPU**, and `v6 8MB` at 3 of 12 threads is not interpretable at
all.

#### 4. The run that drifted, and the control that said so

`cap=60` is several minutes of near-continuous full load per row: a sizing ramp
of up to 4 launches, then `GPU_REPS = 3` timed launches, then the CPU passes.
Six rows is 18 to 20 minutes.

The paired control caught the cost: `v5 1MB` at the start and end of the run
read 1.2% apart at `cap=25` and **3.8% apart at `cap=60`**, the card losing
performance monotonically as it heated. The 1.96x result is well clear of 3.8%
and stands, but nothing smaller than about 4% from that run should be believed.

**If a longer run is needed, raise the cooldown, not the cap.** And read the
control pair first, every time.

#### 5. What it leaves

The pad question is answered and the answer is "not much": about 2x at 4 MB for
2.4x verification. More useful is what it implies with F62. The component
ratios are HC-128 12.1x, AES roughly 6x, gather 0.6x against us, divergence
1.9x, and a whole nonce lands near 9x.

*VOID, 2026-10-07 later the same day. Every input to this paragraph was wrong.*
HC-128 is **6.04x** (F76: the work-item grid skipped the peak), the core is
**64.9x** (F77: B3 ran, and the AES term here was a CPU proxy), and a whole
nonce measures **18.8x** rather than composing to 9x. The ceiling argument below
is kept for the shape of the reasoning, which is sound, and for none of its
numbers.

**An average cannot exceed its largest
term, so rebalancing v8's existing parts is bounded by HC-128's 12.1x, and v8 is
already at about three quarters of that.**

So pad size, salt size and reseed count are all fractions of a factor. Moving
meaningfully past 12x needs a component more GPU-hostile than HC-128, which is a
design question rather than a tuning one. The ~6x AES term is the weakest link
in that arithmetic, being F59's CPU T-table proxy rather than a measured GPU
number, and measuring it on a card with the `t_hc128` pattern would turn both
the 9x and the 12x into real figures.

*Two qualifications added 2026-10-07.* **This ceiling is about GPUs only, and
must not be read as an ASIC statement.** F65 prices HC-128's expansion at around
500,000x cheaper in silicon, so against an ASIC there is no 12x ceiling and no
cipher term at all; the only bound is the fill's random reads. The arithmetic
above stands for cards and nothing else. Second, F64 shows 12.4x is an **upper
bound** on the GPU gate, since the kernel behind it is a verified transcription
rather than an optimised implementation, so "three quarters of the way to the
ceiling" is the optimistic reading of a ceiling that may itself be lower. One
line above does survive both: **reseed count is not a fraction of a factor.**
F64 makes it the mechanism of the GPU gate rather than a tuning dial.

### F64. HC-128's key setup is SHA-256's message schedule, and the published GPU win does not reach our fill because we never amortise a key setup

*2026-10-07. Opening the silicon question F60 calls the sharpest one in the
project: the ASIC bound is 1.78x if HC-128 is expensive in hardware and 31x if
it is free, and nothing had been done to narrow a 17x spread.*

Two results. The first is structural and points the wrong way for us. The second
is a challenge from the literature to F62's 12.1x, which the whole ceiling
argument rests on, and it survives for a sharper reason than F62 gave.

#### 1. `HC128_Init`'s expansion is literally SHA-256's message schedule

Read off [hc128.c:135](../../src/crypto/hc128.c#L135):

    f1(x) = ROTR32(x,7)  ^ ROTR32(x,18) ^ (x >> 3)
    f2(x) = ROTR32(x,17) ^ ROTR32(x,19) ^ (x >> 10)
    P[i]  = f2(P[i-2]) + P[i-7] + f1(P[i-15]) + P[i-16] + i

SHA-256 defines `sigma0(x) = ROTR7 ^ ROTR18 ^ SHR3` and
`sigma1(x) = ROTR17 ^ ROTR19 ^ SHR10`, and expands its message as
`W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16]`. **These are the
same two functions and the same recurrence**, the only difference being the
added index. Crypto++'s HC-128 carries `f2` in exactly that form, which is a
second pair of eyes on the identification.

`HC128_Init` runs 256 + 496 + 16 + 496 = **1,264 of them**, then 1,024 warm-up
cipher steps. At 257 inits per nonce that is **324,848 SHA-256 message-schedule
steps per nonce.**

**This is the single most ASIC-optimised primitive in existence**, and two
thirds of our fill's cost is built from it. In hardware the rotations and shifts
are wiring and cost nothing; what is left is two XOR trees and three 32-bit
adds. The dependency is only `P[i-2]`, so there are two independent chains and
the critical path is about 632 deep rather than 1,264.

That is evidence toward the **31x** end, which is the bad end. It is not proof,
because the bound depends on throughput per unit area and not on how familiar
the primitive is, and the rest of this entry is why the picture is not settled.

#### 2. The published GPU result says a card wins, and it does not apply here

*Corrected by F80: the inference in this section, that the reseed frequency is
the gate, came from a kernel that consumed one keystream word in sixteen. With
all sixteen, keystream is as GPU-hostile as key setup and the reseeds buy about
1.04x.*

Khalid, Bagchi, Paul and Chattopadhyay (2013) report HC-128 on a GTX 590 at
**0.95 Gbps on a single data stream against a CPU's 10.9 Gbps**, and then
**about 31 Gbps once 32,768 data streams run in parallel**. Taken at face value
that is a GPU beating a CPU by 2.8x at the primitive F62 calls our strongest
anti-GPU gate, and it would invert F62, the ceiling argument and the rejection
of D5 together.

So `t_hc128` was re-run. It already sweeps work-item counts, which is the check
F63 says to apply, and the sweep is the answer:

| work items | rounds/s | against CPU's 6.107e6 |
|---|---|---|
| 1,024 | 3.431e5 | |
| **8,192** | **4.923e5** | **12.4x worse** |
| 32,768 | 2.074e5 | 29x worse |
| 131,072 | 1.929e5 | 32x worse |

**The card peaks at 8,192 items and gets worse from there**, so the paper's
32,768-stream regime is where our kernel is already 29x down. F62's 12.1x
reproduces at 12.4x, and the kernel re-verified bit-identical against
`src/crypto/hc128.c` (`9af7dcfb`) before timing.

**The reconciliation, and it is the useful part.** *This is inference from what
the paper measures, not a statement it makes.* Its figures are keystream
throughput in Gbps, which is a rate over message length, so a key setup is paid
once and amortised away. Our fill re-keys every 16 messages of 64 bytes, 257
times per nonce, so by F60 **76% of a round is `HC128_Init` and none of it ever
amortises**. The paper's good regime is one the fill structurally never enters.
What would refute this is a figure for HC-128 keystream throughput *including*
per-message re-keying, which no source found here reports.

So the anti-GPU property is **not the 4 KB state on its own**, which is what F62
and the standing memory both say. It is the **reseed frequency**, which keeps
the cipher permanently in its setup phase where the state is being written
rather than streamed. The 4 KB matters because it makes a setup expensive; the
257 reseeds are what stop anyone amortising it. That is a sharper claim than
F62's and it says the reseeds are load-bearing for goal 1 as well as for the
serialisation F60 identified.

#### 3. The hardware numbers that exist, and what they do not answer

- Chattopadhyay, Khalid, Maitra and Raizada, ISCAS 2012, report an HC-128
  accelerator at **22.88 Gbps in 65 nm**, the fastest at the time.
- A follow-up achieves **one keystream word per cycle** by splitting P and Q
  across several SRAMs for parallel access, so the state dependency is not a
  fundamental barrier in hardware the way it is on a GPU.

Both measure **keystream**, which is the regime section 2 just showed we never
reach. 22.88 Gbps is 7.15e8 words/s, and a nonce needs 65,536 words, so pure
keystream for a nonce is about 92 us against a 7950X thread's 744 us whole fill.
Fast, but it is answering the amortised question.

**What is still missing is the one number that decides this: how many cycles a
key setup takes in hardware.** Our CPU pays about 8,750 cycles. A one-word-per-
cycle design would pay roughly 1,264 expansion words plus 1,024 warm-up steps,
order 2,300 cycles, which at a plausible clock makes a single hardware unit
**comparable to a single CPU core on our init-dominated workload**. If that
holds, the attacker's only lever is replication, and replication costs 4 KB of
SRAM per nonce in flight and then runs into the 16,384 random reads per nonce
that F62 measured.

That is the shape of the answer and it is not yet a number. The paywalled
state-splitting paper is the likely source; the ISCAS 2012 one is the other.

#### 4. One caveat on our own 12.4x

The GPU kernel is a transcription verified bit-identical, which makes it
*correct*, not *optimal*. The paper's authors optimised theirs and had access to
layout tricks ours does not use. **12.4x should be read as an upper bound on the
gate**, and a competent GPU implementer would narrow it. The direction survives
because of section 2's amortisation argument, which is structural and does not
depend on either kernel's quality.

#### 5. Sources

- HC-128 specification, Hongjun Wu:
  <https://personal.ntu.edu.sg/wuhj/research/hc/hc128.pdf>, and the project page
  <https://www3.ntu.edu.sg/home/wuhj/research/hc/index.html>
- Khalid, Bagchi, Paul, Chattopadhyay, *Optimized GPU Implementation and
  Performance Analysis of HC Series of Stream Ciphers*, 2013. IACR ePrint
  <https://eprint.iacr.org/2013/059> (free; the title, authors and all three
  throughput figures above were read from this record). The GTX 590 attribution
  comes from the hgpu listing <https://hgpu.org/?p=8899> rather than the
  abstract, which does not name the device.
- Chattopadhyay, Khalid, Maitra, Raizada, *Designing High-Throughput Hardware
  Accelerator for Stream Cipher HC-128*, ISCAS 2012, 22.88 Gbps in 65 nm:
  <https://publications.rwth-aachen.de/record/206990> and
  <https://pure.qub.ac.uk/en/publications/designing-high-throughput-hardware-accelerator-for-stream-cipher-/>
- *One Word/Cycle HC-128 Accelerator via State-Splitting Optimization*,
  SPACE 2014: <https://doi.org/10.1007/978-3-319-13039-2_17>. **Paywalled and
  not read.** Only its abstract's claims are used here, via
  <https://pure.qub.ac.uk/en/publications/one-wordcycle-hc-128-accelerator-via-state-splitting-optimization/>
- Crypto++ carries HC-128's `f2` in the SHA-256 sigma1 form, a second reading of
  the identification in section 1:
  <https://www.cryptopp.com/docs/ref850/hc128_8cpp_source.html>

### F65. The expansion half of the chain fill is 500,000x cheaper in current silicon, so the fill is cipher-bound on a CPU and memory-bound on an ASIC

*2026-10-07, answering F60's "sharpest open question in the project" without a
paper and without Bento-Box. `contrib/powbench/bitcoin-proxy.py`.*

F64 established that `HC128_Init`'s expansion is SHA-256's message schedule.
That primitive does not need a synthesis run to price, because **it has a public
competitive market**: Bitcoin miners are sold on joules per hash, and the
schedule is a fixed fraction of a hash.

#### 1. The method

Frontier hardware in 2026 is about **9.5 J/TH** (Antminer U3S23H, 1,160 TH/s at
11,020 W; mainstream parts sit at 12 to 13.5, per
<https://hashrateindex.com/blog/top-10-bitcoin-mining-asic-machines-for-2026/>).
Using a frontier part is the conservative choice here: it makes the attacker as
strong as the market allows, and a mainstream 13.5 J/TH part would only lower
the ratio by a third, which does not move an order-of-magnitude conclusion. One
Bitcoin nonce is two SHA-256
compressions once the first 64 header bytes are reused as a midstate, and each
compression is 48 schedule steps against 64 main rounds. Weighting those by
32-bit gate equivalents, with rotations and shifts free because they are wiring,
puts the schedule at **24.0%** of a compression.

That gives **2.37e-14 J per schedule step** in current silicon. Nerva pays
1,264 of them per init and 257 inits per nonce, so **324,848 per nonce**.

#### 2. The result, from two independent directions

| | CPU, 7950X at 30 threads | 2026 ASIC | ratio |
|---|---|---|---|
| per schedule step | 1.22e-8 J | 2.37e-14 J | **514,606x** |
| per nonce, expansion only | 4.08e-3 J | 7.71e-9 J | **528,930x** |

The two routes share no intermediate quantity: the first divides 8,750 measured
cycles per init by step count against per-core-cycle energy, the second takes
F57's 11,782 H/s at 230 W and F60's share table. **They agree to 3%.**

**The control is what makes it believable.** The same arithmetic says an ASIC
beats this CPU at Bitcoin itself by 16,140x. Our figure is 32x larger, and it
should be: `hc128.c` computes the schedule with general-purpose integer ops at
3.8 cycles per step, while the Bitcoin comparison lets the CPU use SHA-NI. A
32x gap is the SHA-NI speedup, which is the right size.

So the answer, to an order of magnitude, is **10^5, and the honest reading is
that the expansion phase provides no ASIC resistance whatsoever.**

#### 3. The fill has a different composition on each machine

This is the part that matters, and it reconciles F38 with F60.

F60 measured the fill at **94% HC-128 and 5.7% memory** and concluded the fill
is not memory bound. That measurement is correct **and it is a property of the
CPU**. Make the cipher 10^5 times cheaper and the same fill becomes almost
entirely memory on the attacker's machine.

| | cipher | memory |
|---|---|---|
| on a 7950X, measured, F60 | 94% | 5.7% |
| on Bitcoin-class silicon | ~0% | ~100% |

**F38 and F60 were both right, about different machines.** F38 said the fill's
protection is random-access database bandwidth; F60 said the fill's *cost* is a
stream cipher. Both hold, because cost and protection live on different
hardware. F60's retraction of F38 went one step too far, and this is the step
back.

**So the ASIC bound is F60's 31x case, not its 1.78x case**, and 31x is itself
optimistic for us because it assumes the attacker's memory runs no faster than a
CPU's, when F62 measured even a consumer GPU doing the gather 1.64x to 2.73x
better.

#### 4. What this closes

**The synthesis route is no longer worth doing.** The remaining unpriced half is
the 1,024 warm-up steps, and it cannot rescue the conclusion: it would have to
be some five orders of magnitude harder than the expansion to move the answer,
and the state-splitting literature reports HC-128 at one keystream word per
cycle. Either the warm-up is also cheap, in which case the cipher vanishes
entirely, or it is merely expensive, in which case the cipher still collapses
far enough for memory to bind. A day of Verilog would refine a number that does
not change a decision.

**D1's ASIC-bound claim is void as stated.** Taking the fill from 56% to 74% of
a nonce "tightens the bound from 1.70x to 1.36x" is arithmetic on the CPU's
composition. On the attacker's composition it moves nothing, because what it
raises is the share of a primitive the attacker gets for free. D1's real case is
the 1.313x verification speedup, which is goal 4 and is measured and solid.

**What actually defends v8 against an ASIC is the 16,384 random reads into a
database that grows**, which is F38's original claim, now the only one standing.
The reseeds remain load-bearing against GPUs for F64's amortisation reason, but
that is a different machine and a different argument.

### F66. The window is a GPU gift too, F62's gather figures were truncated, and P5 was wrong without moving the criterion it was written for

*2026-10-07, the first measurement under [D3-ODDS-PREREG.md](D3-ODDS-PREREG.md),
run after that file was committed and signed at 82306c4. Raw output in
`D:\Claude\gather\`.*

The prereg's P5 predicted a GPU would be relatively **worse** at window-sized
reads, because 5.3 MB is L3-resident on every CPU in the table and does not fit
an RTX 3050's 2 MB L2. **It is the opposite, and by a wide margin.**

#### 1. The gather curve, which had only ever been sampled at its far end

`t_gather` with `g_log2_entries` swept, 7950X at 30 threads against an RTX 3050.

| table | GPU / CPU |
|---|---|
| **3.5 MB, window-sized** | **5.65x to 6.91x** |
| 7 MB | 4.61x |
| 14 MB | 3.98x |
| 28 MB | 1.05x |
| 56 MB | 1.77x |
| **224 MB, mainnet today** | **1.98x** |

**A card is roughly three times more dominant at window size than at full-chain
size.** The window was introduced to keep 95% of reads cache-resident for a
syncing node. It does that, and it hands the same residency to every attacker:
block RAM on an FPGA, and the regime where a GPU is strongest.

The 3.5 MB row is quoted as a range because the CPU side moved 17% between two
runs there, being cache-resident and sensitive to machine state. The 224 MB row
moved 1.2% and is the trustworthy one.

#### 2. F62's gather numbers were taken at a truncated sweep

Caught by the prereg's own void list, which was written before any of this ran:
*"a peak that sits at the end of the swept range means the range was too short."*

Three of six sizes peaked at **4,096 work items, the lowest value tested**,
including 224 MB, which is F62's headline. F62 states that curve is "flat across
every work-item count, which is the signature of a bandwidth-bound
measurement." **At 224 MB it is not flat, it decreases monotonically**, so the
peak lay below the swept range and the figure was a floor rather than a
measurement.

Re-running with the sweep extended to 256 items, all peaks interior:

| | F62 | corrected |
|---|---|---|
| gather at 224 MB | 1.64x | **1.98x** |

So **F62 understated the GPU by 21% on this axis.** Its composed whole-fill
figure barely moves, 10.5x to 10.4x, because gather is a small term beside
HC-128, so the conclusion stands and the input was wrong. `t_gather`'s item
array now starts at 256.

This is F63's launch-cap trap wearing different clothes, in the same harness
family, three weeks after that lesson was written down. The difference is that
this time a pre-registered void condition caught it instead of a reviewer.

#### 3. P5 was wrong by a factor of 8 and C-7 did not move

| | prereg arithmetic | with measured ratios |
|---|---|---|
| assumed window ratio | 1.5x against the GPU | **0.177x**, i.e. 5.65x for it |
| fill GPU resistance, odds 13 to 256 | 11.49x to 9.55x | 11.43x to 9.52x |
| **C-7 regression** | **-17%** | **-17%** |

**An input was wrong in direction and by eightfold, and the criterion built on
it did not shift by a point.** The reason is worth keeping: on the GPU side the
whole memory term is 10.8 us against 8,504 us of HC-128, so what a card does
with the reads is noise. The regression is not about the GPU being good at
memory. **It is that raising the odds slows the honest CPU's fill by 1.21x while
slowing the GPU's by 1.011x.**

That reframes C-7. The cost is not "we hand a card the part it is better at",
it is "we pay 21% and the attacker pays nothing". Same number, different reason,
and the different reason is the one that generalises to the other candidates.

#### 4. Where D3 stands after one measurement

**C-7 passes at the maximum candidate, with 3 points of margin against a 20%
threshold.** That is tighter than it looks, since the composition carries the
modelling caveat recorded in the prereg, and intermediate candidates will cost
less. Nothing else is settled: C-2's fairness cost is the next and larger
question and needs the laptop.

### F67. Raising the full-history odds costs almost nothing in fairness, and three of the five pre-registered predictions were wrong

*2026-10-07, the second and decisive measurement under
[D3-ODDS-PREREG.md](D3-ODDS-PREREG.md), committed and signed at 82306c4 before
any of this ran. `t_v8_fill` extended from four arms to seven, same static
binary on both machines. Raw output in `D:\Claude\fill\` and
`D:\Claude\NervaResults\laptop_fill_0*.PNG`.*

#### 1. The measurement

Seven arms interleaved A-B-C-D-E-F-G-G-F-E-D-C-B-A in one process, 40 s,
height 4,500,000, 240 MB cache, 5.3 MB window. Two runs per machine. The 7950X
pair agree to **0.27%** and the i7-7700HQ pair to **1.52%**, both inside the
pre-registered 4% void threshold.

| odds | fill, 7950X | fill, 7700HQ | fill spread | nonce spread (C-2) | honest cost (C-3) | gain (C-1) |
|---|---|---|---|---|---|---|
| **13, shipped** | 0.7050 | 1.2993 | 1.843x | 2.171x | 1.000x | 1.0x |
| 32 | 0.7251 | 1.3507 | 1.863x | 2.177x | 1.018x | 2.4x |
| 64 | 0.7527 | 1.4220 | 1.889x | 2.185x | 1.043x | 4.7x |
| **128** | 0.7940 | 1.5163 | 1.910x | **2.188x** | **1.075x** | **9.2x** |
| **256** | 0.8339 | 1.6899 | 2.027x | **2.247x** | **1.136x** | **17.3x** |

Thresholds: C-1 at least 5x, C-2 at most 2.50x, C-3 at most 1.25x.

**Odds 128 and 256 pass every measurable criterion.** C-7 passes too, at the
-17% computed in F66 against a -20% threshold. 32 and 64 fail only C-1, by
being too small to be worth the change.

#### 2. Three of five predictions were refuted, and the decision is still clear

This is the entry's main value, because it is what the pre-registration was for.

**P1, confirmed.** The laptop does rise faster: 1.301x against the desktop's
1.183x across the full odds range.

**P2, refuted and not narrowly.** The prediction was that the fill spread would
widen into 2.6x to 3.5x. It goes from **1.84x to 2.03x**, a widening of 9.9%,
and the whole-nonce spread moves only **2.17x to 2.25x**. The fairness cost that
this entire measurement was built to find is **3.6%**, and the threshold set for
it had 15% of room. **The thing predicted to decide the outcome turned out not
to matter.**

**P3, refuted, and the direction is inverted.** The prediction was a concave
curve, most of the cost arriving early, so a middle candidate would win. The
marginal cost per extra full-history read **falls** from 16.5 ns at the bottom
of the range to 4.9 ns at the top. The cost is convex, gain-over-cost rises
monotonically, and **the maximum is the most efficient point available**, not a
compromise.

**P5 was already refuted in F66**, by a factor of eight and in the wrong
direction, without moving the criterion built on it.

So the pre-registration's predictive record is 1 of 4 on the measured ones. Its
**criteria** held perfectly, which is the argument for separating the two: had
the thresholds been chosen after seeing that the fairness cost was 3.6%, no one
could tell whether 2.50x was reasoning or rationalisation.

#### 3. Why the fairness cost is so small, and it is F65's point again

*F82 qualifies the caveat below: the window-only arm draws less keystream than
the hot arm, so coming in under it is a real effect and not noise.*

Because the fill is **94% HC-128 on both machines**: 93.9% and 94.1% on the
laptop here, against F60's 94% on the desktop, measured independently. The odds
only move the other 6%, so even tripling the memory term moves a nonce by a
tenth.

The same fact that makes v8 weak against an ASIC, the cipher dominating the
fill, is what makes raising the odds nearly free for honest CPUs. **One property
pays for the other**, which is the first time in this project that two
conclusions have pointed the same way.

*A caveat on the desktop numbers.* The 7950X's memory term is at its noise
floor: `window only` came in **below** the `one hot entry` floor in both runs,
which is physically impossible and puts the noise near 1% against a 1.5% signal.
F60 measured 5.7% on the same machine. The laptop resolves it cleanly at 6.1%,
which is why that machine carries this result and the desktop is the control.

#### 4. A reseed sweep that arrived free, and it is Option 3's answer

The harness prints it alongside. Laptop, ms per fill:

| reseed every | reseeds | ms | vs shipped |
|---|---|---|---|
| **16 msgs, shipped** | **257** | 1.3066 | 1.00x |
| 32 | 128 | 0.8592 | 0.66x |
| 64 | 64 | 0.6676 | 0.51x |
| 4096 | 1 | 0.4598 | **0.35x** |

**The reseeds are 65% of the fill.** F64 made reseed frequency the mechanism of
the GPU gate rather than a tuning dial; this prices the dial. Halving the
interval to reseed every 8 messages would roughly double the fill, which is far
beyond anything C-3 would allow, so **reseed count can be defended but not
cheaply increased.** That closes Option 3 as a lever while leaving F64's finding
that it must not be *decreased* intact.

### F68. C-4 measured: the odds cost 0.17 ms a block, which is free at the fork and crosses its threshold about 16 months later

*2026-10-07, in the daemon on real blocks, closing the last measurable criterion
in [D3-ODDS-PREREG.md](D3-ODDS-PREREG.md). Log in
`contrib/powbench/results/c4-odds-sync-2026-10-07.txt`.*

#### 1. Method, which reuses an instrument rather than building one

`NERVA_SALT_ODDS_AB` already A/Bs odds 256 against 13 as **two shadow fills
inside one call**, alternating order per call, both discarded while the real
fill runs untouched. That avoids F57's void run, where four separate daemon
processes drifted 25% apart on a 5 GB database.

The chain copy sat at the tip, so 2,500 blocks were popped via `pop_blocks` and
re-synced from peers, which F61 established does re-verify PoW in full with
`precomputed=0`. Run with `--log-level "global:INFO"`, without which the report
is invisible, which is the trap that cost hours in F61.

The node returned to the tip with **zero invalid, rejected or reorg messages**,
so the blocks really were re-verified and the copy is still usable.

#### 2. The result, over 2,048 interleaved pairs

| | TSC ticks per fill |
|---|---|
| windowed, odds 13 | 6,505,613 |
| full history, odds 256 | 7,773,423 |
| **ratio** | **1.1949x** |

**The harness said 1.183x on the same machine (F67), so the daemon and the bench
agree to 1%.** Two different instruments, one synthetic cache and one real LMDB
chain, which is the kind of agreement that makes a number believable.

| | ms per block |
|---|---|
| extra, v13 conditions as measured | 0.282 |
| extra, projected under v14 | **0.173** |

The projection divides by F57's measured 1.63x, since the same fill costs that
much more under v13's 8 MB pad than under v14's 1 MB one. This run was
necessarily under v13, because HF14 is not live.

#### 3. C-4 passes, and the interesting part is when it stops passing

The odds change is v14-only, so it costs nothing for any block below HF14.

| | blocks verified | extra sync |
|---|---|---|
| at HF14 launch | 0 | **0 s** |
| 1 year after | 525,600 | 91 s |
| **1.32 years after** | **693,642** | **120 s, the threshold** |
| 2 years after | 1,051,200 | 182 s |

**C-4 passes, and P4 was right: the arithmetic predicted 29 s against today's
111,762 blocks above assume-valid and the measurement gives 31.6 s, an error of
9%.** That is the one prediction in this pre-registration drawn from arithmetic
rather than intuition, and it is the only one of the four that held.

**The threshold is crossed about 16 months after the fork if
`ASSUME_VALID_HEIGHT` is never bumped.**

*Corrected on review, same day: that framing is misleading, and the growth is
bounded in practice.* The verified range is `tip - ASSUME_VALID_HEIGHT`, a
**subtraction, not an accumulation**, so bumping the height **resets it to near
zero**. The only constraint is that a hardcoded checkpoint must sit at or above
the new value, which [checkpoints.cpp:221](../../src/checkpoints/checkpoints.cpp#L221)
enforces by refusing to start otherwise.

And checkpoints are already added on a cadence: the last eight sit at
3,700,000 through 4,300,000, **every 100,000 blocks, which is 69 days**, plus
one at 4,320,000 for HF13 activation. If assume-valid keeps tracking them, the
verified range stays near one interval and **D3's sync cost never exceeds about
17 to 26 seconds**:

| verified range | D3's extra sync |
|---|---|
| 100,000 blocks, one checkpoint interval | **17.3 s** |
| 111,762, today's tip minus assume-valid | 19.3 s |
| 150,000, a lax interval | 25.9 s |

So the 2-year figure above describes a project that stopped maintaining its
checkpoints, not this one, which has bumped them eight times in the visible
history. **The honest framing is the one that does not depend on cadence at
all: D3 does not change which blocks get verified, only how long each takes.**
It adds 0.173 ms to a v14 nonce of about 1.325 ms, so it makes PoW verification
**13% slower**, or about 17% if D1 lands too and the nonce it is a fraction of
gets cheaper.

### F69. The fill's cost depends on how close the chain height is to a power of two, so D3 gets cheaper for the next seven years rather than dearer

*2026-10-07, measured while checking an assumption in F68 that turned out to be
backwards. `t_v8_fill` at three heights,
`contrib/powbench/results/fill-future-heights-2026-10-07.txt`.*

F68 presented D3's 0.173 ms per block as fixed. The obvious objection is that it
should **grow** with the chain, since the extra reads go into a block cache that
gets bigger. Measured, it shrinks:

| height | cache | accept rate | odds 256 minus shipped |
|---|---|---|---|
| 4,500,000 | 240 MB | 53.6% | **0.1326 ms** |
| 6,078,000 | 325 MB | 72.5% | 0.0944 ms |
| 7,128,000 | 381 MB | 85.0% | 0.0748 ms |

**It is not a memory effect.** `HC128_U32` at
[hc128.h:61](../../src/crypto/hc128.h#L61) draws by masking to the next power of
two and **redrawing on overflow**, so its cost is set by the acceptance rate,
and a rejected draw consumes keystream and pulls `HC128_NextKeys` forward.
Acceptance is `height / 2^ceil(log2(height))`.

Delta multiplied by acceptance is 0.071, 0.068 and 0.064 across the three rows,
near enough constant, so the increment is about **0.067 / acceptance** ms and
the model is confirmed rather than fitted.

Only **full-history** picks use `height` as their range; window picks use a
constant 100,000, whose acceptance is a fixed 76.3%. That is why only the
odds-256 arm moves with height, and it is what made the effect visible at all.

#### What it means

**A sawtooth, bounded at roughly where we already are.** Acceptance falls to 50%
just above a power of two and climbs to 100% just below, so the increment ranges
about 0.067 to 0.134 ms. **Today sits at 53.6%, which is near the worst point**,
and the chain does not cross the next power of two, 8,388,608, until about **7.4
years** after HF14.

So the honest answer to "does this get worse as the chain grows" is **no, it
gets better for seven years, then resets to about today's value.** The intuition
that a bigger database must cost more is wrong here, because the fill's marginal
cost is dominated by the cipher rather than by memory, which is F60 and F65
arriving a third time.

**This is a property of the live algorithm, not of D3.** v13's fill pays the
same sawtooth today, on every block, and nobody had noticed. D3 only multiplies
how many picks are exposed to it, from 832 to 16,384.

*Not pursued:* a draw that did not reject, for example Lemire's multiply-shift,
would remove the sawtooth and make the fill slightly cheaper for everyone. It
is a consensus change to shared v13 code and so is not free, and it would
**reduce** the attacker's work as well as ours, so it is not obviously wanted.
Recorded so the next person who finds this knows it was seen and left alone.

### F70. D1 and D3 together are 11% faster to verify than shipping neither, and better on every goal except fairness

*2026-10-07. Every D3 criterion in F67 was measured on an algorithm that still
has the sweeps, so none of them had been checked in combination with D1. This
closes that.*

#### 1. Method, and a correction to F67's split

The core was re-measured today with `t_v8_sweep`: **0.5510 ms as it stands,
0.2515 ms with the sweeps gone**, against F58's 0.5418 and 0.2463. The ratio
agrees to 0.5%, so F58's cross-machine anchors still hold and the composition
below rests on current numbers.

Anchors are F58's rebased pair, both machines in one session: nonce 1.325 and
2.877 ms, core 0.535 and 1.257, core after D1 0.243 and 0.646. The two
multipliers are measured fresh: the fill at odds 256 over odds 13 is
**1.1828x** on the 7950X and **1.3006x** on the i7-7700HQ.

*Correction to F67.* That entry derived the core by subtracting `t_v8_fill`'s
fill from the daemon's nonce, giving 0.620 ms, where `t_v8_sweep` measures the
core directly at 0.535. The two harnesses disagree about where the boundary
sits, and the direct measurement is the better one. **F67's C-2 for D3 alone
should read 2.289x rather than 2.247x.** Both pass; the conclusion does not
move; the method here is the one to reuse.

#### 2. The combination

| | nonce, 7950X | nonce, 7700HQ | C-2 spread | C-3 vs baseline |
|---|---|---|---|---|
| baseline | 1.325 | 2.877 | 2.171x | 1.000x |
| D1 only | 1.033 | 2.266 | 2.194x | 0.780x |
| D3 only | 1.469 | 3.364 | 2.289x | 1.109x |
| **D1 + D3** | **1.177** | **2.753** | **2.338x** | **0.889x** |

**C-2 passes at 2.338x against a 2.50x threshold**, with 6.5% of margin. The two
candidates are close to additive on the spread, which was the assumption worth
checking and it held.

**C-3 is not a cost at all for the pair.** The threshold was 1.25x and the
combination comes in at **0.889x: 11% faster to verify than shipping neither.**
D1 pays for D3 with change left over, on both machines.

**C-7 is unaffected by D1**, because the pre-registration defines it on the
fill's GPU ratio and D1 does not touch the fill. It stands at -17%.

#### 3. Whole-nonce GPU resistance, and why B3 is not needed to decide this

The whole-nonce figure needs the core's GPU ratio, which has never been measured
and is B3. So it is swept rather than assumed. F59 found D1 roughly doubles the
AES asymmetry, so the D1 arms use `2r`.

| core ratio `r` | baseline | D1 | D3 | **D1 + D3** | pair vs baseline |
|---|---|---|---|---|---|
| 3 | 8.03x | 10.15x | 7.15x | **8.79x** | **+9.6%** |
| 6 | 9.24x | 11.56x | 8.24x | **10.03x** | **+8.6%** |
| 10 | 10.85x | 13.45x | 9.69x | **11.68x** | **+7.7%** |

**The sign does not flip anywhere in the plausible range**, so the pair improves
whole-nonce GPU resistance by 8 to 10% whatever B3 turns out to say. That is the
answer to whether B3 gates this decision: **it does not.**

The shape is worth seeing: **D1 improves GPU resistance, D3 degrades it, and the
pair nets positive.** Neither candidate reads well alone on this axis and
together they do.

#### 4. The scorecard

| goal | D1 + D3 against baseline |
|---|---|
| 1, GPU | **+8 to 10%** |
| 1, FPGA | **94.9% of reads servable on-chip falls to 0%** |
| 1, ASIC | D1 neutral per F65, D3 **+17.6x** against DRAM-class attackers |
| 2, CPU parity | **worse: 2.171x to 2.338x**, the only regression |
| 3, pool | untested for either; argued safe, since both leave the chain-binding intact |
| 4, sync | **11% faster** |

**One regression against four improvements**, and the regression is 7.7% on a
quantity with 15% of pre-registered room. Goal 3 is the honest gap and it is an
argument rather than a measurement.

### F71. Goal 3's barrier is 237 MB, not a full node, and the number comes from a struct definition rather than a security argument

*2026-10-07, from the code and arithmetic rather than a bench. It corrects a
premise this file states in two places and that the project's roadmap was built
on.*

#### 1. The claim, and why it is wrong

This file says at two points that a miner "cannot mine without being a full
node", and the pool-resistance roadmap builds Nerva's main differentiator on it:
that every pool participant must run a full node, so there is no thin-client
onboarding, every worker validates, and every worker can defect or spot a
censoring template.

**The error is assuming that needing chain data per hash means needing a node.**

The fill reads only `block_cache_data`
([db_lmdb.h:75](../../src/blockchain_db/lmdb/db_lmdb.h#L75)): a 32-byte hash and
three uint64, **56 bytes per block and nothing else.** `body()` makes four
random picks and takes one field from each. Transactions, signatures, outputs,
key images and every index are untouched, and they are most of the 5 GB.

| | size |
|---|---|
| full database | ~5 GB |
| what a miner actually needs | **237 MB** at 4.43M blocks |
| compressed, since only the hash is incompressible and the other 24 B delta-code | **135 to 170 MB** |
| staying current | 56 B/block, 79 KB/day |

**So a thin client is possible.** A pool builds the array from its own node,
ships it once, and the worker needs no database and no validation.

#### 2. What that costs, stated plainly

Every property the differentiator rests on fails for such a worker. It **cannot
validate**, having no transactions; **cannot see a censoring template**, for the
same reason; **cannot defect or solo instantly**, which needs a real node; and
**cannot verify the blob it was handed**, because `block_cache_data` carries
`hash` but no `prev_hash`, so the array has no chain linkage and the worker
trusts the pool completely.

That is the thin-client aggregator model the roadmap was written to say Nerva
forbids.

#### 3. What survives, so this is a correction rather than a collapse

The barrier is real and Monero has none: RandomX needs a block blob and a seed
hash that rotates every 2048 blocks, so a Monero thin miner carries **~0 bytes**
of chain. **237 MB resident and current rules out browser miners, phone miners
and casual aggregators, and makes pool software substantially harder to write.**

It is a genuine differentiator. It is a **soft** one, and it should not be
described as a full-node requirement anywhere, including in anything public.

#### 4. The lever, and why it is still the wrong one

**The barrier size is set by a struct definition, not by a security argument.**
56 bytes per block was a choice, and it alone decides whether a pool ships
237 MB or 5 GB. Having the fill read from LMDB instead of a summary would raise
it to the full database and grow it with the chain.

**Do not do it.** That is the slow random-access sync the 95/5 window exists to
avoid, and D7 plus F62 both established today that bigger working sets favour
bandwidth-rich attackers: GPU over CPU on random gather goes 1.64x at 224 MB to
2.73x at 3.5 GB. The roadmap already said not to fight pools by cranking
chain-dependence because it taxes honest users more than an operator; this is
the third independent confirmation.

**The tool that actually addresses it is non-outsourceable PoW**, which does not
depend on data size at all. That is a research track for a later fork, not an
HF14 item.

*F83 studied it: it cannot be added to v8, the weak form is defeated for free on
Nerva, and it is not pursued now.*

#### 5. What it does not affect

**Nothing in D1 or D3.** Neither changes `block_cache_data`, the fetch ordering,
or the data a miner must hold. D1 and D3 together *improve* the feeder bound by
13%, from 188.7 to 212.4 MB/s per mining thread, because faster nonces demand
more bandwidth per unit of hashrate. A 1 Gbps link feeds 0.57 of a thread either
way, so the remote-feeder attack was never the live one. **The live one is the
thin client, and it is untouched by both.**

### F72. D1 is in. The sweeps and the four extra hashes are gone from the consensus code

*2026-10-07. The port, not a measurement. Verified against F58's candidate
digest rather than by inspection.*

#### 1. What changed

`salt_pad_v8` and the blake/groestl/jh/skein calls are removed from
`slow-hash-v8-impl.h`. With them went:

- **`slow-hash-v8-defer.h`**, 290 lines, deleted. It existed to make the sweeps
  cheap and there was nothing left to defer. It also owned `pre_aes_v8`,
  `post_aes_variant_v8` and `aes_sw_variant_v8`, which read the pad through
  `CN_V8_COMP` because the pad held `logical ^ comp`. With comp identically
  zero those reduce term for term to the plain v11 steps, so the v8 core now
  uses `pre_aes()`, `post_aes_variant()` and `aes_sw_variant()` directly over a
  1 MB pad.
- **`r2`**, whose only consumer was the sweep. The two AES arms differed at
  exactly that pointer, `&c` in hardware and `&b` in software, and F58 flagged
  it as a divergence that would surface only on machines without AES-NI and
  only in the field. **It is no longer reachable.**
- **`contrib/powbench/v8ns-{hw,sw}.c`**, the D1 candidate TUs, deleted. Their
  own header said to delete them when D1 was decided and make the change in the
  real translation units, which is what happened.

#### 2. How it was verified, in the order the checks were run

**The grid digest is the proof.** `t_v8_grid` over all 1600 consensus draws now
reports the shipped hash at **`09d34831c25f506c`** on both AES arms. That is
byte for byte the digest F58 recorded for the no-sweep candidate before any of
this was ported. The production code and the candidate are the same function.

**The vector generator proved the live algorithms are untouched.** Regenerating
all four tables gives **v10, v11 and v13 byte-identical** and only v14 moved.
That is a stronger statement than diffing the sources, because it is a property
of what the code computes rather than of how it reads.

**`t_kat` passes both gates** with the new vectors, on hardware AES dispatch.
The daemon builds and starts without refusing, which it would do if either gate
failed.

**`t_v8_sweep` confirms the speedup reached production:** the shipped core went
from **0.5510 to 0.2657 ms** per nonce, and all three of that harness's arms now
agree within 0.3% because they compile the same code.

#### 3. What the harnesses lost, stated so nobody looks for it later

`t_v8_grid`'s checks 2, 3 and the second half of 6 are gone. They compared the
candidate against the shipped hash, and those are now one function, so the
comparison could only ever be a function against itself. **A tautological PASS
is worse than no check**, which is F15's lesson in a different costume. What
carries the guarantee forward is the digest: if it ever moves off
`09d34831c25f506c`, something changed the hash.

Check 6's surviving half is now a property of the shipped algorithm: **v8
depends only on `(xx-1)*yy + iters`.** The daemon still draws three numbers, and
the comment at the draw site now says why: collapsing them would change how much
HC-128 keystream the draw consumes, which would change the salt seed and every
hash after it. The three draws are load-bearing for keystream accounting, not
for the hash.

#### 4. What this does not do

**It does not decide D3.** The odds change is separate and still owed its
testnet round. F70 measured the pair together and that result stands: 11% faster
to verify than shipping neither, C-2 at 2.338x against a 2.50x threshold.

**It does not regenerate v13's vectors**, and the generator proving that is the
point. v8 has never validated a block, so changing what it computes is a
question we are allowed to ask. v13 validates mainnet today and is untouched.

### F73. D3 is implemented: v14 draws every pick from full history, v13 keeps its window

*2026-10-07. The port. The runtime observation on the v14 path is owed and is
named as such below.*

#### 1. What changed, and what it did not cost

`CNA_V6_FULL_HISTORY_ODDS_V14` is 256, and `v14_fetch_salt` passes it.
`get_block_longhash_v13` passes the old 13. **The fork cost the
pre-registration said would not apply did not apply:** `odds` became one
parameter threaded through `get_cna_v6_data`, the two fill bodies and the
selfcheck call. There is no v14-only copy of the fill and no second consensus
path to keep in step.

**The known-answer vectors did not move**, and that is expected rather than
lucky: the KAT entry point takes no salt callback, so `CN_V8_FETCH_SALT` does
nothing and the fill never runs. D3 changes which blocks a real nonce reads,
not the hash function. `t_kat` passes both gates unchanged.

#### 2. The window is now version-scoped, and the compiler enforces it

At odds 256 every pick is full-history, so the window branch is unreachable for
v14 while v13 still uses it. One constant meaning two things is the kind of
thing this project has been bitten by, so it is pinned from both directions:

- renamed to **`CNA_V6_WINDOW_BLOCKS_V13`**, so a reader sees the scope
- a **`static_assert`** in db_lmdb.cpp ties the name to the value:
  `CNA_V6_FULL_HISTORY_ODDS_V14 == 256`, with a message pointing at F66 and F67

The name is a claim that nothing structural enforces, since `get_cna_v6_data`
is shared and only the value keeps v14 out of the window branch. The assert is
what makes the claim true.

**The assert was tested by making it fail.** Setting v14's odds to 128 gives
`static assertion failed: v14 below 256 makes the window live again`. An assert
that is never seen to fire is indistinguishable from one that does not compile,
which is worth thirty seconds to rule out.

#### 3. What is NOT yet verified, stated plainly

*ANSWERED the same day by F74: the daemon printed `odds 256 of 256, window
unused` on the real v14 path, and the cost came in at 1.155x rather than the
1.183x predicted below. The section is kept as written because it is the
reasoning that made the observation worth taking.*

**That the v14 call site passes 256 at runtime.** The constant is passed
directly at one readable call site and the build type-checks it, but that is
reading, not observing.

**No consensus test can catch this.** If the odds were mis-wired, every node
would be mis-wired identically and would agree with each other perfectly, so a
testnet round would pass with D3 silently inert. That is the same shape as F61,
where instrumented code looked dead for hours because its log category was
never enabled.

So the daemon now **announces each distinct odds value once** at INFO:
`chain fill: full-history odds 256 of 256, window unused`. It is cheap, it is
permanent, and it turns "the call site reads correctly" into "the daemon said
so". F61's lesson is that an instrumented path which never announces itself
cannot be distinguished from one that never runs.

Observing it needs v14 blocks, which mainnet does not have: HF14 sits at
4,500,000 and the chain is at 4,431,763. The measurement is therefore a
mainnet-copy experiment, recorded separately, and testnet is the wrong venue
for the cost half of it because its block cache is far smaller than mainnet's
237 MB and the memory behaviour would not transfer.

#### 4. What the cost is expected to be

From measurements already taken, so these are predictions to check against:

| | source |
|---|---|
| fill, odds 13 to 256 | **1.1949x** in the daemon on real blocks, F68 |
| same, harness | 1.183x, F67 |
| whole nonce with D1 also in | 11% **faster** than shipping neither, F70 |

### F74. D3 is observed live on the v14 path, and costs 1.155x there rather than the 1.183x predicted

*2026-10-07. The runtime observation F73 said was owed. Mainnet copy with HF14
moved locally to the chain tip, 11,337 v14 blocks mined at fixed difficulty on
`nerva-t2`. The HF14 edit was never committed.*

#### 1. The wiring proof, which no consensus test could have given

    chain fill: full-history odds 256 of 256, window unused

F73 recorded that a mis-wire would leave every node mis-wired identically, so
they would agree with each other and a testnet round would pass with D3 inert.
**The daemon now says which fill it is running**, and on the v14 path it says
256. That is the whole purpose of the announce line.

#### 2. The cost, measured where it actually applies

`NERVA_SALT_ODDS_AB`, 2,048 interleaved pairs, height 4.43M, 237 MB block cache:

| | cycles per fill |
|---|---|
| windowed, odds 13 | 4,805,636 |
| full history, odds 256 | 5,551,393 |
| **ratio** | **1.155x** |

| where measured | ratio |
|---|---|
| harness, `t_v8_fill` (F67) | 1.183x |
| daemon, **v13** path (F68) | 1.195x |
| **daemon, v14 path (here)** | **1.155x** |

**D3 is cheaper on the algorithm it ships with than on either proxy**, and the
reason is structural rather than noise: v13 carries an 8 MB pad that crowds the
cache, v14 carries 1 MB, so v14 has more cache left for the block cache and the
extra full-history reads cost it less. F57 measured the same effect from the
other side, with the fill 1.63x dearer under v13 than v14.

**Every earlier number for D3 was therefore slightly pessimistic**, which is the
preferable direction to be wrong in but worth stating plainly: the proxies were
measuring a harder problem than the one we ship.

#### 3. What it does to the pair

| | nonce | vs baseline |
|---|---|---|
| F70, predicted at 1.183x | 1.1776 ms | 11.1% faster |
| **measured at 1.155x** | **1.1555 ms** | **12.8% faster** |

So D1 and D3 together verify **12.8% faster than shipping neither**, up from the
11% F70 projected.

#### 4. The real fill cost on the v14 path, for later reference

`NERVA_SALT_AB` over 8,192 calls while mining: reference 8,966,970 cycles,
run-ahead **5,843,175** cycles, so A1's run-ahead is worth **1.53x** on the v14
fill. At 4.491 GHz the shipped fill is **1.301 ms** per nonce.

#### 5. A trap that cost 2,400 blocks of silence, again

The announce line printed immediately; the fill A/B printed nothing. **`MGINFO`
is global and obeys `--log-level "global:INFO"`; `MCINFO("salt.fill", ...)`
needs its category enabled as well.** This is F61 exactly, where instrumented
code looked dead because its category was never set.

The fix needs no restart, so a long run is not lost:

    curl -X POST http://127.0.0.1:<rpc>/set_log_categories -d '{"categories":"*:INFO"}'

That is a **plain endpoint, not a json_rpc method**; through `/json_rpc` it
returns "Method not found".

### F75. HF14 syncs 3.98x faster than v13, measured end to end on a second machine at 4.4M height

*2026-10-07. Two machines on a LAN, mainnet copy, HF14 moved locally to the
chain tip. The first end-to-end sync measurement this project has; every earlier
sync figure was composed from a per-block delta.*

#### 1. Method

The 7950X mined 11,337 v14 blocks onto a copy of mainnet at 4,431,764 and then
served as the **only** peer (`--out-peers 0`, so it could not reach real
mainnet, whose far greater cumulative difficulty would have reorganised the
mined blocks away mid-test). The i7-7700HQ took a copy of that chain, popped
20,000 blocks and re-synced them, crossing the fork partway:

| | blocks |
|---|---|
| v13, 8 MB pad with the VM, odds 13 | 7,936 |
| v14, 1 MB pad, D1 and D3, odds 256 | 11,294 |

**Both halves in one process**, so the comparison is within-run. Both with
`--fixed-difficulty 1`, so neither pays the difficulty calculation. Both over
blocks that are ~99.6% coinbase-only, measured: 42 transactions across the
10,000 real v13 blocks in range, median block size 86 bytes. So transaction
content cannot explain the difference.

The crossing is confirmed in the log rather than inferred, by the announce line
added in D3: `odds 13 of 256, windowed` at 17:32:14, then `odds 256 of 256,
window unused` at 17:34:48.

#### 2. The result

| | per block | rate |
|---|---|---|
| v13 | **17.83 ms** | 56.1 blk/s |
| v14 | **4.48 ms** | 223.1 blk/s |
| | **3.98x faster** | |

PC-side sampling of the peer's advertised height independently gave 3.36x; the
laptop's own log is the better figure, since advertised height lags.

#### 3. PoW is the dominant cost of syncing, which I had guessed wrong

Mid-measurement I speculated that PoW looked like a small slice of the per-block
cost and that "every sync number in F68 and F70 is noise against the real
bottleneck". **That is wrong, and these two numbers bound it without needing any
model.**

Everything that is not PoW (network, transaction checks, database write,
difficulty) is identical across the two halves: one machine, one run, one
process, near-identical block contents. Call that shared overhead `O`. Since
v14's PoW cannot be negative, `O <= 4.48 ms`. Therefore:

**v13's PoW is at least 13.35 ms of its 17.83 ms per block, so at least 75% of
v13 sync time is proof of work.**

So sync cost *is* PoW cost, and the sync arithmetic in F68 and F70 was measuring
the thing that matters rather than noise. The correction is recorded because the
wrong version was stated out loud first.

#### 4. What this is and is not

**It is the whole v13 to v14 change**, not D1 and D3 alone: an 8 MB pad with a
VM program becoming a 1 MB pad with no sweeps and full-history draws. D1 and D3
are a part of it, worth 12.8% between them by F74.

**It is the laptop**, which F58 puts at roughly 2.2x slower than the desktop, so
the absolute milliseconds are that machine's. The 3.98x ratio is within-machine
and is the figure that transfers.

### F76. HC-128's GPU gate is 6.0x, not 12.1x, because the work-item grid skipped the peak; and the reseeds are confirmed as the mechanism but priced out as a lever

**Superseded in part by F78, same day.** 6.04x is the figure with HC-128's
state in `__global`. Staged into `__local` the gate is **2.92x**, and the
reseeds are worth 1.13x rather than the 1.36x below. The correction to 12.1x
and the mechanism finding both stand; the level does not.

**The mechanism finding does not stand either: F80.** The kernels consumed one
keystream word in sixteen, so the card skipped most of its keystream work and
looked better the more keystream a row had. With all sixteen consumed the
disadvantage is flat across the reseed mix, 7.5x to 8.3x in `__global`, and
the shipped mix reads 7.8x there and 3.11x in `__local`.

*2026-10-07, the first of the three measurements opened after D1 and D3 shipped.
`t_hc128` extended to sweep the reseed mix and to resolve the work-item curve.
Transcripts in `results/hc128-reseed-sweep-2026-10-07.txt` (fine grid, the one
to read) and `results/hc128-reseed-sweep-coarse-2026-10-07.txt`.*

Two results. The second is the one the measurement was built for and it confirms
F64. The first was not being looked for and it halves a number this project has
built three arguments on.

#### 1. The correction: 12.4x was a resolution failure, and the old points still reproduce

F62 published HC-128 at 12.1x and F64 reproduced it at 12.4x, both from a
work-item array of `{1024, 8192, 32768, 131072}`. F64 applied F66's void test,
found the peak interior at 8,192, and passed it.

**The peak is at 4,096, which neither run sampled.** Filling the grid in:

| work items | rounds/s, nextper 40 |
|---|---|
| 1,024 | 3.533e5 |
| 2,048 | 6.987e5 |
| 3,072 | 8.852e5 |
| **4,096** | **1.027e6** |
| 5,120 | 8.461e5 |
| 6,144 | 5.964e5 |
| 8,192 | 5.063e5 |

A smooth interior maximum with a shoulder on both sides, reproduced at every
point of the reseed sweep and across two runs with different grids.

**The old points reproduce, which is what makes this a resolution failure rather
than a disagreement.** At 1,024 F64 read 3.431e5 against 3.533e5 here, at 8,192
4.923e5 against 5.063e5, and the CPU side 6.107e6 against 6.207e6. Everything
F64 measured is confirmed to within a few percent. It simply never looked
between 1,024 and 8,192, an 8x gap with the answer inside it.

| | published | corrected |
|---|---|---|
| **HC-128, GPU against CPU** | **12.1x to 12.4x** | **6.04x** |

Two bracketing control arms at the shipped mix read 6.04x and 6.05x, and the
drift control is **0.2%**, so this is not a noisy reading.

**The lesson is sharper than F66's and is the third time this harness family has
produced a figure that was really a grid artifact.** F66 established that a peak
at the end of the swept range voids the row. That test is necessary and **not
sufficient**: F64's peak was interior and still wrong, because an interior peak
on a grid with 8x gaps locates nothing. The rule to carry: *a peak is only worth
the resolution of the grid around it*. `t_hc128`'s array now has twelve points
with the region around the peak sampled at 1,024-item spacing.

#### 2. The reseeds are the mechanism, measured rather than inferred

*Refuted by F80: this sweep ran on a kernel that consumed one keystream word in
sixteen. With all sixteen the curve is flat.*

F64 argued from a paper's units that the gate is the reseed frequency and not
the 4 KB state, since a throughput figure in Gbps amortises key setup away and
our fill never amortises one. That was an inference. Sweeping the mix tests it
directly: at `nextper = 0` every round is a key setup, and at large `nextper` the
setup amortises exactly as the paper's regime does.

| NextKeys per Init | GPU is worse by | against shipped |
|---|---|---|
| **0, pure key setup** | **7.51x** | 1.24x |
| 10 | 7.23x | 1.20x |
| **40, shipped** | **6.04x** | 1.00x |
| 160 | 4.46x | 0.74x |
| 640, keystream-dominated | **3.40x** | 0.56x |

**Monotonic, and F64 is confirmed.** The 4 KB state on its own is worth 3.40x;
the reseeds take it to 6.04x and would reach 7.51x in the limit. So reseed count
is a mechanism and not a dial, and F64's instruction that it must not be
*decreased* is now measured: halving the reseed rate would cost 14% of the gate.

The same sweep prices the cipher directly. Fitting per-round cost at one thread
gives **Init = 1.99 us and NextKeys = 0.0159 us**, so one key setup is worth
**125 keystream blocks**, and at the shipped mix Init is **76.5%** of the fill's
cipher cost. F60 reached two thirds by a different route and F64 quoted 76%.
Three independent confirmations.

#### 3. So the reseed lever is real and still not worth pulling

F67 section 4 priced doubling the reseed rate at roughly 2x on the fill without
knowing what it buys. Both halves are now measured. Reseeding every 8 bodies
instead of 16 gives 512 inits against the same ~10,500 NextKeys, so
`nextper` falls to 20.5:

| | fill cipher cost | GPU gate |
|---|---|---|
| shipped, reseed every 16 | 679 us | 6.04x |
| **reseed every 8** | **1,186 us, 1.75x** | **6.65x, +10.0%** |
| reseed every 32 | 422 us, 0.62x | 5.18x, -14% |

**1.75x on the fill to buy 10% on one component of goal 1.** The fill is about
70% of a post-D1 nonce, so that is roughly 1.5x on every honest nonce and on
every block of sync. Decisively a bad trade, and the curve is convex in the
unhelpful direction: the reseeds we already have are cheap to keep and expensive
to add to. **Option 3 is closed as a lever, for the second time and now on both
sides of the trade.**

#### 4. What the 2x correction does and does not move

**It does not move any decision taken to date**, and C-7 moves slightly in our
favour rather than cancelling exactly, which is worth stating precisely because
the loose version of this claim was written first:

- **C-7, D3's GPU criterion, improves from about -14.5% to about -13.6%**,
  against a -20% threshold. The correction is *not* a clean cancellation: it
  halves the GPU's cipher term while leaving its memory term alone, so the extra
  full-history reads are now a larger fraction of what a card pays. Taking F66's
  own numbers, the GPU's slowdown from odds 13 to 256 goes 1.011x to 1.022x
  against the CPU's unchanged 1.183x. The *level* falls from 11.4x to about
  5.7x, but the criterion was written on the regression and not the level.
- **F66 section 3 still holds.** Its point was that the GPU's memory term is
  noise beside its cipher term, 10.8 us against 8,504 us. The cipher term halves
  to about 4,250 us and memory is still a quarter of one percent of it.
- **F70's whole-nonce sweep survives**, having been computed across a range of
  core ratios precisely because the core's was unknown. The corrected fill
  figure of ~5.7x now sits inside that swept range rather than above it.
- **D5 stays rejected.** It deletes the component this entry just confirmed is
  the gate.

**It voids the ceiling argument, which is the real cost.** PLAN-v8-PHASE8 and
F63 section 5 both state that rebalancing v8 is bounded by HC-128's 12.1x and
that a whole nonce sits near 9x, "about three quarters of the ceiling". With
HC-128 at 6.04x the composed 9x **exceeds its own largest term**, which is
impossible, so at least one of the two is wrong. The 9x was composed using an
AES term of roughly 6x that F59 took from a CPU T-table proxy rather than from a
card.

**So B3 stops being optional.** It was the cheapest of the three measurements and
is now the one that decides whether v8's headline GPU figure is 9x or something
closer to 6x, and therefore whether there is any headroom left in rebalancing at
all. That is the next entry.

### F77. B3 measured: the hash core is 65x against a card and the fill's cipher is 6x, so the share lever in PLAN-v8-PHASE8 points the wrong way

**Superseded on its headline by F78, same day.** The 64.9x was almost entirely
the constant-memory AES table this entry's section 5 warns about: with the
table in `__local` the core is **~10.7x** and a whole nonce **3.04x** rather
than 18.8x. Sections 1 and 4, the two harness defects and the run-ahead
coupling, are unaffected. Section 6's suspension of the share lever is
resolved by F78, and not in the direction this entry leaned toward.

*2026-10-07, the second of the three measurements opened after D1 and D3
shipped. It needed two defects in the GPU harness fixed first, and those are
section 1 because they invalidate figures this project has published.
Transcripts in `results/b3-core-only-2026-10-07.txt`,
`results/b3-whole-nonce-2026-10-07.txt` and
`results/fill-serial-arm-2026-10-07.txt`.*

B3 has been the named open question since PLAN-v8 and has never run. F70 swept
the core's GPU ratio over 3, 6 and 10 because nobody had measured it, and
concluded the sweep made the answer not matter. **It is 65, outside that range
by a factor of six, and the conclusion it supported is reversed.**

#### 1. Two things the harness was measuring that the daemon does not run

Both found while preparing the measurement, neither being looked for.

**It modelled pre-D1 v8.** `vm_ref.h` and `vm_kernels.cl.h` still ran the
`salt_pad` sweep and its mix64 stand-in inside every `xx`/`yy` step, which D1
deleted from consensus the same morning (dbd4fd7). So **every GPU figure in this
file was taken against an algorithm that no longer exists**, including F63's pad
curve, which is the entire evidence base for growing the pad.

**It modelled the serial fill.** `chain_fill.h` was ported from
`cna_v6_data_reference` and has no prefetching, while consensus has run the
run-ahead (4fe2a39) since before v14 existed. That barely mattered at odds 13,
where 95% of reads are window hits with nothing to overlap. After D3 it matters
a great deal.

Both are fixed. `cna_v8_d1` is a new kernel rather than an edit, so `cna_v5`,
`cna_v8` and the FP kernels are byte-for-byte what they were and one run gives
the delta within-run. `chain_fill_v6_run` mirrors `cna_v6_data_run_ahead`, and
gpubench now refuses to time it unless it reproduces the serial arm exactly at
both odds, which is the gate db_lmdb.cpp already applies in the daemon.

**The repaired harness reproduces three independent prior measurements**, which
is what says the repair is right rather than merely different:

| | prior | gpubench now |
|---|---|---|
| D1's verification speedup | 1.313x, F57, daemon | **1.30x** |
| D3's cost on a nonce | 1.109x, F70 | **1.139x** |
| D1 and D3 together | 0.889x, F70 | **0.879x** |

#### 2. B3, both arms core-only

`nofill` drops the chain fill from the CPU arm; the GPU arm never had it. 1%
load, control drift 0.294%, checksum gate passed on every row including the new
kernel. The `v8 D1` and `v8 D1+D3` rows agree to 0.6%, as they must, since D3
touches only the fill: a free control on the change itself.

| core only | GPU H/s | CPU H/s, 32T | CPU is better by |
|---|---|---|---|
| v5 1MB, port control | 619.8 | 25,871 | 41.7x |
| v8 pre-D1 | 621.5 | 25,751 | 41.5x |
| **v8 post-D1** | **829.2** | **53,778** | **64.9x** |

v5 and pre-D1 v8 are the same GPU work by construction and agree to 0.5%, so
this is not a transcription artifact.

**D1 is worth 1.56x on the core's GPU ratio**, measured on a card. F59 predicted
"roughly doubles" from a CPU T-table proxy, so the direction holds and the size
is smaller. D1 removed the AES-neutral half and left the gate, which is a better
reason than the one in its own record.

#### 3. The whole nonce is 18.8x, not the 9x this project has published

Shipped fill, 5% load, control drift 1.004%.

| whole nonce | GPU:CPU | CPU is better by | verify, 1T |
|---|---|---|---|
| v5 1MB | 0.0588x | 17.0x | 2.02 ms |
| v8 pre-D1 | 0.0486x | **20.6x** | 1.42 ms |
| v8, D1 only | 0.0477x | **21.0x** | 1.12 ms |
| **v8, D1 + D3, shipped** | **0.0532x** | **18.8x** | **1.24 ms** |

- **D1 is GPU-neutral on a whole nonce, +2%**, while making verification 1.27x
  cheaper. It improves the core's ratio by 1.56x and shrinks the core's share at
  the same time, and the two nearly cancel.
- **D3 costs 10.6%** of whole-nonce GPU resistance, 21.0x to 18.8x.
- **The pair costs 8.7%.** F70 predicted **+8 to 10%** and had the sign wrong,
  because it swept the core ratio over 3, 6 and 10 and wrote "the sign does not
  flip anywhere in the plausible range". The range was right about itself and
  wrong about where the answer was. Its own table shows the benefit falling as
  the ratio rises, 9.6% at 3 to 7.7% at 10, so the direction was visible and
  nobody extrapolated it.

This does not make D3 a wrong decision. Its case was anti-FPGA, retiring the
5.3 MB window that F66 showed is block-RAM resident, and that stands untouched.
What it does mean is that **C-7 was scoped to the fill and could not see the
whole-nonce price**, which is 10.6% against the -17% it reported on the fill
alone.

#### 4. What the run-ahead is worth now depends on the odds

The same rows with `serialfill`, which is the reference loop:

| | serial | run-ahead | worth |
|---|---|---|---|
| D1, odds 13 | 1.24 ms | 1.23 ms | **~1.0x** |
| D1 + D3, odds 256 | 1.84 ms | 1.32 ms | **1.39x** |

At odds 13 the run-ahead buys almost nothing in this harness, against F57's 6%
in the daemon. At odds 256 it is worth 1.39x, because every read is a DRAM miss
and overlapping them is the whole point.

**So D3 and the run-ahead are coupled, and nobody wrote that down.** D3's cost
is 1.14x with the run-ahead and about 1.48x without it. The run-ahead is on this
branch and ships with HF14, so nothing is broken, but it is now load-bearing for
D3 rather than a 5% optimisation, and reverting it would nearly double D3's
price.

#### 5. The caveat, and why it does not rescue the old picture

**64.9x is an upper bound and should not be quoted as the gate.** The GPU AES
reads its T-table from `__constant` memory with sixteen data-dependent indices
per round ([vm_kernels.cl.h:100](vm_kernels.cl.h#L100)). NVIDIA's constant cache
broadcasts efficiently only when a warp's lanes read the same address, so 32
lanes hitting 32 different entries serialise. That is the worst available place
for an AES table on a GPU, and shared memory or bitslicing would avoid it.

**So the comparison against F76's 6.04x for HC-128 is not like for like**, the
HC-128 kernel having no table lookups at all. The claim "the core is an order of
magnitude stronger a gate than the fill" is **not established** by this entry
and should not be repeated until the AES kernel is fixed.

What survives the caveat, and it is enough to move the design:

1. **The core ratio is far outside 3 to 10**, so every composition in this file
   that assumed that range is wrong in a known direction.
2. **The published 9x whole-nonce figure is wrong independently of the AES
   kernel**, because it was composed from HC-128 at 12.1x, which F76 corrects to
   6.04x. Measured directly the nonce is 18.8x.
3. **The relative numbers are sound**, since the same kernel structure serves the
   control, the pre-D1 row and the post-D1 row. D1's 1.56x and D3's 10.6% do not
   depend on the AES port's quality.

#### 6. What it does to PLAN-v8-PHASE8

That document states the governing lever as: *"there is exactly one lever that
improves goal 1 without trading against it: raise the fill's share of a nonce,
never the core's."* It rests on F38's rule that core work is specialisable,
which is an ASIC argument, and **F65 voided every ASIC bound in the document**.
On the live threat the core is worth more than the document allows and the fill
less, and D3 raising the fill's share at a cost of 10.6% is that sentence being
wrong in a measurable way.

The rule is not reversed into its opposite, because the AES caveat forbids that.
It is **suspended**: neither direction is established, and the measurement that
settles it is a competent GPU AES kernel. That single number decides whether
goal 1 rests on the core or on nothing, and it now gates the pad question, which
was item 3 on the list this work came from.

### F78. Almost all of v8's measured GPU resistance was our kernel. With the tables and state placed competently it is 3 to 5x, not 19x and not 9x, and the AES contributes nothing at all

**Corrected in part by F79 and F80, same day.** The AES row was a harness
defect: `t_aes` let the compiler delete six of eight blocks, and the corrected
gate is **about 4.2x, not 1.04x**, so "the AES contributes nothing at all" is
withdrawn and P3 stands. HC-128 in `__local` is **3.11x**, not 2.92x, and the
reseeds are worth about 1.04x of it. The whole-nonce 3.04x and the core's
~10.7x come from `nerva-gpubench`, which has no such defect, and stand.

*2026-10-07, the third measurement, and the one that decides the others.
`t_aes.cpp` is new; `t_hc128` and `vm_kernels.cl.h` gained local-memory arms
generated from the existing code by address-space substitution rather than
retyped. Transcripts in `results/aes-table-placement-2026-10-07.txt`,
`results/hc128-lds-2026-10-07.txt` and `results/lds-whole-nonce-2026-10-07.txt`.*

F77 published B3 at 64.9x and flagged it as an upper bound because the GPU AES
read its T-table from `__constant`, where a warp's divergent lookups serialise.
That caveat was right and far too gentle.

#### 1. The AES is not a gate. It is parity.

Three implementations of the identical computation, each checked bit for bit
against `_mm_aesenc_si128` before timing. Two runs agreeing to 1%.

| table placement | AES rounds/s | CPU better by |
|---|---|---|
| `__constant`, what F77 measured | 4.71e9 | **20.0x** |
| staged into `__local` | 9.04e10 | **1.04x** |
| four pre-rotated tables in `__local` | 8.99e10 | 1.05x |

**Moving the table to shared memory makes the RTX 3050 19.2x faster and brings
it level with a 7950X at 30 threads.** The four-table arm is within 0.5% of the
one-table arm, so the rotates were free: the kernel was bound entirely on
constant-cache serialisation, not on arithmetic.

**This voids P3.** PLAN-v8-PHASE8 says *"Do not reduce the absolute AES work. It
is the only part a GPU is bad at."* A GPU is not bad at AES. It was bad at our
AES.

**And it voids F59 as a GPU proxy.** F59's 4.9x to 8.0x is what a *CPU* pays for
losing AES-NI. A CPU without AES-NI has sixteen lanes and no shared memory; a
card has thousands and 48 KB per work-group. The two situations have almost
nothing in common, and that proxy underwrites D1's "doubles the asymmetry", the
pad-fill-is-the-gate argument, and D6.

#### 2. The whole nonce falls from 19x to 3x on that one change

`cna_v8_d1_lds` is `cna_core` with the table's address space substituted and
nothing else, run as an extra row beside the untouched constant-memory rows, so
the delta is within-run. The checksum gate passed on it, so it computes the same
hash. 4% load, control drift 1.963%.

| whole nonce | GPU H/s | CPU H/s | CPU better by |
|---|---|---|---|
| v8 D1+D3, constant tables | 811.4 | 15,528 | **19.1x** |
| **v8 D1+D3, the same thing in `__local`** | **4,986.7** | 15,150 | **3.04x** |

The GPU gets **6.15x** faster. The CPU column is the same code and moves 2.4%,
which is noise.

B3 itself follows, since the GPU column is demonstrably unaffected by the
`nofill` flag: **the core with a competent AES is about 10.7x, not 64.9x.**

#### 3. HC-128 moves too, by much less, and the structural argument survives

The obvious next question, since F76's 6.04x was measured with `P` and `Q` in
`__global` and nobody had staged them. `hcbench_lds` is the same two functions
with the state in `__local`, checked against `src/crypto/hc128.c` before timing.

| HC-128, shipped reseed mix | CPU better by |
|---|---|
| state in `__global`, F76 | 5.96x to 5.99x |
| **state in `__local`** | **2.92x** |

2.04x to the GPU, reproduced across two runs, and the top of the item sweep is
flat rather than climbing, so it has converged.

**The 4 KB state is a real constraint in a way the 1 KB table never was.** The
peak sits at a work-group of **4**, not the 12 that 48 KB allows, because larger
groups exhaust shared memory per SM and cut the number of resident groups. So
the card buys latency with occupancy, which is exactly F62's original instinct,
and it still only gets half the gap back. That is the one prediction in this
area that has survived.

**But the reseed story shrinks with it.** In `__global` the reseeds were worth
1.36x of the gate (8.13x at pure key setup against 5.99x shipped). In `__local`
they are worth **1.13x** (3.30x against 2.92x). F76's mechanism holds in
direction and is a third of the size against a competent implementation.

#### 4. Where that leaves goal 1

All on the 7950X and RTX 3050 pairing, which is the only form that transfers:

| | as this project measured it | competently implemented |
|---|---|---|
| AES | 20.0x | **1.04x** |
| HC-128 | 5.99x | **2.92x** |
| whole nonce, host-fed fill | 19.1x | **3.04x** |
| whole nonce, card does everything | ~21x | **~4.7x**, composed |

**v8's GPU resistance is 3 to 5x.** The published figure was 9x, F77 measured
18.8x with a bad kernel, and neither survives.

**These are still upper bounds.** Both local-memory arms are a first attempt by
someone who is not a GPU specialist. Bitslicing removes AES tables entirely, and
nothing here restructures HC-128. A competent attacker does at least this well
and probably better.

#### 5. What it changes

- **P3 is void** and the AES is not worth defending as a gate.
- **D6, growing the pad, is reopened on a different mechanism and its evidence
  is gone.** F63's 1.46x and 1.96x were measured on pre-D1 v8 with the naive AES
  kernel. Pad size no longer matters because it scales AES volume, which is
  free; it matters, if at all, because each nonce needs its own megabyte and a
  card's L2 is 2 MB. That is a capacity-and-latency argument, it is untested,
  and it is plausibly where the core's remaining ~10x lives.
- **The reseeds are worth 1.13x, not 1.36x**, so F76's "defend them" stands and
  its weight is smaller.
- **Every GPU figure this project has ever published is an artifact of the same
  two kernels**, and the correct reading of the whole GPU line of work is that
  it measured our own implementation three times and the algorithm once.

**The honest summary for goal 1: v8 as it stands is only a few times harder on a
card than on a CPU, and no dial inside it changes that by much.** Moving
meaningfully past it is a design question, which is what F63 section 5 said when
it thought the ceiling was 12x. The ceiling is about 3x.

### F79. `t_aes` timed a quarter of the GPU's AES, so the AES gate is about 4x, not parity

*2026-10-07, review of the harnesses behind F78. Transcript of the corrected run
in `results/aes-table-placement-allwords-2026-10-07.txt`.*

**F78's 1.04x is wrong, and the whole-nonce figures in F78 are not.** The
correction is to the AES component and to the reasoning built on it.

#### 1. The defect

Every `t_aes` kernel ended with `out[gid] = s[0] ^ s[31]`. The eight 16-byte
blocks are independent chains, exactly as in `aes_pseudo_round`, so that output
depends on blocks 0 and 7 alone. Blocks 1 to 6 were dead code and the OpenCL
compiler deleted them. The card did two blocks of AES per iteration and the rate
was divided by eight. The correctness gate compared the same two words, so it
passed.

The CPU arm was never affected: `cpu_state` is not inlined and its disassembly
stores all eight blocks through memory, 80 `aesenc` per iteration.

#### 2. Two independent ways to see it

**It exceeded the hardware's ceiling.** An RTX 3050 has 20 SMs, each serving 32
four-byte shared-memory loads per clock at about 1.78 GHz, so about 1.14e12
loads/s. A T-table round needs 16 lookups, so the ceiling is about 7.1e10
rounds/s with no bank conflicts at all. F78 published 9.04e10.

**Changing only the output moves the rate by the predicted 4x.** Same session,
same machine, the only edit being that every kernel folds all 32 state words:

| arm | `s[0] ^ s[31]` | all 32 words | ratio |
|---|---|---|---|
| `__constant` | 4.883e9 | 1.210e9 | 4.04x |
| `__local` | 9.349e10 | 2.351e10 | 3.98x |
| four tables in `__local` | 9.354e10 | 2.352e10 | 3.98x |

#### 3. The corrected figures

The repository `t_aes` now folds every word on both sides. 7950X at 30 threads
against the RTX 3050, peaks interior, gate MATCH on all three arms:

| table placement | rounds/s | CPU better by |
|---|---|---|
| `__constant` | 1.218e9 | 79.9x |
| `__local` | 2.336e10 | **4.16x** |
| four tables in `__local` | 2.339e10 | 4.16x |

A scratch run of the same change read 4.37x, so call it **4.2 to 4.4x**.

#### 4. What it changes

- **P3 is not void.** AES is a gate of about 4x against a competent T-table
  kernel on this pairing. It is still an upper bound: bitsliced AES has no
  tables and was not tried.
- **F78's headline sentence, "the AES contributes nothing at all", is
  withdrawn.** The core's ~10.7x in F78 section 2 is mostly this 4x, which
  removes the need F78 section 5 saw for a capacity mechanism to explain it.
- **F78's whole-nonce 3.04x and core ~10.7x stand.** `nerva-gpubench` writes
  every pad word to global memory and folds all 32 finalize words into its
  output, so nothing in it is dead.

#### 5. The lesson

**An output that reads part of a state made of independent lanes lets the
compiler delete the rest, and a correctness gate on the same partial output
cannot see it.** GPU compilers do this routinely. Fold every word of every lane
into the output on both sides, and check any rate against the device's
theoretical ceiling before believing it. F80 is the same defect in a second
harness.

### F80. `t_hc128` consumed one keystream word in sixteen; with all sixteen the reseeds are not the GPU mechanism

*2026-10-07. Transcripts `results/hc128-allwords-2026-10-07.txt` (corrected)
and `results/hc128-wordzero-same-session-2026-10-07.txt` (the old harness,
re-run in the same session as the control).*

#### 1. The defect

Both kernels accumulated `acc ^= ks[0]` after each 16-step block. In emit mode a
step's only effect beyond updating `P[i0]` is `ks[j] = t3 ^ P[i0]`, where `t3`
is two Q-table lookups, so words 1 to 15 were dead on the card and their
lookups could be dropped. The CPU's `HC128_NextKeys` lives in `hc128.c`, a
separate translation unit, and always computes all sixteen. Every row with
keystream in it was biased toward the card, more so as keystream grew.

#### 2. Same session, old harness against corrected

7950X at 30 threads against the RTX 3050, state in `__global`:

| NextKeys per Init | GPU worse by, `ks[0]` only | GPU worse by, all 16 words |
|---|---|---|
| 0, pure key setup | 7.56x | 7.52x |
| 10 | 6.76x | 7.62x |
| **40, shipped** | **5.90x to 6.04x** | **7.77x to 7.79x** |
| 160 | 4.05x | 7.74x |
| 640, keystream dominated | 3.40x | 8.29x |

The two agree at `nextper` 0, where there is no keystream to skip, which is the
control. The old harness reproduces F76's curve; the corrected one is **flat**.

State in `__local`, shipped mix: **3.11x** (the old harness gave 2.87x in the
same session and 2.92x in F78). At pure key setup both give 3.23x.

#### 3. What it changes

- **F76's mechanism finding and F64's amortisation argument are refuted on this
  harness.** Keystream generation is as GPU-hostile as key setup, about 7.5x to
  8.3x in `__global` and about 3.1x to 3.2x in `__local`. What the card
  struggles with is the 4 KB per-instance state, which is F62's original reading.
- **The reseeds buy about 1.04x of the gate in `__local`**, not 1.13x (F78) or
  1.36x (F76). F76's "defend them" loses its GPU reason; their other job, making
  the index stream depend on data already read (F60 section 5), is untouched.
- **F60's lever 1 is no longer priced against the GPU gate.** Fewer reseeds
  would take the fill to 0.27x to 0.35x of its cost on a CPU (F60, F67) while
  keeping the cipher ratio. What it would still cost: the gather becomes a
  larger share of the fill and a card is better at gather (F66), and the
  precomputation argument needs restating. A lever to evaluate, not a decision.

#### 4. The caveat that still points the other way

The kernels give each work-item a contiguous 4 KB block, so in `__local` every
lane of a work-group strides through the same banks, and the measured peak at a
work-group of 4 fills 4 of 32 lanes. An interleaved layout was not tried.
**3.11x is an upper bound for that reason**, no longer for the DCE one.

### F81. The B2 seed used two of the fill's eight AES lanes, so a feeder needed a quarter of the fill

*2026-10-07. A consensus change to v14's chain entry, made because v8 has never
validated a mainnet block. Verified as listed in section 3.*

#### 1. The defect

`aes_pseudo_round` encrypts each of the eight 16-byte blocks of `text`
independently under one key, so the 1 MB fill is **eight separate chains** of
8,192 dependent steps. `CN_V8_FETCH_SALT` handed `text` to the callback and
`v14_fetch_salt` keyed HC-128 from its first 32 bytes, which are lanes 0 and 1
alone. The salt and every draw were therefore a function of two lanes: a device
producing salts needed 16,384 AES pseudo-rounds per candidate, not 65,536.

PLAN-v8 Phase 6 B2, the comment in `hash-ops.h` and the one at the call site all
say the seed requires the whole fill. It required a quarter of it.

No test could see it. HW == SW compares two arms that do the same thing; the
known-answer vectors pass no callback; `t_v8_grid` compares arms with each
other; and `t_v8_chain`'s check that the seed moves with `init_size_blk` passes
either way, because changing the width changes lanes 0 and 1 too.

#### 2. The fix

The seed is now every byte of `text` folded into 32, byte-wise, `seed[i & 31] ^=
text[i]`. Every lane reaches the seed. Byte-wise means both arms and both byte
orders compute the same bytes, and the loop runs to `init_size_byte`, so it
cannot read past `text` at any width. Cost: 128 XORs per nonce.

#### 3. How it was checked

- **The 13 existing vectors are byte-identical**: the generator's v10, v11, v13
  and v14 tables match `slow-hash.c` exactly. The fold reaches only the chain
  entry, which those vectors never called.
- **A new chain-entry vector pins the seed and the hash.** It runs
  `cn_slow_hash_v14_chain` with `cn_selftest_salt` and compares both the 32-byte
  seed handed to the callback and the digest. `t_gen_kat.c` emits it.
- `t_kat` passes on hardware dispatch and with `NERVA_FORCE_SOFTWARE_AES=1`.
- `t_v8_grid` passes all checks and its digest is unchanged at
  `09d34831c25f506c`, as it must be, since it hashes through the plain entry.
- **The new vector fails when the fold is reverted**, in a scratch copy of
  `src/crypto`, while HW == SW still passes: exactly the gap it closes.

#### 4. What it does and does not change

v14's chain entry computes a different hash, so every testnet node has to be
rebuilt, and C-5's testnet round, already owed for D1 and D3, now covers this
too. It makes B2's stated property true; it does not make it large, since F79
puts AES at about 4x against a card.

### F82. `t_v8_fill`'s hot arm is a floor only at the shipped odds; rejection sampling is about 40% of what F60 and F67 booked as memory at odds 256

*2026-10-07. One run of each arm set, 7950X, height 4.5M, 8 s, quiet machine.*

`t_v8_fill` claimed every arm does identical cipher work. It does not.
`HC128_U32` masks to the next power of two and redraws on overflow: a
full-history pick accepts `height / 2^ceil(log2 height)`, 53.6% at 4.5M, and a
window pick accepts 76.3%. An arm with more full-history picks draws more
keystream and runs more `HC128_NextKeys` before it touches any memory. F69 found
the same mechanism from the height side.

A scratch copy with the hot arm drawing at odds 256, so it is the cipher floor
for the all-history arm:

| | ms per fill |
|---|---|
| hot arm, odds 13 (the shipped floor) | 0.7299 |
| **hot arm, odds 256** | **0.7893, +8.1%** |
| all full history | 0.8706 and 0.8783 |
| shipped, 13 of 256 | 0.7532 and 0.7425 |

Of the all-history arm's increment over the shipped floor, about 0.14 ms, about
**0.059 ms is cipher and 0.089 ms memory**. Memory at odds 256 is about 10% of
the fill, not the 17% to 29% F60 section 2 reports.

**What it changes:**

- **C-7 roughly halves.** The pre-registration modelled D3's whole CPU increment
  as memory a card barely pays. A card pays the rejection draws too. Recomposed
  with `c7-composed.py`'s inputs, cipher at odds 256 is about 759 us and memory
  about 143 us: with HC-128 at 12.1x as the prereg used, 11.43x goes to 10.25x,
  **-10.3%** rather than -17%; with F80's 3.11x, 2.95x goes to 2.69x, -8.7%. The
  direction favours D3 and the decision is unchanged.
- **F67's "physically impossible" is not.** Window-only at odds 0 draws less
  keystream than the odds-13 hot arm, so it can legitimately come in under it.
- **The measured totals are unaffected**: C-2, C-3 and C-4 used totals, never
  the split.

The harness comment is corrected. A permanent per-odds floor arm is the clean
fix and is not added here, since it changes the arm table the pre-registration's
runs were taken with.

### F83. Non-outsourceable PoW cannot be added to v8, its weak form is defeated for free on Nerva, and it is not pursued now

*2026-10-07. A desk study, no measurement. Checked against Miller et al. 2015,
read in full, Chepurnoy and Saxena 2020, Ergo's documentation, and Nerva's
reward constants in the source. Full write-up, sources and our own analysis
marked as such: [NONOUTSOURCEABLE-POW.md](NONOUTSOURCEABLE-POW.md).*

F71 named non-outsourceable PoW as the real answer to thin-client pools. It was
studied as a possible pivot, against the bar that a worker who steals a block
cannot be identified by the pool.

- **The weak form fails that bar by its own paper's account.** The pool
  watermarks the nonce space, a stolen block names the worker, and the
  punishment needs a held balance of one reward, **0.3 XNV**
  (`FINAL_SUBSIDY_PER_MINUTE`), which any payout threshold already holds. Nerva
  having no smart contracts does not help: a pool can hold the collateral
  itself. Ergo shipped this form and removed it at block 417,792 in 2020.
- **The strong form cannot wrap v8.** Its zero-knowledge proof must contain the
  puzzle's whole verification, and v8's is a 1 MB AES fill, 16,384 pad reads and
  a 237 MB chain fill. The paper's security theorem also needs the keyed work to
  dominate, or the operator keeps the key and outsources the keyless part. Both
  point to a new, circuit-friendly puzzle family, which works against goal 1.
- **Even the strong form is one-shot.** A pool can still evict persistently
  unlucky workers, and at 1,440 blocks a day a 1% worker can steal only about
  10% unseen over 30 days (our model). The paper's fix is jackpot-tier rewards,
  an emission change for Nerva. Its 2015 proof time, under 15 s, was justified
  by Bitcoin's 10-minute blocks; at 60 s it is a quarter of the interval.

**Decision: not pursued now.** Nerva has no known pools, so miners already
solo-mine. The write-up ends with three kill criteria (proof latency, the
scratch loop's GPU ratio, statistical detection) for a spike if it is revisited.

### F84. Reseeding every 16th block instead of every block makes a nonce 1.55x cheaper to mine and widens the GPU gap; four of five pre-registered criteria pass on the 7950X

*2026-10-07, against [RESEED-PREREG.md](RESEED-PREREG.md), which was committed
before any of this ran. 7950X and RTX 3050, the user's miner stopped, load 2 to
8%. Transcripts: `results/reseed-fill-7950X-2026-10-07.txt`,
`results/reseed-gpubench-run1-2026-10-07.txt` and `-run2-`,
`results/reseed-hc128-2026-10-07.txt`. C-4 needs the i7-7700HQ and is not yet
run.*

#### 1. The fill, single thread, odds 256

Two 30 s runs, arms interleaved, agreeing to 0.4%:

| k | key setups | ms/fill | vs k = 1 | model |
|---|---|---|---|---|
| 1, shipped | 257 | 0.891 | 1.000x | 0.851 |
| 4 | 65 | 0.484 | 0.544x | 0.477 |
| 8 | 33 | 0.409 | 0.460x | |
| **16** | **17** | **0.369** | **0.414x** | **0.383** |
| 256 | 2 | 0.328 | 0.368x | 0.354 |

The model was built entirely from earlier findings and lands within 5% at every
point it predicted.

#### 2. The criteria

| | measured | threshold | |
|---|---|---|---|
| **C-1** host-fed, CPU better by | **3.18x to 4.91x**, repeat 3.10x to 4.79x | must not fall | **pass** |
| **C-2** all-thread CPU, whole nonce | **1.558x**, repeat 1.547x | 1.30x | **pass** |
| C-3 card does everything, composed | **4.63x to 5.80x** | must not fall | **pass** |
| C-4 fairness, 7950X against i7-7700HQ | 1 thread **1.83x to 1.90x**; all threads **10.3x to 12.6x** | 2.50x | see section 5 |
| C-5 single-thread verify, whole nonce | **1.617x**, repeat 1.625x | 1.30x | **pass** |

C-1 and C-2 are from `nerva-gpubench`, where the k = 16 row runs the identical
GPU kernel as the shipped `v8 LDS-AES` row and only the host's fill changes. The
two GPU columns agree to 0.7% and 0.2%, which is the check that the CPU column
is the only thing that moved. Control drift 0.69% and 1.02%.

**C-2 came in under the model's 1.72x, as section "What could make the model
wrong" item 1 predicted:** at 32 threads the faster nonce asks for more random
reads and the memory system takes back about a quarter of the gain. It is a
quarter, not most of it.

#### 3. HC-128 is not quite flat, and the model's one wrong input

F80 found HC-128's GPU disadvantage flat across the reseed mix. In `__global`
that still holds and even rises (7.68x shipped, 8.22x at the k = 16 mix). In
`__local`, the placement that matters, it falls: **3.07x shipped, 2.80x at the
k = 16 mix.** Key setup and keystream are not equally GPU-hostile once the state
is in shared memory. The grid is flat at the top (work-group 4 holds from 65,536
to 1,048,576 items), so the peak is real.

C-3 uses the measured 2.80x, not the model's 3.11x: core 0.266 ms at 10.7x
(F72, F78), fill cipher at the measured ratio per mix, memory 0.09 ms at the
card's 1.64x advantage (F62, F82). That gives 4.63x shipped and 5.80x at
k = 16. With the flat 3.11x the model assumed it would have been 5.9x; the
correction costs it little because the cipher is a much smaller share of a
k = 16 nonce.

`t_hc128` itself had a defect, fixed before this run counted: its `__local`
loop was hard-coded to two mixes and silently skipped the third.

#### 4. What it means so far

**On the 7950X the lever does what the pre-registration predicted, in
direction and roughly in size.** A miner's nonce is 1.55x cheaper, a verifier's
1.62x, and a card's position worsens whether the host feeds it (+54%) or it
does everything (+25%). That is goals 1 and 4 improving together, which F60
section 7 named as the shape worth looking for, and it does it by removing work.

Still owed before a decision: C-4 on the i7-7700HQ, then the daemon change with
a known-answer vector. The batch-sort risk in the pre-registration is a model
and is not addressed by any of these numbers; k = 16 was chosen with it in mind.

#### 5. C-4 on the i7-7700HQ, and a criterion that was written badly

*2026-10-08. `nerva-gpubench 90 15 25` twice on the laptop, load 0%.
Transcripts `results/reseed-gpubench-laptop-run1-2026-10-08.txt` and `-run2-`.
The GPU rows failed with CL -4 on the 4 GB GTX 1050 Ti at 90% VRAM, which does not touch the CPU columns C-4 uses. The laptop's
fill sweep is `results/reseed-fill-laptop-2026-10-08.txt`, two runs agreeing to
0.3%.*

| | 7950X | i7-7700HQ | spread |
|---|---|---|---|
| 1 thread, shipped | 1.270 ms | 2.325 ms | 1.831x |
| 1 thread, k = 16 | 0.784 ms | 1.488 ms | **1.899x, +3.7%** |
| all threads, shipped | 15,467 H/s | 1,508 H/s | 10.26x |
| all threads, k = 16 | 24,013 H/s | 1,905 H/s | **12.60x, +22.8%** |

Each figure is the mean of the two runs. The 7950X gains 1.553x at all
threads, **the laptop 1.264x**.

**Single thread passes.** This harness reads the shipped spread as 1.83x where
F70's method reads 2.338x; carrying the +3.7% over to F70's basis gives
**2.42x against 2.50x**.

**The all-thread half of C-4 cannot be applied as written.** It compares a
16-core machine with a 4-core one, so the spread was already 10.26x before
anything changed and the 2.50x threshold fails at baseline. That is a defect
in the pre-registration, not a result. What the measurement does say is plain:
**the lever widens all-thread fairness by 23%**, because the laptop gains much
less than the desktop.

**The likely mechanism is L3 capacity, not chain memory.** The harness picks
each row's best thread count from 8, 6, 4 and 2: the laptop's shipped rows run
best at 6 to 8 threads, its k = 16 row at **4**. With the fill cheaper, a larger
share of each nonce is the core, whose 1 MB pad has to stay in cache, and the
laptop's 6 MB L3 holds about four. The 7950X's 64 MB holds all 32. This is the
small-L3 case the V6-MINER-LOG lessons left untested, and it is an inference
from the thread choice, not yet measured directly.

**The single-thread widening has a second cause: the key setups were an
equaliser.** The fill alone, one thread, mean of two runs on each machine:

| k | 7950X | i7-7700HQ | spread |
|---|---|---|---|
| 1, shipped | 0.891 ms | 1.718 ms | 1.93x |
| 4 | 0.485 | 1.023 | 2.11x |
| 8 | 0.409 | 0.904 | 2.21x |
| 16 | 0.369 | 0.833 | 2.26x |
| 256 | 0.328 | 0.762 | 2.32x |

The work k = 16 removes costs the laptop only **1.70x** what it costs the
desktop (0.885 against 0.522 ms), while what it keeps, keystream and memory,
costs **2.26x**. `HC128_Init` is a 4 KB table expansion that runs about as well
on a 2017 core as on a 2022 one, so cutting it removes the most uniform part of
the fill. The trade is smooth across `k`: every step that saves time also
widens the fill's spread, and there is no interval that buys one without the
other. In a whole nonce the core dilutes this to the +3.7% above.

#### 6. The 5600X: the widening is the laptop's, not the lever's

*2026-10-08. Ryzen 5 5600X (6 cores, 32 MB L3) with a Vega FE, the same
package run twice, each pass being two fill sweeps and two `nerva-gpubench`
runs. Pass a at 90% VRAM (the v5 and FP rows were starved, the rows used here
were not), pass b at 50%. One run (b2) read 8% load and is flagged in its
header; it agrees with the other three. Transcripts
`results/reseed-*-5600X-*-2026-10-08.txt`.*

| 5600X | shipped | k = 16 | |
|---|---|---|---|
| all threads, mean of 4 | 4,579 H/s | 7,358 H/s | **1.607x**, runs 1.593x to 1.614x |
| threads chosen | 12 | **12** | no drop |
| 1 thread, whole nonce | 1.441 ms | 0.887 ms | 1.624x |
| 1 thread, fill | 0.999 ms | 0.412 ms | 0.412x, as the 7950X's 0.414x |

Against the 7950X:

| spread | shipped | k = 16 | |
|---|---|---|---|
| all threads | 3.378x | 3.263x | **narrows 3.4%** |
| 1 thread, whole nonce | 1.135x | 1.132x | flat |
| 1 thread, fill | 1.122x | 1.116x | flat |

**The 5600X gains more than the 7950X, 1.61x against 1.55x, and keeps all 12
threads.** So the all-thread widening in section 5 is not a property of the
lever on CPUs below the top. It is a property of a machine whose L3 cannot hold
its own threads' pads once the core dominates: 6 MB against 32 MB, and the
5600X never had to drop a thread. The key-setup equaliser of section 5 does not
appear here either; Zen 3 and Zen 4 run `HC128_Init` and keystream in the same
proportion, so it is a Skylake-against-Zen effect.

**C-1 reproduces on a second vendor.** Host-fed, the Vega FE pairing goes from
the CPU being 1.42x better to **2.27x, +60%**, mean of four runs, against the
RTX 3050's +54%. GPU columns of the two identical-kernel rows agree within each
run.

#### 7. Where the criteria stand

C-1, C-2, C-3 and C-5 pass on the 7950X, and C-1, C-2 and C-5 pass again on the
5600X. C-4 passes at one thread (2.42x on F70's basis). Its all-thread half was
mis-specified and cannot be scored as written; read as a change, it widens 23%
against the i7-7700HQ and narrows 3.4% against the 5600X. The decision is the
user's, under the pre-registration's stated latitude, and goes in its decision
record.

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
7. ~~**The real cost of `get_cna_v6_data` against LMDB is unmeasured.**~~
   **Closed twice over.** F57 did the daemon-side split timing asked for
   here, over 1,005,568 nonces with v14 active: the fill is 56.2% of a
   nonce and the cold-pad correction is +3.3%. And the reason the question
   was being asked, to tighten an ASIC bound, no longer applies: F65 shows
   every `1 / (fill share)` bound is void against an ASIC, because the
   cipher that makes up the fill is near-free in silicon. The sentence "the
   real one should be more expensive and the bound stronger" was the
   intuition this project held for months, and it was backwards.
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
        src/crypto/slow-hash-v8-sw.c src/crypto/cna-vm.c \
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
