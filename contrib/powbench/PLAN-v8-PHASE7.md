# CNA v8, Phase 7: close the implementation gap, keep the resistance

> **A historical record.** Its pad decision (1 MB) stands. Its statement that
> v8 needs no consensus change was overtaken by Phase 8, which changed the hash
> (D1, D3) and, later, the reseed interval. For what v8 is now, read "Current
> state" at the top of [FINDINGS.md](FINDINGS.md).


What to change in v8 before HF14, derived from the v6 miner project rather than
from reasoning. Companion to [PLAN-v8.md](PLAN-v8.md), which has Phases 1 to 6,
and to [FINDINGS.md](FINDINGS.md), which has the evidence.

**The one-sentence answer: v8's implementation gap closes with code that is
already written, and v8 needs no consensus change.** The one design question
that looked genuinely open, whether the pad should be smaller than 1 MB, was
measured on 2026-10-06 and answered no (C1, FINDINGS F54 and F55). Everything
below is that statement with the work attached.

## Where this comes from

Branch `perf/v13-fused-pad-init` on `R0BC0D3R/nerva` took the live v13 (CNA v6)
miner from 597.6 to 3148.6 H/s on a 7950X at 30 threads, a 5.27x, and wrote
down why each step worked. The log is
[V6-MINER-LOG.md](V6-MINER-LOG.md), whose "Lessons for v8" section is the input
to this plan. Nothing here repeats the derivations; it cites them.

That branch is a strict descendant of `pow/cna-v8`, so every file referenced
below exists in both trees and the ports are cherry-picks, not rewrites.

## The deadline, and why it is softer than it looks

HF14 is height **4,500,000** (`cryptonote_config.h:254`), and that height is
still a **placeholder**. The last measured tip in this project was 4,424,749 on
2026-10-04, so at a 60 second target the placeholder is about 75,000 blocks
away, roughly 52 days. **Check the real tip before planning against this, and
check whether the height has been fixed yet.**

The placeholder can move, and that changes the risk calculus for Track C. The
decision rule is not "ship what fits before 4,500,000". It is:

> **There is no known schedule for a hard fork after HF14, so anything v8 should
> be is something v8 should be at HF14.** A consensus change that is right is
> worth moving the placeholder for. A consensus change that is rushed is not
> worth making at all.

So a Track C item is in scope if it can be measured properly and validated on
testnet the way Phase 5 was, and out of scope only if it cannot. That is a
measurement deadline, not a calendar one.

Tracks A and B have no deadline at all. Track A can ship after the fork and
still help, because it is bit-identical.

## The governing idea, and why Track A is the main line

The fairness problem is not the gap between our miner and the theoretical
maximum. It is the gap between a stock miner and a tuned one, because that gap
is what one person can hold privately. There are two ways to close it:

1. **Ship the optimization**, so everyone has it. Works whenever the
   optimization is bit-identical, costs no consensus change, and has a second
   payoff: the same code runs during verification, so sync gets faster too.
2. **Remove the attack**, so nobody has it. Needed only when the optimization is
   not something an honest miner should have to do.

v6 needed option 2 for screening, because screening is not an implementation
improvement, it is skipping work. v8 already closed screening by construction
(Phase 6 B2). **So for the implementation gap, what is left for v8 is almost
entirely option 1.**

That is separate from the design question in C1. The pad size is not a defence
against any attack found here; it is a choice about how much of each nonce is
hash core and how much is chain fill, and the v6 project is what makes that
choice measurable.

v6's own breakdown says how much is left. Of the 13.4x the external miner
reports on v6, the large multipliers are screening (3.06x), trace JIT (1.48x)
and virtual pad (1.51x), and **all three are VM properties that v8 does not
have**. v8's exposure to that toolkit is roughly the 1.4x of plain engineering,
which is exactly the part option 1 covers.

## The transfer table

Every v6 optimization, what it gave there, and what it means here. "Measured on
v8" means a harness was run against v8's own code, not reasoned from v6.

| v6 optimization | v6 gain | applies to v8 | action |
|---|---|---|---|
| fused pad init | +7.6% | no, v8 has no second salt pass to fold | none, checked not assumed |
| run-ahead `get_cna_v6_data` | +7.6% | **yes, shared function, larger share** | **A1, port it** |
| nonce screening | 2.17x | no, B2 closed it | verify with B1 |
| screen early exit, 8-wide screen | +21%, +9.1% | no, screening is closed | none |
| eight-lane HC-128 init | 2.55x on the init | yes in principle | A5, recommend against |
| recomputed final pass | +16.8% | structurally yes, economically no at 1 MB | A7, keep off, re-check in B2 |
| non-temporal fill | +22% | **measured on v8: 39% to 61% loss** | A6, keep off, do not ship |
| hoisted hashing blob | under 2% | yes, algorithm independent | A3, port it |
| thread affinity, huge pages | large, indirect | yes, already present | A4, audit only |

Two rows in that table are the reason this document is short. The two biggest v6
wins after screening, the non-temporal fill and the recomputed final pass, are
both **already defeated by v8's 1 MB pad**, and one of them was measured that
way rather than argued. That is a real defensive property, it was not designed
in deliberately, and Track B exists to find out how much margin it has.

## Track A: ship it. No consensus change, bit-identical output.

Every item here produces byte-identical hashes, so it is a verification speedup
as much as a mining one and carries no fork risk. Order is by measured value.

### A1. Port the run-ahead `get_cna_v6_data`. The single largest item.

`BlockchainLMDB::get_cna_v6_data` is **shared by v13 and v14**, so the rewrite
already running on mainnet in the v6 build is a v8 optimization that nobody has
noticed is one.

What it does, from `db_lmdb.cpp` on the v6 branch: `HC128_NextKeys` advances the
cipher independently of the message, and the keystream `HC128_U32` consumes is
data-independent, so all 64 pick indices and all 16 encrypting keystreams for a
sixteen-count block can be produced before a single block-cache entry is read.
The reads then carry no dependency on each other and issue together. The reseed
is the only step that depends on fetched data, and that is what bounds the
run-ahead at one block.

**Measured 1.57x on the salt.** Almost all of it is the restructuring: with
prefetching removed entirely it is still 1.53x.

Why it is worth more on v8 than it was on v6: the chain salt is **19% of a v13
nonce and 59.5% of a v8 nonce**. The 59.5% is confirmed three independent ways
(the instrumented profile, the external review's 63% unscreenable prefix, and
F52's 1.348 ms real nonce against `v8bench`'s 0.535 ms hash core).

**MEASURED 2026-10-06, and the prediction below missed by more than 4x. See
FINDINGS F57.** The fill speedup is 1.110x under v14, not 1.57x, because the
fork measured it under v13 where an 8 MB pad per thread leaves far more memory
latency to hide. A1 removes 5.8% of a v8 nonce, a 1.062x speedup, and it is
about a quarter the size of PLAN-v8-PHASE8's D1. It remains worth doing: it is
bit-identical, verified 64 of 64 against real chain data, and it speeds
verification for everyone. The prediction is kept below as written.

**Prediction, stated before measuring, per the discipline Phase 1e set:**

```
v8 nonce = 0.405 (hash core) + 0.595 (salt)
with the salt at 1.57x: 0.405 + 0.379 = 0.784
predicted speedup 1.28x, about +27%
```

That prediction is the thing most likely to be wrong here, and lesson 5 says
exactly why: a share taken from one context and applied to another has produced
a wrong prediction twice on this project already. The 1.57x was measured against
a synthetic block cache, while the daemon reads real LMDB with page-cache
misses, and F52 notes the daemon's fill figure is an upper bound from
subtraction. **Measure it on the daemon with A-B-B-A before believing any part
of this paragraph.**

It also applies to verification at the same ratio, because `get_block_longhash_v14`
pays the same fill. If the figure holds, **post-HF14 sync gets about 1.28x
faster** and that is the larger public benefit.

Port includes `NERVA_SALT_SELFCHECK`, the environment switch that computes the
old loop and the new one and compares all 256 KB plus the final cipher state
against real chain data. Keep it. It is what makes "bit-identical" a claim
rather than an assertion, and it costs one predictable branch per salt when off.

Gate: the v8 known-answer vectors and `cn_slow_hash_self_test` must pass
unchanged, and a mainnet resync past 4,320,000 must produce the same chain.

### A2. Page tier bug. Already fixed, confirm and close.

PLAN-v8 Phase A item 2 lists `cn_page_tier_for_version` sending
`major_version >= 13` to the 8 MB buffer. **It now reads `== 13`
(`slow-hash.c:263`), so this is done.** Strike it from Phase A.

Remaining, and carried over from the v6 project's open list: the miner reports
the page tier for **thread 0 only**. At 16 to 30 threads a per-thread fallback
to small pages would be invisible, and on the v6 rig the page tier was the
difference between two baselines 98% apart. It should report the worst tier
across threads. Cheap, and it is a measurement-integrity fix, not a performance
one.

### A3. Port the hoisted hashing blob.

`get_block_hashing_blob` reserialises the whole block for every candidate nonce
when only four bytes differ. Measured at 3,080 cycles per candidate on v6. The
v6 branch serialises once per template and patches the nonce in place, with
`NERVA_NO_BLOB_HOIST=1` forcing the old path so both sides are one binary, and
a fallback that warns if it cannot locate the nonce.

On v6 this was worth under 2% because a v6 nonce is enormous. **A v8 nonce is
1.323 ms against v6's roughly 18 ms single-threaded**, so the same fixed cost is
a larger share and it should be re-measured rather than inherited. This is
algorithm independent and belongs in the miner regardless of version.

### A4. Audit what Phase 6 already landed.

No new work expected, but confirm on this branch and record it, because three
of these are load-bearing for claims made elsewhere:

- sweep deferral (`slow-hash-v8-defer.h`), bit-identical over 1600 vectors,
  1.04x on a 7950X and 1.14x on an i7-7700HQ. Present.
- extra-hash memoization (`salt_hash_memo[4]` in `slow-hash-v8-impl.h`).
  Present. F45 says 26 of 30 extra hashes are redundant.
- `init_size_blk` pinned to 8 (`CN_V8_INIT_SIZE_BLK`). Present.
- salt seeded from the fill's final chain state (`CN_V8_FETCH_SALT`). Present,
  and it is the reason screening is closed.

### A5. Eight-lane HC-128. Recommend against building the batching.

`HC128_Init_x8` is built and verified bit-identical over 320,000 inits
(`hc128-x8.c`, `t_hc128_x8.c`), at 2.55x with gather on Zen 4 and 1.51x with
scalar extraction. Both forms are kept and selected at run time, because the
report this came from measured gather as the slower one on Zen 3.

It is not recommended because of the Amdahl gate: the init is **38.6% of the
salt**, so a 2.55x init buys 1.31x on the salt, and the integration cost is that
the miner must compute eight nonces at once, restructuring the mining loop and
the longhash entry point while the verification path keeps a scalar version.

**Two things would change that verdict, and both should be checked after A1
lands**, because A1 moves the denominator:

1. The run-ahead removes a large part of the `encrypt` component (37.4% of the
   salt, almost entirely `HC128_NextKeys`), which **raises the init's share**.
   If the init becomes most of what is left, the gate reopens.
2. The salt is 59.5% of a v8 nonce against 19% of a v13 one, so the same salt
   speedup is worth roughly three times more here. The v6 verdict was reached at
   a 19% share and does not transfer. Rule 7: when the balance changes, every
   "not worth it" is void, not stale.

So: re-run `t_salt_profile.c` against v8 after A1 and re-decide. Do not start
the batching before that number exists.

### A6. Non-temporal stores on the fill. Do not ship. This is the measured answer.

Streaming stores were added to the shared `expand_key()` in `slow-hash.h`,
behind the same per-thread switch v13 uses, verified bit-identical over 14
vectors spanning every variant, and measured A-B-B-A per thread count with the
salt snapshotted and restored per nonce so both arms hash identical work:

```
threads   pad total   ordinary stores   streaming stores   streaming is
   4        4 MB        2,697,270         6,810,160          -60.4%
   8        8 MB        2,638,065         6,838,888          -61.4%
  16       16 MB        2,986,368         7,035,463          -57.6%
  24       24 MB        4,000,884         7,347,284          -45.6%
  30       30 MB        4,646,828         7,666,864          -39.4%

cycles per nonce, 1.3M nonces total, 0 digest mismatches
```

The shape confirms the mechanism rather than only the verdict: the streaming arm
is flat at 6.81M to 7.67M because it always goes to DRAM, while the ordinary arm
climbs 76% as cache pressure grows. They converge and never cross inside the
usable range.

**Keep the switch, keep it off, and keep the measurement.** It is the tripwire
for B2: if anything ever moves v8's working set past the threshold, this number
flips sign and the attack arrives with it.

### A7. Recomputed final pass. Structurally available, economically a loss at 1 MB.

v8's pad is **98.5% reproducible on every nonce**, measured, not argued:

```
v8 pad 1 MB, 8192 blocks of 128 bytes
blocks the sweeps wrote, 2000 nonces at the consensus draw
  min 23   mean 89.6   max 222   of 8192
  1.09% of the pad written, 98.91% reproducible
  the 32 random-value pokes add at most 32 more, so at least 98.52%
```

So v6's recompute attack applies to v8 structurally, and it applies **more**
completely: on v13 a miner needs screening at 0.4% acceptance to find pads that
clean, while on v8 every nonce is that clean, because the sweep count is bounded
by the draw at (xx-1)*yy + iters, at most 119 operations against 65,536 slots.

It is not exploitable today only because the pad is in cache, so reading beats
regenerating by roughly 20x. **That 20x is an estimate from throughput figures,
not a measurement.** B2 is what turns it into one.

## Track B: measure the three claims v8's security currently rests on

These are the open items that matter. Each one is a claim the design depends on
that has never been checked against v8's own code.

### B1. Run the cost-predictability gate against v8. Highest priority.

PLAN-v8's fifth target is "cost estimable ahead, r < 0.1" and its open item 2
says it **has never been run for v8**. v6 measures r = 0.88 to 0.95 (F6) and
that single property is what the v6 project turned into a 2.17x on the daemon.
The claim that v8 closes it is sound reasoning (the draws come after a fill
whose keystream cannot be fast-forwarded, because `get_cna_v6_data` reseeds from
bytes it has already written) and it is still reasoning.

Why it is now cheap: the v6 project built the whole estimator stack.
`screen.c` is the oracle harness, `screen_grid.c` already times all 75
`(xx, yy, init_size_blk)` cells of v8, `t_v13_screenmine.c` is the end-to-end
daemon-side version, and the v6 work established what a believable answer looks
like.

v8 has no VM, so the estimator must be redesigned around v8's cheapest
predictor, and **that choice is the test**. It should be picked by review rather
than by whoever writes the patch. The candidates, in the order an attacker would
try them:

1. Any prefix of the fill. Should fail: the draws come after all 1 MB of it.
2. The salt's first block. Should fail: the draws come after all 4096 blocks and
   256 reseeds.
3. Abandoning after the fill, which is the only one with a real chance. A
   screener pays the full fill plus the full salt to learn `xx`, `yy` and
   `iters`, then decides whether to pay the hash core.

Item 3 is the one to measure, and the back-of-envelope says the margin is thin
rather than large. The fill is 59.5% and unavoidable, the hash core is 40.5% and
varies by F42's 3.7x. Paying 1.47 units of fill to avoid part of 1 unit of core
only wins while you reject a small fraction, roughly a quarter on a crude
calculation. **State the pre-registered threshold before running it: if a
screener's measured throughput gain exceeds 1.05x, Track C opens.**

F42 gives the ceiling this sits under: pinning `init_size_blk` cut the free-fill
screening ceiling from 2.15x to 1.59x, and the fill is not free.

### B2. Find where the two pad attacks switch on. STREAMING HALF DONE: it never switches on.

**Answered 2026-10-06 for the streaming arm, F55.** 21 points from 0.06x to
3.87x over-subscription, six pad sizes, three thread counts: the sign never
flips. The framing of this item, "in ratio terms", is itself refuted. The ratio
is not the governing variable; pad size and thread count act independently and
in opposite directions. The recompute arm is still unbuilt.

The item is kept as written below because it is what the work was done against.

This is the measurement that tells us how much margin v8 has and it is the one
this project is best equipped to run.

What is known. Both A6 and A7 are held off by one property: the working set not
exceeding L3 by much. The threshold is **not** at 1.0x. Measured on two
machines:

```
                      pads     L3      ratio    streaming store is
v8, laptop, 2 threads   2 MB    6 MB    0.3x      -7.3%
v8, laptop, 8 threads   8 MB    6 MB    1.3x      -6.5%
v8, 7950X, 30 threads  30 MB   64 MB    0.5x     -39.4%
v13, 7950X, 30 threads 240 MB  64 MB    3.8x     +22%
```

Exceeding L3 by a third changes nothing and does not even trend. The sign flips
somewhere between 1.3x and 3.8x and nobody knows where.

**A correction to make first.** Those ratios count pads only. v8 also holds a
**256 KB salt per thread**, so the real per-thread working set is 1.25 MB, not
1 MB, and every v8 ratio above is 25% low. The laptop at 8 threads is 1.67x, not
1.3x. Recompute the table before using it.

How to measure the threshold without owning the machines: the tree already
supports resized v8 builds through `v5pad.inc` and the `CN_SCRATCHPAD_MEMORY`
override, which is how the Phase 3 pad sweep was run. Sweep the pad at **256 KB,
512 KB, 1, 2, 4 and 8 MB** on the 7950X at 30 threads, which spans 0.23x to 4.7x
of over-subscription including the salt, and run both attacks at each point:

- the A6 streaming-store A/B. **Built 2026-10-06**: `t_v8_nt.c` and
  `build-v8-nt.sh`, sweeping all six sizes in one run and printing the working
  set as a ratio to the L3 the operator supplies. It carries a **split-half
  check**, the same ratio recomputed from the first and second halves of each
  point's own window, which is what says whether the window was long enough.
  The fork's version ran a fixed 20 s a point by guess; the halves converge to
  within 0.4 points at 1.5 s, so that was roughly 13x longer than needed. A
  point whose halves disagree is marked UNSTABLE and wants repeats rather than a
  longer window, because at the cliff the variance is bimodal and a longer run
  averages two states instead of resolving either.
- the A7 recompute, which needs `t_v13_recompute.c` adapted to v8's fill and
  v8's dirty-block map, and `t_v8_dirty.c` already produces the map

The two sizes below 1 MB are new and they are the point of C1. See there for
what has to change in the harness to produce them; it is small.

The deliverable is a single number: **the over-subscription ratio at which a
v8 attacker starts winning.** With it, the pad rule stops being a judgement and
becomes arithmetic, and the same number says which real machines are already
close. A machine with 8 MB of L3 running 12 threads is at 1.9x today.

Second deliverable, free with the first: whether the laptop's 6 MB L3 at 8
threads is actually safe, since it is the closest real machine to the line and
it is the machine the fairness target is set by.

### B3. GPU T-table AES against the chained fill. The load-bearing assumption.

v8's GPU resistance and Phase 6 B2's feeder resistance rest on the **same**
assumption: that AES-NI beats T-table AES by enough. RESULTS.md section 6.3
already warns that v5-class resistance "disappears the day a GPU gets
competitive AES". PLAN-v8 flags this as the open question and does not measure
it.

The specific quantity: a feeder that wants to hand a CPU the 256 KB salt now has
to run 1 MB of **chained** AES per candidate first, roughly 655,000 software
block rounds. The chaining means no parallelism inside a nonce, only across
nonces, and a GPU has plenty of nonces. So the question is purely throughput:
**how many 1 MB chained T-table AES fills per second does a modern GPU do, and
what does that do to F46's measured 1.95x feeder advantage?**

**Run it at 1 MB and at 512 KB**, because C1 cannot be decided without the second
point. The gate is proportional to the fill, so the question is not only whether
a card is competitive today but how much margin halving the fill gives away.

`contrib/powbench` already has the OpenCL harness and `vm_kernels.cl.h`. The
honest caveat, carried from RESULTS.md and FINDINGS open question 5: no GPU
number from this project is trustworthy at full occupancy, because a
display-attached card trips TDR and every large-pad row hit the launch cap. This
measurement is 1 MB per nonce and below, which is the size that ran clean
before, so it is the one GPU question this harness can actually answer.

**Two things from the measured v6 hybrid that change how this should be
scoped**, both from `NERVA-ALGO-OPTIMIZATIONS.txt` section 7:

1. **The 234 MB block cache already lives in VRAM on that miner**, uploaded
   incrementally per height. So "the card cannot hold the chain history" is not
   an available argument and should not appear in any v8 reasoning. The history
   fits on a consumer card today, and it is the AES fill gate alone that stops a
   card producing v8 salts.
2. **The hybrid's card does one salt iteration per nonce, not 4096.** It never
   needed the full salt, because v6's oracle let it decide after 1/4096 of one.
   That is the measurement that should be repeated for v8: not "can a card do
   the salt", which it evidently can, but **what a card pays for a full
   `get_cna_v6_data` plus the chained AES fill that B2 now puts in front of
   it.** That single number is the whole of v8's GPU story.

### B4. Split `get_block_longhash_v14` timing in the daemon.

FINDINGS open question 7, and it is now cheap because A1 touches that exact
path. Time the chain fill and the hash core separately inside the daemon rather
than subtracting two different harnesses. It settles three things at once:

- F38's ASIC bound, currently 1.6x from a modelled fill against a synthetic
  247 MB cache. The real fill should be more expensive and the bound stronger.
- F52's decomposition, currently an upper bound by subtraction.
- Exactly where sync time goes after HF14, which is the number anyone reviewing
  the fork will ask for.

Use the `CN_V13_PHASE_TIMING` pattern from the v6 branch, and note its known
trap: **defining that macro makes every v10 and v11 known-answer vector fail
while v13 and v14 pass**, mechanism never found, recorded as open. Build the v8
equivalent as a separate macro and run the known-answer test with it defined
before trusting any number it produces.

## Track C: consensus changes

One of these is a live question to be settled by measurement (C1, the pad size).
The rest are either already settled against or gated on a Track B result that
does not exist yet, and are written down so that a surprise has a prepared
response rather than a rushed one.

## C1. The pad size, reopened downward. ANSWERED 2026-10-06: it stays at 1 MB.

**Measured, decided, closed.** C-1 wanted a 20% improvement in multi-thread
spread at 512 KB and got 10.01%. C-2 failed outright: the smaller pad makes the
streaming-store attack slightly *less* unattractive, not more. Evidence in
[FINDINGS.md](FINDINGS.md) F54 and F55, decision record in
[PAD-DECISION-PREREG.md](PAD-DECISION-PREREG.md).

**Two claims below are wrong and are marked where they appear rather than
deleted**, because a withdrawn number outlives its correction:

- **C1.2's "the lesson 9 attack margin roughly doubles" is wrong in sign.** The
  margin shrinks, 42.5% to 39.2%. Measured in F55.
- **C1.2's fairness projection was optimistic on every axis.** The mechanism is
  real, the laptop does gain more than the desktop, and the gain is about half
  what was claimed.

The structural argument in C1.1, that 512 KB is the only size in range whose
stride modulus is prime, stands and was never the deciding factor. It is kept
because it is the kind of argument that should be made before measuring, and
because it correctly excluded 768 KB without a run.

The rest of this section is kept as written, as the case that was tested.

### C1.0. The premise to correct first: 1 MB is an endpoint, not a minimum

F24 and F27 swept **1, 2, 4 and 8 MB**. Nothing below 1 MB was measured, in
either document or in RESULTS.md. So 1 MB is the smallest point in the sample,
and every trend in that sample points off that end:

- single-thread fairness: 1, 2 and 4 MB within noise, 8 MB far worse
- multi-thread fairness: 11.3x at 1 MB, 19.6x at 2 MB, 23.8x at 4 MB
- ARM (F31): spread worsens **monotonically** with pad size
- verify cost: roughly linear in pad size

The Phase 3 decision was correctly "1 MB beats everything we tried". It was
never "1 MB is the bottom of a bowl", and nothing in the tree brackets the
minimum from below. When every curve is monotonic toward the edge of the
sample, the optimum is usually outside it.

### C1.1. The floor is 256 KB, and 512 KB is structurally the better of the two

The pad and the salt stride are coupled. `CN_V8_SALT_STEP` is
`CN_SCRATCHPAD_MEMORY / CN_SALT_MEMORY` and the static assert in
[slow-hash.h](../../src/crypto/slow-hash.h) requires the pad to be a whole
multiple of the 256 KB salt, because the sweep consumes one salt byte per
`offset_2` pad bytes and the worst case has to land on `CN_SALT_MEMORY`
exactly. Below 256 KB the sweep reads past the salt, so **256 KB is the floor**
without redesigning the coupling.

512 KB and 256 KB both satisfy everything else: a power of two for
`state_index`'s mask, a multiple of 128 for the AES fill, and
`CN_V8_SALT_STEP` inside [1, 128].

There is a difference between them that is not obvious and that decides which
one to prefer. `CN_V8_STRIDE_MOD` is `129 - step`, and
`offset_2 = (temp_1 * offset_1) % MOD + step` where `offset_1 = (d % 64) + 1`,
so `offset_1` ranges over [1, 64]:

| pad | step | stride modulus | offset_2 range | degenerate when |
|---|---|---|---|---|
| 1 MB | 4 | 125 (5³) | [4, 128] | `offset_1` divisible by 5, 19% of draws |
| 512 KB | 2 | **127, prime** | [2, 128] | **never** |
| 256 KB | 1 | 128 (2⁷) | [1, 128] | `offset_1` even, 50% of draws |

At modulus 128 any even `offset_1` forces an even product and therefore an odd
stride, and `offset_1 = 64` collapses the stride to two possible values out of
128. At modulus 127, a prime larger than the largest `offset_1`, the product is
never degenerate. **512 KB has strictly better stride entropy than the shipped
1 MB, and 256 KB has meaningfully worse.**

That is not load-bearing for security while B2 keeps screening closed, since
stride entropy feeds the cost spread rather than the predictability. It is free
quality, and it picks 512 KB as the candidate if this is pursued at all.

### C1.2. What gets better

**The ASIC bound tightens, on the axis F38 says governs.** F38's rule is that
work added to the hash core helps the specialised attacker and the chain fill is
what does not. The contrapositive is what matters here: **work removed from the
hash core hurts them.** The chain salt does not change with pad size at all, so
shrinking the pad raises its share and squeezes the Amdahl bound:

```
                      salt share     ASIC bound, hash free
1 MB    measured          59.5%              1.68x
512 KB  estimated          ~69%              ~1.45x
256 KB  estimated          ~76%              ~1.32x
```

**The two lower rows are arithmetic off the instrumented profile, not
measurements.** They come from how each component scales: the salt, the extra
hashes and `randomize_scratchpad_256k_v8` do not shrink at all (the last runs
exactly 262144 iterations at every pad size, which is F23's invariant); the fill
and finalize shrink linearly; the sweeps shrink as pad times E[1/stride], which
is sub-linear because smaller strides enter the range. E[1/s] is 0.0288 at
1 MB (matching F22), 0.0349 at 512 KB and 0.0424 at 256 KB. Predicted nonce
cost falls about 1.16x at 512 KB and 1.27x at 256 KB.

**The lesson 9 attack margin roughly doubles.** Per-thread working set goes from
1.25 MB to 0.75 MB. The laptop, the closest real machine to the line, drops from
1.67x over-subscription to 1.0x, and both pad attacks move further from
switching on.

> **WRONG, and wrong in sign. Measured 2026-10-06, F55.** The streaming attack
> gets *less* unattractive at a smaller pad, 39.2% against 42.5%, because its
> cost is evicting the pad and that penalty is linear in pad size while the
> nonce is not. The over-subscription ratio is also not the governing variable:
> three points at the same ratio differ by 19.8 points. This paragraph is the
> reasoning C-2 was written to test, and C-2 failed it.

**The missed fairness target is the strongest case, and it reads straight off
F27's own table.** F27 identifies the mechanism as "how many threads each
machine can fit in L3", and that mechanism **has not saturated at 1 MB**: the
laptop fits 4 of its 8 threads and amplifies 3.4x, against the 7950X's 18.6x,
and that gap is what produces the 11.3x multi-thread spread. At 512 KB the
laptop fits all 8 threads while the 7950X already fits all 32 and gains only the
per-nonce saving. A crude projection puts the spread near 8x. **That is the one
target v8 misses**, and it is missed on the axis where "1 CPU = 1 vote"
actually lives.

That projection is arithmetic layered on arithmetic and lesson 5 exists to warn
about exactly that. The mechanism underneath it is measured; the magnitude is
not. The harness that settles it already exists and runs in an afternoon.

**Verification and sync get cheaper** by about the same ratio the nonce does.

### C1.3. What gets worse, and why "GPU resistance" is not one axis

The first draft of this section said "shrinking the pad is better against ASICs
and worse against GPUs". **That is too coarse and the counterexample is the
measured GPU hybrid on v6.** There are three distinct GPU attacks, pad size
moves them in different directions, and they have to be separated before any of
this means anything.

| GPU attack | what it needs | bigger pad | smaller pad |
|---|---|---|---|
| **pad avoidance** (the v6 hybrid) | a cheap cost oracle, and a pad worth not materialising | **worse for us**, the prize scales with the pad | better for us |
| **feeder** (salt offload, F43/F46) | a cheap salt seed | better for us, B2's gate is the fill | **worse for us**, the gate shrinks with it |
| **whole hash on the card** | competitive AES, and occupancy | better for us, fewer resident nonces | **worse for us**, more resident nonces |

#### Pad avoidance, and why the v6 hybrid is evidence for shrinking

0xROOTPLS's GPU hybrid gets +74% on a 5900X with an RX 6800 XT and +80% on a
5600G with an RTX 5060 Ti, on v6, whose pad is 8 MB. The obvious reading is
"8 MB pad, big GPU gain, so a big pad is bad against GPUs". **The obvious
reading is right, and the mechanism is more specific than it looks.**

Read what the card actually does. It screens for "the ~1 in 950 whose VM never
touches the pad" and returns the seed and the VM's final registers; the CPU then
hashes those with a no-pad routine, running the fill and final AES chains side
by side with **no pad, no checkpoints and no VM**, two AES chains instead of
three. The card never materialises an 8 MB pad. Its kernels run the VM with no
pad at all, and the only salt work it does is **one** iteration out of 4096,
which is exactly what v6's broken cost oracle exposes.

So the hybrid is not a memory attack. It is the screening attack with the
screen moved to a card, and **its prize is proportional to the pad, because the
prize is skipping the pad.** At 8 MB there is a great deal to skip. At 1 MB
there would be much less, and the same hybrid would be worth correspondingly
less.

That is a genuine data point on the side of a smaller pad, and it is the
strongest one in this document, because it is a measured attack on a live
algorithm rather than a projection.

Two reasons it does not settle C1 on its own:

1. **Both of its preconditions are already closed on v8.** The cheap oracle is
   gone (Phase 6 B2, and B1 is the gate that verifies it), and there is no
   zero-touch nonce to hunt: both AES passes and every sweep touch the whole pad
   on every v8 nonce, so the no-pad hash the CPU side depends on does not exist
   at any v8 pad size. The attack's pad-size sensitivity is therefore
   **latent on v8, not live**. It becomes live only if B1 comes back above
   1.05x, and then pad size is the second thing to fix, not the first.
2. It is the same mechanism as lessons 7 and 10, which already say this in
   non-GPU terms: v8's pad is 98.5% reproducible, so the pad is avoidable in
   principle on v8 too and only the cache economics stop it. Those economics are
   what B2 measures. **If they ever flip, the hybrid's shape is what the attack
   would take, and it would scale with pad size.** That is an argument for a
   smaller pad and it is the same argument as C1.2's attack-margin point, not a
   separate one.

#### Feeder, which is the one that genuinely argues for a bigger fill

**Phase 6 B2's feeder gate is proportional to the fill.** The entire point of
seeding the salt from the fill's final chain state is that a feeder must run
1 MB of **chained** AES per candidate before it can produce a salt, roughly
655,000 software block rounds against a GPU with no AES instruction. At 512 KB
that gate is halved and at 256 KB quartered. F43 and F46 put the unmitigated
feeder advantage at 1.95x, and the fill is the only thing standing against it.

The hybrid makes this *more* pressing rather than less, and this is the part of
the document most likely to be misread. It records that **the 234 MB block cache
lives in VRAM, uploaded incrementally per height.** The block cache is the whole
chain history, 4.42M entries, and a consumer card holds it comfortably. So
nothing stops a card from doing v8's chain salt: HC-128 is integer work and the
database fits. **The only thing standing between a card and the 59.5% of a v8
nonce that the chain salt occupies is B2's AES fill gate**, and that gate is
exactly what shrinking the pad shrinks.

That also puts a caveat on F38's ASIC bound, which argues that accelerating the
fill is "a server rather than a chip". At 236 MB it is neither; it is a GPU with
ordinary VRAM. The argument survives for an ASIC at ASIC-scale rates and should
not be quoted at GPU scale without that qualification.

#### Whole hash on the card, which is unmeasured in this regime

Every GPU figure in this project is at 1 MB or above, and the large-pad rows ran
starved against the launch cap. At 256 KB a pad starts being plausible to hold
in a card's on-chip memory, which is the cache-hard-not-memory-hard failure mode
in the attacker's favour, and smaller pads raise resident-nonce counts directly.
This is B3's territory and B3 has never run. **B3 is therefore a gate on C1, not
a parallel item**, which is a change from where this plan first put it.

#### Where that leaves the trade

Corrected, and this is the version to carry forward:

> Shrinking the pad is better against ASICs and better against the pad-avoidance
> attack the v6 hybrid demonstrates. It is worse against the feeder and against
> a card running the whole hash. The ASIC side is measured, the pad-avoidance
> side is measured on v6 but closed by construction on v8, and the two that
> argue against are both unmeasured at any pad size.

So the honest state is that **three of the four arguments have evidence and the
one that is currently load-bearing does not.** B3 is what fixes that, and it is
why C1 cannot be decided without it.

**Pool resistance is unchanged**, and that is worth stating because it is the
property most worth protecting. The salt stays 256 KB, F23's invariant holds at
every size down to the floor so every salt byte is consumed every hash, and
`CNA_V6_WINDOW_BLOCKS` and `CNA_V6_FULL_HISTORY_ODDS` are untouched. If anything
it strengthens in relative terms, since the database read becomes a larger share
of a cheaper nonce.

Minor: at 256 KB each thread's pad is one eighth of a 2 MB huge page, so
huge-page consumption stops tracking useful memory. Already true of the salt.

### C1.4. How to build the sub-1 MB rows. Small, and here are the three details.

`contrib/hf14checks/v5pad.inc` is the resize template and it already does
everything needed. Two new units, matching the existing `v5pad1.c` pattern:

```
v5pad05.c    V5PAD_TAG p05    V5PAD_BYTES (512 * 1024)
v5pad025.c   V5PAD_TAG p025   V5PAD_BYTES (256 * 1024)
```

Both are powers of two, so neither needs `V5PAD_MOD`. Three details that will
otherwise cost a day each:

1. **`V5PAD_SALT_WRAP` must become the identity below 1 MB as well.** It is
   currently `#if CN_SCRATCHPAD_MEMORY == 1048576`. The wrap is a provable
   no-op at every size **at or below** 1 MB, because v5's minimum stride is 4
   so the salt index tops out at pad/4, which is 262144 only at exactly 1 MB.
   Left as written, the sub-1 MB v5 rows carry an AND that the control row does
   not, which is precisely the asymmetry the comment in that file records as
   having already overstated v8 by 3 to 5 points once. Change it to
   `<= 1048576`.
2. **`v8bench.c` needs the rows and the declarations.** Add
   `cn_slow_hash_v11_p05` / `_p025` and `cn_slow_hash_v14_p05` / `_p025` to the
   extern block near line 239, and two entries to the pad table near line 938.
   Raise the iteration counts for the new rows: the table already scales them
   inversely with pad size (4000 at 1 MB down to 800 at 8 MB) because the
   shorter the nonce the noisier the row, and these are the shortest nonces in
   the sweep. Start at 8000 and 16000 and check the reported spread.
3. **`build-v8bench.sh` needs the two files in its source list**, next to
   `v5pad1.c` through `v5pad8.c`.

No consensus file is touched to produce the measurement. Changing the shipped
pad afterwards is a one-constant change to `CN_SCRATCHPAD_MEMORY_V8`, plus
regenerating the v14 known-answer vectors, which is a deliberate act that must
be stated in the commit (see the note at the end of FINDINGS.md: generate the
v10/v11/v13 tables from master, never from a branch that touches those
algorithms).

### C1.5. What has to be true to change the pad

**Done, 2026-10-06: [PAD-DECISION-PREREG.md](PAD-DECISION-PREREG.md)** fixes the
thresholds, the predictions and what each outcome means, and is not to be edited
once measuring starts. It also records the structural argument that picks the
candidate before any timing exists: `CN_V8_STRIDE_MOD` is 127 at 512 KB, prime
and larger than the largest `offset_1`, so **512 KB is the only size in the
plausible range whose stride draw is never restricted**. 768 KB is excluded
there, with the reason.

The summary, with the numbers in the pre-registration:

1. **Multi-thread spread improves materially**, F27's measurement repeated at
   256 KB and 512 KB on all four machines. The target is the 2.2x single-thread
   and the 11.3x multi-thread; "materially" means outside the 12% run-to-run
   swing F52 measured on the denominator, so call it a 20% improvement in the
   multi-thread spread.
2. **B2's over-subscription sweep shows the smaller pad further from the
   attack threshold, not merely different.** Expected, since the working set
   falls, but it has to be seen.
3. **B3 has run and says a GPU does not get competitive at the smaller pad.**
   This is the gate. Without a GPU number at 512 KB, shrinking the pad trades a
   measured ASIC gain for an unmeasured GPU risk, and PLAN-v8's own rule is not
   to settle a pad question with an unmeasured argument. It was used as a
   tiebreaker twice and both decisions were later reversed.
4. **Verification and sync are re-measured, not inferred.** Cheaper is expected;
   it still has to be on the weakest machine in the set, per PLAN-v8's rule.
5. **A testnet fork round, the way Phase 5 ran one**, including the
   cross-machine bit-identical check that F49 says is the only part not
   self-confirming.

If 1, 2, 4 and 5 pass and 3 cannot be run, the honest outcome is to leave the
pad at 1 MB and record why, not to ship on the strength of the three that did
pass.

### C1.6. And the direction that is already settled: do not grow it

PLAN-v8's "what not to do" already says this on fairness grounds. The v6 project
found a second and stronger reason, and it inverts the usual intuition.

If v8's pad grew past the point where it stops fitting in cache, **both attacks
switch on at once, and the larger pad helps the attacker more than the
defender**:

- the honest miner pays a larger fill, a larger final-pass read, and DRAM for
  both
- the attacker pays a larger fill and regenerates the final pass, trading DRAM
  for AES, which is the trade that was worth +16.8% on v13's 8 MB pad

This is not a thought experiment. **F11 records that HF13 raised v13's pad from
4 MB to 8 MB deliberately**, reasoning that overflowing L3 forces every machine
class to DRAM latency so they even out. That reasoning is right about an honest
miner and wrong about an optimised one, and the difference is measured:

```
                         v13, 8 MB, exceeds L3     v8, 1 MB, fits in L3
non-temporal fill             +22%                     -39% to -61%
recomputed final pass         +16.8%                   a loss, see A7
together                      1.29x                    nothing
```

**The decision to push v13's pad past L3 is what handed its attacker that
1.29x.** A v8 pad increase to 4 MB, the size v13 had before HF13, would put v8
straight into the same regime.

The root cause, stated so it can be checked against any future proposal:

> Pad size only buys memory-hardness to the extent that something writes the pad
> unpredictably, in proportion to its size. A pad whose write count is fixed
> while its size grows is buying sequential bandwidth, and sequential bandwidth
> over reproducible data is not a cost an attacker has to pay.

v8's write count is **at most 119 operations regardless of pad size**. So if the
pad is ever grown, the sweep count has to scale with it or the growth is worse
than useless.

**Note which way that argument runs when the pad shrinks**, because it is the
same argument and it is easy to misread as symmetric. A fixed write count over a
smaller pad means the random-access work is unchanged while the sequential,
reproducible, attacker-avoidable work falls. The thing that is lost by
shrinking is not memory-hardness, which the pad size was not buying; it is the
fill's size, and the fill matters for the B2 feeder gate rather than for
hardness. That is why C1.3 is the objection to shrinking and this section is
not.

Whatever size is chosen, state it as a **ratio to the target machine's L3 per
thread**, including the 256 KB salt, not in megabytes, and re-check it as caches
and thread counts grow. B2 supplies the threshold to state it against.

### C2. The `xx` and `yy` variance question. Gated on B1.

There is a genuine tension between two rules this project produced and it should
be named rather than left implicit.

**Lesson 2 says narrow it.** v8's cost still varies by F42's measured 3.7x
through `xx` and `yy`. Cost that varies is only safe while it is unpredictable,
two defences are better than one, and a PoW where every nonce costs the same is
easier to reason about. It also makes per-block verification time uniform, which
is a sync-predictability benefit.

**Phase 6 B3 says keep it**, because per-nonce loop bounds make a GPU warp run
at `max(count)` rather than its own, worth roughly 1.9x on that portion, and
because B2 already closes screening so there is nothing left to narrow.

**Resolution: keep it, and let B1 decide.** If B1's post-fill screener comes
back under the pre-registered 1.05x, B3's argument wins outright and this closes
permanently. If it comes back above, pinning `xx` and `yy` becomes the cheapest
available fix and there is still time to make it. Do not pre-empt the
measurement in either direction.

Note what pinning would **not** be: moving them to the stable block hash, which
the external report recommends and which PLAN-v8 correctly refuses. That
reintroduces predictability. Pinning means making them constants, the way
`init_size_blk` already is.

### C3. Document `CN_SALT_MEMORY` as load-bearing.

It is 262144, and it is the only thing setting the cost of the feeder attack:
F43 and F46 put a GPU-feeds-CPU split at 1.95x, and the limit is PCIe bandwidth
at **256 KB of salt per nonce**. Shrink that constant and the attack gets
cheaper in direct proportion.

Nothing in the tree says so. It reads like a tuning parameter and it is a
security parameter. One comment, and a line in "what not to do".

The same treatment belongs on `CNA_V6_WINDOW_BLOCKS` (100000) and
`CNA_V6_FULL_HISTORY_ODDS` (13 of 256): the ~5% of reads that draw from the
whole history is what forces a miner to hold the entire database, and that is
the pool resistance. The 95% window is a deliberate sync concession and the 5%
is not. Raising the window or dropping the odds would quietly weaken the one
property that cannot be recovered after the fork.

### C4. Do not add work to the hash core. Three measurements now say so.

Carried from F38 and re-confirmed by the v6 project. Work added to the hash core
is work a specialised attacker can specialise; the chain fill is the part they
cannot. The pattern has appeared three times:

- GPU (F37): the floating-point stage costs the card 0.4% and the CPU 4.4%, so
  the ratio worsens
- ASIC (F38): the stage inflates the specialisable half, so the Amdahl bound
  loosens from 1.6x to 1.8x in the attacker's favour
- thread load (F35): under full load the stage gets cheaper on Zen desktops

Which disposes of the obvious proposals in advance. Phase 2 floating point stays
unshipped. Raising `iters` is closed by F48 (+0.67 ms at 64K against a
pre-registered +0.5 ms ceiling, and the chase never leaves L2 at 1 MB). Making
`salt_pad`'s sweep non-commutative to block the deferral costs about 9% of
verification, widens the cross-CPU spread and buys nothing.

If more margin is ever wanted, F38 says it has to come from the chain fill, and
the price of that is sync speed, directly.

## Additions to PLAN-v8's "what not to do"

New entries earned by the v6 project, to be folded into the main plan when this
one is adopted:

- **Do not cost a pad by its size.** Two factors of two sit between "the pad is
  N bytes" and what a miner pays: writing N bytes costs 2N of bus traffic
  through read-for-ownership, which `_mm_stream_si128` removes, and any part of
  the pad that is a pure function of a cheap chain is never read at all. A
  defender who multiplies pad size by passes is wrong by up to 4x, in the
  direction that flatters the design.
- **Do not evaluate a defence against a stock miner.** Screening modelled at
  1.3x to 1.4x against stock v6; the finished miner attributes 3.06x to it. Both
  are right. Removing a share of the part that varies is worth more as the fixed
  parts get optimised away, so a gate run against a stock baseline
  systematically understates every attack of this shape.
- **Do not transfer a percentage between implementations.** The non-temporal
  fill is +4% in the external report and +22% here, and both are probably
  correct for their own miner. A published optimization's percentage is a
  property of the miner it was measured in.
- **Do not assume a pass over memory is memory work.** It is memory work only
  while the pad's contents **at the moment that pass runs** are not reproducible
  from less state than the pad holds. Ask it of every pass separately. v8's fill
  leaves the pad reproducible from 128 bytes, so any pass immediately after it
  is free; what protects the later passes is that every sweep touches
  everything, **not** that the pad is 1 MB. A change making any sweep
  conditional, data-dependent or skippable reopens this, and it would not look
  like a memory change when it was made.

## Measurement rules this plan is to be executed under

Seven rules, each earned by a confidently wrong number on the v6 project. The
full versions are in [V6-MINER-LOG.md](V6-MINER-LOG.md). The three that will
bite here:

- **A-B-B-A, never A-B-A.** An A-B-A on this daemon returned its two baselines
  10.7% apart and produced a confident -5.5% that was pure drift. Print the
  A1-to-A2 gap as a gate and void the run above 2%.
- **Compare inside a run, never across runs.** The same binary on the same
  7950X reads about 760 H/s quiet and about 670 with a browser open, a 12%
  swing, which is larger than most effects worth looking for.
- **A measurement whose key diagnostic is missing cannot be debugged.** Every
  v8 daemon A/B must print the page tier and must assert the daemon took the
  options it was given. Dropping the page-tier check from a rewritten script is
  how a 17% outlier got taken seriously on the v6 project.

And one environment trap, because it cost a day: **a compound shell command
ending in `tail` reports `tail`'s exit code**, so a failed build was reported as
success and a stale binary was staged. Capture `rc=$?` immediately and echo it
last. Compare md5 sums, not paths; the build directory is keyed on branch name.

## Suggested order

Track A1 first, because it is the largest measured win, it is already written,
it speeds verification as much as mining, and B4 wants the same code path open
anyway.

Revised: the pad question is now the headline, not a footnote, because the fork
height is a placeholder and there is no known fork after HF14. So the pad work
runs first and in parallel with A1, which is independent of it.

```
1.  C1.4  build the 256 KB and 512 KB rows: two v5pad units, the
          V5PAD_SALT_WRAP fix, the v8bench table, the build script
2.  C1.5  pre-register the five criteria, in writing, before any number
3.  F27   repeat the multi-thread fairness sweep on all four machines, now
          with 256 KB and 512 KB. This is the measurement the decision turns on
4.  B2    the over-subscription sweep over the same six sizes, both attacks
5.  A1    port the run-ahead salt, measure it, A-B-B-A on the daemon
6.  B4    split the fill and core timing while that path is open
7.  B1    the cost-predictability gate, 1.05x threshold pre-registered
8.  B3    the GPU measurement at 512 KB. Gates C1; needs an outside hand
9.  A3    the blob hoist, re-measured on a v8-sized nonce
10. A5    re-run the salt profile and re-decide the eight-lane init
11. A2    worst-tier page reporting across threads
12. C3    the load-bearing-constant comments
13. C2, C4   contingency, real work only if B1 or B2 says so
```

**Items 1 to 4 are done, 2026-10-06, and the pad decision is closed.** What remains is items 5 to 13, none of which depends on the pad question.

Items 1 to 4 were one session's work and produced the pad decision's evidence.
Item 8 is the gate on acting on it and is the one most likely to need someone
else. Items 5 to 7 are independent of the pad question and can run in any gap.

**Do items 1 and 2 before item 3.** The criteria have to be written down before
the numbers exist, because this decision has been reversed by measurement twice
and both reversals came from a criterion invented after the data.

## What would change this plan

Four results, each of which moves work into Track C and makes the fork height
something to argue about rather than inherit:

1. **The sub-1 MB fairness rows coming back as C1.2 predicts.** The pad changes
   to 512 KB for HF14, the known-answer vectors are regenerated deliberately,
   and a Phase 5 style testnet round runs again. This is the most likely of the
   four, and it is the reason the pad work is now first.
2. **B3 showing competitive GPU AES**, at 512 KB or at 1 MB. At 512 KB it
   blocks C1. At 1 MB it is worse than that: Phase 6 B2's feeder resistance goes
   with it, and the replacement has to come from the chain fill, which is the
   expensive place to take it from. Note that the "card cannot hold the chain
   history" fallback is already gone: the measured v6 hybrid keeps the 234 MB
   block cache in VRAM.
3. **B1 above 1.05x.** Screening is not closed after all, and `xx` and `yy` get
   pinned.
4. **B2's threshold below the laptop's real ratio of 1.67x.** The closest real
   machine is already in the attackable regime, which is an independent argument
   for shrinking the pad and would make C1 urgent rather than merely open.

Note that 1 and 4 point the same way and 2 points against, which is the trade
C1.3 states. Nothing in Track A is affected by any of them, which is why A1 can
proceed in parallel with the whole pad question.
