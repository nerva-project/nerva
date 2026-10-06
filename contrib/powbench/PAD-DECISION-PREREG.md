# Pad decision: pre-registration

**Written 2026-10-06, before the multi-thread measurement was run.** It fixes
what will be measured, what the thresholds are, and what each outcome means, so
that the decision cannot be settled by a criterion invented after the data. This
project has reversed a pad decision by measurement twice, and both times the
reversal came from a criterion chosen once the numbers were visible.

**Nothing in this file may be edited after the measurement starts.** Results go
in [FINDINGS.md](FINDINGS.md) and the verdict goes in
[PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md) C1. If a criterion here turns out to be
wrong, say so in the result and leave this file alone; a withdrawn criterion is
more informative than a quietly amended one.

Background and the full argument: [PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md) C1.
Evidence it rests on: [V6-MINER-LOG.md](V6-MINER-LOG.md) lessons 7, 9 and 10.

## The question

v8 ships at a 1 MB pad. F24 and F27 swept 1, 2, 4 and 8 MB and never measured
below 1 MB, so 1 MB is the smallest size ever tried rather than a bracketed
minimum, and every trend in that sample points off the bottom end.

**Should v8's pad be 512 KB instead of 1 MB at HF14?**

256 KB is in the sweep as the floor and as a curve point, not as a candidate.

## The candidate set, and why it is this one

The pad must be a whole multiple of `CN_SALT_MEMORY` (262144) or the salt sweep
reads past the salt, and a power of two or `state_index`'s mask silently
confines every access to a prefix of it. That leaves 256 KB, 512 KB, 1 MB, 2 MB,
4 MB and 8 MB as the sizes measurable on equal footing.

**768 KB is excluded and the reason generalises.** It satisfies the salt
coupling, 786432 / 262144 = 3, but its block count is not a power of two, so it
would need `V5PAD_MOD` and would be timed through a multiply-high rather than a
mask, which is not comparable with the other rows. Separately,
`CN_V8_STRIDE_MOD = 129 - step` makes its modulus 126 = 2·3²·7, which has twelve
divisors at or below 64.

That last point decides which size is preferred before any timing exists. The
reachable strides for a given `offset_1` are the multiples of
`gcd(offset_1, CN_V8_STRIDE_MOD)`, and `offset_1 = (d % 64) + 1` lies in [1, 64]:

| pad | step | modulus | divisors ≤ 64 |
|---|---|---|---|
| 256 KB | 1 | 128 = 2⁷ | 1, 2, 4, 8, 16, 32, 64 |
| **512 KB** | 2 | **127, prime** | **none** |
| 768 KB | 3 | 126 = 2·3²·7 | twelve |
| 1 MB | 4 | 125 = 5³ | 5, 25 |
| 2 MB | 8 | 121 = 11² | 11 |

**512 KB is the only size in the plausible range whose stride draw is never
restricted**, because 127 is prime and exceeds the largest `offset_1`. The only
other prime modulus below 2 MB belongs to 4 MB, which is already disqualified on
fairness. This is recorded here because it is an argument from structure that
does not depend on any measurement, and it should not be re-derived later as if
the data suggested it.

## What will be measured

One `v8bench` binary, all six sizes in one run, so every comparison is inside a
run rather than across runs. Built by
[build-v8bench.sh](build-v8bench.sh) from `v5pad025.c` through `v5pad8.c`.

1. **Single-thread cost per size.** The pad sweep rows.
2. **Multi-thread peak total H/s per size**, across the thread ladder, on every
   machine available. **This is the measurement the decision turns on**, because
   multi-threaded fairness is where one CPU one vote actually lives and it is
   the axis the 2.2x target is missed on.
3. **Cross-machine spread per size**, slowest divided by fastest at each size,
   computed from the `SCALE` lines.

Minimum viable machine set: the **Ryzen 9 7950X** and the **i7-7700HQ**. F52
establishes that the whole cross-machine spread is the laptop, with three Zen
generations of desktop sitting within 1.29x of each other, so those two bracket
it. More machines are better and none of the thresholds below change if more
arrive.

### What `v8bench` does not measure, stated now so no result is misread

**`v8bench` hands the hash a synthetic salt and never calls
`get_cna_v6_data`** (F52). The chain fill is about 59.5% of a real nonce and
does not change with pad size. So every ratio this harness reports is a ratio on
the hash core alone, roughly 40% of a nonce, and **must be converted before it
is quoted as a nonce or hashrate figure**. The conversion uses the fill cost
measured in the same session, not a remembered one.

A nonce-level claim requires either B4's daemon-side split timing or a daemon
A-B-B-A. Neither is part of this pre-registration and neither gates the
decision.

## Predictions, stated before the measurement

Scored afterwards, right or wrong. The point is to find out whether the model in
C1.2 predicts or merely post-explains.

**Already observed on 2026-10-06, so not predictions:** the single-thread sweep
on the 7950X gave 0.2714, 0.3441, 0.5749, 1.0337, 2.5488 and 4.4920 ms for
256 KB through 8 MB, hardware AES, controls passing at 1.33% and 1.17% against a
2.00% gate, no monotonicity taint. Hash core only, per the section above.

Predictions proper, all for the multi-thread run:

1. **7950X peak total H/s scales with single-thread cost and little else.** At
   1 MB it already fits all 32 threads in L3 (32 × 1.25 MB of pad plus salt
   against 64 MB), so there is no occupancy left to gain. Expect 512 KB at
   1.5x to 1.8x the 1 MB peak and 256 KB at 1.9x to 2.3x, bracketing the 1.67x
   and 2.12x the single-thread rows imply.
2. **i7-7700HQ gains more than that**, because it has occupancy to gain. At
   1 MB it fits 4 of its 8 threads in 6 MB of L3; at 512 KB it fits all 8.
   Expect 512 KB at **2.0x to 2.8x** the 1 MB peak, above the 7950X's range.
3. **The multi-thread spread therefore falls.** F27 measured 11.3x at 1 MB.
   Expect **7x to 9x at 512 KB**, and the same or slightly better at 256 KB.
4. **The peak thread count moves up on the laptop and not on the 7950X.**
5. **Single-thread spread barely moves.** F24 found 1, 2 and 4 MB within noise
   of each other, and nothing about a smaller pad should change that. Expect it
   to stay inside 2.2x to 2.5x.

Prediction 2 is the load-bearing one. If the laptop does not gain more than the
7950X, the fairness case for shrinking collapses, and that is the single result
most worth looking for.

## The five criteria

Taken from PLAN-v8-PHASE7 C1.5, with the numbers fixed here.

**C-1. Multi-thread spread improves materially.** Measured at every size in one
run, across at least the two machines above. **Threshold: the multi-thread
spread at 512 KB is at least 20% better than at 1 MB in the same run.** 20%
rather than something tighter because F52 measures a 12% swing on the
denominator of exactly this kind of figure, and a margin smaller than the noise
on its own inputs is not a result.

**C-2. The smaller pad is further from the attack threshold, not merely
different.** B2's over-subscription sweep, both attacks, over the same six
sizes. **Threshold: at 512 KB the streaming-store arm loses by at least as much
as it does at 1 MB**, which is the sign that the pad is further inside the
cached regime rather than closer to the edge. A smaller loss at 512 KB than at
1 MB would be the opposite of what C1.2 claims and would need explaining before
anything else proceeds.

**C-3. B3 has run and says a GPU does not get competitive at 512 KB.** This is
the gate. Phase 6 B2's feeder resistance is proportional to the fill, and
halving the pad halves it. **Threshold: a card's cost for a full
`get_cna_v6_data` plus the chained AES fill at 512 KB leaves the feeder at worse
than parity with a CPU doing the whole nonce**, with the same margin it has at
1 MB stated alongside it.

**Without C-3 the pad does not move.** PLAN-v8's own rule is not to settle a pad
question with an unmeasured argument; it was used as a tiebreaker twice and both
decisions were later reversed. Shrinking on C-1 alone would trade a measured
fairness gain for an unmeasured GPU risk, which is the same mistake in the
opposite direction.

**C-4. Verification and sync are re-measured, not inferred**, on the weakest
machine in the set rather than the fastest, per PLAN-v8's standing rule.
**Threshold: no regression.** Cheaper is expected and is not required.

**C-5. A testnet fork round passes**, the way Phase 5's did, including the
cross-machine bit-identical block check that F49 identifies as the only part of
that round which is not self-confirming.

## What each outcome means

| C-1 | C-3 | decision |
|---|---|---|
| pass | pass | **move the pad to 512 KB for HF14**, subject to C-2, C-4, C-5 |
| pass | not run | **leave it at 1 MB and record why.** The fairness gain is real and unbanked; it is not worth an unmeasured GPU risk |
| pass | fail | leave it at 1 MB. C-3 failing at 512 KB is also a warning about 1 MB and B3 becomes urgent on its own |
| fail | either | leave it at 1 MB. C1.2's fairness case was the main reason to move |

A pass on C-1 with C-3 unrun is the most likely outcome and the one worth
deciding in advance, because it is the one where the temptation to ship on
partial evidence is strongest.

## What voids a run

Any of these and the run is discarded rather than interpreted:

- the harness reports **SOFTWARE** on its AES line
- a **control row outside its gate**, currently v8 at most 2.00% slower than the
  shipped function
- the **monotonicity taint** firing, which now spans all six rows and says a
  larger pad came out cheaper than a smaller one
- the machine not quiet: mining running, a browser open, or the PC locked during
  the run. F52 measures the same binary on the same 7950X at about 760 H/s quiet
  and about 670 with a browser open, a 12% swing, which is larger than most of
  the effects being looked for
- a **thread count at or above the logical CPU count** without affinity, where
  the scheduler is free to double some cores and idle others; this varied two
  identical points by 18.9% on the v6 project

## Addendum, 2026-10-06, written before the repeat runs

The first run on each machine is in. **C-1 came back at 18.64% against the 20%
threshold**, a shortfall of 1.4 percentage points, from one run per machine.

That margin is smaller than the 12% swing F52 measures on this kind of figure,
so at n=1 it is neither a pass nor a confident fail. This section fixes how that
is resolved, and it is written **before** any further measurement.

**The threshold does not move.** 20% stands, for the reason it was chosen.

What changes is only the precision of the estimate it is applied to:

- **Three runs per machine, back to back, inside one quiet window.** Same
  binary, same arguments, nothing else running, machine not locked.
- **Median** of the three per-machine peaks at each pad size. Median, not mean,
  because a thermal or scheduling excursion is a one-sided contaminant.
- Spread recomputed from those medians, and the 20% threshold applied **once**.
- **Whatever that says, stands**, including a result at 19%.

The runs already taken, the 7950X at 10:11 and the i7-7700HQ at 07:21, are from
a different quiet window. They are reported alongside as a between-window drift
check and are **not** in the median, so that the three medianed runs are
genuinely back to back. Excluding a run already seen is as much a choice as
including it, so they are kept visible rather than discarded.

**No further repeats after these three.** Measuring until a threshold is crossed
is the failure mode this whole file exists to prevent, and the only protection
is that the stopping rule is fixed now.

The same three runs serve a second purpose: their spread is the first direct
measurement of this harness's run-to-run noise, which is what B2's sample counts
should be sized from rather than guessed at.

## The decision record

**Closed 2026-10-06. The pad stays at 1 MB.** Full write-up in
[FINDINGS.md](FINDINGS.md) F54 and F55.

| criterion | threshold | measured | |
|---|---|---|---|
| C-1, multi-thread spread at 512 KB | 20% better | **10.01%** | FAIL |
| C-2, streaming arm loses at least as much at 512 KB | no worse than 1 MB | 39.2% against 42.5% | **FAIL** |
| C-3, GPU not competitive at 512 KB | gate | not run | n/a |
| C-4, verification no regression | no regression | not run | n/a |
| C-5, testnet fork round | pass | not run | n/a |

C-1 and C-2 both failed, so the outcome table's bottom row applies and C-3 to
C-5 were never reached. Predictions scored in F54: two of five correct, one half
right, two wrong.

**What the pre-registration was actually worth**, since it is tempting to
conclude a file like this only matters when it changes a decision:

1. **It caught an outlier that would have changed the answer.** One earlier
   laptop run read 13% low at 1 MB. Against that single reading C-1 came out at
   18.78% and looked like a near miss worth arguing about. The three-run median
   put it at 10.01%. The threshold did not save this; the **stopping rule** did,
   because it was fixed before the first result made a fourth run tempting.
2. **It caught a mechanism stated backwards.** C-2 was written to fail loudly if
   a smaller pad lost less, with the note that this "would need explaining
   before anything else proceeds". It did, and the explanation is that C1.2 had
   the sign wrong.
3. **It did not save the threshold's own justification.** 20% was chosen because
   F52 measures a 12% swing on this kind of figure. That figure came from a
   daemon with a browser open; `v8bench` on a quiet machine repeats to 0.4% at
   1 MB. The threshold was right for the wrong reason, which is recorded here
   rather than quietly benefited from.

**One error in this file, left in place rather than edited out.** The void list
says "a control row outside its gate, currently v8 at most 2.00% slower than the
shipped function". Reading `v8bench.c`, that 2.00% gates the v8-against-v5
comparison, and the shipped-against-recompiled control figures are printed but
never gated. Two laptop runs read 2.09% and 2.07% and were **not** void; there
was no control threshold to exceed. The verdict is unaffected either way: using
only the run with the tightest control gives 10.98%.

## If this is ever reopened

It should not be reopened on fairness grounds; that is what was measured. The
two things that would justify revisiting are:

- **a change that makes the sweep count scale with the pad.** The rule in
  PLAN-v8-PHASE7 C1.6 is that pad size only buys hardness in proportion to what
  writes the pad unpredictably, and v8's write count is fixed at 119 operations
  at every size. A design where that scales is a different question from this
  one.
- **B3 running.** It gates the shrink direction and was never reached. It also
  bears on the current size: if a card is competitive at 1 MB, the problem is
  not which side of 1 MB to be on.

Reopening needs a new pre-registration, not an amendment to this one.
