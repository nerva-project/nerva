# Full-history odds: pre-registration

**Written 2026-10-07, before the cross-machine measurement was run.** It fixes
the question, the candidates, the thresholds and the predictions while the
answer is still unknown, because this project has twice produced a number and
then chosen the criterion that number passed.

**Nothing in this file may be edited after the measurement starts.** Results go
in FINDINGS.md and the outcome goes in the decision record at the bottom.

Companions: [FINDINGS.md](FINDINGS.md) F60 (the odds sweep on one machine), F61
(what the window is worth), F65 (why this question is worth reopening at all),
and [PAD-DECISION-PREREG.md](PAD-DECISION-PREREG.md) for the format.

## The question

**Should `CNA_V6_FULL_HISTORY_ODDS` rise from 13 of 256 at HF14, and to what?**

It is reopened because **F60 closed it on the wrong metric.** F60 measured that
forcing every draw to full history moves the fill 1.06x to 1.29x and concluded
the lever was too small to pay for itself. That is a measurement of *our* cost.
F65 then established that an ASIC gets the cipher for free, so the only thing it
pays for is full-history reads, and that quantity was never measured. The two
numbers differ by more than an order of magnitude and point opposite ways.

## What the odds actually control

Confirmed by reading `cna_v6_data_reference` in
[db_lmdb.cpp](../../src/blockchain_db/lmdb/db_lmdb.cpp): `body()` makes **four**
independent `pick_index()` calls and the loop runs 4,096 bodies, so a fill makes
**16,384 index picks**, each drawing full-history with probability `odds/256`.

| | 13 of 256 | 256 of 256 |
|---|---|---|
| full-history reads per nonce | 832 | 16,384 |
| window reads per nonce | 15,552 | 0 |

At 256 the window is never read, so `CNA_V6_WINDOW_BLOCKS` becomes dead and the
decision to delete it has to be taken with this one.

## Scored per threat, which is how this has to be judged

*Added 2026-10-07, before any measurement, and it corrects the framing this file
was started with.* D3 was first argued as an anti-ASIC measure worth 17.6x. That
is one threat of three and not the nearest one. Scored separately:

| threat | effect of raising odds | basis |
|---|---|---|
| **FPGA** | **strongly positive** | block RAM is tens of MB, so the **5.3 MB window fits on-chip today**. At 13 of 256 an FPGA serves **94.9%** of its reads without touching external memory. At 256 it serves none |
| **GPU** | **negative, about -17%** | fill GPU resistance 11.49x to 9.55x, because the memory share goes 5.7% to 22.2% and memory is the half a card is *better* at (F62: 1.64x) |
| ASIC, external DRAM | +17.6x | the arithmetic below |
| ASIC, 240 MB on-die SRAM | **nothing** | see C-6 |

**The window is specifically a gift to FPGAs**, and nobody wrote that down when
it was introduced. It was added to make sync fast by keeping 95% of reads
cache-resident, and the same property makes 95% of reads block-RAM-resident for
the one attacker class that is nearer term than an ASIC and cheaper to build.

**So D3's real case is anti-FPGA, not anti-ASIC**, and its real cost is GPU
rather than sync. Both of those are the near threats, which is why this now has
to be measured rather than argued: the two near-term effects point in opposite
directions and only one of them has a measured number.

## The candidate set

**13 (current), 32, 64, 128, 256.** Geometric, so the cost curve's shape is
visible rather than just its endpoints, and 13 is carried as the control arm in
every run rather than compared against a remembered number.

256 is included because it is the maximum and because it is structurally
different, being the only value that retires the window.

## A cost the plan assumed and this does not pay

PLAN-v8-PHASE8 states that D3 "needs the same v14-only fill as D2", which would
fork `get_cna_v6_data` and **double the consensus-critical surface permanently**.
That is the main reason D3 and D2 were treated as expensive.

**It is not true for D3.** `cna_v6_data_shadow()` already exists in the same file
with `odds` as a parameter, written for F61, so the proven change is one argument
threaded through one function: v13 passes 13, v14 passes the new value. One body,
one call site per version. **The fork cost does not apply and D3 is much cheaper
structurally than the plan records.**

## What will be measured

1. **Fill cost at each candidate, on the 7950X and on the i7-7700HQ**, with
   `t_v8_fill`'s existing odds sweep, a 240 MB cache and a 5.3 MB window as
   mainnet has. The laptop is the machine that matters: 6 MB of L3 against a
   5.3 MB window means full-history reads should evict the window and cost it
   twice, where the 7950X has room for both.
2. **The cross-machine spread at each candidate**, which is the new quantity and
   the one that decides this.
3. **Whole-nonce and sync cost in the daemon** at whichever candidate survives,
   measured rather than scaled from the fill.
4. **Random gather, GPU against CPU, at window size as well as full size**, with
   `t_gather`'s `g_log2_entries`. F62 measured 224 MB (1.64x), 896 MB and 3.5 GB
   but never **5.3 MB**, which is the regime 94.9% of reads are in today. That
   single missing point is what turns C-7 from arithmetic into a measurement,
   and it is the cheapest item here. **Run it first**, because if a card is as
   good at 5.3 MB as at 240 MB then D3 has no GPU cost and the rest of this
   file gets easier.

### What these harnesses do not measure, stated now so no result is misread

**The attacker's side is modelled, not measured.** The 19.7x rests on an ASIC
being throughput-bound on random reads into the full database with the cipher
free. No harness here tests that, and no result below should be quoted as if it
did.

**Nothing here addresses the SRAM threat.** The whole case assumes an attacker
streams a 240 MB database from DRAM. A serious chip can hold 240 MB on-die, and
the cache grows only about 29 MB a year at 56 bytes per block, so it does not
outrun that on its own. **If an attacker caches the database, every number in
this file is worth nothing.** See C-6.

## Predictions, stated before the measurement

**P1. The laptop's fill cost rises faster with odds than the 7950X's.**
Confident on direction. F60 already records that a 7950X holds roughly a third
of a 224 MB table in its 96 MB of cache, where the laptop holds about 2.5% of
it, so the big-cache machine keeps absorbing full-history reads long after the
small one stops.

**P2. The cross-machine spread widens substantially at odds 256, into the range
2.6x to 3.5x on the fill, from about 2.05x today.** This is the prediction most
likely to be wrong and it is the one that decides the outcome. If it lands above
3.5x, D3 at maximum is not affordable and the answer is a point on the curve.

*Note that P2 is the spread of the **fill** and C-2's threshold is the spread of
the **whole nonce**, which are different quantities and must not be compared to
each other.* F58 puts the fill spread at 2.05x and the nonce spread at 2.17x,
and the fill is 56.2% of a nonce, so a fill spread of 3.5x would land the nonce
spread near 2.6x and fail C-2. Both numbers get reported.

**P3. The curve is concave: most of the spread cost arrives early**, because the
window stops being resident once a modest fraction of reads miss it, and after
that further odds only move reads that were already going to DRAM. If P3 holds,
a middle candidate buys most of the goal-1 gain for a fraction of the goal-2
cost, and that is the likely answer.

**P4. Sync cost is negligible**, under two minutes on a full sync, because PoW
is skipped below `ASSUME_VALID_HEIGHT` and only about 180,000 blocks above it
are verified. Stated as a prediction because it is currently arithmetic.

**P5. A GPU is relatively better at window-sized reads than at full-history
reads**, so the measured gather ratio at 5.3 MB will be worse for the card than
F62's 1.64x at 224 MB. The window is L3-resident on every CPU in the table and
does not fit an RTX 3050's 2 MB L2, so the CPU should hold a real advantage
there. **If this is wrong and a card is equally good at both sizes, D3's GPU
cost is smaller than the -17% above and the trade improves.** This is the
cheapest thing on the list to settle and it has never been measured: `t_gather`
already parameterises table size through `g_log2_entries`.

## The criteria

**C-1. The goal-1 gain is real.** External-read multiplier divided by honest
whole-nonce multiplier, at the chosen candidate. **Threshold: at least 5x.**
The arithmetic says 17.6x at odds 256, so there is margin; the threshold exists
so that a candidate scraping past on a technicality is rejected.

*Relabelled on review, 2026-10-07, before measuring.* This was written as an
ASIC criterion and the per-threat section then concluded the ASIC case is not
D3's case, which would have left the file gating on a number it had itself
disowned. **The arithmetic is unchanged and the label was the error.** The
19.7x is the multiplier on reads that must leave the chip, and it applies to
**any device that can hold 5.3 MB on-die but not 240 MB**. That is an FPGA's
block RAM and a DRAM-class ASIC alike, which is why one number serves both rows
of the threat table. It does not apply to a device holding the whole database
on-die, per C-6, nor to a GPU, which holds neither and is covered by C-7.

**C-2. Cross-machine fairness holds.** Whole-nonce spread, 7950X against
i7-7700HQ. It is 2.17x today (F58). **Threshold: no worse than 2.50x**, about
+15%.

That number is a judgement and here is its reasoning, so it can be argued with
rather than guessed at. The spread is what decides whether a modest CPU can
mine at all, and it is the goal this project has been least willing to trade.
15% is roughly the margin by which the pad decision was willing to move the same
quantity, and it keeps v8 inside the range it has occupied since Phase 5. If the
best candidate needs more than that, the honest answer is that goals 1 and 2 are
in direct conflict here and the decision goes back to you rather than to a
threshold.

**C-3. Honest cost stays bounded.** Whole-nonce cost increase.
**Threshold: no more than 1.25x.** Every miner pays this forever, and it is
electricity rather than security.

**C-4. Sync is re-measured, not inferred**, in the daemon on real blocks above
assume-valid. **Threshold: under 2 minutes added to a full sync.**

**C-5. A testnet fork round passes**, as Phase 5's did.

**C-6. The SRAM threat has a stated position before shipping.** Not a threshold,
a gate. If a funded attacker can hold the block cache on-die, D3 buys nothing
and we would be paying C-3's 1.25x for no return. **D3 must not ship on the
17.6x alone until someone has written down why 240 MB is or is not cacheable by
the attacker we are designing against.** This is the same error F65 just caught,
a bound computed for one machine and applied to another, and it would be
careless to repeat it in the same week.

*Position taken 2026-10-07, and it is the uncomfortable one.* At a realistic
0.04 µm² per bit for a large SRAM array in a 5 to 7 nm class process, 240 MB is
**40 to 80 mm²**. A GPU die is 300 to 600 mm². **A funded ASIC programme can
simply buy this**, so the 17.6x must always be quoted against DRAM-class
attackers and never as an absolute.

Growing the cache to move that threshold was considered and **declined**, see
PLAN-v8-PHASE8 D7. It would need 1 to 2 GB to be out of reach, which is 4x to 8x
the node RAM every honest user pays, and F62 measured that bigger tables favour
bandwidth-rich devices: GPU against CPU on gather goes 1.64x at 224 MB to
**2.73x at 3.5 GB**. So it trades the nearest threat for the furthest.

**C-6 therefore does not block D3, because D3's case no longer rests on the ASIC
number.** It rests on the FPGA result in "Scored per threat". What C-6 does
block is quoting 17.6x as though it held against every attacker.

**C-7. GPU resistance does not regress materially.** New, and it exists because
the threat table above shows the candidate's main cost is a card rather than
sync. Measured as the fill's GPU-against-CPU ratio at the chosen candidate.
**Threshold: no worse than a 20% regression** from the value at 13 of 256,
which the arithmetic puts at -17% for the maximum.

*Method note, since this is the criterion most open to being fudged.* There is
no kernel that runs a whole fill on a GPU, so this ratio is **composed** from
F62's HC-128 figure and the measured gather ratios at window and full size,
exactly as F62 section 3 composed its 10.5x. It is therefore a model with
measured inputs, not a direct measurement, and the honest reading is that the
inputs carry the confidence and the composition does not. The one input that
does not yet exist is the gather ratio at 5.3 MB, which is why it is measured
first.

The reasoning, so it can be argued with: a GPU is the live threat and an ASIC is
not one at Nerva's current size, so a certain loss against cards is a bad price
for a large gain against a chip programme that may never exist. 20% is set just
above the arithmetic's own estimate so that the maximum candidate is not
excluded before it is measured, while anything clearly worse is.

## What each outcome means

- **All seven pass at a candidate:** adopt it, with the window deleted if that
  candidate is 256, and regenerate known-answer vectors.
- **C-2 fails everywhere above 13:** goals 1 and 2 are in direct conflict and
  D3 stays closed, this time for a measured reason rather than F60's wrong one.
- **C-7 fails everywhere above 13:** the two near threats are in direct conflict,
  the window is an FPGA gift we cannot afford to take back, and D3 stays closed.
  This is the outcome the per-threat table says is most likely to bite.
- **C-6 answers "cacheable":** already answered, and the answer is that a funded
  programme can cache it. That removes the ASIC row from D3's case but does not
  close D3, because C-1 now rests on devices that hold the window and not the
  database.
- **P3 holds and a middle candidate wins:** that is the expected outcome and the
  interesting one, because it means the current 13 was never argued for, only
  inherited.
- **P5 is refuted and a card is equally good at both sizes:** C-7's cost
  largely vanishes, the only remaining price is C-2 and C-3, and the maximum
  candidate becomes plausible.

## What voids a run

- Any arm not sharing one process and one block cache with its control. F57's
  void run is the precedent: between-process variation on a large database
  swamped an effect of this size.
- A laptop run whose control arm drifts more than 4% from start to end, per
  F63's thermal lesson.
- Quoting a cross-machine absolute instead of a within-machine ratio, per F63.
- Any run where the 13-of-256 control is not present in the same table.
- Any GPU gather figure taken at a single work-item count. F62's 224 MB number
  is trustworthy because the curve was flat across every count, which is the
  signature of a bandwidth-bound measurement. **A 5.3 MB table may not be
  bandwidth-bound**, so the sweep matters more there, not less, and a peak that
  sits at the end of the swept range means the range was too short.
- Any CPU gather figure where the harness silently changed thread count between
  table sizes, per F63's third trap.

## The decision record

**Measured 2026-10-07. Full write-up in FINDINGS.md F66 and F67.**

| criterion | threshold | odds 128 | odds 256 |
|---|---|---|---|
| C-1 gain | >= 5x | 9.2x | **17.3x** |
| C-2 fairness | <= 2.50x | 2.188x | **2.247x** |
| C-3 honest cost | <= 1.25x | 1.075x | **1.136x** |
| C-4 sync | < 2 min | better than 256 | **0 s at launch, F68** |
| C-5 testnet | pass | *owed* | *owed* |
| C-6 SRAM | position stated | yes | yes |
| C-7 GPU | >= -20% | better than 256 | **-17%** |

**Both 128 and 256 pass every criterion that has been measured.** Only C-5
remains owed, and it is a process gate rather than a threshold.

**C-4 measured 2026-10-07, F68**, in the daemon on 2,500 re-verified real
blocks: 1.1949x against the harness's 1.183x, agreeing to 1%. Since the change
is v14-only it costs **nothing at the fork**, and **0.173 ms per block**
thereafter. One caveat is recorded there rather than hidden here: the count of
PoW-verified blocks grows forever at one a minute, so this threshold is crossed
about **16 months** after the fork unless `ASSUME_VALID_HEIGHT` is bumped. That
is an operational dependency, not a defect, and routine releases satisfy it.

**What the pre-registration was actually worth**, recorded as the pad decision
recorded it, because the honest answer is uncomfortable.

Its **predictions were mostly wrong**: 1 of 4 measured ones survived. P2, named
in this file as "the prediction most likely to be wrong and the one that decides
the outcome", was wrong by a factor of four and the quantity it concerned turned
out not to decide anything. P3's direction was inverted. P5 was wrong by eight.

Its **criteria were worth everything**. The fairness cost came in at 3.6%
against a threshold with 15% of room. Had C-2 been written after seeing that,
nobody could tell whether 2.50x was judgement or rationalisation. The same
applies to the void list, which disqualified three of six rows in the first
measurement including a number F62 had already published.

**The lesson for the next one: pre-register the criteria and the void
conditions, and treat the predictions as a way of finding out how the system
works rather than as a forecast worth trusting.**

**IMPLEMENTED 2026-10-07, F73.** `CNA_V6_FULL_HISTORY_ODDS_V14` is 256 and
`v14_fetch_salt` passes it; v13 keeps 13. The fork cost this file predicted
would not apply did not: one parameter, no second consensus path. The window
constant is renamed `_V13` and a static_assert ties the name to the value.

**Still owed:** C-5's testnet round, and a runtime observation that the v14 path
really passes 256. The second is not pedantry: a mis-wire would leave every node
mis-wired identically, so they would agree with each other and a testnet round
would pass with this change inert. The daemon now announces the odds once at
INFO so the question can be answered by looking rather than by reasoning.

**Decision: adopt 256 of 256 at HF14**, subject to C-4 and C-5. It is the most
efficient point on the curve rather than a compromise, because the cost is
convex, and it retires `CNA_V6_WINDOW_BLOCKS` entirely, which removes the
structure F66 showed is a gift to every attacker class at once. The conservative
alternative is 128, which keeps the window and gives up 1.9x of C-1.

**Not adopted on its own merits alone:** D3 still only buys what F66 and F67
measure, and the ASIC row of its threat table is void per C-6. The case is the
FPGA one.
