# CNA v8, Phase 8: the design pass

What v8 should be, given everything measured. Written 2026-10-06, after the pad
decision closed, and on the standing that **v8 has never validated a block**, so
it is not bound to reproduce what it currently computes.

Companions: [FINDINGS.md](FINDINGS.md) is the evidence,
[PLAN-v8.md](PLAN-v8.md) has Phases 1 to 6, [PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md)
has the implementation gap and the pad decision,
[V6-MINER-LOG.md](V6-MINER-LOG.md) has the attacker's side.

**This is a design pass, not a specification.** It fixes what the evidence
already settles, states what each remaining option costs, and names the one
measurement that gates half of it. Nothing here should be built before its gate.

## The goals, in the order they constrain

1. Resistant to GPUs and specialised hardware
2. CPU friendly
3. Mining pool resistant
4. Decent sync speed

They are not independent. 3 is what makes 1 hard for an attacker to buy their
way around, and 4 is the price of 3.

## What v8 actually is, measured

The instrumented profile over 52,833 nonces, with this week's additions:

| part | share | can a specialist avoid or accelerate it |
|---|---|---|
| chain fill, 256 KB gathered from the whole database | **59.5%** | no: it is random-access storage bandwidth plus chain dependence |
| `salt_pad_v8` sweeps, and the extra hashes they call | **21.1%** | **yes, provably**: deferrable to two passes, bit-identical, F51 |
| AES fill over the pad | 6.5% | yes if it has AES; this is the anti-GPU gate |
| `randomize_scratchpad_256k_v8` | 6.2% | sequential |
| AES finalize over the pad | 6.2% | yes, and the pad it reads is 98.5% reproducible |
| CryptoNight inner loop | **0.05%** | vestigial |

Three measurements this week sharpen that into a statement about the design
rather than about the implementation:

- **The pad is 98.5% reproducible on every nonce**, and v8's count of
  unpredictable pad writes is **fixed at at most 119 regardless of pad size**.
- **Growing the pad is worse than useless and shrinking it fails fairness.**
  F54, decided against pre-registered criteria. 1 MB stands.
- **The streaming-store attack never pays**, at any pad size, up to 3.87x
  over-subscription. F55.

Put together: **v8 is not memory-hard in any meaningful sense, and has not been
for some time. It is a chain-dependent database gather wrapped in sequential
AES.** The CryptoNight scaffolding around it is vestigial, and a 0.05% inner
loop is what that looks like from the inside.

This is not a criticism. PLAN-v8 Phase 6 already concluded "v8's security is the
chain fill, everything else is cost". What is new is being able to say how
completely that is true, and therefore what to do about it.

## The governing lever, and the budget nobody noticed

F38 established the rule and it has now survived three independent tests (GPU in
F37, ASIC in F38, thread load in F35):

> **Work added to the hash core is work a specialised attacker can specialise.
> The chain fill is the part they cannot.**

**The second sentence is false, measured 2026-10-06, F60.** The fill is
**94% HC-128 and 5.7% memory**, and two thirds of the whole fill is
`HC128_Init` key setup, 257 reseeds per nonce. It is not bound by random-access
database bandwidth and never was.

The error is a conflation. **The fill does two jobs: it costs time, and it binds
the nonce to the chain.** The rule assumes the cost provides the binding. The
binding comes from needing the right 16,384 blocks to get the right answer, and
is intact and cheap. The cost is a stream cipher, and a stream cipher is close
to the friendliest thing here to put in silicon.

So **everything below that reads "raise the fill's share" should be read as
"raise the share of HC-128"**, which is not obviously the share of anything an
attacker struggles with. Pool resistance is unaffected, because it rests on the
binding rather than on the cost. The ASIC bounds are: they range from the 1.78x
quoted here to **31x** depending on what HC-128 costs in hardware, which nobody
has established.

So there is exactly one lever that improves goal 1 without trading against it:
**raise the fill's share of a nonce, never the core's.** F38 also states the
price, which is sync speed, directly, because verification pays one fill per
block.

**The price is affordable, and that is the new part.** v8's real nonce is
**1.32 ms** on a 7950X single-threaded (F52, daemon, fill included). Live v6 is
roughly **7 to 8 ms** on the same machine by the same accounting. Mainnet syncs
on v6 today.

So v8 is about **five to six times cheaper to verify than the algorithm
currently running**, and Phase 1 banked that as a win. Read against F38 it is
not only a win, it is **unspent budget on the only axis that buys resistance.**
PLAN-v8 says verify cost "is no longer the constraint anything is traded
against". It should be traded against, deliberately, because the thing it buys
is the thing we want.

## Design principles, each tied to a measurement

**P1. Spend the core on the fill.** Anything in the hash core that is provably
not hard is pure cost: it is paid by every honest CPU and skipped or accelerated
by every specialist. Removing it raises the fill's share for free and makes
verification cheaper at the same time. This is the one move that improves goals
1 and 4 together.

**P2. Do not add work to the hash core, in any form.** Closed three times.
Floating point costs the card 0.4% and the CPU 4.4% (F37) and loosens the ASIC
bound (F38). Raising `iters` costs +0.67 ms at 64K against a pre-registered
0.5 ms ceiling and never leaves L2 at a 1 MB pad (F48). A non-commutative sweep
costs 9% of verification and buys nothing (F44).

**P3. Do not reduce the absolute AES work.** It is the only part a GPU is bad
at, and Phase 6 B2's feeder gate is exactly the chained AES a device must run
before it can produce a salt. Note this constrains P1: **cut the sweeps, not the
AES.** The sweeps are XOR and memory; they are not the gate.

*Measured 2026-10-06, F59, and the principle holds while several of its words
move.* The asymmetry is **4.9x on the core and 2.6x on a whole nonce**, the
first number this sentence has ever had. It is not one number twice over.

**By phase:** the once-per-nonce pad fill runs at 8.1x and the chained main loop
at 1.8x, because a main-loop step is memory bound and the AES is a small part of
it. So **the gate is the pad fill, and pad size is what sets it**, not the
chained loop. B2's feeder gate is the 8x part, which is better than this plan
claimed.

**By machine, and this is the uncomfortable one:** the figures above are the
i7-7700HQ. A 7950X reads 8.0x, 3.8x, 16.0x and 2.4x, roughly double on every
axis. The T-table path is twice as uniform across machines as the AES-NI path,
so **the asymmetry is the quality of the CPU's AES unit rather than a constant
of v8**. The low end is the figure to plan against, since the gate has to hold
for the network as it is. RESULTS.md 6.3 frames the risk as a card gaining
better AES; the other half is a network of CPUs with weaker AES, which needs
nothing to happen.

**D1** does not merely leave the gate alone: by deleting AES-neutral work it
roughly **doubles** the asymmetry, 1.73x on the laptop and 2.03x on the desktop.

**P4. Pad size buys nothing while the write count is fixed.** The rule from
lesson 10: pad size only buys hardness in proportion to what writes the pad
unpredictably. v8 writes at most 119 slots at any size. Either leave the pad
alone or make the write count scale with it, and the second has no evidence
behind it and conflicts with P2.

**P5. Chain binding comes from the pad init, not from the sweeps.** F23:
`randomize_scratchpad_256k_v8` consumes `salt[0 .. 262143]` in full, every hash,
unconditionally, and `state_index` covers the whole pad regardless. This is what
makes P1 safe to act on, and it was established before anyone wanted it to be
true.

**P6. Keep per-nonce loop bounds.** Phase 6 B3: variable counts make a GPU warp
run at `max(count)` rather than its own, worth roughly 1.9x on that portion.
They are safe because B2 moved the draws after the fill, so learning them costs a
full fill. Do not move them to the stable block hash.

## Candidates

Ranked by evidence behind them, not by appeal.

### D1. Remove `salt_pad_v8` and its extra hashes. 21.1% of a nonce, provably not hard.

**The strongest candidate, and the only one that improves every goal at once.**

*Corrected 2026-10-06.* That last clause is no longer true. F58 measured the
cross-machine spread and it widens, from 2.17x to 2.19x on a real nonce. The
amount is inside the noise and does not block anything, but "improves every goal
at once" was a claim and it is now a measured miss. D1 improves goals 1 and 4,
is neutral-to-slightly-negative on fairness, and is untested on goal 3.

The sweeps are already known to be non-hard: A1b defers 30 of them into two
passes and the output is bit-identical over 1600 vectors (F51). Work that can be
reordered into a different number of passes without changing the answer is not
work an attacker has to do in the form we pay for it.

Projected from the measured shares, with the caveat below:

| | now | without the sweeps |
|---|---|---|
| nonce cost | 1.00 | **0.79** |
| fill share | 59.5% | **75.8%** |
| ASIC bound, hash free | 1.68x | **1.32x** |
| verify, 7950X 1T | 1.32 ms | ~1.04 ms |
| absolute chained AES, the GPU gate | 1 MB | **1 MB, unchanged** |
| T-table penalty, measured after the fact | 4.9 to 8.0x | **8.4 to 16.2x**, F59 |

**Measured 2026-10-06 in the daemon with v14 active, F57, and the projection
held.** D1 removes **23.9%** of a nonce, a 1.313x speedup, taking the fill share
to **73.8%** and the ASIC bound to **1.36x**. The projected 0.79, 75.8% and 1.32x
above were within two points on every axis, which is the first time a linear
projection on the share table has survived direct measurement.

So it tightens the ASIC bound by a quarter, makes verification 21% cheaper, and
does not touch the anti-GPU gate. P3 is satisfied because the sweeps are XOR,
not AES.

What is lost, and why P5 says it is affordable: the sweeps spread salt through
the pad before the main loop diffuses it. F23 already asked that question and
answered it, for a different reason, before this change was contemplated.

**Open and genuinely unresolved:** `xx` and `yy` currently bound the sweep loops
*and* the CN steps inside them. Removing the sweeps leaves them bounding CN
steps alone, which P6 says to keep. Whether they should then fold into `iters`
is a simplification question, not a security one, and the answer affects the
warp-divergence argument.

**Answered 2026-10-06, F58, and the answer is stronger than the question.** With
the sweeps gone the three loop bodies are identical, so `xx`, `yy` and `iters`
reach the hash only through `(xx - 1) * yy + iters`, a single count in
`[12, 119]`. Verified by equivalence groups, not by reading the source: every
draw with the same total gives the no-sweep hash the same answer, and the
shipped hash a different one. So the nest is not a simplification question any
more, it is dead structure, and the daemon's three draws become one. P6 is
unaffected: warp divergence depends on the total, and the total's distribution
does not move.

**The first correctness gate passed, F58.** Hardware AES against software AES
over all 1600 consensus draws, for the candidate and for the shipped hash,
plus the chain entry points and the out-of-domain corners. It also closed a gap
that predates D1: `cn_slow_hash_self_test` compared the two arms at
`(3, 3, 64)`, which consensus never draws.

**One cost that was not in this document, F58 section 4.** The sweep's inner
loop length spans 32x and is drawn from data, so it is a second source of GPU
warp divergence worth roughly 1.5x on its own share, and D1 deletes it. P6's
1.9x step-count term survives untouched and is the larger of the two, but the
smaller one was being given up without being named. Modelled, not measured.

**In D1's favour, also F58:** `r2` aliases `&c` in the hardware arm and `&b` in
the software one, and the sweep is its only consumer. D1 makes the two arms
structurally identical, so the one divergence that would appear only on
machines without AES-NI stops being reachable.

### D2. Raise `CN_SALT_MEMORY`. The lever itself.

256 KB is the denominator of the GPU feeder attack: F43 and F46 put a
GPU-feeds-CPU split at 1.95x and the limit is PCIe bandwidth at 256 KB of salt
per nonce. Raising it raises that cost **linearly**, and it adds to the half
nobody can specialise, which is the only thing F38 says works.

With D1 first, projected:

| | now | D1 | D1 + 512 KB salt |
|---|---|---|---|
| nonce cost | 1.00 | 0.79 | 1.39 |
| fill share | 59.5% | 75.8% | **86.3%** |
| ASIC bound | 1.68x | 1.32x | **1.16x** |
| feeder cost per candidate | 1.0 | 1.0 | **2.0** |
| verify, 7950X 1T | 1.32 ms | 1.04 ms | ~1.83 ms |

1.83 ms is still **four times cheaper to verify than live v6**, which is the
budget argument above being spent rather than banked.

**Cost and risk.** It needs a **v14-only chain fill**, because `get_cna_v6_data`
is called by `get_block_longhash_v13` at
[cryptonote_tx_utils.cpp:689](../../src/cryptonote_core/cryptonote_tx_utils.cpp#L689)
and has validated every block since 4,320,000. Its 4096-block loop is where
256 KB is baked in. PLAN-v8 declined to fork that function for F47's cosmetic
gain and was right to; this is not a cosmetic gain, but forking it **doubles the
consensus-critical surface permanently** and that cost is real and forever.

The sync cost is also the least certain number here. It is modelled as linear in
salt size, and the real fill is a random-access gather against a 236 MB block
cache whose behaviour under a doubled working set is not linear and has not been
measured.

### D3. Raise the full-history draw odds. Closed by F60, it cannot work.

**Measured 2026-10-06 and it has nowhere to go.** Forcing *every* draw to full
history, `odds = 256`, moves the fill from 1.06x the HC-128 floor to 1.29x. So
the whole of this lever, used to its absolute maximum, reaches about a quarter
of the fill, and the shipped 13 of 256 already collects a sixth of that. The
ceiling is too low to pay for the v14-only fill it would need. See F60.

`CNA_V6_FULL_HISTORY_ODDS` is 13 of 256, about 5%, with the other 95% drawn from
the last `CNA_V6_WINDOW_BLOCKS` = 100,000 so they stay cache-resident. F38 names
this as the honest weak point: a well-funded attacker gets that cache too and
serves 95% of the fill from fast memory. **What binds them is the 5%.**

Raising the odds forces more of the database to be hot per nonce, which is goal
3 directly, and the cost is cache misses, which is goal 4. It needs the same
v14-only fill as D2, and the two should be decided together since they trade
against the same budget.

### D4. Reconsider the pad once the fill changes. Not now.

The pad verdict was reached with the fill held at 256 KB. The two are coupled
through the salt stride and through the share arithmetic, so if D2 lands the pad
is a different question. **It would need a new pre-registration, not an
amendment**, per the closing note in
[PAD-DECISION-PREREG.md](PAD-DECISION-PREREG.md).

### D5. Chain the fill's reads and drop the reseeds. The largest measured gain on the table.

**New 2026-10-06, out of F60, and it is the first candidate that improves goals
1 and 4 together by a large margin rather than a few percent.**

The fill's cost is in the wrong place. It is 94% HC-128 and 5.7% memory, and two
thirds of the whole fill is `HC128_Init`: 257 reseeds per nonce, each running
the full P and Q expansion.

**The reseeds are not waste.** Each keys HC-128 from the output buffer, so the
index stream depends on blocks already read and an attacker cannot know which
blocks they need in advance. That property is why they cannot simply be deleted.

**But a dependent read chain provides the same property directly and better.**
Index `n+1` derived from the bytes at index `n` gives one dependency barrier per
read instead of one per 64, and pays for it in DRAM latency rather than key
setup. One is inherent; the other is the most ASIC-friendly thing in this
algorithm.

Measured, both levers, against today's 1.323 ms nonce with its 0.744 ms fill:

| chains | fill | nonce | vs today | memory share of a nonce | ASIC bound |
|---|---|---|---|---|---|
| shipped | 0.744 | 1.323 | 1.00x | **2.2%** | **45.6x** |
| 2 | 1.019 | 1.598 | 1.21x | 51.9% | 1.9x |
| **4** | **0.603** | **1.182** | **0.89x** | **35.0%** | **2.9x** |
| 8 | 0.412 | 0.991 | 0.75x | 22.5% | 4.4x |

**At four chains verification gets faster and the ASIC bound improves roughly
sixteenfold**, by removing code rather than adding any. With D1 as well the
nonce is 0.865 ms and the bound 2.1x.

**The objection that could sink it, and it is serious.** A dependent chain
serialises *one nonce*. A device with thousands in flight hides that latency
entirely and is then bound by random-read throughput, while a CPU miner at 30
threads is already near its own limit for outstanding misses. **So the lever may
cost the honest CPU more than it costs the attacker**, which is the exact
failure mode F38's rule exists to catch, arriving from a new direction. What
settles it is random-read throughput per dollar on GPU and ASIC memory against
CPU memory, and that is unmeasured. It is the same B3-shaped question and should
go to whoever answers B3.

It is still the right direction even so: today's cost is a stream cipher, which
is unambiguously cheap in silicon, and DRAM traffic is at worst ambiguous.

**Other costs.** It needs a v14-only fill, so `get_cna_v6_data` forks
permanently and the consensus-critical surface doubles, which D2 declines for a
smaller gain. And the cost grows with chain length, which difficulty absorbs but
verification does not.

**The window objection is now measured and small, F61.** Drawing from full
history costs **1.30x on the fill, +0.311 ms per block**, in the daemon against
real blocks. That is about 34 seconds across every block above the assume-valid
height. The window was introduced to avoid full-history reads, but at today's
chain length it is not load-bearing for sync speed, so reversing it is a far
cheaper decision than this plan assumed.

F60 sections 6 to 8 have the measurements and the full list of objections.

## What is closed, and must not be reopened without new evidence

- **Floating point.** Built and measured. Narrows the cross-machine spread by
  about 8%, costs the CPU more than the card, loosens the ASIC bound. F37, F38,
  F41. Leave unshipped.
- **Raising `iters` or restoring CryptoNight depth.** F48, with a pre-registered
  ceiling it failed.
- **Growing the pad.** F54 and lesson 10. It would help an attacker.
- **Shrinking the pad.** F54 and F55, decided against pre-registered criteria,
  and independently corroborated from the GPU side.
- **Making the sweeps non-commutative to block the deferral.** F44. Note D1
  deletes this question rather than answering it.
- **Moving `xx`, `yy` or `iters` to the stable block hash.** P6.

## The gate on half of this

**Everything about goal 1 rests on an unmeasured assumption: that AES-NI beats
T-table AES by enough.** RESULTS.md section 6.3 has warned about it since before
this phase existed, PLAN-v8 lists it as the open question, and B3 has never run.

It is load-bearing for D1 and D2 in opposite directions. D1 is safe only because
it leaves the absolute AES alone, which only matters if AES is the gate. D2's
whole value is making a feeder pay more chained AES, which is worth nothing if a
card does AES cheaply.

**Half of it is now measured, F59, and the half that moved is D2's.** On a CPU
the penalty for losing the AES instructions is 4.9x to 8.0x on v8's core and
8.4x to 16.2x without the sweeps, the range being the i7-7700HQ against the
7950X. So there is a real asymmetry to lose and D1 widens it rather than
narrowing it, but it is **half as large on the weaker machine**, and the weaker
machine is what the gate has to hold for. What that does to D2 is less comfortable: the chained main
loop is only **2.48x**, so "making a feeder pay more chained AES" was never the
mechanism. The gate is the once-per-nonce pad fill at 16.2x, and **D2 does not
increase the pad fill at all**. D2's case now has to rest on its PCIe bandwidth
argument alone, which is where F43 and F46 actually put it.

The measurement is a CPU doing table lookups out of L1, so it is a floor on the
structural penalty rather than a card's number. B3 is still the gate. What has
changed is that D1 no longer depends on its answer in the direction the plan
assumed, and D2 depends on it more.

Bento-Box's fourth point sharpens it further and is not modelled anywhere here:
the limiter for a CryptoNight-adjacent GPU kernel is **how many nonces stay
resident**, not VRAM, and at 256 KB a pad is inside FPGA block-RAM territory.
Every specialisation argument in this tree is about ASIC SRAM. FPGA is nearer
term and cheaper.

**So: get the GPU number before building D2.** D1 does not depend on it.

## Proposed sequence

```
1. B3, the GPU and feeder number, by measurement or by asking someone
   with the depth. Gates D2 and D3.
2. D1, remove the sweeps. Independent of B3.
      a prediction stated first            done, F57, held to two points
      HW == SW across the grid             done, F58, 1600 cases, PASS on
                                            Zen 4 and Kaby Lake with
                                            bit-identical digests
      the cross-machine spread re-measured  done, F58. 2.17x to 2.19x on a
                                            real nonce, so it does not block
                                            D1, but the direction is the wrong
                                            one and the fairness argument for
                                            D1 is withdrawn
      new known-answer vectors              owed, and only once D1 is decided,
                                            since regenerating them is the
                                            deliberate act that says the hash
                                            changed
      a view on the ASIC area cost          open, the best question for
                                            Bento-Box alongside B3
3. D5, chain the reads and drop the reseeds. Largest measured gain here,
   and the one that changes what the fill IS rather than how much of a
   nonce it occupies. Needs: the random-read throughput question, which is
   B3-shaped and goes to whoever answers B3; a decision on forking
   get_cna_v6_data, since the surface doubles permanently; and a decision
   on the 100,000-block window, which the latency argument reverses.
4. D3 is closed by F60: at its absolute maximum it reaches a quarter of
   the fill, which cannot pay for a v14-only fill.
5. D2 against B3's answer and a measured sync cost, not a modelled one.
   Note F59 removed its stated mechanism, so it now rests on PCIe
   bandwidth alone.
6. D4 only if D2 or D5 lands, and only with a new pre-registration.
```

**The ordering above is by evidence, not by size.** D5 is the largest gain on
the table and arrived last, which is the usual shape: it only became visible
once F60 measured what the fill is made of. D1 stays ahead of it because D1's
correctness gates are through and D5 has not been built.

**Update 2026-10-06: the share table has now been checked directly and it
holds.** F57 measured the whole v8 nonce in the daemon with v14 active: the
chain fill is 56.2% with the run-ahead and 58.7% without, against the table's
59.5%, and the cold-pad correction F52 warned about is +3.3%. So the
projections below stand. A 68% figure briefly replaced 59.5% during that work
and was wrong; it came from a fill measured under v13, where an 8 MB pad per
thread makes the same function cost 1.63x more.

**The original caution, kept because it was right to raise: the share table is
from one instrumented profile and every projection in this document is linear
arithmetic on it.** That is exactly
the kind of reasoning lesson 5 says has produced a wrong prediction twice on this
project. B4, the daemon-side split timing of `get_block_longhash_v14`, would
replace the modelled half with a measured one and is cheap. It should come
before anyone commits to the numbers in D1 and D2.

## What would make this whole direction wrong

Stated now, so it is recognisable later:

- **A card turning out to do chained AES cheaply.** Then the AES is not a gate,
  P3 is void, D2 buys nothing, and v8's GPU resistance has to come from the fill
  alone, which means D3 and a much larger sync bill.
- ~~**The fill turning out to be cheaply servable at scale.**~~ **HAPPENED.**
  Measured 2026-10-06, F60: the fill is 94% HC-128 and 5.7% memory, two thirds
  of it `HC128_Init`. The premise that random-access database bandwidth is the
  binding constraint is false. Pool resistance survives, because it rests on
  needing the chain to get the right answer rather than on the reads costing
  anything. The ASIC bound does not: it ranges from 1.78x to 31x depending on
  what HC-128 costs in silicon. This was the item flagged as deserving its own
  measurement rather than inheritance, and it did.
- **The share table being wrong.** Everything here is proportions. B4 settles it.
