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

### D3. Raise the full-history draw odds. Pool resistance, cheaply.

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
2. D1, remove the sweeps. Independent of B3. Needs: a prediction stated
   first, new known-answer vectors generated deliberately, HW == SW across
   the grid, and the cross-machine spread re-measured since the balance moves.
3. Decide D2 and D3 together against B3's answer and a measured sync cost,
   not a modelled one.
4. D4 only if D2 lands, and only with a new pre-registration.
```

**Before any of it: the share table above is from one instrumented profile and
every projection in this document is linear arithmetic on it.** That is exactly
the kind of reasoning lesson 5 says has produced a wrong prediction twice on this
project. B4, the daemon-side split timing of `get_block_longhash_v14`, would
replace the modelled half with a measured one and is cheap. It should come
before anyone commits to the numbers in D1 and D2.

## What would make this whole direction wrong

Stated now, so it is recognisable later:

- **A card turning out to do chained AES cheaply.** Then the AES is not a gate,
  P3 is void, D2 buys nothing, and v8's GPU resistance has to come from the fill
  alone, which means D3 and a much larger sync bill.
- **The fill turning out to be cheaply servable at scale.** The pool resistance
  and the ASIC bound are the same argument, and both assume random-access
  database bandwidth is the binding constraint. A 236 MB working set is not
  large. F38 flags this as the honest weak point and it deserves its own
  measurement rather than inheritance.
- **The share table being wrong.** Everything here is proportions. B4 settles it.
