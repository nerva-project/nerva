# Rejection-free draw: pre-registration

**Written 2026-10-08 and accepted by the user the same day, before any
measurement for it was run.** Nothing in this file may be edited from here on. Results go in FINDINGS.md and the outcome in the
decision record at the bottom. The latitude stated in RESEED-PREREG.md applies
here too: a narrow miss may be weighed against what the change buys, argued in
the decision record; a wide miss on a kill criterion may not.

Companions: [FINDINGS.md](FINDINGS.md) F69 and F82 (rejection sampling's cost),
F84 and F85 (the reseed change this builds on), and
[RESEED-PREREG.md](RESEED-PREREG.md) for the format.

## The question

**Should v14's chain fill draw its block indices without rejection, and drop
the selector draw that odds 256 makes constant?**

Each of the fill's 16,384 picks today is:

```c
if (HC128_U32(rng, &ki, 256) < odds)          /* selector: 1 word */
    return HC128_U32(rng, &ki, height);       /* index: redraws on overflow */
```

`HC128_U32` masks a keystream word to the next power of two and redraws while
the result is out of range. At height 4.5M it accepts **53.6%** (F82), so an
index costs 1.87 words on average and its loop exit is a coin toss the branch
predictor cannot learn. At v14's odds of 256 the selector is always true and
spends a word to say so.

## Candidates

All are v14-only. v13 keeps `HC128_U32` and its selector and stays
byte-identical, enforced by the known-answer test from F85.

| | selector | index | words per pick |
|---|---|---|---|
| **S, shipped** | 1 word | `HC128_U32`, rejection | 2.87 |
| A | 1 word | `(uint64_t)w * height >> 32`, one word | 2 |
| **B** | **none at odds 256** | **as A** | **1** |

**B is the candidate going in.** A exists to split the two effects.

`(uint64_t)w * height >> 32` maps 2^32 words onto `height` buckets of 954 or
955 words each at 4.5M, so some blocks are 0.1% likelier than others. That is
not a security property: what the picks must do is spread over all of history
with no locality, and a 0.1% tilt spread evenly across the whole chain gives an
attacker nothing to cache. The bias shrinks as the chain grows past 2^32/height.

## Predictions

7950X, one thread, from F60's 15.6 ns per `NextKeys` and a misprediction per
pick at about 16 cycles:

| | fill | nonce | vs S |
|---|---|---|---|
| S, k = 16 as shipped | 0.369 ms (F84) | 0.635 ms | 1.00x |
| A | about 0.31 | about 0.58 | about 1.10x |
| B | about 0.29 | about 0.56 | about 1.13x |

**The GPU direction is genuinely uncertain, which is why this needs a new
measurement.** A card's rejection loop is worse than a CPU's: a warp runs until
its slowest lane accepts, about 5.5 draws for 32 lanes against 1.87 on average.
So the card may save more than the CPU does. Against that, every word removed
is HC-128 work, the half of the fill a card is about 3x worse at, and what is
left is a larger share of memory, where a card is better. No existing harness
models picks on a card, so C-3 cannot be composed honestly and is measured.

## What could make it wrong

1. **The card gains more than the CPU** through the divergence above. Most
   likely failure, and the reason for C-3.
2. **Fairness.** Branch misprediction cost differs across microarchitectures;
   removing it removes a component whose spread is unknown.
3. **The run-ahead's prefetch distance.** With fewer words per pick a block's
   64 indices are produced faster, so the prefetches have less time in flight.
   Likely small; visible in C-2 if not.

## Criteria

| | criterion | threshold | how measured |
|---|---|---|---|
| **C-1** | GPU host-fed, CPU better by | not below S in the same run | `nerva-gpubench`, a B row beside the k16 row |
| **C-2** | CPU mining, whole nonce, all threads, 7950X | **at least 1.05x** S | same run |
| **C-3** | GPU doing the whole fill itself, CPU better by | **not below S**, same session | `t_fill_gpu`, new: the full v14 fill on the card, both draws |
| C-4 | fairness, one thread | at most **2.50x** on F70's basis | `t_v8_fill` draw arms on 7950X and i7-7700HQ |
| C-4b | fairness, all threads | the change in spread against the 5600X and the i7-7700HQ, each **within 5%** | `nerva-gpubench` on all three |
| C-5 | verification, one thread | at least **1.05x** | `t_v8_fill` draw arms plus the core |

C-1 and C-3 are kill criteria. C-4b replaces the all-thread half of
RESEED-PREREG's C-4, which compared machines with different core counts on an
absolute threshold and failed at baseline: here it is the change that is
judged.

**C-3's harness has its own gate before it may be timed:** `t_fill_gpu` must
reproduce the CPU fill bit for bit for both draws, and fold every output word
of every work-item into its result (the dead-code trap in F79 and F80). Its rate
is checked against the card's HC-128 ceiling from `t_hc128`.

## Measurement plan

1. `t_v8_fill`: S, A and B arms at k = 16, odds 256, interleaved, on the 7950X,
   then the i7-7700HQ and the 5600X.
2. `t_fill_gpu`: the whole v14 fill per work-item, block cache in VRAM, HC-128
   state in `__local` as F80 placed it, S and B. Gate first, then timing,
   against the CPU fill at all threads in the same process.
3. `nerva-gpubench`: a B row beside the k16 row, on all three machines.
4. Only if the criteria pass: the daemon change, new v14 known-answer vectors
   from `t_fill_kat`, and the v13 vector unchanged.

## Decision record

**2026-10-08: B REJECTED under C-3, a kill criterion, missed by a wide
margin.** FINDINGS F86.

On the whole fill measured on the card (`t_fill_gpu`, all gates passed), the
CPU's advantage falls from **2.87x under S to 1.26x under B**: the card gains
2.38x, the CPU 1.05x at 32 threads. The rejection loop's warp divergence was
most of a card's fill cost, which the "What could make it wrong" section named
as the likeliest failure and underestimated.

C-1, C-2, C-4, C-4b and C-5 were not run, since nothing in them could rescue a
wide miss on C-3. For the record, the CPU side alone: B makes a fill 1.33x
faster single-threaded and 1.05x at 32 threads (`t_v8_fill`, `t_fill_gpu`). A
was not measured on the card; it uses B's index draw and removes the same loop.

The finding that replaces the lever: the rejection loop is a GPU gate worth
keeping, and possibly worth strengthening, under a separate pre-registration.

*Later the same day, F88: with better kernels for S, the CPU's lead on the fill
under S is bounded between about 1.7x and 2.6x rather than measured at 2.87x.
B, at 1.28x, is below that whole range, so the rejection stands. Strengthening
the divergence is not pursued.*
