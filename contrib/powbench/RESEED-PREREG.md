# Reseed interval: pre-registration

**Written and accepted 2026-10-07, before any measurement for it was run.**
Nothing in this file may be edited from here on. Results go in FINDINGS.md and
the outcome in the decision record at the bottom.

**Accepted with one stated latitude.** A criterion missed narrowly may still be
weighed if the change buys something else in exchange. That case must be argued
in the decision record, naming the miss, its size and the offsetting gain, and
it is not available to a result that misses by a wide margin.

Companions: [FINDINGS.md](FINDINGS.md) F60 (the cost and the lever), F62 and F66
(gather on a card), F78 to F80 (the corrected GPU gates), F82 (rejection
sampling), and [D3-ODDS-PREREG.md](D3-ODDS-PREREG.md) for the format.

## The question

**Should v14's chain fill reseed HC-128 less often than every 16 messages?**

`get_cna_v6_data` runs 256 blocks of 16 messages and calls `HC128_Init` after
every block, plus once at the midpoint: **257 key setups per nonce**. F60 put
them at 67% of the fill on a CPU. It was closed twice on GPU grounds: F62 (D5)
because HC-128 looked like a 12x gate, and F76 because the reseeds looked like
its mechanism. **F80 removed both**: with every keystream word consumed, HC-128
in `__local` is about 3.1x at any mix of setup and keystream, so the reseeds buy
about 1.04x against a card. What they cost a CPU is unchanged.

## Candidates

`k` is the number of 16-message blocks between reseeds. Key setups per nonce are
`256/k + 1` (the midpoint one stays). Each is a v14-only parameter passed the way
D3 passed the odds; v13 passes `k = 1` and stays byte-identical.

| k | key setups | reads between data-dependent barriers |
|---|---|---|
| 1, shipped | 257 | 64 |
| 4 | 65 | 256 |
| 8 | 33 | 512 |
| **16** | **17** | **1,024** |
| 256 | 2 | 8,192 |

**k = 16 is the candidate going in**, chosen before measurement by a rule: the
smallest `k` that removes at least 90% of the key-setup cost that `k = 256`
removes (94%; `k = 8` gives 88%). The rule exists because the saving is nearly
flat past `k = 16` while the risk in the last section keeps growing.

## The model, and the predictions it makes

Inputs, all single-thread 7950X and RTX 3050, all already measured:
`HC128_Init` 1.95 us (F60); keystream and loop 0.26 ms at odds 256 (F60, F82);
memory 0.09 ms at odds 256 (F82); core 0.266 ms (F72); GPU worse by 10.7x on the
core (F78), 3.23x on key setup and 3.11x on keystream in `__local` (F80); GPU
**better** by 1.64x on gather (F62).

| k | CPU fill | CPU nonce | verify vs shipped | GPU worse by, card does everything |
|---|---|---|---|---|
| 1, shipped | 0.851 ms | 1.117 ms | 1.00x | **4.8x** (F78 composed 4.7x) |
| 4 | 0.477 | 0.743 | 1.50x | 5.5x |
| **16** | **0.383** | **0.649** | **1.72x** | **5.9x** |
| 256 | 0.354 | 0.620 | 1.80x | 6.0x |

**The prediction is that this improves goal 1 rather than trading against it.**
The card's cipher ratio does not move (F80), so cutting the cipher shrinks the
card's 3x component and the core's 10.7x becomes a larger share of the nonce.

Host-fed (the card runs the core, a CPU runs the fill), F78 measured 3.04x. The
card is core-bound in that mode, so its rate holds while the CPU's rises by the
nonce ratio: **predicted 3.04x to about 5.2x at k = 16**, and a host core feeds
1.7x more of the card.

Against an ASIC, which F65 says pays only for the reads, the CPU's cost falls
1.72x and the ASIC's does not, so **the ASIC advantage falls by the same 1.72x.**

Goal 4 end to end: 0.47 ms off F75's 4.48 ms per HF14 block, about **1.12x on
sync**, much less than the 1.72x on the hash. Stated now so it is not oversold
later.

## What could make the model wrong

1. **Multi-thread memory.** Every figure above is one thread. At 30 threads a
   faster nonce asks for proportionally more random reads, about 1 MB of lines
   per nonce. If the 7950X runs out of random-read bandwidth first, the mining
   gain shrinks while the card, with far more bandwidth, keeps all of its own.
   This is the one most likely to fail.
2. **Fairness.** Memory's share of a nonce rises from about 8% to 14%, and
   memory varies more across machines than the cipher does. The spread is
   2.34x against a 2.50x limit (F70); the slack is small.
3. **Batch-sort precomputation (model only, not measurable here).** Between two
   data-dependent reseeds the indices are known in advance. An attacker holding
   N nonces in flight can sort their reads by address and sweep the cache
   instead of reading at random. That needs about 4.4M reads per barrier to
   cover every block once: N = 69,000 nonces at k = 1, N = 4,300 at k = 16.
   Fewer reseeds lowers the batch an attacker needs by `k`. It is the reason the
   reseeds exist (F60 section 5) and the reason the candidate stops at 16.

## Criteria

Each must pass at the chosen `k`. C-1 and C-2 are kill criteria: if either
fails by a wide margin, the lever is dropped and no other result rescues it
(see the latitude at the top for a narrow miss).

| | criterion | threshold | how measured |
|---|---|---|---|
| **C-1** | GPU, whole nonce, host-fed | not below shipped's ratio in the same run | `nerva-gpubench` with a reseed parameter, CPU and GPU columns |
| **C-2** | CPU mining, whole nonce, all threads, 7950X | **at least 1.30x** shipped's H/s | same run's CPU column |
| C-3 | GPU, card does everything, composed | not below shipped's | `t_hc128` at the matching `nextper`, same session, plus C-1's core |
| C-4 | fairness, 7950X against i7-7700HQ, whole nonce, 1 thread and all threads | at most **2.50x** | `t_v8_fill` reseed arm plus `v8bench` core, F70's method |
| C-5 | verification, 1 thread | at least **1.30x** | `t_v8_fill` reseed arm plus the core |

C-2's 1.30x is set below the model's 1.72x on purpose: memory contention is
expected to take some of it, and a lever that keeps under three quarters of its
predicted gain has a model too wrong to ship on.

## Measurement plan

1. `t_v8_fill`: a reseed arm at odds 256 (today's sweep is at the old odds) for
   `k` in {1, 4, 8, 16, 256}, single thread, on the 7950X and the i7-7700HQ.
2. `nerva-gpubench`: a reseed-interval argument through both fills, CPU
   reference and GPU, with the bit-for-bit gate extended to each `k`. Shipped
   and `k = 16` interleaved in one run, A-B-A.
3. `t_hc128`: re-run the `nextper` sweep with 620 added (10,500 keystream calls
   over 17 key setups), `__local` arm, same session as step 2.
4. Only if C-1 to C-5 pass: the daemon change, a known-answer vector, the
   `NERVA_SALT_SELFCHECK` reference updated, and the change joins the testnet
   round already owed for D1, D3 and the seed fold.

## Decision record

**2026-10-08: k = 16 ACCEPTED by the user, under the latitude stated at the
top.** Results are FINDINGS F84.

| | 7950X | 5600X | |
|---|---|---|---|
| C-1 host-fed, CPU better by | 3.18x to 4.91x | 1.42x to 2.27x (Vega FE) | pass |
| C-2 all threads | 1.553x | 1.607x | pass |
| C-3 card does everything, composed | 4.63x to 5.80x | not composed | pass |
| C-5 one thread | 1.62x | 1.62x | pass |

**The miss, named.** C-4's one-thread half passes, 2.42x against 2.50x on F70's
basis. Its all-thread half was mis-specified: it compares a 16-core machine
with a 4-core one, so the threshold failed at baseline (10.26x) and cannot be
scored as written. Read as a change, the all-thread spread **widens 23%
against the i7-7700HQ** (10.26x to 12.60x) and **narrows 3.4% against the
5600X**. The laptop gains 1.26x where the desktops gain 1.55x and 1.61x, and its
best thread count falls from 6 to 8 to 4, consistent with a 6 MB L3 that cannot
hold its threads' 1 MB pads once the core dominates.

**What offsets it.** Every machine measured mines faster. The GPU gap widens on
two vendors, +54% and +60% host-fed. The ASIC advantage falls about 1.7x, since
an ASIC pays only for the reads. Verification is about 1.6x faster. And the
widening is confined to one machine class: the user's ruling is that laptops
and phones are not realistic mining targets because they lack the cooling for
sustained load, which F35 already applied to phones.

**Not settled by any measurement:** the batch-sort risk, a model only. The
interval stops at 16 rather than 256 to keep an attacker's required batch at
about 4,300 nonces per barrier rather than 540.

**Next:** the v14-only daemon change, a known-answer vector, the
`NERVA_SALT_SELFCHECK` reference, and the testnet round already owed.
