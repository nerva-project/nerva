# Non-outsourceable proof of work for Nerva

*2026-10-07. A desk study, not a measurement: nothing here was benchmarked on
our machines. Summarised as FINDINGS F83. Each claim names its source; claims
that are our own analysis say so.*

## The question

F71 established that goal 3's barrier is a 237 MB data set, not a full node, so a
thin-client pool is possible, and named non-outsourceable PoW as "the tool that
actually addresses it". The design was re-opened with no deadline, so the
question became whether to pivot v8 to it, and in particular whether it can be
made **truly** pool resistant: a worker who steals a block's reward cannot be
identified or punished by the pool.

**Answer: not as an addition to v8, and not as a pivot now.** The weak form is
defeated for free on Nerva. The strong form, the only one that meets the bar
above, cannot wrap a memory-hard hash, works against goal 1, and still leaves a
statistical attack that only a change to the reward schedule closes.

## Sources

| | |
|---|---|
| **[M15]** | A. Miller, A. Kosba, J. Katz, E. Shi, *Nonoutsourceable Scratch-Off Puzzles to Discourage Bitcoin Mining Coalitions*, ACM CCS 2015. Read in full. <http://soc1024.ece.illinois.edu/nonoutsourceable.pdf> |
| **[CS20]** | A. Chepurnoy, A. Saxena, *Bypassing Non-Outsourceable Proof-of-Work Schemes Using Collateralized Smart Contracts*, WTSC 2020, IACR ePrint 2020/044. Abstract only. <https://eprint.iacr.org/2020/044> |
| **[ERG]** | Ergo documentation on Autolykos, and the Ergo blog post of 2021-08-24 on v2. <https://docs.ergoplatform.com/mining/autolykos> |
| **[L14]** | S. D. Lerner, *Theoretical and Practical Nonoutsourceable Puzzles*, 2014. <https://bitslog.com/2014/06/19/theoretical-and-practical-nonoutsourceable-puzzles> |

## 1. The two definitions

From [M15], sections IV to VI.

- **Weakly non-outsourceable:** for any outsourcing protocol in which the
  operator does only a small fraction of the work, a worker who finds a winning
  ticket can re-bind it to its own payload (its own payout) with little extra
  work. The worker *can* steal.
- **Strongly non-outsourceable:** additionally, the stolen ticket is
  computationally indistinguishable from one found by independent effort, even
  given everything the operator saw. The worker can steal *and the operator
  cannot tell*.

Only the second meets the bar in the question. [M15] says so itself: the weak
form's "critical drawback" is that a thief "may be detected when he spends his
stolen reward, and thus might be held accountable through some external means".

## 2. Why the weak form fails on Nerva

### 2.1 The operator can always identify the thief

[M15] section VI gives the countermeasure: operator and worker agree a prefix of
the nonce space as a watermark, the worker searches only the suffix, and the
operator accepts shares only if they carry the prefix. A stolen block carries
the watermark and names the worker. Nothing in a weak puzzle prevents this,
because the ticket is published in the clear.

### 2.2 Punishing the thief costs the pool nothing on Nerva

Once the thief is known, the pool needs only something to take from it worth
more than the theft. On Nerva that is one block reward:
`FINAL_SUBSIDY_PER_MINUTE` is 0.3 XNV (`cryptonote_config.h`), the supply is
past the point where `get_block_reward` floors to it
(`src/cryptonote_basic/cryptonote_basic_impl.cpp`), and
`DIFFICULTY_TARGET` is 60 s. So **one theft gains 0.3 XNV plus fees**, and any
pool with a payout threshold above that already holds it from every worker.

[CS20] is often quoted as "smart contracts break non-outsourceability", which
would suggest Nerva, with no scripting, is immune. It is not. The contract in
[CS20] is only a trustless escrow for the collateral; a pool that simply holds
the balance itself gets the same deterrent, at the price of being trusted, which
pool operators already are. [CS20]'s abstract also states that the strong
schemes are the exception it does not bypass.

### 2.3 What happened when it shipped

Ergo launched with a weakly non-outsourceable puzzle (Autolykos v1) and removed
it in Autolykos v2, EIP-0009, at block 417,792 in 2020 [ERG]. The stated
reasons were that it could be bypassed with smart contracts and that, after more
than a year, it was "not an attractive option for small miners", who wanted
pools. No other production chain has shipped either form, as far as this
search found.

## 3. What the strong form requires, and why v8 cannot have it

### 3.1 The proof must cover the puzzle's whole verification

[M15]'s strong construction (Figure 1) is generic: encrypt the weak ticket and
attach a NIZK proving that the ciphertext holds a ticket that passes the weak
puzzle's `Verify`. **So the zero-knowledge circuit contains the whole
verification of the underlying puzzle.**

[M15] makes that cheap by choosing a puzzle whose verification is a few dozen
SHA-1 Merkle-branch hashes (2^10 leaves, q = q' = 10). v8's verification is a
1 MB AES fill, 16,384 dependent pad reads and a chain fill reading a 237 MB block
cache. Proving that in zero knowledge, per block, inside a 60 s interval, is not
something any current proof system is close to. **A strong NO puzzle has to be
designed to be cheap to verify in a circuit, and v8 is the opposite.**

Our analysis: circuit-friendly hashes (Poseidon, SHA-family) are cheap on GPUs
and ASICs, and AES, which F79 shows is v8's ~4x GPU gate, is expensive in a
circuit. So the property that makes a hash provable and the property that makes
it CPU-favouring pull in opposite directions.

### 3.2 The key has to be most of the work

[M15] Theorem 2 holds only "if the pool operator's work tC is not a significant
fraction of te", and the proof assumes the cost is dominated by the keyed random
oracle calls, "as long as the cost of the rest of the computation is only a
constant fraction". The Merkle tree's secret leaves are the key; every scratch
attempt needs q of them.

Our analysis of what that means for v8: if a keyed step were bolted onto v8,
the memory-hard part would not need the key. The operator would keep the key,
do the cheap keyed step itself, and outsource the expensive keyless part, and
the worker could not steal. **So non-outsourceability cannot be added to v8; the
puzzle itself must become the keyed structure.** That is a different PoW
family, not a v8 option.

### 3.3 It is a one-shot guarantee, and a pool can still use statistics

[M15] section VIII, "Challenge 2": the definition "describes a one-shot game"
and "does not immediately eliminate statistical enforcement techniques over
time". A pool knows each worker's hashrate from its shares and so its expected
block count. A worker who withholds blocks shows up as persistent bad luck.

Our model at Nerva's 1,440 blocks a day, for a worker stealing up to two
standard deviations below expectation over a 30-day window:

| worker's share of network hashrate | expected blocks / 30 d | 2 sd | can steal unseen |
|---|---|---|---|
| 1% | 432 | 42 | ~10% |
| 0.1% | 43 | 13 | ~30% |

A pool that evicts persistently unlucky workers caps theft at roughly those
rates and pays for it as a margin. Nerva's 60 s blocks give a pool ten times
Bitcoin's samples per day, so detection is faster here than in [M15]'s setting.

[M15]'s fix is a multi-tier reward: frequent small prizes, a 10-minute main
prize, and a rare jackpot (one every three months in their table) that a worker
can steal without statistical trace. **For Nerva that is a change to the
emission schedule**, and the frequent tier conflicts with proof latency (3.4).

### 3.4 Proof latency against a 60 s block

[M15] Table II: under 15 s to prove at its C = 2 setting with libsnark on 32
cores, 7.7 ms to verify each sub-proof, 23 KB per ticket. Their argument that
14 s is acceptable rests on Bitcoin's 10-minute interval. At 60 s it is a
quarter of the interval and a large orphan risk for the thief, which weakens the
deterrent. Proof systems have improved by a large factor since 2015; how much is
**our estimate, not measured**, and is the first thing a spike would measure.

[M15] also allows an honest miner to publish the plaintext ticket instead of a
proof, so only a thief pays the proving cost; verification must accept both.

### 3.5 Bypasses that no definition covers

Our analysis, not from the sources read:

- **Trusted execution.** An operator can run the worker inside an attested
  enclave (SGX on servers, SEV-SNP, TDX) that holds the key and only signs
  payloads paying the operator. Consumer support is uneven, but this is exactly
  the server-farm case.
- **Operators who own the hardware.** Farms and botnets do not outsource to
  strangers, so the puzzle does not touch them. On a CPU coin those are the
  likelier large miners.
- **Free equivocation.** The ticket is not bound to the payload, so its holder
  can sign many different blocks at the same height without extra work. A normal
  PoW makes each variant cost a full solution. Bounded to one block, but new.

## 4. Fit with Nerva's chain

Mechanically it fits. A new block version would hash the previous block and the
ticket, take the coinbase out of the PoW input, and require the coinbase to be
authorised by the ticket's key. Two Nerva-specific notes:

- **A plus:** [M15] expects the thief to bind the reward to a fresh key and
  launder it. On Nerva a coinbase output already goes to a one-time stealth
  address and is spent through a ring signature, so that step is built in.
- **No scripting is irrelevant.** It removes [CS20]'s trustless escrow but not
  the custodial one (2.2), and [CS20] does not reach the strong form anyway.

## 5. Effect on the other goals

| goal | weak | strong |
|---|---|---|
| 1, GPU/ASIC resistance | neutral at best | worse: circuit-friendly puzzle (3.1) |
| 2, CPU fairness | neutral | unknown, likely worse for the same reason |
| 3, pool resistance | defeated for free (2) | real, but capped by statistics (3.3) |
| 4, sync speed | small cost: [M15] puts weak verify at 15.1 ms in unoptimised Python | one proof check per block; a few ms with a modern system (estimate) |
| 51% via rented hashpower | small | real help: a renter cannot trust the rigs it rents. [CS20]'s abstract names rental as a motivation |

The last row is the strongest case for it on a small chain. v8 is not sold on
rental markets today, so its present value is small.

## 6. Decision

**Not pursued now.** Nerva already has the outcome NO is meant to force: there
are no known pools (F71), so miners solo-mine, which is the variance cost Ergo
removed it to avoid. A strong scheme is a new PoW family with an emission change
attached; it would trade goal 1 for goal 3 and has never shipped anywhere. Time
goes to the remaining v8 levers first.

## 7. If it is revisited: a spike with kill criteria

To be pre-registered before running, in the style of `D3-ODDS-PREREG.md`:

1. **Proof latency.** Prove a Merkle-puzzle ticket of [M15]'s shape with a
   current prover on one desktop. Kill if over 10 s, a sixth of the interval.
2. **GPU ratio of the scratch loop**, with the F79 rule: fold every word of every
   lane into the output and check the rate against the card's ceiling. Kill if
   worse than v8's measured 3 to 5x.
3. **Statistical detection** with Nerva's flat 0.3 XNV reward, extending 3.3.
   Kill if a pool can hold theft under its fee margin without a reward-schedule
   change, unless that change is accepted first.
