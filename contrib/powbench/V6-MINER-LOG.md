# v13 (CNA v6) miner optimization log

Running record of the work, the measurements and the mistakes. Started
2026-10-04.

**Provenance.** The code this describes lives on `perf/v13-fused-pad-init` in
[R0BC0D3R/nerva](https://github.com/R0BC0D3R/nerva/tree/perf/v13-fused-pad-init)
and **is not proposed for nerva-project**. This document is on `pow/cna-v8`
because it is the evidence behind
[PLAN-v8-PHASE7.md](PLAN-v8-PHASE7.md), and a reviewer should not have to
trust a plan whose measurements live somewhere else. Every source link below
therefore points at the fork, where that code actually is; the files it names do
not exist on this branch and the line numbers are the fork's.

## Start here

**If you are picking this up to improve v8, read in this order and skip the
rest:**

1. **Lessons for v8**, ten numbered rules distilled from everything below. They
   are written to be checkable against a proposed v8 change without re-deriving
   the attack. Lessons 7, 9 and 10 are the load-bearing ones and all three are
   measured, not argued.
2. **Current state, and how to pick this up cold**, for what is built, what the
   switches are, and what is open.
3. **Measurement rules**, seven of them, each earned by a confidently wrong
   number. Rule 1 and rule 7 have each cost this project a day.

The three findings that matter most for v8, in one place:

- **v8's pad is 98.5% reproducible on every nonce** (lesson 10). v6's recompute
  attack applies structurally, with no screening needed.
- **Both known pad attacks are held off by one property**: the working set not
  exceeding L3 by much. Measured on two machines, the threshold is well above
  1.3x over-subscription, not at 1.0x (lesson 9).
- **Enlarging v8's pad would help an attacker, not hinder one** (lesson 10).
  v13 already ran that experiment: the deliberate 4 MB to 8 MB rise at HF13 is
  what created its 1.29x attack surface.

**If you are a miner wanting to run this**, see
[EXPERIMENTAL-V6-MINER.md](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/EXPERIMENTAL-V6-MINER.md) instead. Nothing in this
file is needed to use the build.

**Numbers in this log were corrected as they were re-measured.** Where a figure
was withdrawn, the old one is shown struck through in prose rather than deleted,
because rule 1 is that a withdrawn number outlives the correction. If two
figures disagree, the one in **Current state** is current.

## Why this exists

The CNA v8 work in PR #162 is measured but not live, so nobody is mining on it
and no improvement there is visible to anyone. This effort applies the same
class of optimization to **v13 (CNA v6), the algorithm mainnet runs today**, so
the result can be seen in the miner that is actually running.

The second purpose is adversarial. 0xROOTPLS reports 8.5x to 13.4x on v6 and
2.43x on v8 from the same techniques. Everything we find and understand here is
something we can design out of v8 before it ships, so the gap between a stock
miner and a tuned one stays small. Getting near his v6 numbers is what makes
that credible.

## The rig

- Build: `make release-static-win64 -j4`, **run inside MSYS2 bash**, see traps.
- Measurement daemon: offline, mainnet DB copy at `D:\Claude\nerva-dbcheck`,
  height 4,424,749. That is past HF13 (4,320,000) and short of the HF14
  placeholder (4,500,000), so the miner is on v13. The A/B script asserts the
  height; outside that window it would silently be measuring another algorithm.
- Mining started over the `start_mining` RPC at 12 threads.
- Reference point: the same machine mining normally through NervaOne reports
  580 to 640 H/s, and the rig's baseline lands at 597.6, so the rig is
  representative.

## Measurement method

A-B-B-A, with the baseline measured both before and after the change. A-B-A was
tried in earlier work and produced a confident **-5.5% that was pure drift**:
its two baseline runs came back 10.7% apart. A-B-B-A cancels linear drift, and
the A1-to-A2 gap is printed as a gate, with the run treated as void above 2%.

**The gate has now caught two fake results, which is the entire reason it
exists.** See the void run below.

Window sizes come from the measured noise rather than a guess:

- `mining_status.speed` is hashes in the last 2-second merge window
  ([miner.cpp:453](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/src/cryptonote_basic/miner.cpp#L453)), not a moving
  average.
- 25 consecutive settled readings ran 286 to 336, mean 308, so **about ±4%**.
- An early guess of "2x swing" was wrong and had the sampling window set four
  times longer than it needed to be. The settle time, by contrast, is genuinely
  needed: a fresh daemon reads high for the first couple of minutes, then steps
  down and stays down, so sampling early measures a transient.

## Stage 0: fused pad init

### What

v13 filled the 8 MB pad with AES and then made a **second full pass** over all
8 MB purely to XOR the chain salt in. The XOR is now folded into the fill's
store and the second pass is deleted, removing **16 MB of memory traffic per
hash** from a nonce that moves roughly 32 MB.

Both arms changed identically in
[slow-hash-impl.h](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/src/crypto/slow-hash-impl.h).

### Why the fold is exact

- The deleted pass advanced the salt offset in lockstep with the pad offset and
  wrapped at `CN_SALT_MEMORY`, so the salt offset was always the pad offset mod
  `CN_SALT_MEMORY` and depended on nothing else.
- `CN_SALT_MEMORY` is 262144 = 2^18, so the modulo is a mask.
- `init_size_byte` is 128 and divides 262144, so a block never straddles the
  wrap and no split case is needed. The highest byte touched is exactly
  `CN_SALT_MEMORY`, so the bounds are unchanged.
- `text` is deliberately not modified: the AES round feeds it back into the
  next iteration, so it carries the chain.

### Verification

Bit-identical over **2000 digests**: 400 seeds x 4 inputs on the hardware arm,
100 x 4 on the software arm. The known-answer test and the hardware-vs-software
self-test both pass, so the daemon starts and the hashes are the network's.

**The verification nearly tested nothing.** The pre-existing digest harness
zeroed the salt before every call. XOR with zero is the identity, so a
completely wrong salt offset would still have produced the right digest and the
run would have reported a clean pass on a check that proved nothing. The
harness now fills the salt with a dense per-seed pattern, and that is itself
checked: with the salt zeroed, 0 of 12 digests match the salted run.

Lesson: when a change touches how a value is mixed in, make the test data make
that value matter, and prove it by breaking it on purpose.

Harness is [t_v13_fold.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/t_v13_fold.c), built with
[build-v13-fold.sh](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/build-v13-fold.sh).

### Result: +7.6%

```
A1  baseline   n=12  mean  597.4  min  579  max  610 H/s   [huge pages]
B1  fused      n=12  mean  644.8  min  627  max  669 H/s   [huge pages]
B2  fused      n=12  mean  640.9  min  620  max  660 H/s   [huge pages]
A2  baseline   n=12  mean  597.8  min  577  max  622 H/s   [huge pages]

A drift across the pair: +0.1%   (within tolerance)
baseline mean 597.6 H/s   fused mean 642.9 H/s   delta +7.6%
```

A standalone benchmark of the hash core alone, excluding the chain salt, gave
**+12.1%** on the same change. The two agree: the core is about 23.4 ms of a
roughly 39.6 ms nonce, and 12.1% x (23.4 / 39.6) is 7.1%, against 7.6%
measured. A prediction made before the daemon run, from an independent
measurement, landing within half a point is the strongest evidence here that
the effect is real and not an artifact.

0xROOTPLS measured +7% for this change on an already-optimized miner.

### Confirmed on the live miner

The fused build run through NervaOne against a live synced mainnet daemon
reports **640 to 720 H/s**, against a remembered 580 to 640 before it. That is
about +11% at the midpoint.

**Quote the +7.6%, not the +11%.** The NervaOne comparison is not controlled:
the two ranges overlap at 640, the baseline is from memory rather than a run
made the same day, and it came from a third binary built at a different moment
from either A/B binary. What it does establish is that the effect is real on
the live miner and on a synced daemon rather than only on an offline database
copy, which the controlled rig could not show.

## The void run, and what it cost

The first daemon A-B-B-A came back:

```
A1 baseline  303.2    B1 fused     287.8
B2 fused     591.3    A2 baseline  600.6
A drift +98.1%  ->  void
```

The two baselines were 98% apart. Run as a plain A-B this would have reported
either a **2x speedup** (B2 against A1) or a 5% regression (B1 against A1), and
both would have been pure noise.

**Cause: two daemons running at once, not large pages.** `nervad-base.log` for
that A/B holds **three** daemon startups for the **two** baseline runs it
performed, the extra one beginning 67 seconds into A1. Two daemons sharing the
machine halves each one's reported rate, which is exactly the factor seen, and
it ended partway through, so B2 and A2 read normally. The source was almost
certainly an earlier A/B task that was force-stopped: that killed the
PowerShell loop but not the daemons it had launched with `Start-Process`, which
are detached and outlive it.

**The large-pages explanation written here first was wrong**, and the evidence
against it was already in the logs. `allocate_hugepage` does fall back to
malloc when memory is fragmented
([slow-hash.c:315](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/src/crypto/slow-hash.c#L315)), but the miner warns
loudly when it does: `Mining is running on normal memory pages`, through
`MGUSER_YELLOW` on the `user` category, which `--log-level 0` still shows, and
`CN_PAGES_MALLOC` is well below the `CN_PAGES_THP` threshold that fires it.
That warning appears in none of the logs, and every page-tier line ever
recorded on this machine says huge pages. A tidy mechanism that explained the
magnitude was accepted before checking the one line that would have falsified
it.

Lesson, and the more useful of the two: **a plausible cause that fits the
magnitude is not evidence.** The check that settled it cost one grep.

Every run now logs at level 1 into its own file and the page tier is parsed back
out and printed beside the number. That gating is worth keeping, since a silent
fallback really would be worth about 2x if it ever happened, but it is not what
was wrong here.

What none of this changes is the +7.6%. That run's four logs show exactly one
daemon start each, the same page tier throughout, and +0.1% drift between the
two baselines. The protection came from the A-B-B-A gate, not from page-tier
gating added on a wrong theory.

**Harness fix owed:** before starting a run, assert that no nervad process
exists and that the RPC port is free, and confirm the daemon answering RPC is
the process just started. Stopping a runner must also stop the daemons it
spawned.

Two earlier confusions have the same root: a claimed "plateau" at 620-634 H/s
that was really a startup transient, and an apparent regime mismatch where the
core benchmark looked slower than a whole nonce. Both came from comparing
against a contended run.

## Stage 2: eight-lane AVX2 HC-128 salt

### The eight-lane init works and is faster than the report expected

`HC128_Init` vectorizes cleanly across eight nonces. The salt loop reseeds on a
fixed cadence that does not depend on the data, so eight inits always run in
lockstep, which is what makes this possible at all. The pick loop between
reseeds does **not** run in lockstep, because `HC128_U32` uses rejection
sampling and consumes a data-dependent number of keystream words.

[t_hc128_x8.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/t_hc128_x8.c) builds it and checks it against the scalar
`HC128_Init` from the tree, not against a reimplementation. **Bit-identical
over 320,000 inits**, in both lookup forms.

```
scalar x8            2.06 us per init
x8 scalar lookup     1.36 us per init   1.51x
x8 gather lookup     0.81 us per init   2.55x
```

The h-function table lookups are the hard part, since each lane indexes its own
table with its own byte. The report measured `vpgatherdd` as the *slower* of
the two options on Zen 3 and recommended scalar extraction. **On this Zen 4
machine gather wins decisively, 2.55x against 1.51x.** Worth knowing before
copying his conclusion: the right lookup form is machine-dependent, so both are
built and selected at run time.

The benchmark varies its key every iteration. With a fixed key the whole call is
loop-invariant and the compiler may hoist it, which would time an empty loop and
report a spectacular speedup.

### The Amdahl gate: init is only 38.6% of the salt

[t_salt_profile.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/t_salt_profile.c) reproduces the salt loop faithfully against
a synthetic block cache of the real size (4.42M entries, 236 MB) and puts rdtsc
accumulators around the three components.

```
component   share     cycles/salt       count  cycles each
init        38.6%         2360832         257       9186
picks       19.3%         1183625       16384         72
encrypt     37.4%         2292665        4097        560
unattributed 4.7%          286042
total                     6123164
```

**So a 2.55x init buys only 1.31x on the salt**, and with the salt at roughly
40% of a nonce that is about +10% overall. Real, and more than Stage 0 gave,
but nothing like the 2.9x the report headlines for this work.

The gap is explained by `encrypt`, which is another 37.4% and is almost entirely
`HC128_NextKeys`: 4097 calls per salt, the same sixteen-step update the init
runs sixty-four times. It is vectorizable by the same code. The obstacle is that
lanes consume keystream at different rates, so they cannot share a refill point,
and the way around it is that **generating keystream ahead is free**: the stream
is deterministic and consumed in order, so all eight lanes can be refilled in
lockstep whenever the hungriest one runs dry, and the lanes that did not need it
simply carry a longer buffer.

With init and encrypt both vectorized the salt should reach roughly 1.8x, which
is about +22% on the nonce. That is the real target for this stage.

This check is the reason the stage is worth doing at the size it is, rather
than being abandoned after the init turned out to be a third of the problem. It
cost one harness and ran while the machine was busy.

### Run-ahead: measured +7.6% on the daemon, and a prediction that missed

```
A1  stage 0            n=11  mean  659.4  min  651  max  666 H/s   [huge pages]
B1  + run-ahead salt   n=12  mean  712.5  min  706  max  722 H/s   [huge pages]
B2  + run-ahead salt   n=12  mean  709.5  min  698  max  720 H/s   [huge pages]
A2  stage 0            n=12  mean  662.6  min  655  max  668 H/s   [huge pages]

A drift +0.5%   stage 0 661.0 H/s   with run-ahead 711.0 H/s   delta +7.6%
```

No overlap between the two groups, drift well inside tolerance, every run on
huge pages, one daemon per run enforced.

**The prediction was +17% and the result was +7.6%.** The error was not in the
salt measurement, which stands at 1.57x, but in the share of a nonce the salt
occupies. That was taken as 40%, derived by subtracting a core benchmark from a
daemon nonce time of 39.6 ms. **That 39.6 ms came from the contended run**, the
one where two daemons were splitting the machine. With a correct baseline of
about 660 H/s at twelve threads the nonce is 18.2 ms, and working backwards
from the measured +7.6% the salt is **about 19% of a nonce, not 40%**.

That reconciles independently: the standalone harness puts one salt at 1333 us,
and against a single-threaded nonce of roughly 8 ms that is 17%.

A bad number does not stop being bad when you stop looking at it. The contended
run was identified and corrected hours earlier, but a figure derived from it had
already been written down and kept being used.

### What this does to the rest of stage 2

The eight-lane init would take the salt from 1.57x to about 2.48x. At a 19%
share that is worth:

| | salt | nonce |
|---|---|---|
| run-ahead only (done) | 1.57x | +7.6% measured |
| run-ahead + x8 init | 2.48x | about +12.8% |

So the eight-lane init adds roughly **+5% on top of what is already banked**,
and it is the change that requires the miner to compute eight nonces at once:
a restructuring of the miner loop and `get_block_longhash_v13`, with the
verification path keeping a scalar version. That is the largest integration in
the project for the smallest measured return in it.

**Recommendation: do not build the eight-nonce batching.** The eight-lane init
stays in the tree as a verified harness, and if the salt ever becomes a larger
share of the nonce it is ready.

### Where the time actually is

The salt is 19% of a nonce, so **the hash core is the other 81%**, and that is
where anything further has to come from. It also means the two stages still
unbuilt are better targets than the one that was supposed to be the big one:

- Non-temporal stores on the 8 MB fill, which is core work.
- K-way nonce interleaving of the VM, which targets the dependent pointer
  chase and is core work.

The report's ordering put the salt first because on his already-optimized miner
the salt was 59.5% of the nonce. On a stock miner it is 19%. His proportions
are not ours, and the stage order should follow our profile, not his.

## What has already failed

**Computed-goto dispatch in `cn_vm_execute`: +0.5%, i.e. nothing.** Predicted 5
to 20%. The VM is deliberately memory-latency-bound, 51 to 63% of its work
being scratchpad operations in a dependent chase, so interpreter dispatch work
hides behind the stalls. Do not retry dispatch-level optimization. This miss
stands as a caveat on estimates made here.

## Next stages

1. **Non-temporal stores.** The fill writes 8 MB it never reads first, so
   `movntdq` skips read-for-ownership. The large-page half of this stage needs
   nothing: master already warns on the fallback and ships
   `nervad --setup-large-pages`. Checked, after briefly proposing to build it
   again.
2. **Eight-lane AVX2 HC-128 salt.** The big one, and it applies to **both v13
   and v8**, since both call `get_cna_v6_data`. The salt is roughly 40% of a
   nonce here. HC-128's update is elementwise on 32-bit words, so 8 salts fill
   8 lanes of a ymm register. Known trap already answered in the source report:
   `vpgatherdd` was measured and rejected at 32.9K cycles, use scalar extracts.
3. **K-way nonce interleaving of the VM.** K nonces per thread in lockstep so K
   scratchpad loads are in flight, aimed at the dependent pointer chase that
   computed-goto could not touch.

**Deliberately out of scope: the v6 nonce screening.** It exploits a trace
degeneracy specific to v6, and a 3x screening edge is a weapon. Unpublished it
creates exactly the unfairness this effort exists to remove; published it harms
a live chain that is being replaced anyway.

## Feeding back into v8

- **Stage 0 has no v8 counterpart.** v8 has no second full-pad salt pass to
  fold: the sweep deferral already removed that class of work. Checked, not
  assumed.
- **Stage 2 applies to v8 unchanged**, because `get_cna_v6_data` is shared. If
  an eight-lane salt is worth what the source report claims, it is an
  optimization an outside miner can also make on v8, and that argues for
  either doing it in-tree or changing the salt so it does not vectorize.

## Stage 3: nonce screening

Built deliberately, as defensive research. The weapon is already in use by at
least one miner on a live chain, so the asymmetry exists whether or not we
understand it; what is optional is whether the people designing the successor
understand it as well as the person exploiting it. v13 is being retired, so what
is learned here is worth more than what is lost.

### The mechanism, in one line

The VM program seed is `blob_hash XOR salt[0..32)`, and `salt[0..32)` is written
by **one of the salt's 4096 loop iterations**. A miner can therefore know what a
nonce will cost for about 1/4096 of a salt plus a walk of the program with no
registers, no memory and no pad.

### What was built

- `cn_vm_screen_cost` in [cna-vm.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/src/crypto/cna-vm.c): generate lazily,
  walk 512 steps assuming every `CN_OP_CBRANCH` taken, count scratchpad ops.
  Slots come off a sequential HC-128 stream so they cannot be random-accessed;
  lazy means generating in order only as far as the walk reaches, which is about
  67 of 512 slots.
- `get_cna_v6_seed` on the DB: the first 64 bytes of the salt only.
- `--mining-screen-threshold N` on the daemon, default 0 (off).

**The safety property is structural, not empirical.** Screening decides *which*
nonces are hashed, never *how* one is hashed. The verification path never calls
it. A block found this way is an ordinary valid block, and a miner may try
whatever nonces it likes.

### Verification

- The lazy screen matches a full-generation reference walk over 2000 programs.
- Extracting `cn_vm_gen_slot` out of `cn_vm_generate_program` to enable lazy
  generation changed nothing: 2000 v13 digests identical. The draw order is the
  generator's definition and a refactor near it has to be proven inert.

### Standalone measurement, and why it is an upper bound

[t_v13_screenmine.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/t_v13_screenmine.c) records the estimate and the real
measured hash time for each nonce, then sweeps the threshold over the recorded
pairs, so nothing is assumed about how estimate and cost relate.

```
screen         17.9 us      full salt   1356.9 us
estimate       min 4  p50 287  p99 396  max 418

  accept   thr    n    mean hash   effective H/s   vs unscreened
      1%    14    6      5.04 ms       126.8 H/s        3.82x
      2%    37   10      5.50 ms       129.0 H/s        3.88x
      5%   130   25      7.50 ms       108.5 H/s        3.27x
     10%   200   50     12.78 ms        69.9 H/s        2.10x
    100%   418  500     28.75 ms        33.2 H/s        1.00x
```

3.8x brackets the published 3.06x. **It is not yet believed.** This harness
reports 30.1 ms per nonce single-threaded while the daemon does 16.9 ms per
nonce per thread with twelve threads running, and one thread cannot be slower
than one of twelve. Most likely the synthetic 236 MB cache evicts the pad harder
than the real block cache does, which would inflate both the mean and the spread
the screen feeds on. The daemon sweep settles it.

### Measured on the daemon: 2.17x

Nine runs, threshold 0 interleaved between every screened run so each one is
compared against its own neighbours. Every run on huge pages, one daemon
enforced, acceptance read back from the daemon's own log.

```
  threshold   acceptance    H/s     local baseline   vs baseline   bracket drift
          0            -    739.1            -             -
         14        1.12%   1392.4          740.0         1.88x           0.3%
         37        2.21%   1605.3          741.1         2.17x           0.1%
        130        3.96%   1397.5          733.1         1.91x           2.1%
        200        9.98%   1098.1          732.4         1.50x           1.9%
```

The five baselines came back 738.8, 741.3, 740.9, 725.3, 739.4, so the machine
was stable throughout and the brackets are tight.

**Peak 2.17x at 2.2% acceptance**, where the estimate's cost and the saving it
buys balance. The curve has a maximum rather than rising forever, because at
tighter thresholds the miner pays `1/q` estimates per accepted nonce: at 1.12%
acceptance the estimate overhead has already pulled the result back down to
1.88x.

**The standalone harness said 3.88x at the same acceptance and was wrong by
1.8x**, exactly as suspected when its single-threaded nonce time came out slower
than the daemon's per-thread time. Its synthetic 236 MB cache evicts the pad
harder than the real block cache does, which inflates both the mean hash time
and the spread the screen feeds on. Recorded because the harness was right about
the shape and wrong about the size, which is the more dangerous kind of wrong.

The published figure for this step is 3.06x. Ours is 2.17x on a less optimised
pipeline, and by rule 3 that is the expected direction: screening removes a
share of what varies, so the less the fixed costs have been cut, the smaller
that share is. Finishing the memory work should move our figure toward his.

### Screening moves the optimal thread count, and that is most of its value

Measured on the offline rig, **a fresh daemon per point on both sides**, every
run on huge pages with no fallback warning.

```
 threads   unscreened    screened   ratio
      12        733.4      1598.8   2.18x
      16        684.6      1706.2   2.49x
      20        641.4      1787.6   2.79x
      24        600.4      1842.7   3.07x
      28        572.7      1860.2   3.25x
      32        564.4      1876.0   3.32x
```

**Unscreened peaks at 12 threads and falls monotonically. Screened climbs all
the way to 32** and is still climbing where the machine runs out of logical
cores.

The mechanism: stock v6 drags an 8 MB pad through the cache hierarchy on every
nonce, so past about twelve threads the extra workers only contend for L3 and
memory bandwidth. At 2.2% acceptance roughly 98% of nonces end at the estimate,
which touches one salt iteration and walks 512 program slots with no registers,
no memory and no pad. Screening converts a bandwidth-bound workload into a
compute-bound one, and compute-bound work scales with cores.

Best against best: **733.4 to 1876.0, 2.56x**, against 2.18x if both are held at
twelve threads. So **roughly a sixth of screening's value is unavailable unless
the thread count is retuned.**

Two independent cross-checks, both clean:

- The 12-thread ratio here is 2.18x; the separate interleaved threshold sweep
  measured 2.17x for the same configuration.
- Live NervaOne on the same machine reported 1.82 to 1.89 kH/s at 24 threads
  and 1.83 to 1.89 at 30; this rig gives 1842.7 at 24 and 1860.2 at 28.

**The rule for v8: measure an attack at the attacker's best configuration, not
the defender's.** An attacker retunes. A design gate that holds thread count
fixed at the stock optimum would have reported 2.18x for an attack worth 2.56x.

#### A method error worth keeping, because it nearly stood

The first version of this sweep changed thread count with
`stop_mining`/`start_mining` inside one daemon, to avoid restart variance. That
introduced a worse bias:

```
unscreened, fresh daemon          709.3 H/s
unscreened, after mining restart  613.1        -13.6%
screened,  fresh daemon          1388.6
screened,  after mining restart  1392.2         -0.3%
```

The penalty lands on pad-heavy work and not on screened work, so the
denominators were depressed and the numerators were not, inflating every ratio.
It also moved the apparent unscreened peak from 12 threads to 16. Both report
huge pages and neither warns, so it is not a page-tier fallback; reallocated
pads simply do not perform like the originals, which is worth knowing
independently.

What exposed it was a 15% disagreement between this sweep's 12-thread baseline
and earlier sweeps' 733 to 739. That gap was within shouting distance of
"drift", and calling it drift would have shipped the wrong table.

**Rule 6: an optimisation to the measurement method is a change that needs
measuring, exactly like a change to the thing being measured.** Removing a
safeguard because it looks unnecessary is the same class of mistake as keeping
a workaround after its cause is gone.

### Early exit in the screen: +21%, mostly by moving the optimum

His section 2 notes "early exit once predicted memops pass the threshold (~40%
fewer slots)". The walk's count only ever rises, so once it passes the caller's
limit the verdict is settled and the rest of the walk, and the lazy slot
generation it drives, is wasted. Rejected nonces are the overwhelming majority,
so that is where the screen's cost lives.

Measured: **screen 11.3 us to 7.9 us, 30% cheaper.**

Verified rather than argued: over 2000 programs, early exit gives the same
accept/reject verdict at every threshold tested and the same exact count
whenever the nonce is accepted.

The throughput gain is larger than the screen saving, because **a cheaper screen
moves the optimum**. Before early exit, tighter thresholds lost on estimate
overhead: threshold 14 scored 1392 against 1599 at threshold 37. After it, the
whole curve shifts left.

Threshold sweep, 30 threads, baseline interleaved between every point:

```
  threshold   acceptance      H/s
          3       0.34%     2274.0
          4       0.41%     2280.2    <- peak
          6       0.56%     2267.4
          8       0.71%     2238.3
         14       1.07%     2137.3
         24       1.63%     2011.7
         37       2.12%     1883.4
         60       2.57%     1774.2
```

**1876 to 2280 H/s, +21%**, from a change that only made the estimate 30%
cheaper. The optimum moved from threshold 37 at 2.1% acceptance to threshold 4
at 0.41%.

The 30-thread cap costs nothing: threshold 8 reads 2238.3 at 30 threads against
2233.8 at 32. The machine is a workstation, not a mining rig, so harnesses are
capped at 30 of 32 logical threads.

#### What this says about where the cost now sits

The curve is flat between thresholds 3 and 6, which means the screen itself has
become the wall. At 0.41% acceptance a miner runs about **244 screens per
accepted nonce**, so at 7.9 us each that is ~1.9 ms of screening against roughly
3 ms for the accepted hash. **Screening is now about 40% of the work.**

That reverses an earlier judgement in this log. When the screen was 5% of the
time, cutting its cost looked worth about 4% and was deprioritised. At 0.41%
acceptance the same work is worth far more, and it compounds, because each
reduction moves the optimum tighter again. The published figures for the screen
path are 43k to 8.6k cycles, about 5x, via four-way AVX2 Keccak, eight-lane
AVX2 HC-128 init, a faster lazy generator and prefetched picks.

**The eight-lane init is already built and verified here at 2.55x**, and
batching the *screen* eight-wide is far less invasive than batching the hash:
the screen is a pure function of the blob and never touches the pad, so the hash
path can stay scalar.

### Eight-wide screening: correct, 2.37x on the part it touches, and worth nothing

A negative result, kept because the reasoning that led to it was sound and the
next person will otherwise redo it.

At 0.41% acceptance the screen is roughly 40% of the work and each screen is two
HC-128 key schedules, so vectorising the schedules looked like the obvious next
move. [hc128-x8.c](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/src/crypto/hc128-x8.c) does eight at a time, in its own
translation unit at AVX2 while the rest of the binary stays at baseline, with a
cpuid plus XGETBV check and a scalar fallback.

**Verified:** bit-identical to eight `HC128_Init` calls over 12,000 schedules,
including the transpose back to ordinary `HC128_State` values and four keystream
blocks drawn from each result. That last part matters: a state can match field
for field and still be unusable if `counter1024` or the keystream buffer is
wrong. **2.37x per schedule**, 1.95 us to 0.83 us.

**Measured on the daemon, threshold 4, 30 threads:**

```
scalar screen                        2280.2 H/s
x8 screen, 64 KB allocated per call  2101.7      -7.8%
x8 screen, thread-local buffer       2260.6      -0.9%
```

So a 2.37x faster key schedule converts to **nothing**. The screen's selection
is provably identical, acceptance reads 0.41% to three digits either way, so
this is not a correctness problem. The transposed per-lane state costs about
what the vectorisation saves: the scalar screen reuses one 4 KB `HC128_State`
that stays hot, while the batched one writes and reads back eight of them twice
per batch, roughly 8 KB per nonce of traffic the scalar path never does.

It is off by default behind `--mining-screen-batch`. Adding it did not cost the
default path anything: A-B-B-A gives pre 2274.7, post 2260.3, delta -0.6%
against a baseline drift of -0.5%, so the difference is not separable from
noise.

**The allocation finding is the useful part.** A 64 KB allocation per call cost
**7% at 30 threads and was invisible single-threaded**, because the
microbenchmark called it in a tight loop where the allocator hands back the same
block every time. A microbenchmark can be correct, repeatable, and still answer
a question nobody asked.

**If it is ever worth revisiting**, the way is the one the published
implementation takes: keep the state lane-interleaved for the whole screen and
run `NextKeys` eight-wide too, so there is no transpose at all. That needs a
per-lane block queue because keystream consumption diverges. The eight-lane init
is also worth far more on **v8**, whose salt is 55% of a nonce against v13's
19%, and there it would serve the salt itself rather than screening, so the
transpose penalty would not land in the same place.

A single run at 8 threads came back +5% for batching, which fits the
cache-pressure explanation, but it was one unrepeated point in an uninterleaved
sequence and 12 threads came back -11% against 30 threads' -0.9%. **Not
believed**, and the flag exists so a low-core machine can be tested properly,
not because it has been shown to help.

### The rig was finding blocks all day

The offline daemon mines against a stale chain copy whose difficulty drifts
down, so it had been finding real blocks: height moved 4424749 to 4424751 over
the day's runs. Each find rebuilds the template and stalls the miner, and it is
what made `start_mining` intermittently return busy.

At roughly a 2% chance per 30-second run the distortion was small, and the drift
gates would have caught a badly affected run, but it was an uncontrolled
variable present in every measurement and it would have grown as difficulty
fell. All harnesses now pass `--fixed-difficulty 100000000`.

**The plan file written at the start of this project said to do exactly that.**
It was not done, and was not noticed for a full day.

### Second machine: an i7-7700HQ laptop, 4 cores, 256 KB L2

Measured live through NervaOne against a synced mainnet node, so a different
CPU, a different generation and a real chain rather than the offline copy.

```
stock v0.3.0.0        2t 47.5   4t 73.0   6t 88.0   7t 93.0
final, threshold 4    2t 144.5  4t 263.5  6t 325.0  7t 373.0   8t 394.0

7 threads, threshold sweep
  thr  0    105.0     (fused pad init + run-ahead salt only)
  thr  2    344.5
  thr  4    373.0
  thr  8    385.5     best of those tested, still rising
  thr  8 + --mining-screen-batch   400.5

8 threads, with --mining-screen-batch
  thr 14    413.5     peak
  thr 24    388.5
```

```
stock, 7 threads                     93.0 H/s
+ fused pad init, run-ahead salt    105.0     1.13x
+ screening (thr 8)                 385.5     4.15x
+ eight-wide screen                 400.5     4.31x
+ thr 14, 8 threads                 413.5     4.45x
```

**The optimum threshold is 14 on the laptop against 4 on the 7950X**, 3.5x
looser, which is the machine dependence the corrected model above predicts: the
screen's four random block-cache reads cost more on a machine with worse latency
and less cache, so screening hard stops paying sooner.

**4.31x on the laptop against 3.82x on the 7950X.** Screening alone is 3.67x
there (105 to 385.5) against 3.11x here.

#### A prediction that was half wrong, and the model it fixes

Written before the data: *the optimum threshold will be tighter than 4 on the
laptop, and screening will be worth more.*

The second half holds. **The first half is wrong: the optimum is looser, 8 or
above.**

The error was treating the screen as pure compute. It is not: the salt prefix
does **four random reads into a 236 MB block cache**, which are DRAM-latency
bound. The laptop has worse latency and far less cache, so the screen is
relatively *more* expensive there, and screening harder stops paying sooner.
The hash's bandwidth sensitivity was modelled correctly and the screen's memory
component was left out of the model entirely.

Consequence worth carrying: **the optimal threshold is a machine property and
has to be swept per machine.** It is not a constant of the algorithm, and the
default in the help text is right only for the machine it was measured on.

#### The eight-wide screen is vindicated on low core counts

`--mining-screen-batch` gives **+3.9%** here (385.5 to 400.5), matching the +5%
at 8 threads measured on the 7950X and dismissed at the time as one
uncontrolled point. Two machines, two generations, same direction.

So the earlier negative result stands as stated but is incomplete: the eight-
wide screen is worth nothing at 30 threads and worth about 4% at 7 to 8. The
transposed per-lane state costs roughly what the vectorisation saves, and which
side wins depends on how much cache pressure the machine is already under. Off
by default remains right for the 7950X and wrong for the laptop, which is what
the flag is for.

> **Superseded.** This is wrong as of the recomputed final pass and the
> non-temporal fill, which removed two thirds of the memory traffic and with it
> the cache pressure this paragraph blames. Re-measured, the eight-wide screen
> is **+9.1% at 30 threads** and is on in the best configuration. It was never a
> core-count effect. See "Eight-wide screening, re-measured" and rule 7, which
> exists because of this.

### Recomputing the final pass instead of reading it: +16.8%

v13 writes all 8 MB of the pad in the fill and reads all 8 MB back in the final
pass. Between them the VM mutates it. The final pass is therefore reading data
that is a pure function of the fill's AES chain everywhere the VM did not write,
and the fill's chain is cheap to replay. So the final pass regenerates those
blocks instead of reading them: a clean block is `aes_pseudo_round(fill_text)`
XOR the salt at the same offset, and the final pass already walks the blocks in
the same order the fill wrote them, which is why no checkpoints are needed.

```
30 threads, one binary, flag off vs on, fresh daemon per point

screened   (threshold 4)   2217.3 -> 2590.5 H/s   1.17x
unscreened (threshold 0)    558.8 ->  516.0 H/s   0.92x
baseline drift across the run                      1.0%
```

The unscreened loss is the result that makes the gain believable, and it was
predicted before the run rather than explained after it: unscreened, 90.7% of
blocks are dirty, so almost nothing is regenerated and the replay's AES is paid
for all 65536 blocks anyway.

#### How clean a screened nonce really is

This is the number the whole change rests on, and it is much stronger than the
estimate it was planned from. The design assumed roughly 3,700 writes and about
94% of the pad never written. Measured over 1000 screened and 1000 unscreened
digests:

```
                  dirty blocks of 65536
screened (thr 4)  median 32     mean 1751    range 32 to 64870
unscreened        mean 59416                 range 32 to 65536
```

**The median screened nonce dirties exactly 32 blocks, which is exactly the 32
blocks the random values poke. The VM writes nothing at all.** Screening does
not just select cheap nonces. It selects nonces that never touch the pad.

The screened mean is dragged to 1751 by a tail that reaches 64870, and the tail
is explainable rather than noise. `cn_vm_screen_cost` walks the program assuming
`CN_OP_CBRANCH` is always taken, which it is except about once in 2^16.5, so a
real run that falls through visits instructions the estimate never counted. The
screen is a cheap estimate that is occasionally wrong in the expensive
direction, which costs throughput and never correctness.

#### Why it is opt-in

`cn_vm_execute` is also the verification path. There a nonce is unscreened,
writes hundreds of thousands of times and leaves the pad fully dirty, so
recording which blocks it wrote would be pure overhead for no benefit. The map
is a per-thread pointer that is NULL unless a mining thread sets it, and NULL
means the old code path byte for byte. `--mining-recompute-final`, off by
default.

#### Verification

`contrib/powbench/t_v13_recompute.c`. 2200 digests, each computed twice inside
one binary, tracking off then on, and compared. Both AES arms, dense per-seed
salt, dense random values, and both nonce populations. All identical.

Two things would have made that comparison vacuous, and both are checked rather
than assumed:

- **A zero salt.** XOR with zero is the identity, so a wrong salt offset would
  still give the right digest. The salt is dense and per-seed, and `SALT_ZERO=1`
  is the control.
- **A fully dirty pad.** If nothing is ever regenerated the comparison proves
  nothing, so the harness prints the dirty-block count it actually exercised and
  says so explicitly if nothing was regenerated. Half the seeds are drawn the
  way a screening miner draws them, by rejecting any seed over the threshold.

The random values matter too, and an earlier harness got this wrong in a way
worth remembering: it zeroed them, which makes every poke "add 0 at index 0".
The pad comes out unchanged, so failing to mark the blocks they touch would not
have changed a single digest. Here they are dense and never write a value back
unchanged.

**Negative control.** Deleting the poke marking, which is the silent-corruption
risk the design flagged, produces 24 mismatches out of 32. The harness has
teeth.

#### The optimum did not move, which is the first time it has not

Every cost reduction so far has moved the best screening threshold, so it was
re-swept rather than assumed. With the recomputed final pass on, 30 threads:

```
threshold   2    2437.6 H/s   accept 0.26%
threshold   4    2520.5        0.41%     (first and last point: 2570.4, drift 2.0%)
threshold   6    2533.5        0.56%
threshold   8    2473.9        0.71%
threshold  12    2330.8        0.98%
threshold  20    2113.4        1.48%
```

The peak reads at 6 rather than 4, by 0.5%, which is inside the spread of either
point and inside the run's own drift. **Treat it as unchanged at 4.**

The prediction before the sweep was that it would move looser, because
throughput is roughly `1 / (hash + screen / acceptance)` and making the hash
cheaper raises the screen's share. That is the right first-order reasoning and
it is not what happened, because a second effect pulls the other way: a looser
threshold accepts nonces whose programs do write the pad, and a dirty block has
to be read rather than regenerated, so the recompute itself earns less as the
threshold loosens. The two cancel almost exactly. Worth remembering before
predicting the next one: a change that makes accepted work cheaper **and** makes
the saving depend on acceptance does not move the optimum.

#### The one-binary A/B

Every earlier A/B here compared two binaries, which needs the md5 checked by
hand because the version banner is stamped from the git hash and does not
distinguish builds. A flag removes that whole class of error: the two sides are
the same file, and the daemon logs which options are live so the run can be
checked against what it was meant to be measuring. Worth doing this way from
now on.

### Non-temporal stores on the fill: +22%, and it is bigger than the recompute

His figure for this step was +4%. Measured here at 30 threads, threshold 4, one
binary, 0.4% drift across the run, which makes it the cleanest measurement on
the project:

```
neither     2223.0 H/s
nt only     2711.3        1.22x over neither
rec only    2578.7        1.16x over neither
rec + nt    2875.8        1.29x over neither, 1.12x over rec alone
```

**8 MB of ordinary stores is 16 MB of bus traffic.** A store that misses fetches
the line before modifying it, even though the fill overwrites every byte of it
and never reads what was there. That read is invisible in the source, it is pure
waste, and `_mm_stream_si128` skips it. Writing the number down for both passes
is what made this obvious, and the estimate the change was planned from was out
by exactly the factor it omitted.

#### They do not compound, and the reason is the useful part

1.22 times 1.16 is 1.42, and the measured combination is 1.29. Two changes that
both remove traffic from the same bottleneck cannot each be worth what they were
worth alone. The traffic budget per accepted nonce says it plainly:

```
                fill          final pass      total       throughput
neither      16 MB (RFO+WB)     8 MB          24 MB      2223 H/s   53 GB/s
nt only       8 MB              8 MB          16 MB      2711       43
rec only     16 MB            ~ 0             16 MB      2579       41
rec + nt      8 MB            ~ 0              8 MB      2876       23
```

#### The threshold, swept again, and a prediction that did not land

The hash just got 1.29x cheaper, which raises the screen's share of the total,
so this time the optimum really should move looser. 30 threads, both switches
on:

```
threshold   4    2797.8 H/s and 2860.2 H/s   accept 0.41%   (first and last point)
threshold   6    2884.7                             0.56%
threshold   8    2864.0                             0.70%
threshold  12    2726.2                             0.98%
threshold  20    2446.8                             1.47%
```

Threshold 4 averages 2829.0 across its two readings, so 6 is 2.0% above it and 8
is 1.2% above it, against 2.2% of drift in the same run. **4, 6 and 8 are
indistinguishable.** The plateau is visibly wider than it was, and the peak
reads at 6 both times it has been swept, but neither sweep establishes a move.
Keep 4, and do not record this as a shift on the strength of a reading inside
the drift.

#### The conclusion that changes the roadmap

**Traffic fell by 3x and throughput rose by 1.29x, so this workload is no longer
memory bound.** At 23 GB/s there is clearly headroom on a machine that was
moving 53 GB/s an hour ago.

That re-prices everything still on the list, and in opposite directions:

- **The remaining memory items are worth much less than their published
  numbers.** Virtual pad and K-way nonce interleaving both buy memory traffic or
  memory-stall overlap, and there is now far less of either to buy. Virtual pad
  would take the fill's remaining 8 MB to nearly nothing, but on this evidence
  that is worth well under the 1.51x it is advertised at.
- **The compute items are worth more.** What is left per hash is roughly 15.7M
  AES operations across three passes over the chain, about 1M interpreted VM
  instructions, and the screen's 244 rejected candidates per accepted nonce.

  *Superseded, and left here because the reasoning is still right while the
  conclusion is not.* This originally read that the trace JIT was now the most
  valuable unbuilt item. Measuring the screen from inside the daemon rather
  than by subtracting harnesses put the VM at 29% of a nonce, capping a perfect
  JIT at 1.41x and a realistic one at 1.15x to 1.25x. See the screen cost split
  below.

This is the clearest case yet of rule 5 paying off in reverse: the result had
the wrong **shape** for the model, the model was wrong rather than the result,
and the correction is worth more than the measurement was.

### Where a nonce's time actually goes, and the roadmap it overturned

The roadmap had the trace JIT next, ranked on an **instruction count**: about
1.05M interpreted VM instructions per hash against about 15.7M AES operations.
Turning those counts into a time budget accounted for only about 60% of a hash,
which is not a basis for weeks of emitter work, so the split was measured
instead.

Measured by instrumenting the real `cn_slow_hash_v13` behind
`CN_V13_PHASE_TIMING`, a macro the daemon never defines, rather than by timing a
copy of the algorithm. A copy drifts, and then the breakdown describes the copy.

```
30 threads, threshold 4, recompute and non-temporal fill on

                          cycles/hash    share of a nonce
screen, modelled part      11,568,000       24.8%
screen, get_cna_v6_seed     7,960,000       17.0%   (by difference, see below)
  screen total             19,530,000       41.8%
VM, 2048 passes            13,689,000       29.3%
final pass                  8,636,000       18.5%
fill, 8 MB                  4,737,000       10.1%
everything else               107,000        0.2%
                           46,700,000
```

**The screen is the largest single cost, not the VM.** The estimate it replaced
had the VM at 18% and the screen at 7%. Both were wrong, and in opposite
directions.

What that does to the trace JIT: eliminating the VM **entirely** caps at 1.41x,
and a JIT removes interpreter dispatch rather than the memory operations
underneath it, so the realistic prize is 1.15x to 1.25x for an x86-64 emitter
plus deopt handling. Halving the screen is worth 1.26x by itself. The JIT went
from "next" to "not next" on one afternoon's measurement.

#### The control that caught the first version being wrong

The harness models the miner's duty cycle, screen included, so **it has to
reproduce the daemon's hashrate or its breakdown is a breakdown of something
else.** The first version reported 3726.7 H/s against the daemon's 2875.8, and
the cause was found rather than patched: `screen_block_nonce_v13` does four
things per candidate, a blob hash, an `HC128_Init` for the salt prefix,
`get_cna_v6_seed`, and `cn_vm_screen_cost`, and the harness timed only the last.
Adding the first two took it to 3467.1. The rest is `get_cna_v6_seed`'s reads
into the block cache, which need the database, and that is the row derived by
difference above.

**Caveat, stated rather than buried, and it turned out to matter.** That derived
row assumes the hash-internal costs are the same in harness and daemon.

**It was wrong by more than 5x.** Measured from inside the daemon, as the screen
cost split below records, `get_cna_v6_seed` is 3.1% of the screen, not 17% of a
nonce. The gap the subtraction charged to it was mostly the second `HC128_Init`
inside `cn_vm_screen_cost` and the per-candidate blob rebuild. **Do not use the
derived row for anything**; it is kept only because a plan was built on it and
rule 1 says to show what was withdrawn.

### Eight-wide screening, re-measured: from worth nothing to +9.1%

It was recorded as worth nothing at 30 threads, and the reason given was cache
pressure: the transposed per-lane state cost about what the vectorisation saved.
Since then per-hash traffic has fallen from 24 MB to 8 and the screen has gone
from a small share of a nonce to the largest one, so both halves of that trade
had moved. Re-measured rather than re-read:

```
30 threads, recompute and non-temporal fill on, 0.6% drift

thr 4 serial  (mean of two readings)   2886.4 H/s
thr 4 batched                          3148.6        +9.08%
thr 6 batched                          3111.3        +7.79%
thr 8 batched                          3004.7        +4.10%
```

The threshold was then swept downward as well, since a cheaper screen lowers the
price of rejecting a candidate and should make being pickier affordable:

```
thr 4 batched (mean of two readings)   3117.1 H/s
thr 3 batched                          3109.8        -0.24%
thr 2 batched                          2965.4        -4.87%
thr 1 batched                          2846.4        -8.68%
```

Flat from 3 to 4 and falling away below. **Threshold 4 stands.** It has now been
predicted to move looser once and tighter once, and has not moved either time,
which is worth recording as a property of the algorithm rather than continuing
to re-derive it: the optimum is robust at 4 across every configuration measured
on this machine.

**This is the second result on this project to reverse itself**, and both
reversed for the same reason: a measurement is a property of the configuration
it was taken in. The first time, the eight-wide screen was worth nothing at 30
threads and 4% at 7 to 8, so it looked like a core-count effect. It was not. It
was a cache-pressure effect, and removing two thirds of the memory traffic
turned it positive on the machine where it had been worthless.

**Rule: when a change alters the balance, every "not worth it" result taken
under the old balance is void, not merely stale.** Keep a list of them. On this
project the list was `--mining-screen-batch` and it was worth 9%.

### Live confirmation on mainnet: 13 blocks found, 13 credited, none rejected

An overnight run through NervaOne on mainnet with the full configuration, from
02:21 to 09:58. The daemon log confirms what was running:

```
Mining has started with 12 threads
v13 miner options: screen threshold 4 (batched), final pass recomputed, fill stores non-temporal
Mining scratchpads on huge pages
```

13 blocks found, and all 13 heights appear as credited transfers in the wallet.
No rejections, no orphans, no alternative-chain entries, no errors. The only
warnings are DNS-disabled and "no incoming connections", neither related to
mining.

**This is the end-to-end confirmation that matters.** Screening only changes
which nonces are tried, so it cannot produce an invalid block. The recomputed
final pass and the non-temporal fill do change how a nonce is hashed, and the
6600-digest harness says they are bit-identical. A night of accepted blocks says
the harness was testing the right thing.

Live acceptance was 0.410%, against 0.41% on the rig. The live hashrate falls
straight out of the same log line: 3433 hashes per two-second merge window,
**1716 H/s at 12 threads**.

#### Thread scaling: linear to 16 cores, then SMT

Measured live after the thread count was actually applied. All three points are
the same build with the same settings:

```
12 threads   1733 H/s    144.4 per thread    live, NervaOne
16 threads   2277 H/s    142.3 per thread    live, NervaOne
30 threads   3148.6      105.0 per thread    rig, offline

12 -> 16   1.33x threads -> 1.31x throughput   efficiency 0.99
16 -> 30   1.88x threads -> 1.38x throughput   efficiency 0.74
```

**Linear to 16, then a cliff.** This machine has 16 physical cores and 32
logical, so threads 1 to 16 each get a core to themselves and scale perfectly.
Every thread after that is an SMT sibling sharing a core's execution units, and
each one adds about 62 H/s against a physical core's 142, roughly 44%.

That is a textbook SMT curve, and it is the strongest independent evidence yet
that **the work is compute bound rather than memory bound**. A memory-bound
workload goes sublinear long before 16 threads, because all sixteen cores share
one memory controller no matter how many of them are busy. Perfect scaling to
the physical core count says the contention that remains is for execution units,
which is exactly what the phase breakdown says the work now consists of: AES and
the screen's HC-128 schedules.

It also retires a claim this section carried for one night. An earlier version
read the 12-thread run as 16 and concluded scaling had become linear overall. It
has not: it is linear up to the physical core count and 0.74 of linear beyond.
The distinction matters, because "linear" would have implied more headroom from
threads than actually exists.

Caveat, per rule 6: the 12 and 16 point comparison is clean, same session, same
setup. The 16 to 30 comparison crosses live NervaOne against the offline rig.
The effect there is large enough to survive that, and the two setups have agreed
closely wherever they overlap, but it is not a within-run comparison.

#### The diagnostic that ate the log

The run produced 13,658 log lines and 13,565 of them were the `screen:`
acceptance line, 99.3% of the file. The merge interval is two seconds, so at
`MGINFO` it writes 1784 lines an hour into the ordinary daemon log forever.

It is a research diagnostic and it is now `MINFO`: silent at the default log
level, visible at `--log-level 1`, which is what the measurement scripts already
pass. **A diagnostic added for a measurement has to be given a log level before
it ships**, and the place that becomes obvious is someone else's overnight log.

### Hoisting the hashing blob: 6% of the screen, under 2% of throughput

`get_block_hashing_blob` reserialised the whole block for every candidate nonce,
header plus a merkle root over the transaction hashes into a fresh string, when
only the nonce differs. The miner now serialises once per template and patches
four bytes. The offset is found by serialising twice with different nonces and
taking the run that differs, then checked by confirming that patching reproduces
a fresh serialisation for four probe values; if any of that fails it falls back
to the old path and warns.

```
                cycles/candidate    of which blob
blob per candidate    55,992            3,166
blob hoisted          52,641                0
removed                3,351            6.0% of the screen
```

Throughput at 30 threads is between 0% and 2%: a drift-controlled A-B-B-A gave
+0.17% at 0.4% drift, and a back-to-back pair gave +1.78%. **Per-thread compute
savings do not convert to throughput one for one at 30 threads on 16 cores**,
because a freed execution slot goes to the SMT sibling. The cycles figure is the
honest one; the throughput figure is bounded, not resolved.

Kept anyway: it is strictly less work, it validates itself, and it falls back
safely.

#### Three measurement lessons, all self-inflicted

**A rewritten script dropped a diagnostic that existed for a reason.** When this
A/B was written fresh instead of derived from an earlier one, it lost the
page-tier check that the project added after an early run came back with two
baselines 98% apart. Without it a 17% outlier looked like a result for several
minutes. **A script rewrite has to carry the checks forward, and the checks are
the part worth copying.**

**An explicit log-category string replaces the default set, it does not extend
it.** `--log-level "*:WARNING,miner.screen:INFO"` silently dropped `user:INFO`
and `global:INFO`, so the options banner and the page tier both vanished and the
run aborted on a missing banner. The spec has to list everything it wants:
`*:WARNING,user:INFO,global:INFO,miner.screen:INFO`.

**This rig's 16-thread numbers are bimodal and not currently usable.** Three
runs, every point on huge pages, readings clustering at either ~2280 or ~1950
H/s, with one 36-second window spanning both. `--mining-affinity` did not fix
it, so it is not thread placement. 30 threads is stable to 0.4% and is where
conclusions should be drawn until this is understood. **Noted as open rather
than explained.**

### Where this leaves the project

Each row at its own best thread count, which is the only fair way to compare
once the optimum moves:

Each row at its own best configuration, with the thread count stated, because
the optimum moves as the work changes:

```
stock,                     12 threads            597.6 H/s
+ fused pad init,          12 threads              661.0      1.11x
+ run-ahead salt,          12 threads              711.0      1.19x
+ screening (thr 37),      12 threads             1605.3      2.69x
+ retuned,                 32 threads             1876.0      3.14x
+ screen early exit (thr 4), 30 threads           2280.2      3.82x
+ recomputed final pass,     30 threads           2590.5      4.33x
+ non-temporal fill,         30 threads           2875.8      4.81x
+ eight-wide screening,      30 threads           3148.6      5.27x
```

Best unscreened is 733.4 H/s at 12 threads, so screening and its retuning are
worth **3.11x** on their own.

A caution on reading that table. The same configuration read 2520.5, 2570.4 and
2590.5 across two runs on the same evening, a spread of about 3%, which is
larger than several of the individual effects in it. Every multiplier above was
measured **inside one run** against its own baseline, which is the only
comparison the rig supports at this resolution. See rule 6.

Live through NervaOne on the same machine, 24 to 30 threads: 1.82 to 1.89 kH/s,
which agrees with the rig.

Against the published v6 progression on a comparable machine (his 5900X stock
558 H/s against this 7950X's 597.6), his figure after the same two steps,
memory work and screening, is 976 H/s scaled from a 5600G or about 2233 on the
5900X. His next step, the equivalent of the recomputed final pass, took him
from 2233 to 2889, 1.29x. Ours was 1.17x on that step alone, and the gap closed
exactly where the guess said it would: adding non-temporal stores takes the pair
to 1.29x and 2875.8 H/s, level with his 2889. His single step evidently bundled
both, which is the more natural way to write it, and splitting them is what made
the traffic arithmetic legible here.

## Lessons for v8

The point of the v6 work. Written as rules, so a future change to v8 can be
checked against them without re-deriving the attack each time.

### 1. Anything that determines a nonce's cost must not be computable more cheaply than the nonce

This is the governing rule, and v6 breaks it in one line. The VM program seed is
`blob_hash XOR salt[0..32)`, and `salt[0..32)` falls out of **one of the salt's
4096 loop iterations**. So a miner can learn what a nonce will cost for about
1/4096 of the salt plus a register-free walk, measured here at **17.9 us**
against a nonce costing milliseconds. That ratio is the entire break.

**v8 already satisfies the rule**, by construction rather than by accident:
`get_cna_v6_data` reseeds its HC-128 state 256 times from bytes it has already
written, so the keystream cannot be fast-forwarded, and `xx`, `yy` and
`init_size_blk` are drawn only afterwards. The cheapest possible oracle costs a
full fill.

**What to check on any future v8 change:** if a per-nonce parameter moves
earlier in the pipeline, or if any value that influences cost becomes derivable
from a prefix of the fill, this rule is broken and the screening attack returns.
The draw ordering is load-bearing and should be commented as such where it is
written, not only here.

### 2. Cost that varies is only safe while it is unpredictable, so prefer cost that does not vary

v6's spread is enormous: the cheap estimate ranges 4 to 418 scratchpad
operations per pass across 500 nonces, and the cheapest 1% hash about 5.7x
faster than the mean. v8 narrows this by pinning `init_size_blk` (F42: that one
axis alone was worth up to 2.24x in time and bought nothing), but `xx` and `yy`
still vary cost by F42's measured 3.7x.

That is currently safe only because of rule 1. **Two defences are better than
one**, and narrowing the spread costs nothing in fairness: a PoW where every
nonce costs the same is strictly easier to reason about, and difficulty then
means what it is assumed to mean.

### 3. Evaluate a defence against an optimised miner, not a stock one

FINDINGS F6b modelled v6 screening at 1.3 to 1.4x; the published miner
attributes 3.06x to it. **Both can be right.** Screening removes a share of the
part of a nonce that varies, so the more the fixed parts have been optimised
away, the larger that share becomes and the more screening is worth.

A design gate run against a stock baseline therefore **systematically
understates** every attack of this shape. v8's gates should be re-run against
the fastest implementation we know how to build, which after this project is a
better implementation than when they were first run.

### 4. Shipping an optimisation is a defensive act

The gap that matters is not between our miner and the theoretical maximum, it
is between a stock miner and a tuned one. Every optimisation that lands in the
stock miner is one nobody can hold privately. This is the whole logic of the
project, and it has a concrete instance: the run-ahead salt is worth +7.6% here
and would be worth far more on v8, because v8's fill is a much larger share of
its nonce.

### 5. Proportions do not transfer between implementations

The salt is **19% of a v13 nonce** and about **55% of a v8 nonce**, because
v8's pad is 1 MB against v13's 8 MB so everything else shrank around it. The
same salt change is therefore worth roughly four times more on v8 than on v13.

The published report orders its work with the salt first because on **its**
pipeline the salt was 59.5% of a nonce. Our stage order should follow our own
profile, and v8's order should follow v8's. Twice now a figure taken from one
context and applied to another has produced a wrong prediction here.

### 6. What dies with the VM, and what does not

Of the published 13.4x on v6, the progression attributes 1.96x to engineering
and the rest to screening (3.06x), trace JIT (1.48x) and virtual pad (1.51x).
**All three of the large multipliers are VM properties and v8 has no VM.** The
GPU hybrid likewise hunts "the ~1 in 950 whose VM never touches the pad", and
v8 has no such nonce: both AES passes and every sweep touch the whole pad on
every nonce.

So v8's exposure to that toolkit is roughly the 1.4x of engineering, which rule
4 says to ship ourselves. **The residual is not screening at all**: it is GPU
offload of the fill, which does not predict cost but pays it elsewhere, so the
draw ordering does nothing against it. See F43, and note `CN_SALT_MEMORY` is
load-bearing there and is not documented as such.

### 7. A pass over memory is only memory work while the memory is not reproducible

v13's final pass reads all 8 MB of the pad and does real AES on every byte of
it. It looks like 8 MB of memory work and it is not. Everywhere the VM did not
write, the pad holds a pure function of a 128-byte running state and the salt,
so a miner regenerates it for the price of an AES round and never touches DRAM.
Measured: +16.8% on this machine, and the pass goes from 8 MB of reads to
essentially none.

The pad's **size** bought nothing on that pass. What bought something was that
the VM had written parts of it, and screening reduces that to nothing: the
median accepted nonce at threshold 4 leaves exactly 32 dirty blocks, and all 32
are the random-value pokes rather than anything the VM did.

So **32 bytes of chain-dependent data were the entire residual memory-hardness
of an 8 MB pass**, and they are cheap to track around. A handful of
chain-dependent pokes is not a defence.

The rule, and it is checkable rather than a judgement call:

> For a pass over the pad to cost memory, the pad's contents **at the moment
> that pass runs** must not be reproducible from less state than the pad holds.

Ask it of every pass in v8 separately, because the answer differs per pass. v8's
fill writes the pad from an AES chain, so immediately after the fill the pad is
reproducible from 128 bytes and any pass at that point is free. What protects
the later passes is that the sweeps touch the whole pad, so reproducing the pad
means redoing the sweeps, which is the work itself. That is the right property,
but note what it rests on: **it rests on every sweep touching everything, not on
the pad being 1 MB.** A change that makes a sweep conditional, data-dependent or
skippable re-opens this, and it would not look like a memory change when it was
made.

This is the same question `salt_pad_v8` already answers for the salt, where the
reseeding is what stops the keystream being fast-forwarded. The pad deserves the
question asked explicitly in the same way, and currently FINDINGS does not ask
it.

### 8. A pad's size is not its bandwidth cost, in either direction

Two factors of two sit between "the pad is N bytes" and what a miner actually
pays for it, and both were found the hard way today.

**Upward, for an unoptimised miner.** Writing N bytes costs 2N of bus traffic,
because a store that misses fetches the line before modifying it. The fill never
reads what was there, so that fetch is pure waste, and `_mm_stream_si128` skips
it. Worth +22% here.

**Downward, for an optimised one.** Any part of the pad that is a pure function
of a cheap chain is not read at all. See lesson 7.

So a defender who sizes a pad and calls the product its memory cost is wrong by
up to 4x, and wrong in the direction that flatters the design: the number they
imagine is the one a naive miner pays, and the attacker is not running a naive
miner. **Cost a pad by what an optimised miner moves across the bus, measured,
not by its size.**

There is a sharper version of this for v8 specifically. v8's fill writes 1 MB,
and whatever bandwidth argument is made for it should be made at 1 MB of
streaming stores rather than 2 MB of ordinary ones, because that is what an
attacker pays. Nothing in the design stops them, and nothing should: the fix is
not to try to force ordinary stores, it is to stop counting the saved traffic as
a defence.

It also explains a discrepancy that looked like noise. The published figure for
this step is +4% and it measured +22% here. Both are probably right, for
different balances: +4% is what it is worth when the rest of the miner is still
moving a lot of traffic, and +22% is what it is worth once the other passes have
been removed. **A published optimisation's percentage is a property of the miner
it was measured in, not of the optimisation.** That is lesson 5 again, and it
has now cost a prediction twice.

### 9. v8's small pad already defeats the non-temporal store attack, and that is luck worth understanding

Non-temporal stores were worth **+22% on v6**, the largest single win of the
whole project after screening. The obvious question for v8 is how much an
attacker gets for free there today. The answer, measured, is **nothing: it is a
large loss at every thread count.**

`expand_key()` in `slow-hash.h` is shared by v8, v11, v10 and v9, so one change
covers four consensus paths. Streaming stores were added to it behind the same
per-thread switch v13 uses, verified bit-identical over 14 vectors spanning
every variant, and measured A-B-B-A per thread with the salt restored before
every nonce so both arms hash identical work:

```
threads   pad total   ordinary stores   streaming stores   streaming is
   4        4 MB        2,697,270         6,810,160          -60.4%
   8        8 MB        2,638,065         6,838,888          -61.4%
  16       16 MB        2,986,368         7,035,463          -57.6%
  24       24 MB        4,000,884         7,347,284          -45.6%
  30       30 MB        4,646,828         7,666,864          -39.4%

cycles per nonce, 1.3M nonces total, 0 digest mismatches
```

**Why, and this is the part that generalises.** v13's pad is 8 MB a thread, so at
any useful thread count it cannot stay in cache; an ordinary store misses, pays
a read-for-ownership out to DRAM, and streaming skips that read. v8's pad is
1 MB. At 30 threads that is 30 MB against 32 MB of L3 per CCD with 15 threads on
each, so **the pad never leaves cache, the fill's stores never reach DRAM, and
there is no read-for-ownership to save.** Streaming only forces traffic that was
not happening.

The shape confirms the mechanism rather than just the verdict. The streaming arm
is nearly flat across thread counts, 6.81M to 7.67M cycles, because it always
goes to DRAM. The ordinary arm climbs 76% as cache pressure grows. The two
converge and do not cross inside the usable range.

#### What this is and is not

It **is** a measured defensive property of v8: the attack that gave the most on
v6 gives nothing here, and the pad size is the reason.

It is **not** something to rely on blindly, for two reasons.

**It is machine-dependent, but not in the way first assumed, and the correction
is the useful part.** The first version of this section said the defence was
"threads times 1 MB stays under L3", and predicted that the i7-7700HQ, 6 MB of
L3 with 8 threads and 8 MB of pads, would flip the sign. Measured there:

```
laptop, 4 cores, 6 MB L3        ordinary     streaming    streaming is
2 threads  (2 MB, fits)         4,744,656    5,118,068      -7.30%
4 threads  (4 MB, fits)         4,777,506    5,191,240      -7.97%
6 threads  (6 MB, at the line)  6,841,954    7,263,431      -5.80%
8 threads  (8 MB, over)         8,589,103    9,188,864      -6.53%
```

**It never flips, and it does not even trend.** Exceeding L3 by a third changes
nothing. So "fits in cache" is the wrong threshold.

What does fit the data is the **over-subscription ratio**, how many times the
working set exceeds L3:

```
                      pads     L3      ratio    streaming
v8, laptop, 2 threads   2 MB    6 MB    0.3x      -7.3%
v8, laptop, 8 threads   8 MB    6 MB    1.3x      -6.5%
v8, 7950X, 30 threads  30 MB   64 MB    0.5x     -39.4%
v13, 7950X, 30 threads 240 MB  64 MB    3.8x     +22%
```

The mechanism this implies: streaming stores remove the fill's
read-for-ownership, but they also guarantee that whatever reads the pad next
goes to DRAM. At 0.3x to 1.3x a useful fraction of the pad is still cached, so
the forced DRAM reads cost about what the removed RFO saved, and the net is a
small loss. At 3.8x nothing was going to be cached anyway, so the removed RFO is
pure gain with no added read cost.

**REFUTED 2026-10-06, see FINDINGS F55.** Swept across six pad sizes and three
thread counts on v8, the sign never flips at all, up to 3.87x, and three points
at the same ratio differ by 19.8 percentage points. Pad size and thread count
move the result in opposite directions, so the ratio collapses two variables
that do not travel together. Thread count behaves as described below; pad size
does not. Do not use the ratio rule stated at the end of this lesson.

**The attack switches on somewhere well above 1.3x over-subscription, not at
1.0x.** v13 at 8 MB a thread sits at 3.8x and is wide open. v8 at 1 MB sits at
0.3x to 1.3x everywhere tested and is not. That is a far more useful boundary
than "fits or does not fit", and it is only visible because the laptop was
measured rather than reasoned about.

The larger penalty on the desktop, 39% to 61% against the laptop's 6% to 8%, is
the same mechanism from the other side: a big fast L3 makes the cached read the
streaming store gives up much more valuable.

**It raises a bigger question than it answers.** If v8's pad is cache-resident
at every realistic thread count on a modern desktop CPU, then the memory in
memory-hard is doing less work than the design intends. CryptoNight's original
2 MB was sized against the L3 of 2014; caches have grown far faster than the pad
has. A pad that fits in cache is cache-hard rather than memory-hard, which is a
weaker property and a friendlier one to an ASIC with embedded SRAM. The
measurement here does not settle that, and the contention visible in the
ordinary column, 76% growth from 8 to 30 threads, says the pads are not getting
a free ride. But **the question deserves asking directly rather than inheriting
the answer from CryptoNight**, and nothing in FINDINGS asks it.

#### Rule

A pad sized to exceed cache is doing a different job from a pad that fits in it,
and which one a design has depends on the machine, not on the algorithm. **State
the pad size as a ratio to the target machine's cache per thread, not in
megabytes**, and re-check it when caches grow.

### 10. v8's pad is 98.5% reproducible on every nonce, and only its size hides that

Lesson 7 says a pass over memory is memory work only while the memory is not
reproducible. Asked of v8 and measured rather than argued:

```
v8 pad 1 MB, 8192 blocks of 128 bytes
blocks the sweeps wrote, 2000 nonces at the consensus draw
  min 23   mean 89.6   max 222   of 8192
  1.09% of the pad written, 98.91% reproducible
  the 32 random-value pokes add at most 32 more, so at least 98.52%
```

Everything else in the pad at the moment the final pass reads it is the fill's
AES chain XOR the salt, both of which a miner can regenerate for the price of an
AES round. **v6's recomputed final pass therefore applies to v8 structurally.**

It applies *more* completely than it does to v6. On v13 a miner needs screening
at 0.4% acceptance to find nonces whose pads are that clean. On v8 **every nonce
is that clean**, because the write count is bounded by the draw: xx and yy in
[4,8] and iters in [0,63] give at most (xx-1)*yy + iters = 119 sweep operations,
each writing two 16-byte slots, against 65,536 slots in the pad.

#### Why it is not currently exploitable, and what that rests on

Regenerating a block costs an AES pseudo-round; reading one costs a memory
access. Which is cheaper depends entirely on where the pad lives. At 1 MB a
thread the pad is in L3 (lesson 9), so reading is cheap: regenerating all 8192
blocks is roughly 655,000 AES operations, call it 330,000 cycles, against maybe
16,000 cycles to stream 1 MB out of L3. A 20x loss. *That is an estimate from
throughput figures, not a measurement; what is measured is the mechanism behind
it, in lesson 9, where streaming stores lost 39% to 61% for the same reason.*

So v8 is protected from this, and from the non-temporal store attack, by one
property and the same one in both cases: **the pad's working set does not exceed
L3 by enough to matter.** Lesson 9 puts that threshold well above 1.3x
over-subscription, measured on two machines; v8 sits between 0.3x and 1.3x
everywhere tested, and v13 at 3.8x is where both attacks pay.

#### The consequence that inverts the usual intuition

If v8's pad were made larger to increase memory-hardness, past the point where
it stops fitting in cache **both attacks switch on at once**, and the larger pad
helps the attacker more than the defender:

- the honest miner pays a larger fill, a larger final-pass read, and DRAM for
  both
- the attacker pays a larger fill and regenerates the final pass, trading DRAM
  for AES, which is exactly the trade that was worth +16.8% on v13's 8 MB pad

**Growing the pad would not raise the attacker's cost. It would lower it
relative to the honest miner's.** That is the opposite of what "bigger pad, more
memory-hard" predicts, and it is the single most useful thing this project has
produced about v8.

#### This is not a thought experiment: v13 already ran it

FINDINGS F11 records that **HF13 raised the pad from 4 MB to 8 MB deliberately**,
reasoning that 8 MB per thread overflows L3-per-core on nearly every machine
class, so every class falls back to DRAM latency and they even out.

That reasoning is right about an honest miner and wrong about an optimised one,
and this project measured the difference. The two attacks that a
cache-overflowing pad enables are exactly the two measured here, and on the two
versions they land in opposite directions:

```
                         v13, 8 MB, exceeds L3     v8, 1 MB, fits in L3
non-temporal fill             +22%                     -39% to -61%
recomputed final pass         +16.8%                   a loss, see above
together                      1.29x                    nothing
```

**The decision to push the pad past L3 is what handed the v13 attacker that
1.29x.** Forcing every machine class to DRAM latency does even them out, but
only among miners who go to DRAM. An optimised miner responds by not going to
DRAM at all: it regenerates the 94% to 99.95% of the pad that nothing wrote, and
pays AES instead. The bigger the pad, the more that trade is worth.

*Caveat on the comparison:* v13 and v8 differ in more than pad size, v13 having
the VM and v8 the sweeps. But both attacks target the fill and the final pass,
which are structurally the same sequential AES passes in both, so the comparison
is sound for these two attacks specifically and should not be stretched further.

So F11's rationale deserves an amendment rather than a contradiction: a pad that
overflows L3 evens out **honest** machine classes, and simultaneously creates
the headroom an optimised miner uses to leave that class entirely.

#### The root cause, stated so it can be designed against

**v8's count of pad-dirtying operations is constant at at most 119, regardless
of how big the pad is.** The pad's size buys fill cost and final-pass cost, both
sequential, both prefetchable, and both reproducible from a 128-byte chain state
plus the salt. It does not buy random-access work, because the random-access
count does not scale with it.

So the rule for any future change:

> Pad size only buys memory-hardness to the extent that something writes the pad
> unpredictably, in proportion to its size. A pad whose write count is fixed
> while its size grows is buying sequential bandwidth, and sequential bandwidth
> over reproducible data is not a cost an attacker has to pay.

If v8's pad is ever resized, the sweep count has to scale with it, or the resize
is worse than useless. If it is left at 1 MB, the safety is real but it is
over-subscription safety: **state it as a ratio to L3 rather than in megabytes,
and re-check it as caches and thread counts change**, per lesson 9.

The quantitative version, which is what a future change should be checked
against: **v8 at 1 MB a thread reaches v13's 3.8x over-subscription only at
roughly 24 threads on a 6 MB L3, or at a 4 MB pad on a 64 MB one.** Either is a
plausible accident. A pad increase to 4 MB, the size v13 had before HF13 raised
it, would put v8 straight into the regime that is now measured to be worth 1.29x
to an attacker.

## Current state, and how to pick this up cold

Branch `perf/v13-fused-pad-init` on remote `robcoder` (R0BC0D3R/nerva). Nothing
here is proposed for nerva-project.

### Best known configurations

```
7950X, 16C/32T, 1 MB L2 per core
  nervad --mining-screen-threshold 4 --mining-recompute-final --mining-nontemporal-fill
         --mining-screen-batch
                                                30 threads   3148.6 H/s   5.27x over stock
  (threshold 4 is the optimum; 3 ties it, 2 and below and 6 and above are worse)

  Same build live on mainnet through NervaOne:
    12 threads  1733 H/s     16 threads  2277 H/s
  (13 blocks found overnight at 12 threads, 13 credited, none rejected)
  Scaling is linear to 16, the physical core count, and 0.74 of linear beyond.

i7-7700HQ, 4C/8T, 256 KB L2
  nervad --mining-screen-threshold 14 --mining-screen-batch   8 threads   413.5 H/s   4.45x
  (--mining-recompute-final and --mining-nontemporal-fill are both UNMEASURED
   here, and the laptop's 256 KB L2 and lower memory bandwidth make it the
   machine most likely to gain from each)
```

Builds for every platform come from the `depends` GitHub workflow, which now
triggers on pushes to this branch as well as on manual dispatch. User-facing
instructions, including how to publish a pre-release from the artifacts, are in
[EXPERIMENTAL-V6-MINER.md](https://github.com/R0BC0D3R/nerva/blob/perf/v13-fused-pad-init/contrib/powbench/EXPERIMENTAL-V6-MINER.md).

Binaries used for the A/Bs are under `D:/Claude/v6miner/ab/`. The newest is
`nervad-hoist.exe`. They are not in git; rebuild from the branch if they are
gone. The build directory is keyed on the branch name, so a branch switch sends
output somewhere else; check the md5, not the path.

### What is built

| | state |
|---|---|
| fused pad init | shipped, +7.6% |
| run-ahead salt | shipped, +7.6% |
| nonce screening | shipped, `--mining-screen-threshold`, default off |
| screen early exit | shipped, +21% via moving the optimum |
| eight-lane HC-128 init | shipped, `HC128_Init_x8`, verified 2.37x |
| eight-wide screen | shipped, `--mining-screen-batch`, default off; **+9.1% at 30 threads** on re-measurement, after first being recorded as worth nothing there. See rule 7 |
| recomputed final pass | shipped, `--mining-recompute-final`, default off; +16.8% screened, -7.7% unscreened |
| non-temporal fill | shipped, `--mining-nontemporal-fill`, default off; +22% alone, +12% on top of the recompute |
| phase timing | `CN_V13_PHASE_TIMING`, off; instruments the real hash, see the breakdown above |
| screen profiling | on, its own log category; `--log-level "*:WARNING,user:INFO,global:INFO,miner.screen:INFO"` |
| hoisted hashing blob | on, `NERVA_NO_BLOB_HOIST=1` disables; removes 3,351 cycles a candidate, under 2% of throughput at 30 threads |
| non-temporal fill, shared | `cn_fill_store` in the shared `expand_key()`, covering v8, v11, v10 and v9; same switch, default off. **Measured a 39% to 61% loss on v8 at every thread count**, see lesson 9 |

### Next, and it is not what it was this morning

**Read this before picking an item.** The workload is no longer memory bound.
Per-hash traffic is down from 24 MB to 8 MB, 53 GB/s to 23 GB/s, and the last 3x
of traffic bought only 1.29x of throughput. Every remaining item on the original
list was priced against a memory-bound miner, and those prices are now wrong.

What a hash actually costs now, at threshold 4 and 30 threads:

```
AES          ~15.7M operations, three passes over the chain
             (fill, the final pass's replay, the final pass itself)
VM           ~1.05M interpreted instructions, 2048 passes of 512 steps
screen       ~244 rejected candidates per accepted nonce, two HC-128
             key schedules each
memory        8 MB of streaming stores
```

In order:

- **The screen, which the phase breakdown says is 42% of a nonce.** Measured
  from inside the daemon, a candidate costs about 52,600 cycles and splits:

  ```
  HC128_Init, salt prefix     16,350   31%   vectorised by --mining-screen-batch
  cn_vm_screen_cost          ~34,550   66%   a second HC128_Init plus the walk
  get_cna_v6_seed              1,700    3%   not worth attacking
  blob rebuild                     0    0%   hoisted out
  ```

  So the screen is **two HC-128 key schedules at about 59% plus a walk at about
  30%**. The schedules are already eight wide. The walk, roughly 12.5% of a
  nonce, is the largest piece nothing has attacked, and it resists the same
  treatment because it is lazy slot generation whose lanes diverge at different
  points. Both schedules are keyed per nonce, so neither can be cached.

- **Trace JIT, now demoted on measurement rather than promoted on a count.**
  The VM is 29% of a nonce, so eliminating it *entirely* caps at 1.41x, and a
  JIT removes interpreter dispatch rather than the memory operations
  underneath, so the realistic prize is 1.15x to 1.25x for an x86-64 emitter
  plus deopt handling. Worth doing eventually, not worth doing next.

- **One fewer AES pass.** The recomputed final pass does the fill's AES work a
  second time. Half of it could be avoided at K-block granularity by keeping
  checkpoints of `fill_text` during the fill, which is the same machinery the
  virtual pad needs. Cheaper to try than the JIT, and it attacks what is now the
  largest single cost.

- **A three-way XOR in `aes_pseudo_round_xor`.** The recomputed path builds each
  clean block into a scratch buffer and then XORs it in, so there is a 128-byte
  store and reload per block that a three-operand variant removes. Small, but
  it is 8 MB of L1 traffic per hash and the measurement is cheap.

- **Screen cost.** At 0.41% acceptance the screen runs 244 times per hash. It
  was 4% of the total when the hash was expensive; the hash is now 1.29x
  cheaper, so it is worth re-deriving rather than re-reading the old share.
  `--mining-screen-batch` is still off on this machine and may be worth
  re-measuring now that cache pressure has fallen.

**Demoted, with the reason:**

- **Virtual pad**, advertised 1.51x. It removes the fill's remaining 8 MB, which
  is now 23 GB/s of headroom rather than a wall. On this evidence it is worth a
  fraction of its published number, and it is still the largest piece of work on
  the list. The checkpoint machinery is worth building anyway for the AES-pass
  item above, which is the cheap half of it.
- **K-way nonce interleaving**, advertised +23%. Its value is overlapping memory
  stalls and there are far fewer left to overlap.

Verify anything here with `contrib/powbench/t_v13_recompute.c`, which runs the
full 2x2 of the existing switches against the base path and prints the
dirty-block count so a vacuous comparison is visible rather than silent.

### Open

- The optimal threshold is a machine property; sweep it per machine rather than
  trusting the default in the help text. It did not move when the recomputed
  final pass went in, which is the first time it has not.
- **`--mining-recompute-final` is unmeasured on the laptop.** It should help
  there at least as much, and plausibly more: 256 KB of L2 and less memory
  bandwidth per core is exactly the machine that gains most from trading DRAM
  for AES. Its best threshold is 14, which is looser than this machine's 4, so
  the pad will be dirtier and some of the gain comes back off.
- The recomputed final pass builds each clean block into a scratch buffer and
  then XORs it in, so a 128-byte store and reload happens per block that a
  three-way XOR variant of `aes_pseudo_round_xor` would remove. Cheap to try,
  and only worth it if it shows up next to the DRAM saving.
- The miner reports the page tier for **thread 0 only**; it should report the
  worst tier across threads. At 24 to 30 threads a per-thread fallback would be
  invisible.
- F36's big-endian `e2i` missing `SWAP64LE` is still unfixed, unrelated to this
  work but noted in FINDINGS.
- **Unexplained: defining `CN_V13_PHASE_TIMING` makes every v10 and v11
  known-answer vector fail, while v13 and v14 pass.** Ruled out: the timing
  marks themselves (removing them from the hardware unit does not fix it), a
  thread-local array in `slow-hash.c` on its own (does not reproduce it), the
  `<x86intrin.h>` include (replaced with `__builtin_ia32_rdtsc`, still fails),
  and the optimisation level (the clean tree passes at -O1, -O2 and -O3 with
  identical digests). The wrong value is stable across runs, so it is
  deterministic rather than uninitialised memory, and in the same binary the
  same arguments give the right digest from a harness and the wrong one from
  inside the known-answer test. Nothing committed is affected: the macro is
  off, and the tree passes. **Worth its own session.** The KAT now names the
  failing vector, which is what made this visible at all.
- Thread scaling is now measured at 12, 16 and 30. Between 16 and 30 only SMT
  siblings are being added, each worth about 44% of a core, so there is no
  reason to expect anything interesting in that range.
- **This rig's 16-thread readings are bimodal**, roughly 2280 or 1950 H/s, on
  huge pages, with affinity pinning on, and with one sampling window spanning
  both modes. Unexplained. Draw conclusions at 30 threads until it is.
- The screen is two HC-128 key schedules at about 59% plus a walk that is mostly
  keystream generation. `--mining-screen-batch` already vectorises the
  schedules eight wide. The walk, about 30% of the screen and 12.5% of a nonce,
  is the largest piece nothing has attacked, and it resists the same treatment
  because lanes diverge at different points.

## Measurement rules

Earned the hard way on this project. Each one is here because ignoring it
produced a confident wrong number.

### Rule 1. When a measurement is invalidated, re-derive everything built on it

Deleting a bad number does not delete what was computed from it. This has now
cost twice in one day:

- A nonce time of 39.6 ms came from a contended run. The run was identified and
  discarded, but the salt's 40% share of a nonce, derived from it, stayed in use
  and produced a prediction of +17% against a measured +7.6%. The true share is
  19%.
- An early daemon appeared to read high and then step down, which was the same
  contention episode. The cause was corrected; the 150-second settle built to
  work around it was not, and silently cost two minutes per run for the rest of
  the day. A calibration run later showed the rate is flat from the first
  sample, 717 to 747 H/s with no trend.

**When a measurement is withdrawn, list what was justified by it and re-check
each one.** The derived belief outlives the number and is harder to see.

### Rule 2. A measurement whose key diagnostic is missing cannot be debugged

The first screening sweep was uninterpretable because the screened-nonce counter
existed but was never logged, so there was no acceptance rate to check the
throughput against. A measurement needs the number being reported *and* the
number that says whether the mechanism did what it claims.

### Rule 3. Measure the settle, do not inherit it

See rule 1. Settle time is a parameter like any other and costs nothing to
calibrate once: one cold run sampled every 10 seconds says what it should be.

### Rule 4. Do not touch the machine during a run, including locking it

Locking a Windows session and unlocking it changes power and scheduling state,
and a run spanning that transition is not comparing like with like. One sweep
here alternated high and low across runs in a way that tracked run order rather
than the parameter being swept, and a lock/unlock during it is the most likely
explanation. The session now stays unlocked for the duration of any
measurement.

### Rule 5. Know the shape the result should have before reading it

Screened throughput is not monotonic in the threshold: a tighter threshold
accepts cheaper nonces but pays the estimate more times per accepted nonce, so
the effective rate has a peak. Calling a non-monotonic result "impossible" was
wrong; what was actually anomalous was one point, not the shape. Predict the
shape first, then the deviations stand out instead of the noise.

### Rule 6. Compare inside a run, never across runs

The same configuration read 2520.5, 2570.4 and 2590.5 H/s across two runs on the
same evening with nothing changed. That is a spread of about 3%, and it is
larger than several of the effects measured on this project. Each run's own
A-B-B-A or repeated baseline bounds the drift **within** that run, usually to
1 to 2%, and that is the only comparison the rig supports at this resolution.

So a number from yesterday's run is not a baseline for today's change. Measure
the baseline again, in the same run, every time. The cost is one extra point and
it is always worth paying.

### Rule 7. When the balance changes, every "not worth it" is void, not stale

A measurement is a property of the configuration it was taken in. Eight-wide
screening was recorded as worth nothing at 30 threads and 4% at 7 to 8, which
looked like a core-count effect and was filed as one. It was a cache-pressure
effect. Removing two thirds of the memory traffic made it worth 9.1% on the
machine where it had been worthless, and the code had been sitting finished and
switched off the whole time.

So a change that alters the balance does not merely make old negative results
stale, it voids them. **Keep an explicit list of everything rejected under the
old balance and re-run it.** On this project that list had one entry and it was
worth 9%.

This is rule 1 pointed at negative results instead of positive ones, and the
negative ones are easier to miss because nothing downstream depends on them.

## Environment traps

- **The build must run inside MSYS2 bash.** In Git for Windows bash, `make`
  hands recipes to Git's `sh`, which cannot create a temp file, and CMake's
  `forbid_undefined_symbols()` probe fails first, so the build dies at
  `Undefined symbols test failure` as though the code were broken.
  `MINGW_PREFIX` is also unset there, so `MSYS2_FOLDER` resolves to
  `C:/Program Files/Git`. Wrap it:
  `MSYSTEM=MINGW64 CHERE_INVOKING=1 /c/msys64/usr/bin/bash.exe -lc 'cd ... && make release-static-win64 -j4'`.
- **`--start-mining` was recorded here as silently not starting the miner, and
  live evidence now contradicts that.** NervaOne launches the daemon with
  `--start-mining <address> --mining-threads N` and the miner starts: an
  overnight mainnet run on that path found 13 blocks. Whatever was observed
  originally, the flag is not simply inert, so **re-test before relying on
  either version of this**. The `start_mining` RPC remains the safer choice for
  scripted runs because it returns a status that can be checked, which is why
  the measurement scripts use it.
- **Never redirect the daemon's stdout.** It reads EOF on stdin and exits
  immediately, which looks exactly like a crash.
- **A build's exit code is not the exit code you get back.** Running
  `make ... > log 2>&1; echo $?; tail -3 log` as one command reports the exit
  code of `tail`, and a background task's completion notice reports the same
  thing, so a failed build is announced as a success. It happened here: the
  non-temporal fill failed to compile over a namespace qualifier, the run was
  announced as exit 0, and the binary that got staged was the previous one.
  **The md5 check is what caught it**, which is the second time that check has
  earned its place in one project. Capture `rc=$?` immediately and make it the
  last thing printed.
- **The version banner does not distinguish builds.** It is stamped from the
  git hash, so a tree with uncommitted changes reports the last commit. Go by
  file, and check the two binaries differ before trusting an A/B.
- **Standalone harnesses need the MinGW DLLs on PATH** or they exit 127, and a
  script parsing their output silently sees empty readings.
- **Bash heredocs mangle backslashes inside string literals.** Write C and
  Python with a file-writing tool, not inline heredocs.
- **In PowerShell, anything written to the output stream inside a function
  becomes part of its return value.** Use `Write-Host` for progress, or the
  caller gets an array and the arithmetic fails.
