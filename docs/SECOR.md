# SECOR

https://github.com/masari-project/research-corner/blob/master/secor/secor.pdf

## Proposal Summary

I would like to increase the speed of Nerva transactions by integrating the "Simple Extendend Consensus Resolution" (SECOR) protocol into Nerva.

The goal is to better define how the network should respond to temporary chain forks when an orphan block is found and reduce deep chain reorganizations.

### Consensus

When two blocks are found for the top block height, all network participants should reorganize so that the block with Proof-of-Work which clears the highest difficulty should be on top.

Miners should include the hash of the losing block in their next block via the `uncle_hash` block field.

A miner will be rewarded an additional bonus for including that uncle block hash in their block, and the difficulty for the uncle block will be included in the chain cumulative difficulty, giving a miner who includes a valid uncle hash an advantage over miners who may choose not to.

### Miner Transaction Format

Miner transactions should include only 1 reward output if the uncle_hash is null.

If an uncle block is included in the block, then the miner transaction must include a secondary transaction output.

In order to generate a transaction on behalf of another miner in a non-interactive way without compromising privacy, we re-use the keys associated with the original uncle block miner transaction from the alt chain into the nephew block.

Since output index is a part of the stealth address generation algorithm, `Hs(aR|i)*G + B = Hs(rA|i)G + B` (see cryptonote whitepaper section 4.3), the ordering of the output destinations in the transaction is important.

If a block doesn't reference an uncle block, then there should be only one output in the reward transaction, which should be used to reward the person who mined the block. If that block is then included into a nephew block as an uncle block, then the nephew block must place the reward for the uncle miner, using the output key from the uncle block miner tx, into the nephew block miner transaction at index 0. The reward for the person who found the nephew block should be placed at index 1 in the reward transaction.

If an uncle block references an uncle block itself, then the reward to the true uncle miner should be at index 1 in the uncle block. To accomodate this, the reward to the nephew miner in the main chain should be addressed to output index 0 so that the uncle reward from index 1 may be recycled.

### Block Reward Bonuses

I use the reward constants proposed in the original SECOR paper: +5% of the base reward amount to the nephew miner and 50% of the base reward amount to the uncle miner. The impact of this is detailed in the "Block Reward Rationale" section.

The optimal reward for Nerva's implementation is still an active research question.

### Block Time Target and Transaction Maturity

Nerva currently has a target block time of 1 minute and requires a maturity of 20 blocks to spend non-miner transaction outputs. I propose to use a 15 second block time as proposed in the original SECOR paper. The first (and only known?) project to integrate SECOR with CryptoNote was Masari, which decreased from a 2 minute to a 1 minute block time. Therefore, real-world behavior with a 15 second block time is currently unknown. Further research should be done to select/confirm the optimal block time for Nerva.

With a 20 block transaction maturity threshold and a 15 seconds block target, it should take about 5 minutes for a transaction to mature. If we succeed in preventing blockchain reorganizations > depth 1, then we may be able to decrease the threshold to only 5 blocks, or 75 seconds.

## Block Reward Rationale
Maximum block reward emission per minute, R, given base reward X:
```
R = X + (X/2) + (X/20)
R = X + (10X/20) + (X/20)
R = X + (11X/20)
```

If we keep the base emission reward the same, X=0.3, then...
```
R = 0.3 + ((11*0.3)/20) = 0.465
```

If we preserve the current emission target of R=0.3 then...
```
0.3 = (20X/20) + (11X/20) = 31X/20
0.3 * 20 = 31X
X = (0.3 * 20) / 31 = 0.19354838709
```

If you have an estimate of how frequently uncle blocks are included in the blockchain, Z, then you can scale the reward to produce the same estimated average emission.
```
R = X + (((X/2) + (X/20)) * Z)
R = X + ((11X/20) * Z)
```

If we think that uncle blocks will be included in half of the main chain blocks then...
```
0.3 = X + ((11X/20) * 0.5)
0.3 = X + (11X/40)
0.3 = 51X / 40
X = (0.3 * 40) / 51 = 0.23529411764
```

## Modeling Orphan/Uncle Block Frequencies

Mining is essentially an [IID process](https://en.wikipedia.org/wiki/Independent_and_identically_distributed_random_variables) as the output of the hashing function used for mining should be an IID random variable. Each time the miner chooses a nonce and produces a hash, the miner has either found a valid block for the given difficulty, or they have not and must attempt again with a successive independent trial. The probabilities for this kind of binary problem follow a [bernoulli distribution](https://en.wikipedia.org/wiki/Bernoulli_distribution). Therefore, a [binomial distribution](https://en.wikipedia.org/wiki/Binomial_distribution) where k=1, aka a [geometric distribution](https://en.wikipedia.org/wiki/Geometric_distribution), can be used to model the cumulative probability of finding a block after mining `n` hashes.

A block difficulty target is used to control the rate at which blockchain can be written to. Nerva currently has a block time target of 1 block per minute. If there are 10 miners on the network, each mining at a rate of 5 hashes/second, then the target difficulty should eventualy fit to about `10*5*60`.

#### Scenario A - Few miners, low difficulty.
```
Suppose:
There is a target block time of 60 seconds.
There are 2 miners, miner A and miner B, on the network, each mining at a rate of 1 H/s.

Then:
The network difficulty should be 1*2*60=120
The probability that miner A finds a block after 1 second of hashing is 1/120.
The probability that miner B has found a block after 1 second of hashing is also 1/120.

The probability that miner A finds a block after 2 seconds of hashing is 2/120.
The probability that miner B has found a block after 2 seconds of hashing is also 1/120.

The probability that miner A and miner B both find a block after 1 second of mining (at the same time) is (1/120)*(1/120) per IID joint probability.

The cumulative probability that miner A finds a block after 2 seconds of mining is 1 - (1-(1/120))^2 per geometric CDF
The cumulative probability that miner B finds a block after 2 seconds of mining is 1 - (1-(1/120))^2 per geometric CDF

The probability that miner A and miner B have both found a block after 2 seconds of mining is (1 - (1-(1/120))^2)^2

The probability that miner A and miner B have both found a block after 10 seconds of mining is (1 - (1-(1/120))^10)^2

The probability that a given miner finds a block after mining for 1 minute is 1 - ((1-(1/120))^60), roughly 40%.

The probability that both miners have each found a block after 1 minute of mining is (1 - ((1-(1/120))^60))^2, which is roughly 15%.
```

#### Scenario B - Few miners, higher difficulty.
```
Suppose:
There is a target block time of 60 seconds.
There are 2 miners, miner A and miner B, on the network, each mining at a rate of 1,000 H/s.

Then:
The network difficulty should be 1000*2*60=120000
The probability that miner A finds a block after mining a single hash is 1/120000.
The probability that miner B has found a block after mining a single is also 1/120000.

The probability that miner A and miner B both find a block at the same time after each mining a single hash is (1/120000)^2 per IID joint probability.

The probability that a given miner finds a block after mining for 1 second is 1 - ((1-(1/120000))^1000) per geometric CDF.

The probability that miner A and miner B have both found a block after mining 10 hashes is (1 - (1-(1/120000))^10)^2

The probability that miner A and miner B have both found after 1 second of mining is (1 - (1-(1/120000))^1000)^2

The probability that a given miner finds a block after mining for 1 minute is 1 - ((1-(1/120000))^60000), which is roughly 40%. This is the same as when the network hashrate is only 2 H/s.

The probability that both miners have each found a block after mining for 1 minute is (1 - ((1-(1/120000))^60000))^2, which is roughly 15%.
```

#### Scenario C - Many miners
```
Suppose:
There is a target block time of 60 seconds.
There are 100 miners on the network, each mining at a rate of 1,000 H/s.

Then:
The network difficulty should be 1000*100*60=6000000
The probability that a given miner finds a block after mining a single hash is 1/6000000.

The probability that 2 miners both find a block at the same time after each mining a single hash is (1/6000000)^2 per IID joint probability.

The probability that a given miner finds a block after mining for 1 second is 1 - ((1-(1/6000000))^1000) per geometric CDF.

The probability that two miners have both found a block after mining 10 hashes is (1 - (1-(1/6000000))^10)^2

The probability that two miners have both found after 1 second of mining is (1 - (1-(1/6000000))^1000)^2

The cumulative probability that a given miner finds a block after mining for 1 minute is 1 - ((1-(1/6000000))^60000), which is just less than 1%.

The probability that any two miners have each found a block after mining for 1 minute is (100*99/2)*((1-(1-(1/6000000))^(60000))^2)*(((1-(1/6000000))^(60000))^98), per binomial distribution (100, 2) which is about 18%
```

Overall, the network difficulty adjusts in a way that adding miners to the network doesnt affect the probability of chain splits significantly assuming that mining power is distributed evenly among miners. This model does not account for the fact that adding miners to the network increases the amount of work required for block propogation across all miners on the network.

### Mining Difficulty Considerations

The current difficulty algorithm adjusts based on the observed difference between block timestamps of recently found blocks compared against the target solve time. We will be lowering that target solve time from 60 seconds to 15 seconds. The algorithm should adjust quickly, but it will be a bit wonky for the first ~60 blocks after hard forking.

Currently the LWMA algorithm uses the parameter N=60 so we are using the most recent 60 blocks when calculating the weighted average. Since we are lowering the target block time, that means we will only be using 15 minutes worth of block histories instead of the last 1 hour worth of blocks. Is this OK?

The "future time limit" used in the difficulty algorithm is intended to be 500 seconds according to the comments in the code. Currently this is, in fact, hard coded to 300 seconds (`CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V6`). Since we are lowering the target solve time, the (FTL / T) ratio increases. Should this be adjusted?

## Status

This proposal is a work in progress. I am seeking community feedback to see if I should continue working on this idea, and to get an idea of what people want to do about the block reward.

### TODOs

#### Coding

* Address the TODO comments

* graceful database migration - currently a sync from scratch is required after upgrading

#### Research

* Confirm that the difficulty algorithm doesnt require further adjustment

* How long does it currently take for a block to propogate throughout the network ?

* Quantify frequency of orphans / chain re-organizations

* Decide transaction maturity blocks #

#### Testing

* Unit test the whole thing

* Deploy to testnet
