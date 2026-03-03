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

In order to generate a transaction on behalf of another miner in a non-interactive way without compromising privacy, we re-use the keys associated with the original uncle block miner transaction in the nephew block.

The uncle block transaction public key from the uncle block transaction extra field should be included in nephew miner transaction at index 1. The output key from the uncle block should be re-used at nephew miner transaction output index 1. Since output index is a part of the stealth address generation algorithm,
```
Hs(aR|i)*G + B = Hs(rA|i) + B 
```
(see cryptonote whitepaper section 4.3),
wallets should use index 0 to compute the shared secret for both outputs in a nephew block miner reward transaction.

### Block Reward Bonuses

I use the reward constants proposed in the original SECOR paper: +5% of the base reward amount to the nephew miner and 20% of the base reward amount to the uncle miner. The impact of this is detailed in the "Block Reward Rationale" section.

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

## Status

This proposal is a work in progress. I am seeking community feedback to see if I should continue working on this idea, and to get an idea of what people want to do about the block reward.

### TODOs

#### Coding

* Address the TODO comments

* graceful database migration - currently a sync from scratch is required after upgrading

#### Research

* How does changing the difficulty target affect the rest of the difficulty algo parameters ?
    * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 references this. TX locking can be done with unix timestamps instead of blocks. This should be consistent.
    * DIFFICULTY_BLOCKS_COUNT - should the DIFFICULTY_WINDOW be adjusted ?

* How long does it currently take for a block to propogate throughout the network ?

* Quantify frequency of orphans / chain re-organizations

* Decide transaction maturity blocks #

#### Testing

* Unit test the whole thing

* Deploy to testnet
