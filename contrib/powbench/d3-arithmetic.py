# D3 re-scored under F65: the only ASIC-binding term is full-history reads.
# All inputs are measured: F60 (fill vs odds), F57 (fill share, H/s), code.

PICKS_PER_NONCE = 4096 * 4          # body() makes 4, 4096 bodies. = 16384
ODDS_NOW, ODDS_MAX = 13, 256        # out of 256, applied per pick

full_now = PICKS_PER_NONCE * ODDS_NOW / 256.0
full_max = PICKS_PER_NONCE * ODDS_MAX / 256.0

# F60, measured on a 7950X at height 4.5M, 240 MB cache, 5.3 MB window
fill_hot, fill_now, fill_max = 0.7019, 0.7441, 0.9026   # ms
FILL_SHARE = 0.562                  # F57, fill as a fraction of a nonce

honest_fill = fill_max / fill_now
honest_nonce = 1.0 + (honest_fill - 1.0) * FILL_SHARE
attacker = full_max / full_now

print("ATTACKER (cipher free, only full-history reads bind)")
print(f"  full-history reads/nonce   {full_now:,.0f} -> {full_max:,.0f}")
print(f"  attacker cost multiplier   {attacker:.1f}x")
print()
print("HONEST CPU (measured)")
print(f"  fill                       {fill_now} -> {fill_max} ms  = {honest_fill:.3f}x")
print(f"  whole nonce                {honest_nonce:.3f}x")
print()
print(f"  NET GAIN IN ASIC RESISTANCE  {attacker/honest_nonce:.1f}x")
print()

# What does it cost a syncing node? PoW is skipped below ASSUME_VALID_HEIGHT.
NONCE_MS, ASSUME_VALID, TIP = 1.325, 4_320_000, 4_500_000
pow_blocks = TIP - ASSUME_VALID
extra_ms = NONCE_MS * (honest_nonce - 1.0)
print(f"SYNC COST: PoW runs on {pow_blocks:,} blocks above assume-valid")
print(f"  extra per block            {extra_ms:.3f} ms")
print(f"  extra for a full sync      {pow_blocks*extra_ms/1000:.0f} s single-threaded")
print()
# memory term implied by F60, as a cross-check on the linear model
mem_now, mem_max = fill_now - fill_hot, fill_max - fill_hot
print(f"CROSS-CHECK: memory term {mem_now*1000:.1f} -> {mem_max*1000:.1f} us = {mem_max/mem_now:.1f}x")
print(f"  reads grew {attacker:.1f}x but CPU memory time grew only {mem_max/mem_now:.1f}x,")
print(f"  i.e. the CPU absorbs most of it in cache. An ASIC without that")
print(f"  cache does not, which is the whole asymmetry D3 is buying.")
