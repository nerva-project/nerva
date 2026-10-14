SALT_KB = 262144/1024.0        # CN_SALT_MEMORY, bytes a feeder must ship PER NONCE
CACHE_MB = 4431762*56/1048576  # block_cache_data at today's tip
print(f"salt per nonce {SALT_KB:.0f} KB    block cache {CACHE_MB:.0f} MB\n")

print("FEEDER: bandwidth to keep ONE mining thread fed, by nonce cost")
for lbl, ms in (("baseline", 1.325), ("D3 only", 1.469), ("D1 only", 1.033), ("D1 + D3", 1.177)):
    mbs = (SALT_KB/1024.0) / (ms/1000.0)
    print(f"  {lbl:<10} {ms:.3f} ms/nonce -> {mbs:6.1f} MB/s per thread   "
          f"{mbs*30/1024:5.2f} GB/s for 30 threads")
print()
print("  against real links:")
for lbl, mbs in (("1 Gbps LAN", 125), ("10 Gbps LAN", 1250), ("PCIe 4.0 x16", 25000), ("100 Mbit WAN", 12.5)):
    print(f"    {lbl:<14} {mbs:>7.1f} MB/s = {mbs/217.4:5.2f} mining threads")
print()
print("SHIP-THE-CACHE: the other pool model, where miners hold the data")
print(f"  one-time download        {CACHE_MB:.0f} MB")
print(f"  incremental per block    56 B")
print(f"  per day                  {56*1440/1024:.0f} KB")
