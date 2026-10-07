# C-4: sync cost of odds 256, measured not inferred.
WIN, FULL = 6505613.0, 7773423.0      # TSC ticks/fill, daemon, 2048 interleaved pairs
TSC_GHZ   = 4.491                     # F58's calibration for this part
TIP, ASSUME_VALID, HF14 = 4431762, 4320000, 4500000
V13_OVER_V14 = 1.63                   # F57: the same fill costs 1.63x more under v13

extra_ms = (FULL - WIN) / (TSC_GHZ * 1e9) * 1000.0
blocks   = TIP - ASSUME_VALID
print(f"daemon ratio                 {FULL/WIN:.4f}x   (harness said 1.183x on the same box)")
print(f"extra per block, v13 cond.   {extra_ms:.3f} ms")
print(f"extra per block, v14 cond.   {extra_ms/V13_OVER_V14:.3f} ms  (F57: v14's 1 MB pad makes the fill cheaper)")
print()
print(f"blocks above assume-valid    {blocks:,}")
print(f"  full sync, v13 conditions  {blocks*extra_ms/1000:.1f} s")
print(f"  full sync, v14 conditions  {blocks*extra_ms/V13_OVER_V14/1000:.1f} s")
print()
print("But the odds change is v14-only, so it applies only above HF14:")
for label, n in (("at HF14 launch", 0), ("1 year after", 525600), ("2 years after", 1051200)):
    print(f"  {label:<16} {n:>9,} blocks  {n*extra_ms/V13_OVER_V14/1000:6.1f} s")
print()
print("C-4 threshold: under 2 minutes (120 s)")
