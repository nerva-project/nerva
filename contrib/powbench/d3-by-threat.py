# D3 scored per threat class, not as one number.
# r = GPU-or-device time / CPU time. r > 1 means the device is WORSE, good for us.
# Inputs: F60 (fill vs odds), F62 (gather ratios, HC-128 ratio).

cipher = 701.9                      # us, odds-independent (F60 "one hot entry")
mem_now, mem_max = 42.2, 200.7      # us, F60 odds 13/256 and 256/256

# F60's two implied per-read costs on a 7950X: window 2.06 ns, full 12.25 ns.
# Split the odds-13 memory term by where the time actually goes.
full_t_now = 832 * 12.25 / 1000.0
win_t_now  = mem_now - full_t_now

R_HC128   = 12.1                    # F62, measured
R_FULL    = 1/1.64                  # F62, 240 MB gather: GPU 1.64x BETTER
R_WINDOW  = 1.5                     # 5.3 MB is L3-resident on a CPU. UNMEASURED.

def gpu_ratio(c, w, f):
    return (c*R_HC128 + w*R_WINDOW + f*R_FULL) / (c + w + f)

now = gpu_ratio(cipher, win_t_now, full_t_now)
mx  = gpu_ratio(cipher, 0.0, mem_max)
print(f"GPU resistance of the fill   {now:.2f}x -> {mx:.2f}x   ({(mx/now-1)*100:+.0f}%)")
print(f"  memory share of the fill   {mem_now/(cipher+mem_now)*100:.1f}% -> {mem_max/(cipher+mem_max)*100:.1f}%")
print("  D3 grows the part a GPU is BETTER at. Cost is modest only because")
print("  HC-128 dominates the fill either way.")
print()
print("FPGA: block RAM is tens of MB, so the 5.3 MB window fits on-chip today")
print("  and 240 MB does not.")
for name, odds in (("now", 13), ("64", 64), ("max", 256)):
    on_chip = (256-odds)/256
    print(f"  odds {name:>3}: {on_chip*100:5.1f}% of reads servable from block RAM")
