# C-7 recomposed with the MEASURED window and full-size gather ratios.
cipher = 701.9                    # us, odds-independent (F60)
win_t, full_t_now = 32.0, 10.2    # us at odds 13, split by F60's implied per-read costs
mem_max = 200.7                   # us at odds 256, all full-history
R_HC128 = 12.1                    # F62, measured
R_WIN   = 1/5.65                  # MEASURED 2026-10-07, 3.5 MB, interior peak
R_FULL  = 1/1.98                  # MEASURED 2026-10-07, 224 MB, interior peak (F62 said 1.64x)

now = (cipher*R_HC128 + win_t*R_WIN + full_t_now*R_FULL) / (cipher + win_t + full_t_now)
mx  = (cipher*R_HC128 + mem_max*R_FULL) / (cipher + mem_max)
print(f"fill GPU resistance  {now:.2f}x -> {mx:.2f}x   ({(mx/now-1)*100:+.0f}%)   C-7 threshold -20%")
print()
print("Why P5 being wrong by 8x barely moved this:")
print(f"  GPU memory time, odds 13 : {win_t*R_WIN + full_t_now*R_FULL:.1f} us of {cipher*R_HC128 + win_t*R_WIN + full_t_now*R_FULL:.0f} us total")
print(f"  the regression is the CPU's fill slowing {902.6/744.1:.2f}x while the")
print(f"  GPU's slows only {mx*902.6/(now*744.1):.3f}x. Memory is noise on the GPU side.")
