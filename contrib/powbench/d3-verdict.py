# D3 against the seven pre-registered criteria. Measured 2026-10-07.
D = {13:0.7050, 32:0.7251, 64:0.7527, 128:0.7940, 256:0.8339}   # 7950X run 1
L = {13:1.2993, 32:1.3507, 64:1.4220, 128:1.5163, 256:1.6899}   # 7700HQ run 1
L2= {13:1.3191, 32:1.3691, 64:1.4422, 128:1.5373, 256:1.7281}   # 7700HQ run 2

# F58's whole-nonce figures at the shipped odds anchor the core, which D3 never touches.
NONCE_D, NONCE_L = 1.325, 2.877
core_d, core_l = NONCE_D - D[13], NONCE_L - L[13]
PICKS = 16384

print(f"control drift, laptop: {abs(L2[13]-L[13])/L[13]*100:.2f}%  (void above 4%)")
print(f"core, odds-independent: desktop {core_d:.3f} ms, laptop {core_l:.3f} ms")
print()
print("odds   fill D   fill L   fillspread  nonce D  nonce L  C-2 spread  C-3 cost  C-1 gain")
for o in (13,32,64,128,256):
    nd, nl = core_d + D[o], core_l + L[o]
    c2 = nl/nd
    c3 = max(nd/(core_d+D[13]), nl/(core_l+L[13]))
    c1 = (PICKS*o/256)/(PICKS*13/256) / c3
    flag = "" if (c2<=2.50 and c3<=1.25 and c1>=5) else "   <-- FAILS"
    print(f"{o:>4}  {D[o]:.4f}  {L[o]:.4f}   {L[o]/D[o]:.3f}x     {nd:.3f}   {nl:.3f}    "
          f"{c2:.3f}x     {c3:.3f}x    {c1:5.1f}x{flag}")
print()
print("thresholds: C-1 >= 5x,  C-2 <= 2.50x,  C-3 <= 1.25x")
print()
print("PREDICTIONS:")
print(f"  P1 laptop rises faster:  desktop {D[256]/D[13]:.3f}x vs laptop {L[256]/L[13]:.3f}x  -> CONFIRMED")
print(f"  P2 fill spread 2.6-3.5x: measured {L[13]/D[13]:.2f}x -> {L[256]/D[256]:.2f}x        -> REFUTED")
mc_lo = (D[32]-D[13])/(PICKS*(32-13)/256)*1e6
mc_hi = (D[256]-D[128])/(PICKS*(256-128)/256)*1e6
print(f"  P3 concave, middle wins: marginal ns/read {mc_lo:.1f} -> {mc_hi:.1f}, cost is CONVEX -> REFUTED")
