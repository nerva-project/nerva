# D1 + D3 combined. Anchors are F58's rebased cross-machine pair (one session,
# both machines); the two multipliers are measured fresh today.
ND, NL = 1.325, 2.877        # nonce, 7950X / 7700HQ (F58)
CD, CL = 0.535, 1.257        # core
CD1_D, CD1_L = 0.243, 0.646  # core after D1 (per-machine: the laptop gains less)
FD, FL = ND-CD, NL-CL        # fill, unchanged by D1

# measured today, same binary both machines: fill at odds 256 / odds 13
R_FILL_D, R_FILL_L = 0.8339/0.7050, 1.6899/1.2993
# measured today on the 7950X: core after D1 / core now  -> 0.4564 vs F58's 0.4542
print(f"core ratio check: today {0.2515/0.5510:.4f} vs F58 {CD1_D/CD:.4f}  (agree to 0.5%)")
print(f"fill ratio odds256/13: desktop {R_FILL_D:.4f}, laptop {R_FILL_L:.4f}")
print()

combos = {
 "baseline":  (CD,    FD,            CL,    FL),
 "D1 only":   (CD1_D, FD,            CD1_L, FL),
 "D3 only":   (CD,    FD*R_FILL_D,   CL,    FL*R_FILL_L),
 "D1 + D3":   (CD1_D, FD*R_FILL_D,   CD1_L, FL*R_FILL_L),
}
print(f"{'':<10} {'nonce D':>8} {'nonce L':>8} {'C-2 spread':>11} {'C-3 vs base':>12}")
for k,(cd,fd,cl,fl) in combos.items():
    nd, nl = cd+fd, cl+fl
    print(f"{k:<10} {nd:>8.3f} {nl:>8.3f} {nl/nd:>10.3f}x {nd/ND:>11.3f}x")
print("  thresholds: C-2 <= 2.50x,  C-3 <= 1.25x")
print()
# whole-nonce GPU resistance. r = core's GPU ratio, never measured (B3).
# F59: D1 roughly doubles the AES asymmetry, so D1 arms use 2r.
RF13, RF256 = 11.43, 9.52    # fill GPU ratio, F66 measured
print("whole-nonce GPU resistance, swept over the UNMEASURED core ratio r:")
print(f"{'r':>4} {'baseline':>9} {'D1':>8} {'D3':>8} {'D1+D3':>8}   {'D1+D3 vs base':>14}")
for r in (3,6,10):
    g = lambda c,f,rc,rf: (c*rc + f*rf)/(c+f)
    b  = g(CD,    FD,          r,   RF13)
    d1 = g(CD1_D, FD,          2*r, RF13)
    d3 = g(CD,    FD*R_FILL_D, r,   RF256)
    dd = g(CD1_D, FD*R_FILL_D, 2*r, RF256)
    print(f"{r:>4} {b:>8.2f}x {d1:>7.2f}x {d3:>7.2f}x {dd:>7.2f}x   {dd/b-1:>+13.1%}")
