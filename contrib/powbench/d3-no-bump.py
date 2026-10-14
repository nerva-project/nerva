# Worst case: assume-valid bumped at HF14 launch and then NEVER again.
BLOCKS_YR = 365*24*60                 # 1 block/min
NONCE     = 1.325                     # ms, v14 nonce, 7950X 1 thread (F58)
D1_SPEEDUP= 1.313                     # F57, measured in the daemon
D3_EXTRA  = 0.173                     # ms/block, F68, measured

base   = NONCE
d3     = NONCE + D3_EXTRA
d1     = NONCE / D1_SPEEDUP
d1d3   = NONCE / D1_SPEEDUP + D3_EXTRA

print("per-block PoW verification cost, single thread")
for lbl, v in (("today, neither", base), ("D3 only", d3), ("D1 only", d1), ("D1 + D3", d1d3)):
    print(f"  {lbl:<16} {v:.3f} ms   {(v/base-1)*100:+6.1f}%")
print()
print("PoW component of a FULL SYNC with no assume-valid bump after HF14")
print(f"{'years':>6} {'blocks':>10} | {'today':>9} {'D3 only':>9} {'D1 only':>9} {'D1+D3':>9}")
for y in (1, 2, 3, 5):
    n = BLOCKS_YR * y
    f = lambda v: f"{n*v/60000:8.1f}m"
    print(f"{y:>6} {n:>10,} | {f(base)} {f(d3)} {f(d1)} {f(d1d3)}")
print()
print(f"D3's own slice alone: {BLOCKS_YR*D3_EXTRA/60000:.1f} min per year of unbumped chain")
print("Single-threaded. Verification is parallelised, so wall clock is lower,")
print("and PoW is only one component of sync alongside tx checks and DB writes.")
