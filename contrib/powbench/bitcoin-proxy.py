# Price HC-128's expansion phase against the Bitcoin ASIC market.
# HC128_Init's expansion IS SHA-256's message schedule (F64), and that
# primitive has a public, competitive market price in J/hash.

# --- Bitcoin side -----------------------------------------------------
J_PER_TH   = 9.5           # Antminer U3S23H, 1160 TH/s at 11020 W, 2026 frontier
J_PER_HASH = J_PER_TH / 1e12

# A nonce costs 2 SHA-256 compressions once the midstate of the first
# 64 header bytes is reused. Each compression: 48 schedule steps (W[16..63])
# and 64 main rounds.
SCHED_STEPS_PER_HASH = 2 * 48

# Gate-equivalent weighting, 32-bit datapath. Rotations/shifts are wiring.
ADD, XOR32, CH, MAJ = 200, 32, 74, 128
sched_step = 2*(2*XOR32) + 3*ADD          # sigma0 + sigma1 + 3 adds
main_round = 2*(2*XOR32) + CH + MAJ + 7*ADD
sched_frac = (48*sched_step) / (48*sched_step + 64*main_round)

J_PER_SCHED_STEP = J_PER_HASH * sched_frac / SCHED_STEPS_PER_HASH

# --- Nerva side -------------------------------------------------------
STEPS_PER_INIT = 256 + 496 + 16 + 496     # 1264, counted in hc128.c
INITS_PER_NONCE = 257
sched_steps_per_nonce = STEPS_PER_INIT * INITS_PER_NONCE
asic_J_per_nonce = sched_steps_per_nonce * J_PER_SCHED_STEP

# --- CPU side, two independent routes ---------------------------------
WATTS, HPS = 230.0, 11782.0               # 7950X, 30 threads, F57
cpu_J_per_nonce = WATTS / HPS

# share of a nonce that is expansion: fill x init x expansion-of-init
WARMUP_STEPS = 1024
exp_frac_of_init = STEPS_PER_INIT / (STEPS_PER_INIT + WARMUP_STEPS)
exp_share = 0.562 * 0.673 * exp_frac_of_init
cpu_J_expansion = cpu_J_per_nonce * exp_share

# route B: straight from cycles
CYC_PER_INIT, GHZ, CORES = 8750.0, 4.5, 16
cyc_per_step = CYC_PER_INIT * exp_frac_of_init / STEPS_PER_INIT
J_per_core_cycle = WATTS / (CORES * GHZ * 1e9)
cpu_J_per_step = cyc_per_step * J_per_core_cycle

print(f"schedule fraction of a SHA-256 compression : {sched_frac*100:.1f}%")
print(f"ASIC J per schedule step                   : {J_PER_SCHED_STEP:.3e}")
print(f"CPU  J per schedule step                   : {cpu_J_per_step:.3e}")
print(f"  ratio, route B (per step)                : {cpu_J_per_step/J_PER_SCHED_STEP:,.0f}x")
print()
print(f"schedule steps per Nerva nonce             : {sched_steps_per_nonce:,}")
print(f"expansion share of a nonce                 : {exp_share*100:.1f}%")
print(f"ASIC J per nonce, expansion only           : {asic_J_per_nonce:.3e}")
print(f"CPU  J per nonce, expansion only           : {cpu_J_expansion:.3e}")
print(f"  ratio, route A (per nonce)               : {cpu_J_expansion/asic_J_per_nonce:,.0f}x")
print()
# sanity: how much better is an ASIC than this CPU at Bitcoin itself?
CPU_SHA_HPS = 1.5e9
print(f"control: ASIC vs this CPU at Bitcoin       : {(WATTS/CPU_SHA_HPS)/J_PER_HASH:,.0f}x")
print("  (our figure should exceed this by roughly the SHA-NI speedup,")
print("   since hc128.c uses general-purpose integer ops, not SHA-NI)")
