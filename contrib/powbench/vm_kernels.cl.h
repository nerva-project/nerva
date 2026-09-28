#pragma once
// Faithful OpenCL ports of the CNA memory-hard cores.
//
// These replace the earlier "chase" approximations, which modelled v5, v6 and
// v7 as near-identical dependent walks and therefore could not see the thing
// that actually separates them: v6 and v7 run a 512-instruction per-nonce
// program on a register VM, and v5 runs no program at all.
//
// Ported from src/crypto/cna-vm.c (cn_vm_execute, cn_vm_execute_v7) and
// src/crypto/slow-hash-impl.h (cn_slow_hash_v11's inner loop), instruction for
// instruction. cpu_ref.h holds the matching C. Neither is trusted: main.cpp
// checksums both and refuses to report a row whose GPU and CPU checksums
// disagree, which is what keeps the two copies from drifting.
//
// EVERY WORK-ITEM GETS ITS OWN PROGRAM. That is the point. A GPU running one
// shared program sees no divergence and looks far better than it deserves;
// real mining gives every nonce a different instruction sequence with
// data-dependent branches, which is the barrier being measured.
//
// Deliberately omitted, with reasons:
//   Keccak framing and the blake/groestl/jh/skein finalisation. Fixed cost,
//   identical across variants, and porting four hashes buys nothing here.
//   salt_pad's 200-byte extra_hash, replaced by a mix64 chain of equal call
//   count. Measured at well under 1% of a v5 nonce.
//   The chain salt's CONTENT (get_cna_v5_data / _v6_data). Its cost is on the
//   host either way: 256 KB per nonce is 62 MB/s at 235 H/s and about half a
//   core to generate, so a GPU on a full node gets it nearly free. Its
//   RESIDENCY is modelled, because that is a real VRAM cost.
static const char *VM_KERNEL_SRC = R"CLC(
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define CN_REG_COUNT   8
#define CN_SALT_MEMORY 262144

// Pads are spread over up to 4 buffers because CL_DEVICE_MAX_MEM_ALLOC_SIZE is
// a per-allocation limit, often a quarter of VRAM or less.
#define PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3)                    \
    ( ((gid) / (per_buf)) == 0 ? (b0) + ((gid) % (per_buf)) * (qw) :  \
      ((gid) / (per_buf)) == 1 ? (b1) + ((gid) % (per_buf)) * (qw) :  \
      ((gid) / (per_buf)) == 2 ? (b2) + ((gid) % (per_buf)) * (qw) :  \
                                 (b3) + ((gid) % (per_buf)) * (qw) )

typedef struct { uchar op; uchar dst; uchar src; uchar shift; uint imm; } cn_ins_t;

// cna-vm.c opcodes, same numbering
#define CN_OP_IADD_RS 0
#define CN_OP_ISUB    1
#define CN_OP_IMUL    2
#define CN_OP_IXOR    3
#define CN_OP_IROR    4
#define CN_OP_CBRANCH 5
#define CN_OP_SP_READ 6
#define CN_OP_SP_WRITE 7
#define CN_OP_MIX     8

static inline ulong ror64(ulong x, uint r)
{
    r &= 63;
    if (r == 0) return x;
    return (x >> r) | (x << (64 - r));
}

// cna-vm.c mix64, verbatim
static inline ulong mix64(ulong val, uint key_material)
{
    ulong k = (ulong)key_material * 0x9e3779b97f4a7c15UL;
    val ^= k;
    val ^= val >> 30;
    val *= 0xbf58476d1ce4e5b9UL;
    val ^= val >> 27;
    val *= 0x94d049bb133111ebUL;
    val ^= val >> 31;
    return val;
}

// 10 AES rounds per 16-byte block, 8 blocks: matches aes_pseudo_round.
// T-table AES, which is what a GPU must use; the CPU side uses AES-NI. That
// asymmetry is real and is left in deliberately.
static void aes_fill_pad(__global uint *buf, uint iters,
                         __constant uint *te0, __constant uint *rk, ulong gid)
{
    uint s[32];
    uint seed = (uint)gid * 2654435761u + 1u;
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; s[i] = seed; }
    for (uint it = 0; it < iters; it++) {
        for (int b = 0; b < 8; b++) {
            uint a0 = s[b*4+0], a1 = s[b*4+1], a2 = s[b*4+2], a3 = s[b*4+3];
            for (int r = 0; r < 10; r++) {
                uint t0 = te0[a0 & 0xff] ^ ROTL32(te0[(a1>>8)&0xff],8) ^ ROTL32(te0[(a2>>16)&0xff],16) ^ ROTL32(te0[(a3>>24)&0xff],24) ^ rk[r*4+0];
                uint t1 = te0[a1 & 0xff] ^ ROTL32(te0[(a2>>8)&0xff],8) ^ ROTL32(te0[(a3>>16)&0xff],16) ^ ROTL32(te0[(a0>>24)&0xff],24) ^ rk[r*4+1];
                uint t2 = te0[a2 & 0xff] ^ ROTL32(te0[(a3>>8)&0xff],8) ^ ROTL32(te0[(a0>>16)&0xff],16) ^ ROTL32(te0[(a1>>24)&0xff],24) ^ rk[r*4+2];
                uint t3 = te0[a3 & 0xff] ^ ROTL32(te0[(a0>>8)&0xff],8) ^ ROTL32(te0[(a1>>16)&0xff],16) ^ ROTL32(te0[(a2>>24)&0xff],24) ^ rk[r*4+3];
                a0=t0; a1=t1; a2=t2; a3=t3;
            }
            s[b*4+0]=a0; s[b*4+1]=a1; s[b*4+2]=a2; s[b*4+3]=a3;
        }
        __global uint *dst = buf + it * 32;
        for (int i = 0; i < 32; i++) dst[i] = s[i];
    }
}

// finalize_hash: a SECOND full AES pass over the pad, XORing each block in as
// it goes (aes_pseudo_round_xor). Every variant runs this and leaving it out
// understated the AES share of a nonce, which flatters the GPU because the
// GPU pays T-tables where the CPU pays AES-NI.
static ulong aes_finalize(__global const uint *buf, uint iters,
                          __constant uint *te0, __constant uint *rk, ulong gid)
{
    uint s[32];
    uint seed = (uint)gid * 2654435761u + 99u;
    for (int i = 0; i < 32; i++) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; s[i] = seed; }
    for (uint it = 0; it < iters; it++) {
        __global const uint *src = buf + it * 32;
        for (int b = 0; b < 8; b++) {
            uint a0 = s[b*4+0] ^ src[b*4+0], a1 = s[b*4+1] ^ src[b*4+1];
            uint a2 = s[b*4+2] ^ src[b*4+2], a3 = s[b*4+3] ^ src[b*4+3];
            for (int r = 0; r < 10; r++) {
                uint t0 = te0[a0 & 0xff] ^ ROTL32(te0[(a1>>8)&0xff],8) ^ ROTL32(te0[(a2>>16)&0xff],16) ^ ROTL32(te0[(a3>>24)&0xff],24) ^ rk[r*4+0];
                uint t1 = te0[a1 & 0xff] ^ ROTL32(te0[(a2>>8)&0xff],8) ^ ROTL32(te0[(a3>>16)&0xff],16) ^ ROTL32(te0[(a0>>24)&0xff],24) ^ rk[r*4+1];
                uint t2 = te0[a2 & 0xff] ^ ROTL32(te0[(a3>>8)&0xff],8) ^ ROTL32(te0[(a0>>16)&0xff],16) ^ ROTL32(te0[(a1>>24)&0xff],24) ^ rk[r*4+2];
                uint t3 = te0[a3 & 0xff] ^ ROTL32(te0[(a0>>8)&0xff],8) ^ ROTL32(te0[(a1>>16)&0xff],16) ^ ROTL32(te0[(a2>>24)&0xff],24) ^ rk[r*4+3];
                a0=t0; a1=t1; a2=t2; a3=t3;
            }
            s[b*4+0]=a0; s[b*4+1]=a1; s[b*4+2]=a2; s[b*4+3]=a3;
        }
    }
    ulong acc = 0;
    for (int i = 0; i < 32; i += 2) acc ^= (((ulong)s[i+1]) << 32) | s[i];
    return acc;
}

static void init_regs(ulong regs[CN_REG_COUNT], ulong gid)
{
    ulong x = gid * 0x9e3779b97f4a7c15UL + 0x123456789abcdefUL;
    for (int i = 0; i < CN_REG_COUNT; i++) { x = mix64(x, (uint)i + 1u); regs[i] = x; }
}

// The register file MUST live in registers. Written as ulong regs[8] and
// indexed with a runtime dst/src, it lands in scratch memory on every GPU:
// private arrays with dynamic indices cannot be register-allocated. That is a
// property of the hardware, not a guess. An unoptimised kernel therefore
// measures the porter's laziness rather than the algorithm's resistance, and
// reports far better resistance than is real. Eight scalars plus a
// binary-tree select keeps them in registers, which is what anyone actually
// attacking this would write.
#define REG_RD(i) (((i)<4) ? (((i)<2) ? (((i)==0)?r0:r1) : (((i)==2)?r2:r3))   \
                           : (((i)<6) ? (((i)==4)?r4:r5) : (((i)==6)?r6:r7)))
#define REG_WR(i,v) do { ulong _v = (v);                                        \
    if ((i) < 4) { if ((i) < 2) { if ((i)==0) r0=_v; else r1=_v; }               \
                   else        { if ((i)==2) r2=_v; else r3=_v; } }              \
    else         { if ((i) < 6) { if ((i)==4) r4=_v; else r5=_v; }               \
                   else        { if ((i)==6) r6=_v; else r7=_v; } } } while (0)
#define REG_LOAD() r0=regs[0];r1=regs[1];r2=regs[2];r3=regs[3]; \
                   r4=regs[4];r5=regs[5];r6=regs[6];r7=regs[7];
#define REG_STORE() regs[0]=r0;regs[1]=r1;regs[2]=r2;regs[3]=r3; \
                    regs[4]=r4;regs[5]=r5;regs[6]=r6;regs[7]=r7;

// One VM instruction, register file in scalars. PAD_EXPR names the pad and
// CHAIN the running dependency value, so v6 and v7 share this body.
#define VM_CASE_ALU(ins, dst, src, imm)                                          \
    case CN_OP_IADD_RS: REG_WR(dst, REG_RD(dst) + (REG_RD(src) << ((ins)->shift & 3))); break; \
    case CN_OP_ISUB:    REG_WR(dst, REG_RD(dst) - REG_RD(src)); break;           \
    case CN_OP_IMUL:    REG_WR(dst, REG_RD(dst) * REG_RD(src)); break;           \
    case CN_OP_IXOR:    REG_WR(dst, REG_RD(dst) ^ REG_RD(src)); break;           \
    case CN_OP_IROR:    REG_WR(dst, ror64(REG_RD(dst), (uint)(REG_RD(src) & 63))); break; \
    case CN_OP_MIX:     REG_WR(dst, mix64(REG_RD(dst) ^ REG_RD(src), (imm))); break;

// ---------------------------------------------------------------------------
// v6: cn_vm_execute against the pad, CN_VM_ITERATIONS passes.
// ---------------------------------------------------------------------------
__kernel void cna_v6(__global ulong *b0, const ulong qw,
                     __global const cn_ins_t *progs, const uint prog_size,
                     const uint iters, __global const uchar *salt,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *pad = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    __global const cn_ins_t *prog = progs + (size_t)gid * prog_size;

    aes_fill_pad((__global uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);

    // chain-salt XOR, one linear pass over the pad cycling a 256 KB salt
    {
        uint s_off = 0;
        __global uint *p32 = (__global uint *)pad;
        const uint n32 = (uint)(qw * 2);
        for (uint i = 0; i < n32; i++) {
            uint sv = ((__global const uint *)salt)[s_off >> 2];
            p32[i] ^= sv;
            s_off += 4; if (s_off >= CN_SALT_MEMORY) s_off = 0;
        }
    }

    ulong regs[CN_REG_COUNT];
    init_regs(regs, gid);

    const ulong sp_mask = ((qw * 8) - 1) & ~7UL;
    const uint  pc_mask = prog_size - 1;

    ulong r0,r1,r2,r3,r4,r5,r6,r7;
    REG_LOAD();
    for (uint pass = 0; pass < iters; pass++) {
        uint pc = 0;
        ulong chain = 0;                      // resets per pass, as cn_vm_execute does
        for (uint step = 0; step < prog_size; step++) {
            __global const cn_ins_t *ins = &prog[pc & pc_mask];
            uint next_pc = pc + 1;
            const uchar dst = ins->dst, src = ins->src;
            const uint  imm = ins->imm;
            switch (ins->op) {
            VM_CASE_ALU(ins, dst, src, imm)
            case CN_OP_CBRANCH:
                if (REG_RD(dst) & ((ulong)imm | 1UL))
                    next_pc = (uint)((int)pc + (int)((char)ins->shift) + (int)prog_size) & pc_mask;
                break;
            case CN_OP_SP_READ: {
                ulong addr = (REG_RD(src) + (ulong)imm + chain) & sp_mask;
                ulong v = pad[addr >> 3];
                REG_WR(dst, v);
                chain = v;
                break;
            }
            case CN_OP_SP_WRITE: {
                ulong addr = (REG_RD(dst) + (ulong)imm + chain) & sp_mask;
                ulong tmp = pad[addr >> 3] ^ REG_RD(src);
                pad[addr >> 3] = tmp;
                chain += tmp;
                break;
            }
            default: break;
            }
            pc = next_pc;
        }
    }
    REG_STORE();

    ulong acc = 0;
    for (int i = 0; i < CN_REG_COUNT; i++) acc ^= regs[i];
    acc ^= aes_finalize((__global const uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);
    out[gid] = acc ? acc : 1UL;             // never 0: 0 means "kernel did not run"
}

// ---------------------------------------------------------------------------
// v7: cn_vm_execute_v7. Serial chase over a per-nonce buffer, interleaved with
// program slices; SP_WRITE goes to a small separate pad.
// ---------------------------------------------------------------------------
__kernel void cna_v7(__global ulong *b0, const ulong qw,
                     __global const cn_ins_t *progs, const uint prog_size,
                     const uint iters, __global const ushort *seg_hops_all, __global const uchar *salt,
                     __global ulong *vals_all, __global ulong *pads_all,
                     const uint hops, const uint segments, const uint pad_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *buf = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    __global const cn_ins_t *prog = progs + (size_t)gid * prog_size;
    __global const ushort *seg_hops = seg_hops_all + (size_t)gid * segments;
    // vals[] is 8 KB per nonce. It does not fit in private memory, and a real
    // GPU miner would face the same, so it lives in global memory per work-item.
    __global ulong *vals = vals_all + (size_t)gid * hops;
    __global ulong *pad  = pads_all + (size_t)gid * pad_qw;

    // cn_slow_hash_v14 AES-fills and salt-XORs only the 256 KB pad. The 24 MB
    // buffer gets a cheap splitmix fill. An earlier version of this kernel
    // AES-filled all 24 MB, which is ~96x the real AES work, and since a GPU
    // pays T-tables where a CPU pays AES-NI that phantom work dominated the
    // measurement and made v7 look far more GPU-resistant than it is.
    aes_fill_pad((__global uint *)pad, (uint)(pad_qw * 8 / 128), te0, rk, gid);
    {
        uint s_off = 0;
        __global uint *p32 = (__global uint *)pad;
        const uint n32 = pad_qw * 2;
        __global const uint *s32 = (__global const uint *)salt;
        for (uint i = 0; i < n32; i++) {
            p32[i] ^= s32[s_off >> 2];
            s_off += 4; if (s_off >= CN_SALT_MEMORY) s_off = 0;
        }
    }
    {
        ulong fx = 0x9e3779b97f4a7c15UL ^ (gid * 0x2545F4914F6CDD1DUL);
        if (fx == 0) fx = 0x9e3779b97f4a7c15UL;
        for (ulong bi = 0; bi < qw; bi++) {
            fx = (fx ^ (fx >> 29)) * 0xbf58476d1ce4e5b9UL;
            buf[bi] = fx;
        }
    }

    ulong regs[CN_REG_COUNT];
    init_regs(regs, gid);

    const ulong sp_mask   = ((ulong)(pad_qw * 8) - 1) & ~7UL;
    const uint  pc_mask   = prog_size - 1;
    const uint  seg_steps = prog_size / segments;
    ulong chain = 0;
    ulong r0,r1,r2,r3,r4,r5,r6,r7;
    REG_LOAD();

    for (uint pass = 0; pass < iters; pass++) {
        uint pc = 0, consume = 0, filled = 0, walk_pc = 0;
        ulong wchain = 0;
        for (uint seg = 0; seg < segments; seg++) {
            const uint nh = (uint)seg_hops[seg];
            for (uint h = 0; h < nh; h++) {
                __global const cn_ins_t *hop = &prog[walk_pc & pc_mask];
                const uint hop_reg = (hop->src + h) & (CN_REG_COUNT - 1);
                const ulong addr_material = REG_RD(hop_reg) + (ulong)hop->imm + chain;
                const ulong idx = mul_hi(addr_material, qw);
                const ulong v = buf[idx];
                buf[idx] = v ^ addr_material;
                chain = v + (ulong)h;
                walk_pc += 1u + (uint)(v & 3u);
                vals[filled++] = v;
            }
            for (uint step = 0; step < seg_steps; step++) {
                __global const cn_ins_t *ins = &prog[pc & pc_mask];
                uint next_pc = pc + 1;
                const uchar dst = ins->dst, src = ins->src;
                const uint  imm = ins->imm;
                switch (ins->op) {
                VM_CASE_ALU(ins, dst, src, imm)
                case CN_OP_CBRANCH:
                    if (REG_RD(dst) & ((ulong)imm | 1UL))
                        next_pc = (uint)((int)pc + (int)((char)ins->shift) + (int)prog_size) & pc_mask;
                    break;
                case CN_OP_SP_READ:
                    REG_WR(dst, REG_RD(dst) ^ (vals[consume & (hops - 1)] + (ulong)imm));
                    consume++;
                    break;
                case CN_OP_SP_WRITE: {
                    ulong addr = (REG_RD(dst) + (ulong)imm + wchain) & sp_mask;
                    ulong tmp = pad[addr >> 3] ^ REG_RD(src);
                    pad[addr >> 3] = tmp;
                    wchain += tmp;
                    break;
                }
                default: break;
                }
                pc = next_pc;
            }
        }
        r0 ^= wchain;
    }
    REG_STORE();

    ulong acc = 0;
    for (int i = 0; i < CN_REG_COUNT; i++) acc ^= regs[i];
    acc ^= aes_finalize((__global const uint *)pad, (uint)(pad_qw * 8 / 128), te0, rk, gid);
    out[gid] = acc ? acc : 1UL;
}

// ---------------------------------------------------------------------------
// v5: cn_slow_hash_v11's inner loop. No VM. An AES round plus a 64x64 multiply
// per step, and salt_pad sweeping the whole pad between steps.
// ---------------------------------------------------------------------------
__kernel void cna_v5(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *pad = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    // v5 re-reads its salt roughly 30 times per nonce, so unlike v6 it cannot
    // stream it: the 256 KB stays resident for the whole hash. Modelled.
    __global ulong *salt = salts_all + (size_t)gid * salt_qw;
    // Derive the per-nonce salt from gid. Real v5 gets it from the chain, but
    // the content does not affect timing and deriving it here means the CPU
    // reference can produce the same bytes, which is what lets the checksum
    // gate verify this kernel. About 200K ops against a hash of many millions.
    {
        ulong sx = (ulong)gid * 0x9e3779b97f4a7c15UL + 0xABCDEFUL;
        for (uint i = 0; i < salt_qw; i++) { sx = mix64(sx, i + 1u); salt[i] = sx; }
    }

    const uint xx    = 4u + params[gid * 4 + 0];
    const uint yy    = 4u + params[gid * 4 + 1];
    const uint it_n  = params[gid * 4 + 2];
    const uint d     = params[gid * 4 + 3];

    aes_fill_pad((__global uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);

    // randomize_scratchpad_256k: one BYTE every four XORed with successive
    // salt bytes, PAD/4 iterations. Not the same as v13's salt pass, which
    // XORs a full 32-bit word every four bytes.
    {
        __global uchar *sp8 = (__global uchar *)pad;
        __global const uchar *ss8 = (__global const uchar *)salt;
        uint x = 0;
        const uint nb = (uint)(qw * 8);
        for (uint i = 0; i < nb; i += 4) {
            sp8[i] ^= ss8[x++];
            if (x >= CN_SALT_MEMORY) x = 0;
        }
    }

    const ulong nblocks = qw / 2;            // 16-byte blocks
    ulong a0 = pad[0], a1 = pad[1];
    ulong b_0 = pad[2], b_1 = pad[3];
    ulong salt_acc = 0;
    // salt_pad walks the pad as BYTES with a byte stride (hp_state is uint8_t*
    // in slow-hash.h), so the sweep is PAD/offset_2 iterations. Indexing
    // 32-bit words did a quarter of the work.
    const uint salt_mask8 = (salt_qw * 8) - 1;

    for (uint k = 1; k < xx; k++) {
        for (uint l = 0; l < yy; l++) {
            // pre_aes + aesenc + post_aes_variant
            ulong j = (a0 >> 4) % nblocks;
            ulong c0 = pad[j*2], c1 = pad[j*2+1];
            // one AES round on the 16-byte block, key = a
            uint x0=(uint)c0, x1=(uint)(c0>>32), x2=(uint)c1, x3=(uint)(c1>>32);
            uint k0=(uint)a0, k1=(uint)(a0>>32), k2=(uint)a1, k3=(uint)(a1>>32);
            uint t0 = te0[x0 & 0xff] ^ ROTL32(te0[(x1>>8)&0xff],8) ^ ROTL32(te0[(x2>>16)&0xff],16) ^ ROTL32(te0[(x3>>24)&0xff],24) ^ k0;
            uint t1 = te0[x1 & 0xff] ^ ROTL32(te0[(x2>>8)&0xff],8) ^ ROTL32(te0[(x3>>16)&0xff],16) ^ ROTL32(te0[(x0>>24)&0xff],24) ^ k1;
            uint t2 = te0[x2 & 0xff] ^ ROTL32(te0[(x3>>8)&0xff],8) ^ ROTL32(te0[(x0>>16)&0xff],16) ^ ROTL32(te0[(x1>>24)&0xff],24) ^ k2;
            uint t3 = te0[x3 & 0xff] ^ ROTL32(te0[(x0>>8)&0xff],8) ^ ROTL32(te0[(x1>>16)&0xff],16) ^ ROTL32(te0[(x2>>24)&0xff],24) ^ k3;
            ulong n0 = ((ulong)t1 << 32) | t0, n1 = ((ulong)t3 << 32) | t2;
            pad[j*2]   = b_0 ^ n0;
            pad[j*2+1] = b_1 ^ n1;
            ulong j2 = (n0 >> 4) % nblocks;
            ulong p0 = pad[j2*2], p1 = pad[j2*2+1];
            ulong hi = mul_hi(n0, p0), lo = n0 * p0;
            a0 += hi; a1 += lo;
            pad[j2*2] = a0; pad[j2*2+1] = a1;
            a0 ^= p0; a1 ^= p1;
            b_0 = n0; b_1 = n1;

            // salt_pad: a strided sweep of the whole pad against the salt.
            // The 200-byte extra_hash is replaced by a mix64 chain of the same
            // call count; measured at well under 1% of a nonce.
            salt_acc = mix64(salt_acc ^ a0, (uint)(k * 31u + l));
            uint off1 = ((uint)(salt_acc & 63)) + 1u;
            uint off2 = (((uint)(salt_acc >> 8) * off1) % 125u) + 4u;
            uint sx = 0;
            __global uchar *p8 = (__global uchar *)pad;
            __global const uchar *s8 = (__global const uchar *)salt;
            const uint nbytes = (uint)(qw * 8);
            for (uint jj = off1; jj < nbytes; jj += off2) {
                p8[jj] ^= s8[sx & salt_mask8];
                sx++;
            }
        }
    }
    for (uint i = 0; i < it_n; i++) {
        ulong j = (a0 >> 4) % nblocks;
        ulong c0 = pad[j*2], c1 = pad[j*2+1];
        uint x0=(uint)c0, x1=(uint)(c0>>32), x2=(uint)c1, x3=(uint)(c1>>32);
        uint k0=(uint)a0, k1=(uint)(a0>>32), k2=(uint)a1, k3=(uint)(a1>>32);
        uint t0 = te0[x0 & 0xff] ^ ROTL32(te0[(x1>>8)&0xff],8) ^ ROTL32(te0[(x2>>16)&0xff],16) ^ ROTL32(te0[(x3>>24)&0xff],24) ^ k0;
        uint t1 = te0[x1 & 0xff] ^ ROTL32(te0[(x2>>8)&0xff],8) ^ ROTL32(te0[(x3>>16)&0xff],16) ^ ROTL32(te0[(x0>>24)&0xff],24) ^ k1;
        uint t2 = te0[x2 & 0xff] ^ ROTL32(te0[(x3>>8)&0xff],8) ^ ROTL32(te0[(x0>>16)&0xff],16) ^ ROTL32(te0[(x1>>24)&0xff],24) ^ k2;
        uint t3 = te0[x3 & 0xff] ^ ROTL32(te0[(x0>>8)&0xff],8) ^ ROTL32(te0[(x1>>16)&0xff],16) ^ ROTL32(te0[(x2>>24)&0xff],24) ^ k3;
        ulong n0 = ((ulong)t1 << 32) | t0, n1 = ((ulong)t3 << 32) | t2;
        pad[j*2]   = b_0 ^ n0;
        pad[j*2+1] = b_1 ^ n1;
        ulong j2 = (n0 >> 4) % nblocks;
        ulong p0 = pad[j2*2], p1 = pad[j2*2+1];
        ulong hi = mul_hi(n0, p0), lo = n0 * p0;
        a0 += hi; a1 += lo;
        pad[j2*2] = a0; pad[j2*2+1] = a1;
        a0 ^= p0; a1 ^= p1;
        b_0 = n0; b_1 = n1;
    }
    (void)d;
    ulong acc = a0 ^ a1 ^ b_0 ^ b_1 ^ salt_acc;
    acc ^= aes_finalize((__global const uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);
    out[gid] = acc ? acc : 1UL;
}



// What a perfect JIT would emit for v6: straight-line code, registers in
// registers, no instruction fetch, no switch dispatch, no register select
// trees. Same step count (prog_size x iters), same pad, same dependency
// chain, and an op mix matching the generator's average (9 memory and 7 ALU
// per 16, so 56%, against the generator's 51-63%).
//
// Ratio cna_v6 / cna_v6_ideal is an UPPER BOUND on JIT headroom, and a loose
// one: it assumes an attacker gets compile-time specialisation per nonce,
// which on a GPU is hard because work-items in a warp share an instruction
// stream and every nonce has a different program. Read it as "no JIT can
// beat this", not as "a JIT will achieve this".
//
// The previous attempt at this measurement swapped pad accesses for mix64 and
// was meaningless: mix64 is nine dependent ops, so it priced a memory access
// against comparable ALU work rather than against nothing, and it left the
// fetch and dispatch (the things a JIT actually removes) in place.
__kernel void cna_v6_ideal(__global ulong *b0, const ulong qw,
                           __global const cn_ins_t *progs, const uint prog_size,
                           const uint iters, __global const uchar *salt,
                           __constant uint *te0, __constant uint *rk,
                           __global ulong *out, __global ulong *b1, __global ulong *b2,
                           __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *pad = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);

    aes_fill_pad((__global uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);
    {
        uint s_off = 0;
        __global uint *p32 = (__global uint *)pad;
        const uint n32 = (uint)(qw * 2);
        __global const uint *s32 = (__global const uint *)salt;
        for (uint i = 0; i < n32; i++) {
            p32[i] ^= s32[s_off >> 2];
            s_off += 4; if (s_off >= CN_SALT_MEMORY) s_off = 0;
        }
    }

    ulong regs[CN_REG_COUNT];
    init_regs(regs, gid);
    ulong r0=regs[0],r1=regs[1],r2=regs[2],r3=regs[3];
    ulong r4=regs[4],r5=regs[5],r6=regs[6],r7=regs[7];

    const ulong sp_mask = ((qw * 8) - 1) & ~7UL;
    const uint groups = prog_size / 16;

    for (uint pass = 0; pass < iters; pass++) {
        ulong chain = 0;
        for (uint g = 0; g < groups; g++) {
            ulong a, v, t;
            // 9 memory ops, same read/write ratio and dependency chain as the
            // generator produces (~55% of memory ops are reads)
            a = (r1 + 0x1234u + chain) & sp_mask; v = pad[a>>3]; r0 = v; chain = v;
            a = (r2 + 0x2345u + chain) & sp_mask; v = pad[a>>3]; r1 = v; chain = v;
            a = (r3 + 0x3456u + chain) & sp_mask; t = pad[a>>3] ^ r4; pad[a>>3] = t; chain += t;
            a = (r5 + 0x4567u + chain) & sp_mask; v = pad[a>>3]; r2 = v; chain = v;
            a = (r6 + 0x5678u + chain) & sp_mask; t = pad[a>>3] ^ r7; pad[a>>3] = t; chain += t;
            a = (r0 + 0x6789u + chain) & sp_mask; v = pad[a>>3]; r3 = v; chain = v;
            a = (r4 + 0x789Au + chain) & sp_mask; t = pad[a>>3] ^ r1; pad[a>>3] = t; chain += t;
            a = (r7 + 0x89ABu + chain) & sp_mask; v = pad[a>>3]; r5 = v; chain = v;
            a = (r2 + 0x9ABCu + chain) & sp_mask; t = pad[a>>3] ^ r6; pad[a>>3] = t; chain += t;
            // 7 ALU ops, one of each kind the generator emits
            r4 += r5 << 2;
            r6 -= r7;
            r0 *= r1;
            r2 ^= r3;
            r5 = ror64(r5, (uint)(r6 & 63));
            r7 = mix64(r7 ^ r0, 0xABCDu);
            if (r3 & 0x5Au) r1 += r2;          // stands in for CBRANCH
        }
    }

    ulong acc = r0^r1^r2^r3^r4^r5^r6^r7;
    acc ^= aes_finalize((__global const uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);
    out[gid] = acc ? acc : 1UL;
}


// ---------------------------------------------------------------------------
// v5 salt_pad sweep, written two ways, to bound how much an optimising GPU
// miner could gain over the naive mapping used in cna_v5.
//
// The sweep is the only part of v5 with NO loop-carried dependency, so it is
// the only part anyone can restructure. cna_v5 does it the obvious way: one
// work-item per nonce, one BYTE read-modify-write per hit. A miner would
// instead coalesce every hit that lands in the same 8-byte word into a single
// load and store. Both kernels apply exactly the same XORs to the same bytes,
// so the ratio is a clean speedup figure and the outputs can be compared.
//
// This matters only for v5. v6 and v7 chain every pad access to the previous
// one's value, so nothing can be reordered and one work-item per nonce is
// already optimal for them.
// ---------------------------------------------------------------------------
__kernel void sweep_naive(__global uchar *pads, const ulong padbytes,
                          __global const uchar *salt, const uint nsweeps,
                          __global ulong *out)
{
    const size_t gid = get_global_id(0);
    __global uchar *p8 = pads + (size_t)gid * padbytes;
    for (uint s = 0; s < nsweeps; s++) {
        const uint off1 = 1u + (uint)((gid * 7u + s * 13u) & 63u);
        const uint off2 = (uint)(((gid * 31u + s * 17u) % 125u)) + 4u;
        uint sx = 0;
        for (ulong jj = off1; jj < padbytes; jj += off2)
            p8[jj] ^= salt[sx++ & (CN_SALT_MEMORY - 1)];
    }
    ulong acc = 0;
    for (int i = 0; i < 8; i++) acc ^= p8[i * 977];
    out[gid] = acc | 1UL;
}

__kernel void sweep_vec(__global uchar *pads, const ulong padbytes,
                        __global const uchar *salt, const uint nsweeps,
                        __global ulong *out)
{
    const size_t gid = get_global_id(0);
    __global uchar *p8 = pads + (size_t)gid * padbytes;
    __global ulong *p64 = (__global ulong *)p8;
    for (uint s = 0; s < nsweeps; s++) {
        const uint off1 = 1u + (uint)((gid * 7u + s * 13u) & 63u);
        const uint off2 = (uint)(((gid * 31u + s * 17u) % 125u)) + 4u;
        uint sx = 0;
        ulong jj = off1;
        while (jj < padbytes) {
            const ulong w = jj >> 3;
            ulong v = p64[w];
            // fold every hit inside this 8-byte word into one load/store
            while ((jj >> 3) == w && jj < padbytes) {
                v ^= ((ulong)salt[sx++ & (CN_SALT_MEMORY - 1)]) << ((jj & 7u) * 8u);
                jj += off2;
            }
            p64[w] = v;
        }
    }
    ulong acc = 0;
    for (int i = 0; i < 8; i++) acc ^= p8[i * 977];
    out[gid] = acc | 1UL;
}

)CLC";
