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
// FP64 is an optional OpenCL feature. Guarded rather than assumed: a device
// without it must still build the v5/v6/v7 kernels, so the FP kernels simply
// do not exist there and main.cpp skips those rows instead of the whole
// program failing to build.
#if defined(cl_khr_fp64)
#  pragma OPENCL EXTENSION cl_khr_fp64 : enable
#  define CN_HAVE_FP64 1
#elif defined(cl_amd_fp64)
#  pragma OPENCL EXTENSION cl_amd_fp64 : enable
#  define CN_HAVE_FP64 1
#endif

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



// ---------------------------------------------------------------------------
// PLAN-v8 Phase 2: the floating-point stage, ported from src/crypto/slow-hash-fp.h.
// That file and the CN_FP_STAGE() hook have left the tree; both are at tag
// archive/cna-v8-fp-stage. This port and vm_ref.h's twin are self-contained
// and kept as the evidence behind FINDINGS F37.
//
// Runs once per nonce, between the xx/yy loop and the iters loop, exactly
// where CN_FP_STAGE() sat in slow-hash-v8-impl.h. Seeded from a and two pad
// lines, folded back into both pad lines and a. 9,600 rounds of five
// operations, with the rounding mode reselected from data every sixteenth
// round.
//
// THE POINT OF THIS KERNEL. OpenCL cannot change the rounding mode at all:
// round-to-nearest-even is the only mode for arithmetic,
// cl_khr_select_fprounding_mode was deprecated in OpenCL 1.1 and no current
// vendor implements it, and only the convert_* builtins take a rounding
// suffix. So the three kernels below separate the two costs that argument
// turns on. cna_v8 is the baseline, cna_v8_fp_rne adds the arithmetic at fixed
// nearest-even, and cna_v8_fp adds the data-driven rounding an OpenCL miner
// would actually have to produce. The gap between the last two is what a
// rounding mode costs a GPU; a CPU pays one MXCSR or FPCR write.
// ---------------------------------------------------------------------------
#ifdef CN_HAVE_FP64

#define CN_V8_FP_ROUNDS      9600
#define CN_V8_FP_ROUND_MASK  15

// RandomX constExponentBits = 0x300: sign cleared, top three exponent bits
// forced to 011, so every value is a positive normal in [2^-255, 2).
static inline double fp_bits_to_e(ulong bits)
{
    const ulong e = 0x300UL | ((bits >> 52) & 0xFFUL);
    return as_double((e << 52) | (bits & 0x000FFFFFFFFFFFFFUL));
}

// One ULP toward +inf (dir > 0) or -inf (dir < 0). The zero case cannot arise
// from this stage's operands but is handled rather than assumed away, since
// getting it wrong would produce a NaN from a bit pattern rather than a wrong
// number, and the checksum gate would report it as drift.
static inline double fp_nudge(double x, int dir)
{
    ulong b = as_ulong(x);
    if ((b << 1) == 0UL)
        return dir > 0 ? as_double(1UL) : as_double(0x8000000000000001UL);
    const int neg = (int)(b >> 63);
    if ((dir > 0) == (neg != 0)) b -= 1UL;
    else                         b += 1UL;
    return as_double(b);
}

// esign is the sign of (exact result - r), where r is the nearest-even result.
// The exact value lies between two adjacent doubles and r is one of them, so
// the directed result is either r or its neighbour on the side esign names.
// mode indexes cn_fp_modes in slow-hash-fp.h: 0 nearest, 1 down, 2 up, 3 zero.
static inline double fp_apply(double r, int esign, int mode)
{
    if (mode == 0 || esign == 0) return r;
    const int want = (mode == 1) ? -1
                   : (mode == 2) ?  1
                   : (((as_ulong(r) >> 63) != 0UL) ? 1 : -1);
    return (want == esign) ? fp_nudge(r, esign) : r;
}

static inline int fp_esign(double err)
{
    return (err == 0.0) ? 0 : (((as_ulong(err) >> 63) != 0UL) ? -1 : 1);
}

// The five operations under an arbitrary IEEE rounding mode. Each recovers the
// exact residual of the nearest-even result: 2Sum for add and subtract, and a
// single fma for multiply, divide and square root. Those identities need the
// residual to be representable, which the group-E constraint guarantees here:
// operands live in [2^-255, 2), so no sum, product, quotient or residual can
// overflow or reach a subnormal.
//
// Written branch-free on purpose. A per-lane switch on the mode would diverge
// across a warp and inflate the cost, and a miner would not write that. Giving
// the GPU the strongest implementation is the conservative choice when the
// number is going to be used to argue about GPU resistance.
static inline double fp_add_m(double a, double b, int mode)
{
    const double s   = a + b;
    const double bb  = s - a;
    const double err = (a - (s - bb)) + (b - bb);
    return fp_apply(s, fp_esign(err), mode);
}

static inline double fp_mul_m(double a, double b, int mode)
{
    const double p = a * b;
    return fp_apply(p, fp_esign(fma(a, b, -p)), mode);
}

static inline double fp_div_m(double a, double b, int mode)
{
    const double q = a / b;
    // exact a - q*b; sign(exact quotient - q) = sign(residual) * sign(b)
    int es = fp_esign(fma(-q, b, a));
    if ((as_ulong(b) >> 63) != 0UL) es = -es;
    return fp_apply(q, es, mode);
}

static inline double fp_sqrt_m(double a, int mode)
{
    const double s = sqrt(a);
    return fp_apply(s, fp_esign(fma(-s, s, a)), mode);
}

// The round body, twice: once on native nearest-even arithmetic and once on
// the emulated modes. Both constrain every result before anything reads it,
// which is what makes fma contraction structurally impossible here as well as
// on the CPU: no multiply result is ever consumed by an add.
#define CN_FP_ROUND_RNE(e)                                  \
    e[0] = fp_bits_to_e(as_ulong(e[0] + e[1]));             \
    e[1] = fp_bits_to_e(as_ulong(e[1] - e[2]));             \
    e[2] = fp_bits_to_e(as_ulong(e[2] * e[3]));             \
    e[3] = fp_bits_to_e(as_ulong(e[3] / e[0]));             \
    e[0] = fp_bits_to_e(as_ulong(sqrt(e[0])));

#define CN_FP_ROUND_MODE(e, M)                              \
    e[0] = fp_bits_to_e(as_ulong(fp_add_m(e[0],  e[1], M))); \
    e[1] = fp_bits_to_e(as_ulong(fp_add_m(e[1], -e[2], M))); \
    e[2] = fp_bits_to_e(as_ulong(fp_mul_m(e[2],  e[3], M))); \
    e[3] = fp_bits_to_e(as_ulong(fp_div_m(e[3],  e[0], M))); \
    e[0] = fp_bits_to_e(as_ulong(fp_sqrt_m(e[0],      M)));

// emulate = 0: fixed nearest-even, which is all OpenCL can express natively.
// emulate = 1: the algorithm as specified, modes selected from data.
static void cn_fp_stage_cl(__global ulong *pad, ulong nblocks,
                           ulong *pa0, ulong *pa1, const int emulate,
                           const uint rounds)
{
    const ulong mask = nblocks - 1UL;
    const ulong a0 = *pa0, a1 = *pa1;
    __global ulong *p0 = pad + ((a0 >> 4) & mask) * 2UL;
    __global ulong *p1 = pad + ((a1 >> 4) & mask) * 2UL;
    double e[4];

    e[0] = fp_bits_to_e(p0[0]);
    e[1] = fp_bits_to_e(p0[1]);
    e[2] = fp_bits_to_e(p1[0] ^ a0);
    e[3] = fp_bits_to_e(p1[1] ^ a1);

    if (emulate) {
        int mode = 0;
        for (uint r = 0; r < rounds; r++) {
            if ((r & CN_V8_FP_ROUND_MASK) == 0)
                mode = (int)((as_ulong(e[0]) >> 3) & 3UL);
            CN_FP_ROUND_MODE(e, mode)
        }
    } else {
        for (uint r = 0; r < rounds; r++) {
            CN_FP_ROUND_RNE(e)
        }
    }

    // p1 before p0, matching slow-hash-fp.h, so a j0 == j1 collision resolves
    // the same way on both sides.
    p1[0] ^= as_ulong(e[2]);
    p1[1] ^= as_ulong(e[1]);
    p0[0] ^= as_ulong(e[0]);
    p0[1] ^= as_ulong(e[3]);

    *pa0 = a0 ^ as_ulong(e[0]) ^ as_ulong(e[2]);
    *pa1 = a1 ^ as_ulong(e[1]) ^ as_ulong(e[3]);
}

#endif /* CN_HAVE_FP64 */

// ---------------------------------------------------------------------------
// v8: v5 with salt_pad's hash selector widened from a % 3 to a & 3, plus the
// Phase 2 FP stage. The selector change is invisible here because the model
// replaces extra_hash with a mix64 chain of equal call count, so cna_v8 with
// fp_mode -1 computes what cna_v5 computes. That is deliberate: the "v5 1MB"
// and "v8 1MB" rows are then the same work through two separate code paths,
// which is the control that catches the dead FP code costing registers and
// occupancy in the baseline. If those two rows disagree, the ratios below are
// measuring the port rather than the algorithm.
//
// One body, three kernels, so the FP rows cannot drift from the baseline they
// are divided by. fp_mode is a compile-time constant at each call site, so the
// unused path is dead code in every one of them.
// ---------------------------------------------------------------------------
static void cna_core(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf,
                     const int fp_mode, const uint fp_rounds, const int no_sweep)
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
            //
            // D1 DELETED ALL OF THIS from consensus on 2026-10-07, dbd4fd7.
            // no_sweep is a literal at every call site, so the compiler drops
            // this block from cna_v8_d1 and leaves cna_v8 exactly as it was.
            if (!no_sweep) {
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
    }
#ifdef CN_HAVE_FP64
    // CN_FP_STAGE() in slow-hash-v8-impl.h sits here, between the xx/yy loop
    // and the iters loop, and runs once per nonce.
    if (fp_mode >= 0) cn_fp_stage_cl(pad, nblocks, &a0, &a1, fp_mode, fp_rounds);
#else
    (void)fp_mode; (void)fp_rounds;
#endif

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

// v8 AS SHIPPED, post-D1. Identical to cna_v8 with the salt_pad sweep and its
// mix64 stand-in removed, which is what commit dbd4fd7 did to consensus on
// 2026-10-07. Added because every GPU figure this project has published was
// taken against cna_v8, which models an algorithm that no longer exists: the
// sweeps were 23.9% of a nonce (F57) and are the part F59 found to be
// AES-neutral, so leaving them in understates v8's current GPU resistance.
//
// It is a separate kernel rather than an edit to cna_v8 so that one run gives
// both and the delta is within-run, which F63 section 3 establishes is the only
// form that transfers between machines.

// ---------------------------------------------------------------------------
// LOCAL-MEMORY AES. Generated from the three functions above by substituting
// the table's address space; nothing else differs, which is the point.
//
// WHY. F77 published B3 at 64.9x as an upper bound because the AES table above
// lives in __constant, where a warp's divergent lookups serialise. t_aes then
// measured that placement alone: staging the same table into __local makes the
// RTX 3050 **19.2x faster** at AES and brings it to **1.04x of a 7950X's
// AES-NI at 30 threads**, which is parity. So the constant-memory table was
// most of the 64.9x.
//
// This arm exists to turn that composition into a measurement of a whole v8
// nonce. The constant-memory kernels above are untouched so the comparison is
// within-run, and the checksum gate validates this arm against the same CPU
// reference as every other.
// ---------------------------------------------------------------------------
static void aes_fill_pad_lds(__global uint *buf, uint iters,
                         __local uint *te0, __constant uint *rk, ulong gid)
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

static ulong aes_finalize_lds(__global const uint *buf, uint iters,
                          __local uint *te0, __constant uint *rk, ulong gid)
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

static void cna_core_lds(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __local uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf,
                     const int fp_mode, const uint fp_rounds, const int no_sweep)
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

    aes_fill_pad_lds((__global uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);

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
            //
            // D1 DELETED ALL OF THIS from consensus on 2026-10-07, dbd4fd7.
            // no_sweep is a literal at every call site, so the compiler drops
            // this block from cna_v8_d1 and leaves cna_v8 exactly as it was.
            if (!no_sweep) {
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
    }
#ifdef CN_HAVE_FP64
    // CN_FP_STAGE() in slow-hash-v8-impl.h sits here, between the xx/yy loop
    // and the iters loop, and runs once per nonce.
    if (fp_mode >= 0) cn_fp_stage_cl(pad, nblocks, &a0, &a1, fp_mode, fp_rounds);
#else
    (void)fp_mode; (void)fp_rounds;
#endif

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
    acc ^= aes_finalize_lds((__global const uint *)pad, (uint)(qw * 8 / 128), te0, rk, gid);
    out[gid] = acc ? acc : 1UL;
}

__kernel void cna_v8_d1_lds(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf,
                     const uint fp_rounds)
{
    __local uint T[256];
    const size_t lid = get_local_id(0), lsz = get_local_size(0);
    for (size_t i = lid; i < 256; i += lsz) T[i] = te0[i];
    barrier(CLK_LOCAL_MEM_FENCE);
    cna_core_lds(b0, qw, params, salts_all, salt_qw, T, rk, out, b1, b2, b3, per_buf,
             -1, fp_rounds, 1);
}

__kernel void cna_v8_d1(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf,
                     const uint fp_rounds)
{
    cna_core(b0, qw, params, salts_all, salt_qw, te0, rk, out, b1, b2, b3, per_buf,
             -1, fp_rounds, 1);
}

__kernel void cna_v8(__global ulong *b0, const ulong qw,
                     __global const uchar *params, __global ulong *salts_all,
                     const uint salt_qw,
                     __constant uint *te0, __constant uint *rk,
                     __global ulong *out, __global ulong *b1, __global ulong *b2,
                     __global ulong *b3, const uint per_buf,
                     const uint fp_rounds)
{
    cna_core(b0, qw, params, salts_all, salt_qw, te0, rk, out, b1, b2, b3, per_buf,
             -1, fp_rounds, 0);
}

#ifdef CN_HAVE_FP64
__kernel void cna_v8_fp_rne(__global ulong *b0, const ulong qw,
                            __global const uchar *params, __global ulong *salts_all,
                            const uint salt_qw,
                            __constant uint *te0, __constant uint *rk,
                            __global ulong *out, __global ulong *b1, __global ulong *b2,
                            __global ulong *b3, const uint per_buf,
                            const uint fp_rounds)
{
    cna_core(b0, qw, params, salts_all, salt_qw, te0, rk, out, b1, b2, b3, per_buf,
             0, fp_rounds, 0);
}

__kernel void cna_v8_fp(__global ulong *b0, const ulong qw,
                        __global const uchar *params, __global ulong *salts_all,
                        const uint salt_qw,
                        __constant uint *te0, __constant uint *rk,
                        __global ulong *out, __global ulong *b1, __global ulong *b2,
                        __global ulong *b3, const uint per_buf,
                        const uint fp_rounds)
{
    cna_core(b0, qw, params, salts_all, salt_qw, te0, rk, out, b1, b2, b3, per_buf,
             1, fp_rounds, 0);
}
#endif /* CN_HAVE_FP64 */

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
