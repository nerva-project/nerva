#pragma once
// Memory-hard core of each CNA variant, one work-item per nonce.
// v5/v6 fill with real AES (10 rounds/block, 8 blocks, PAD/128 iterations) as
// aes_pseudo_round does. v7 fills with splitmix, which is what it actually uses.
static const char *KERNEL_SRC = R"CLC(
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32-(n))))

// Pads are spread over up to 4 buffers because CL_DEVICE_MAX_MEM_ALLOC_SIZE is
// often a quarter of VRAM or less (1 GB on a 4 GB 1050 Ti, 2 GB on an 8 GB
// 3050). Holding everything in ONE allocation capped those cards to a handful
// of nonces, starved the GPU of parallelism, and made whichever variant had
// the biggest pad look artificially resistant. A real miner would just
// allocate several buffers, so the harness does too. per_buf is uniform, so
// the buffer index is a plain divide.
#define PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3)                    \
    ( ((gid) / (per_buf)) == 0 ? (b0) + ((gid) % (per_buf)) * (qw) :  \
      ((gid) / (per_buf)) == 1 ? (b1) + ((gid) % (per_buf)) * (qw) :  \
      ((gid) / (per_buf)) == 2 ? (b2) + ((gid) % (per_buf)) * (qw) :  \
                                 (b3) + ((gid) % (per_buf)) * (qw) )

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

__kernel void chase_v7(__global ulong *b0, const ulong qw, const uint passes,
                       const uint hops, __constant uint *te0, __constant uint *rk,
                       __global ulong *out, __global ulong *b1, __global ulong *b2,
                       __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *buf = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    ulong fx = 0x9e3779b97f4a7c15UL ^ (gid * 0x2545F4914F6CDD1DUL);
    for (ulong i = 0; i < qw; i++) { fx = (fx ^ (fx >> 29)) * 0xbf58476d1ce4e5b9UL; buf[i] = fx; }
    ulong chain = fx, reg = fx ^ 0x1234567UL;
    for (uint p = 0; p < passes; p++)
        for (uint h = 0; h < hops; h++) {
            ulong am = reg + (ulong)h + chain;
            ulong idx = mul_hi(am, qw);
            ulong v = buf[idx];
            buf[idx] = v ^ am;
            chain = v + (ulong)h;
            reg ^= v;
        }
    out[gid] = chain ^ reg;
}

__kernel void chase_v6(__global ulong *b0, const ulong qw, const uint steps,
                       const uint fill_iters, __constant uint *te0, __constant uint *rk,
                       __global ulong *out, __global ulong *b1, __global ulong *b2,
                       __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *buf = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    aes_fill_pad((__global uint *)buf, fill_iters, te0, rk, gid);
    // mul_hi maps uniformly into [0,qw) for ANY qw. The old (qw-1) mask needed
    // a power-of-two pad, which the 1.25 and 1.5 MB sweep points are not; a
    // mask there would have quietly confined every access to the low 1 MB and
    // made the bigger pad look free. Used for v5 and v6 alike so the whole
    // sweep indexes the same way and the rows stay comparable.
    ulong chain = 0, reg = buf[0];
    for (uint s = 0; s < steps; s++) {
        ulong addr = mul_hi(reg + (ulong)s + chain, qw);
        ulong v = buf[addr];
        if ((s & 7u) < 3u) { buf[addr] = v ^ reg; chain += v ^ reg; }
        else               { chain = v; }
        reg += v;
    }
    out[gid] = chain ^ reg;
}

__kernel void chase_v5(__global ulong *b0, const ulong qw, const uint steps,
                       const uint fill_iters, __constant uint *te0, __constant uint *rk,
                       __global ulong *out, __global ulong *b1, __global ulong *b2,
                       __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *buf = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    aes_fill_pad((__global uint *)buf, fill_iters, te0, rk, gid);
    ulong a = buf[0], b = buf[1];
    for (uint s = 0; s < steps; s++) {
        ulong addr = mul_hi(a, qw);          // see chase_v6 on why not a mask
        ulong v = buf[addr];
        ulong t = v ^ b;
        buf[addr] = t;
        b = v;
        a = t + (a >> 3);
    }
    out[gid] = a ^ b;
}
// ---- proposal: 256 KB pad (L2-resident on any CPU), AES inside the dependency
// chain. Every step: dependent load, one AES round, store back. A CPU uses
// AES-NI; a GPU must emulate with T-tables and cannot cache the pad.
__kernel void chase_v8(__global ulong *b0, const ulong qw, const uint steps,
                       const uint fill_iters, __constant uint *te0, __constant uint *rk,
                       __global ulong *out, __global ulong *b1, __global ulong *b2,
                       __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *buf = PICK_BUF(gid, per_buf, qw, b0, b1, b2, b3);
    aes_fill_pad((__global uint *)buf, fill_iters, te0, rk, gid);

    const ulong blocks = qw / 2;              // 16-byte blocks
    uint a0 = (uint)buf[0], a1 = (uint)(buf[0] >> 32);
    uint a2 = (uint)buf[1], a3 = (uint)(buf[1] >> 32);
    ulong chain = buf[0];

    for (uint s = 0; s < steps; s++) {
        ulong idx = (chain ^ (ulong)s) % blocks;
        __global uint *blk = (__global uint *)(buf + idx * 2);
        uint b0 = blk[0], b1 = blk[1], b2 = blk[2], b3 = blk[3];
        a0 ^= b0; a1 ^= b1; a2 ^= b2; a3 ^= b3;
        uint t0 = te0[a0 & 0xff] ^ ROTL32(te0[(a1>>8)&0xff],8) ^ ROTL32(te0[(a2>>16)&0xff],16) ^ ROTL32(te0[(a3>>24)&0xff],24) ^ rk[0];
        uint t1 = te0[a1 & 0xff] ^ ROTL32(te0[(a2>>8)&0xff],8) ^ ROTL32(te0[(a3>>16)&0xff],16) ^ ROTL32(te0[(a0>>24)&0xff],24) ^ rk[1];
        uint t2 = te0[a2 & 0xff] ^ ROTL32(te0[(a3>>8)&0xff],8) ^ ROTL32(te0[(a0>>16)&0xff],16) ^ ROTL32(te0[(a1>>24)&0xff],24) ^ rk[2];
        uint t3 = te0[a3 & 0xff] ^ ROTL32(te0[(a0>>8)&0xff],8) ^ ROTL32(te0[(a1>>16)&0xff],16) ^ ROTL32(te0[(a2>>24)&0xff],24) ^ rk[3];
        blk[0] = t0; blk[1] = t1; blk[2] = t2; blk[3] = t3;
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        chain = ((ulong)t1 << 32) | t0;       // next address depends on the AES output
    }
    out[gid] = chain ^ (((ulong)a3 << 32) | a2);
}
// ---- v7b (mmokhi, parked): shared READ-ONLY dataset + 256 KB per-nonce pad.
// No memory cap on nonce count. Defence is per-nonce program divergence, so
// the program slices with their data-dependent branches are the point.
__kernel void chase_v7b(__global ulong *b0, const ulong pad_qw,
                        __global const ulong *dataset, const ulong ds_qw,
                        const uint passes, __constant uint *te0, __constant uint *rk,
                        __global ulong *out, __global ulong *b1, __global ulong *b2,
                        __global ulong *b3, const uint per_buf)
{
    const size_t gid = get_global_id(0);
    __global ulong *pad = PICK_BUF(gid, per_buf, pad_qw, b0, b1, b2, b3);
    const ulong pad_mask = pad_qw - 1;

    // per-nonce program: 64 slots, opcode and operands from the nonce seed
    uchar op[64], dst[64], src[64]; uint imm[64];
    uint r = (uint)gid * 2654435761u + 12345u;
    for (int i = 0; i < 64; i++) {
        r ^= r << 13; r ^= r >> 17; r ^= r << 5;
        op[i]  = (uchar)(r % 7u);
        dst[i] = (uchar)((r >> 8) & 7u);
        src[i] = (uchar)((r >> 12) & 7u);
        imm[i] = r;
    }
    ulong regs[8];
    for (int i = 0; i < 8; i++) { r ^= r << 13; r ^= r >> 17; r ^= r << 5; regs[i] = (ulong)r * 0x9e3779b97f4a7c15UL; }

    ulong chain = regs[0], wchain = 0;
    for (uint p = 0; p < passes; p++) {
        int pc = 0;
        for (int seg = 0; seg < 8; seg++) {
            chain ^= regs[seg & 7];
            for (int h = 0; h < 128; h++) {           // serial chase over the shared dataset
                ulong idx = mul_hi(chain, ds_qw);
                ulong v = dataset[idx];
                chain = v + (ulong)h;
            }
            for (int s = 0; s < 8; s++) {             // program slice: this is the divergence
                int i = pc & 63;
                uchar o = op[i]; uchar d = dst[i]; uchar sc = src[i];
                if (o == 0) regs[d] += regs[sc] << (imm[i] & 3);
                else if (o == 1) regs[d] -= regs[sc];
                else if (o == 2) regs[d] *= regs[sc];
                else if (o == 3) regs[d] ^= regs[sc];
                else if (o == 4) regs[d] = rotate(regs[d], (ulong)(regs[sc] & 63));
                else if (o == 5) { if (regs[d] & ((ulong)imm[i] | 1UL)) pc += (int)(imm[i] & 7) - 4; }
                else { ulong a2 = (regs[d] + chain) & pad_mask; ulong t = pad[a2] ^ regs[sc];
                       pad[a2] = t; wchain += t; }
                pc++;
            }
        }
    }
    out[gid] = chain ^ wchain ^ regs[0];
}

)CLC";
