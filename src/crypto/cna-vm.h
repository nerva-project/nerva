// Copyright (c) 2018-2026, The Nerva Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <stdint.h>
#include <stddef.h>

// CryptoNight-Adaptive v6 virtual machine for HF13 (pool-resistant + ASIC/GPU-resistant).
//
// The VM generates a random program per block from a chain-rooted seed,
// then executes it against an 8 MB scratchpad.  Combining random code
// execution (defeats fixed ASIC circuits) with a large scratchpad
// (kills GPU occupancy) while keeping the blockchain-DB seed dependency
// that makes pool mining architecturally impossible.

// Must be a power of 2 so pc wrapping works with a bitmask.
#define CN_PROGRAM_SIZE    512
#define CN_REG_COUNT       8
#define CN_VM_ITERATIONS   2048

// CNA v7 (HF14): the memory-hard work is a strictly serial chase over a
// per-nonce buffer that the walk writes back to as it goes. The buffer is
// filled cheaply from the per-nonce seed, and the chase covers ~63% of it and
// mutates every cell it touches, so touched cells diverge from the fill and
// the buffer cannot be regenerated on the fly: a miner is forced to keep the
// whole thing resident. That caps how many nonces a GPU/ASIC can hold at once
// (one buffer each), the way v6's 8 MB pad did, while the chase itself stays
// DRAM-latency-bound so a small board keeps pace with a desktop: one box ~ one
// vote. Per pass, CN_V7_SEGMENTS segments of [CN_V7_HOPS / CN_V7_SEGMENTS
// serial hops, then a program slice], each segment gated on a register the
// program just mutated so the walk cannot advance without executing the
// per-nonce random program (the GPU/ASIC barrier, same class as v6). All
// values consensus-critical.
#define CN_V7_HOPS           1024
#define CN_V7_SEGMENTS       8
// Per-nonce chase buffer: 24 MB. Big enough to spill any commodity L3 (so the
// chase is DRAM-latency-bound, not cache/clock-bound) and to starve a GPU of
// parallel nonces (VRAM / 24 MB), small enough to keep block verify ~0.3-0.5 s.
#define CN_V7_BUFFER         (24 * 1024 * 1024)
// v14 pass count = buffer qwords / hops-per-pass, so the chase touches ~63% of
// the buffer. That coverage is what forces full residency: below it a
// checkpoint attacker could store the buffer sparsely and recompute the rest.
// Verify lands ~0.3-0.5 s/hash, roughly equal on every box since the chase is
// DRAM-latency-bound. v13 keeps CN_VM_ITERATIONS.
#define CN_VM_ITERATIONS_V14 (CN_V7_BUFFER / (8 * CN_V7_HOPS))

// Instruction opcodes — kept small so the opcode byte fits in uint8_t.
typedef enum {
    CN_OP_IADD_RS   = 0,  // r[dst] += r[src] << (shift & 3)
    CN_OP_ISUB      = 1,  // r[dst] -= r[src]
    CN_OP_IMUL      = 2,  // r[dst] *= r[src]  (lower 64 bits)
    CN_OP_IXOR      = 3,  // r[dst] ^= r[src]
    CN_OP_IROR      = 4,  // r[dst] = ror64(r[dst], r[src] & 63)
    CN_OP_CBRANCH   = 5,  // if (r[dst] & (imm|1)) pc = (pc + shift) % SIZE
    CN_OP_SP_READ   = 6,  // r[dst] = scratchpad[(r[src]+imm+chain) & mask] (8B); chain = r[dst]
    CN_OP_SP_WRITE  = 7,  // scratchpad[(r[dst]+imm+chain) & mask] ^= r[src]; chain += prev value
    CN_OP_MIX       = 8,  // r[dst] = mix64(r[dst] ^ r[src], imm)
    CN_OP_COUNT     = 9
} cn_vm_opcode_t;

typedef struct {
    uint8_t  op;    // cn_vm_opcode_t stored as byte
    uint8_t  dst;   // destination register [0, CN_REG_COUNT)
    uint8_t  src;   // source register      [0, CN_REG_COUNT)
    uint8_t  shift; // shift amount / signed branch offset (interpreted as int8_t for CN_OP_CBRANCH)
    uint32_t imm;   // immediate operand
} cn_vm_instruction_t;

typedef struct {
    cn_vm_instruction_t instructions[CN_PROGRAM_SIZE];
} cn_vm_program_t;

// Generate a deterministic random program from a 32-byte seed.
// The seed must embed both per-height chain data and per-nonce blob hash
// so that the program is unique per (height, nonce) tuple.
void cn_vm_generate_program(cn_vm_program_t *prog, const uint8_t seed[32]);

// Execute one pass of prog against scratchpad, mutating both scratchpad
// and regs in place.  Executes exactly CN_PROGRAM_SIZE steps (no infinite
// loops possible).  Call CN_VM_ITERATIONS times with the same prog and
// evolving regs to accumulate scratchpad mutations.
void cn_vm_execute(cn_vm_program_t *prog, uint8_t *scratchpad, uint64_t regs[CN_REG_COUNT]);

// Execute one HF14 pass: CN_V7_SEGMENTS repetitions of [serial chase over
// the per-nonce buffer, then a slice of prog].  Each hop reads a buffer cell
// then writes it back (buffer[idx] ^= chain), so touched cells diverge from
// the fill and the buffer cannot be regenerated on the fly.  buffer_qwords is
// its length in 64-bit words (>= 1, any length: addressing maps the chain
// value through a mul128 high word, no power-of-two requirement).  SP_READ
// consumes the chased values, SP_WRITE mutates the small pad
// (CN_SCRATCHPAD_MEMORY_V14 bytes, write-hardness only).  *chain_state
// carries the walk position across passes so the chase stays sequential for
// the whole hash and cannot be precomputed.  Call CN_VM_ITERATIONS_V14 times.
void cn_vm_execute_v7(cn_vm_program_t *prog, uint8_t *buffer, uint64_t buffer_qwords,
                      uint8_t *pad, uint64_t regs[CN_REG_COUNT], uint64_t *chain_state);
