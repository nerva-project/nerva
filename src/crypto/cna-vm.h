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
// then executes it against a 4 MB scratchpad.  Combining random code
// execution (defeats fixed ASIC circuits) with a large scratchpad
// (kills GPU occupancy) while keeping the blockchain-DB seed dependency
// that makes pool mining architecturally impossible.

// Must be a power of 2 so pc wrapping works with a bitmask.
#define CN_PROGRAM_SIZE    512
#define CN_REG_COUNT       8
#define CN_VM_ITERATIONS   2048

// Instruction opcodes — kept small so the opcode byte fits in uint8_t.
typedef enum {
    CN_OP_IADD_RS   = 0,  // r[dst] += r[src] << (shift & 3)
    CN_OP_ISUB      = 1,  // r[dst] -= r[src]
    CN_OP_IMUL      = 2,  // r[dst] *= r[src]  (lower 64 bits)
    CN_OP_IXOR      = 3,  // r[dst] ^= r[src]
    CN_OP_IROR      = 4,  // r[dst] = ror64(r[dst], r[src] & 63)
    CN_OP_CBRANCH   = 5,  // if (r[dst] & (imm|1)) pc = (pc + shift) % SIZE
    CN_OP_SP_READ   = 6,  // r[dst] = scratchpad[(r[src]+imm) & mask]  (8 bytes)
    CN_OP_SP_WRITE  = 7,  // scratchpad[(r[dst]+imm) & mask] ^= r[src]
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
