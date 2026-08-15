// Copyright (c) 2018-2026, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary, with or without modification, are
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

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

namespace tools
{

/*!
  \brief UTXO snapshot file format for fast blockchain bootstrap.

  This file format stores the complete UTXO set (unspent transaction outputs)
  at a given block height. A new node can import this snapshot to skip
  processing historical blocks, reducing bootstrap time from hours to minutes.

  The snapshot is anchored by a checkpoint: the height and block hash of the
  snapshot point must match a known checkpoint. The importing node verifies
  this anchor before trusting the UTXO set.

  File format:
    Offset  Size   Field
    0       4      Magic: 0x4E565355 ("NVSU" = Nerva Snapshot UTXO)
    4       8      Height (uint64, little-endian) - block height of the snapshot
    12      32     Block hash (the hash of the block at this height)
    44      8      Output count (uint64, little-endian)
    52      N*72   Output entries, each:
                      8 bytes: amount (uint64, atomic units)
                      32 bytes: public key (output target key)
                      32 bytes: commitment (RCT pedersen commitment)

  The file is compressed with zstd after generation to reduce size
  (the UTXO set at height 4M is approximately 50-100 MB uncompressed,
  ~10-20 MB compressed).

  See also: QuickSync (src/checkpoints/quicksync.h) which exports block
  hashes for PoW skipping. This snapshot exports the actual UTXO state.
*/

#define SNAPSHOT_MAGIC 0x4E565355
#define SNAPSHOT_VERSION 1

struct snapshot_header
{
    uint32_t magic;          ///< SNAPSHOT_MAGIC
    uint32_t version;        ///< SNAPSHOT_VERSION
    uint64_t height;         ///< Block height of the snapshot
    crypto::hash block_hash; ///< Hash of the block at this height
    uint64_t output_count;   ///< Number of UTXO entries in the file
};

struct snapshot_entry
{
    uint64_t amount;           ///< Output amount in atomic units
    rct::key public_key;       ///< Output target key (recipient's ephemeral pubkey)
    rct::key commitment;       ///< Pedersen commitment (for RCT outputs)
};

class snapshot_file
{
public:
    /*!
      \brief Write a UTXO snapshot to a file.
      \param path Output file path
      \param header Snapshot header (height, block_hash, output_count)
      \param entries Vector of UTXO entries
      \return true on success
    */
    static bool write(const std::string& path, const snapshot_header& header,
                       const std::vector<snapshot_entry>& entries);

    /*!
      \brief Read a UTXO snapshot from a file.
      \param path Input file path
      \param header Output: snapshot header
      \param entries Output: UTXO entries
      \return true on success, false on format error or truncation
    */
    static bool read(const std::string& path, snapshot_header& header,
                      std::vector<snapshot_entry>& entries);

    /*!
      \brief Validate a snapshot header against a known checkpoint.
      \param header The snapshot header to validate
      \param expected_height The checkpoint height
      \param expected_hash The checkpoint block hash
      \return true if the snapshot matches the checkpoint
    */
    static bool validate(const snapshot_header& header, uint64_t expected_height,
                          const crypto::hash& expected_hash);
};

} // namespace tools
