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

#include <string>
#include <vector>

namespace net
{

/*!
  \brief Zstd compression wrapper for P2P payloads.

  This module provides optional zstd compression for P2P messages (blocks,
  transactions). Compression is negotiated via the P2P handshake support
  flags: both peers must advertise P2P_SUPPORT_FLAG_ZSTD for compressed
  messages to be used.

  The compressed format prepends a 4-byte header:
    [1 byte] compression algorithm (0x00 = none, 0x01 = zstd)
    [3 bytes] original size (big-endian, max 16 MB)

  This allows the receiver to allocate the correct buffer before
  decompression and fall back to raw data if the algorithm byte is 0x00.

  Compression level: 3 (fast, ~40% ratio on RCT transactions)
  Threshold: payloads < 256 bytes are not compressed (overhead > benefit)

  Usage:
    std::string compressed = net::zstd_compress(raw_payload);
    std::string decompressed = net::zstd_decompress(compressed);
*/

/// Compression algorithm identifiers
enum class compression_algo : uint8_t
{
    NONE = 0x00,   ///< No compression (passthrough)
    ZSTD = 0x01,   ///< Zstd compression
};

/// Minimum payload size for compression to be worthwhile
#define ZSTD_MIN_COMPRESS_SIZE 256

/// Maximum compressed payload size (16 MB)
#define ZSTD_MAX_PAYLOAD_SIZE (16 * 1024 * 1024)

/// Compress a payload using zstd.
/// \param data The raw data to compress
/// \return Compressed data with 4-byte header, or empty string on failure
std::string zstd_compress(const std::string& data);

/// Decompress a zstd-compressed payload.
/// \param data The compressed data (with 4-byte header)
/// \return Decompressed data, or empty string on failure
std::string zstd_decompress(const std::string& data);

/// Check if a payload should be compressed (size > threshold)
bool should_compress(size_t payload_size);

/// Check if zstd is available at runtime (library linked)
bool zstd_available();

} // namespace net
