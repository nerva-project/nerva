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

#include "p2p_zstd.h"

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.zstd"

namespace net
{

bool zstd_available()
{
#ifdef HAVE_ZSTD
    return true;
#else
    return false;
#endif
}

bool should_compress(size_t payload_size)
{
    return payload_size >= ZSTD_MIN_COMPRESS_SIZE && payload_size <= ZSTD_MAX_PAYLOAD_SIZE;
}

std::string zstd_compress(const std::string& data)
{
    if (!should_compress(data.size()))
    {
        // Below threshold or too large: passthrough with NONE header
        std::string result;
        result.push_back(static_cast<char>(compression_algo::NONE));
        // 3-byte original size (big-endian)
        uint32_t size = static_cast<uint32_t>(data.size());
        result.push_back(static_cast<char>((size >> 16) & 0xFF));
        result.push_back(static_cast<char>((size >> 8) & 0xFF));
        result.push_back(static_cast<char>(size & 0xFF));
        result += data;
        return result;
    }

#ifdef HAVE_ZSTD
    // Allocate the compressed buffer
    size_t bound = ZSTD_compressBound(data.size());
    std::string compressed;
    compressed.resize(bound);

    // Compress at level 3 (fast, good ratio for RCT data)
    size_t compressed_size = ZSTD_compress(
        compressed.data(), bound,
        data.data(), data.size(),
        3
    );

    if (ZSTD_isError(compressed_size))
    {
        MWARNING("zstd compression failed: " << ZSTD_getErrorName(compressed_size) << ", falling back to raw");
        std::string result;
        result.push_back(static_cast<char>(compression_algo::NONE));
        uint32_t size = static_cast<uint32_t>(data.size());
        result.push_back(static_cast<char>((size >> 16) & 0xFF));
        result.push_back(static_cast<char>((size >> 8) & 0xFF));
        result.push_back(static_cast<char>(size & 0xFF));
        result += data;
        return result;
    }

    // Build the final payload: algo byte + 3-byte original size + compressed data
    std::string result;
    result.push_back(static_cast<char>(compression_algo::ZSTD));
    uint32_t orig_size = static_cast<uint32_t>(data.size());
    result.push_back(static_cast<char>((orig_size >> 16) & 0xFF));
    result.push_back(static_cast<char>((orig_size >> 8) & 0xFF));
    result.push_back(static_cast<char>(orig_size & 0xFF));
    result.append(compressed.data(), compressed_size);

    MDEBUG("zstd: " << data.size() << " -> " << result.size() << " bytes ("
            << (100 * result.size() / data.size()) << "%)");

    return result;
#else
    // zstd not compiled in: passthrough
    std::string result;
    result.push_back(static_cast<char>(compression_algo::NONE));
    uint32_t size = static_cast<uint32_t>(data.size());
    result.push_back(static_cast<char>((size >> 16) & 0xFF));
    result.push_back(static_cast<char>((size >> 8) & 0xFF));
    result.push_back(static_cast<char>(size & 0xFF));
    result += data;
    return result;
#endif
}

std::string zstd_decompress(const std::string& data)
{
    if (data.size() < 4)
    {
        MERROR("zstd: payload too short for header");
        return "";
    }

    // Read header
    uint8_t algo = static_cast<uint8_t>(data[0]);
    uint32_t orig_size = (static_cast<uint32_t>(static_cast<uint8_t>(data[1])) << 16)
                       | (static_cast<uint32_t>(static_cast<uint8_t>(data[2])) << 8)
                       | static_cast<uint32_t>(static_cast<uint8_t>(data[3]));

    const char* payload = data.data() + 4;
    size_t payload_size = data.size() - 4;

    if (algo == static_cast<uint8_t>(compression_algo::NONE))
    {
        // Passthrough
        return std::string(payload, payload_size);
    }

    if (algo != static_cast<uint8_t>(compression_algo::ZSTD))
    {
        MERROR("zstd: unknown compression algorithm: " << static_cast<int>(algo));
        return "";
    }

#ifdef HAVE_ZSTD
    if (orig_size > ZSTD_MAX_PAYLOAD_SIZE)
    {
        MERROR("zstd: decompressed size too large: " << orig_size);
        return "";
    }

    std::string decompressed;
    decompressed.resize(orig_size);

    size_t result = ZSTD_decompress(
        decompressed.data(), orig_size,
        payload, payload_size
    );

    if (ZSTD_isError(result))
    {
        MERROR("zstd decompression failed: " << ZSTD_getErrorName(result));
        return "";
    }

    decompressed.resize(result);
    return decompressed;
#else
    MERROR("zstd: compressed payload received but zstd is not compiled in");
    return "";
#endif
}

} // namespace net
