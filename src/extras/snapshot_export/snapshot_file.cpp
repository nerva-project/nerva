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

#include "snapshot_file.h"

#include <boost/endian/conversion.hpp>
#include <cstring>
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "snapshot"

namespace tools
{

bool snapshot_file::write(const std::string& path, const snapshot_header& header,
                          const std::vector<snapshot_entry>& entries)
{
    try
    {
        std::ofstream file(path, std::ios::binary);
        if (!file)
        {
            MERROR("Failed to open snapshot file for writing: " << path);
            return false;
        }

        // Write header
        snapshot_header h = header;
        h.magic = SNAPSHOT_MAGIC;
        h.version = SNAPSHOT_VERSION;
        // Write fields individually (avoid struct packing issues)
        uint32_t magic = boost::endian::native_to_little(h.magic);
        uint32_t version = boost::endian::native_to_little(h.version);
        uint64_t height = boost::endian::native_to_little(h.height);
        uint64_t output_count = boost::endian::native_to_little(h.output_count);

        file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        file.write(reinterpret_cast<const char*>(&version), sizeof(version));
        file.write(reinterpret_cast<const char*>(&height), sizeof(height));
        file.write(reinterpret_cast<const char*>(h.block_hash.data), sizeof(h.block_hash.data));
        file.write(reinterpret_cast<const char*>(&output_count), sizeof(output_count));

        // Write entries
        for (const auto& entry : entries)
        {
            uint64_t amount = boost::endian::native_to_little(entry.amount);
            file.write(reinterpret_cast<const char*>(&amount), sizeof(amount));
            file.write(reinterpret_cast<const char*>(&entry.public_key), sizeof(entry.public_key));
            file.write(reinterpret_cast<const char*>(&entry.commitment), sizeof(entry.commitment));
        }

        MINFO("Snapshot written: " << path << " (" << entries.size() << " outputs at height " << header.height << ")");
        return true;
    }
    catch (const std::exception& e)
    {
        MERROR("Failed to write snapshot: " << e.what());
        return false;
    }
}

bool snapshot_file::read(const std::string& path, snapshot_header& header,
                          std::vector<snapshot_entry>& entries)
{
    try
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            MERROR("Failed to open snapshot file for reading: " << path);
            return false;
        }

        // Read header
        uint32_t magic, version;
        uint64_t height, output_count;

        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        file.read(reinterpret_cast<char*>(&height), sizeof(height));
        file.read(reinterpret_cast<char*>(header.block_hash.data), sizeof(header.block_hash.data));
        file.read(reinterpret_cast<char*>(&output_count), sizeof(output_count));

        magic = boost::endian::little_to_native(magic);
        version = boost::endian::little_to_native(version);
        height = boost::endian::little_to_native(height);
        output_count = boost::endian::little_to_native(output_count);

        if (magic != SNAPSHOT_MAGIC)
        {
            MERROR("Invalid snapshot magic: 0x" << std::hex << magic << " (expected 0x" << SNAPSHOT_MAGIC << ")");
            return false;
        }

        if (version != SNAPSHOT_VERSION)
        {
            MERROR("Unsupported snapshot version: " << version << " (expected " << SNAPSHOT_VERSION << ")");
            return false;
        }

        header.magic = magic;
        header.version = version;
        header.height = height;
        header.output_count = output_count;

        // Read entries
        entries.clear();
        entries.reserve(static_cast<size_t>(output_count));

        for (uint64_t i = 0; i < output_count; ++i)
        {
            snapshot_entry entry;
            uint64_t amount;
            file.read(reinterpret_cast<char*>(&amount), sizeof(amount));
            entry.amount = boost::endian::little_to_native(amount);
            file.read(reinterpret_cast<char*>(&entry.public_key), sizeof(entry.public_key));
            file.read(reinterpret_cast<char*>(&entry.commitment), sizeof(entry.commitment));
            if (!file)
            {
                MERROR("Truncated snapshot at entry " << i);
                return false;
            }
            entries.push_back(entry);
        }

        MINFO("Snapshot read: " << path << " (" << entries.size() << " outputs at height " << header.height << ")");
        return true;
    }
    catch (const std::exception& e)
    {
        MERROR("Failed to read snapshot: " << e.what());
        return false;
    }
}

bool snapshot_file::validate(const snapshot_header& header, uint64_t expected_height,
                              const crypto::hash& expected_hash)
{
    if (header.height != expected_height)
    {
        MERROR("Snapshot height mismatch: " << header.height << " vs expected " << expected_height);
        return false;
    }

    if (memcmp(header.block_hash.data, expected_hash.data, sizeof(expected_hash.data)) != 0)
    {
        MERROR("Snapshot block hash mismatch at height " << header.height);
        return false;
    }

    return true;
}

} // namespace tools
