// Copyright (c) 2018-2024, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers


#include "quicksync.h"

#include "checkpoints.h"
#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "quicksync"

namespace cryptonote
{
  quicksync::quicksync() { }
  //---------------------------------------------------------------------------
  bool quicksync::check_block(uint64_t height, const crypto::hash &h, bool &is_present) const
  {
    is_present = false;

    if (!m_is_loaded)
      return false;

    auto it = m_data.find(height);

    if (it == m_data.end())
      return false;

    is_present = true;
    return it->second == h;
  }
  //---------------------------------------------------------------------------
  bool quicksync::check_against_checkpoints(const checkpoints &cp) const
  {
    for (const auto &point : cp.get_points())
    {
      const uint64_t height = point.first;
      auto it = m_data.find(height);
      if (it == m_data.end())
        continue;
      if (it->second != point.second)
      {
        MERROR("Quick sync hash at height " << height << " conflicts with hardcoded checkpoint; rejecting quick sync file");
        return false;
      }
    }
    return true;
  }
  //---------------------------------------------------------------------------
  bool quicksync::load(const std::string &qs_file)
  {
    auto qs = boost::filesystem::path(qs_file);
    boost::system::error_code errcode;
    if (!boost::filesystem::exists(qs, errcode))
    {
      LOG_PRINT_L1("Quick sync file not found");
      return false;
    }

    LOG_PRINT_L1("Adding hashes from quick sync file");
    
    std::ifstream import_file;
    import_file.open(qs_file, std::ios_base::binary | std::ifstream::in);

    if (import_file.fail())
    {
      MWARNING("import_file.open() fail");
      return false;
    }

    uint32_t quicksync_magic = 0x149f943e;

    uint32_t comp = 0;
    import_file.read ((char*)&comp, sizeof(comp));

    if (comp != quicksync_magic)
    {
      MERROR("Quick sync file magic incorrect. ignoring file");
      return false;
    }

    if (!import_file.read((char*)&m_min, sizeof(m_min)) ||
        !import_file.read((char*)&m_max, sizeof(m_max)))
    {
      MERROR("Quick sync file header truncated. ignoring file");
      return false;
    }

    if (m_min > m_max)
    {
      MERROR("Quick sync file header invalid: min " << m_min << " > max " << m_max << ". ignoring file");
      return false;
    }

    // Bound the entry count by the real file size so a hostile header can't drive a huge allocation.
    const std::streampos data_start = import_file.tellg();
    import_file.seekg(0, std::ios::end);
    const std::streamoff bytes_available = import_file.tellg() - data_start;
    import_file.seekg(data_start);

    const uint64_t count = (uint64_t)m_max - (uint64_t)m_min;
    if (data_start == std::streampos(-1) || bytes_available < 0 ||
        (uint64_t)bytes_available < count * sizeof(crypto::hash))
    {
      MERROR("Quick sync file truncated: header declares " << count << " hashes but file is too small. ignoring file");
      return false;
    }

    LOG_PRINT_L0("Loading quick sync data for blocks " << m_min << " - " << m_max);

    uint64_t height = m_min;

    for (uint64_t i = 0; i < count; i++)
    {
      crypto::hash h = crypto::null_hash;
      if (!import_file.read((char*)&h.data, sizeof(h.data)))
      {
        MERROR("Quick sync file read failed at block " << height << ". ignoring file");
        m_data.clear();
        return false;
      }
      m_data[height++] = h;
    }

    m_is_loaded = true;
    return true;
  }
}
