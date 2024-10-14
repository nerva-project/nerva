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

#include "quicksync_file.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

namespace po = boost::program_options;

using namespace cryptonote;
using namespace epee;

namespace
{
  std::string refresh_string = "\r                                    \r";
}

bool QuickSyncFile::open_writer(const boost::filesystem::path& file_path, uint64_t block_start, uint64_t block_stop)
{
  const boost::filesystem::path dir_path = file_path.parent_path();
  if (!dir_path.empty())
  {
    if (boost::filesystem::exists(dir_path))
    {
      if (!boost::filesystem::is_directory(dir_path))
      {
        MFATAL("export directory path is a file: " << dir_path);
        return false;
      }
    }
    else
    {
      if (!boost::filesystem::create_directory(dir_path))
      {
        MFATAL("Failed to create directory " << dir_path);
        return false;
      }
    }
  }

  m_raw_data_file = new std::ofstream();

  MINFO("creating file");

  m_raw_data_file->open(file_path.string(), std::ios_base::out | std::ios::trunc);
  if (m_raw_data_file->fail())
    return false;

  initialize_file(block_start, block_stop);

  return true;
}


bool QuickSyncFile::initialize_file(uint64_t block_start, uint64_t block_stop)
{
  uint32_t bsa = (uint32_t)block_start;
  uint32_t bsb = (uint32_t)block_stop;

  m_raw_data_file->write(reinterpret_cast<const char *>(&quicksync_magic), 4);
  m_raw_data_file->write(reinterpret_cast<const char *>(&bsa), 4);
  m_raw_data_file->write(reinterpret_cast<const char *>(&bsb), 4);
  return true;
}

bool QuickSyncFile::close()
{
  if (m_raw_data_file->fail())
    return false;

  m_raw_data_file->flush();
  delete m_raw_data_file;
  return true;
}

bool QuickSyncFile::store_blockchain(Blockchain* _blockchain_storage, boost::filesystem::path& output_file, uint64_t block_start, uint64_t block_stop)
{
  m_blockchain_storage = _blockchain_storage;
  uint64_t num_blocks_written = 0;
  uint64_t progress_interval = 1000;

  MINFO("source blockchain height: " <<  m_blockchain_storage->get_current_blockchain_height()-1);

  if (block_stop == 0)
    block_stop = m_blockchain_storage->get_current_blockchain_height() - 1;

  MINFO("Exporting blockchain range: " << block_start << " - " << block_stop);

  MINFO("Storing quick sync data...");
  if (!QuickSyncFile::open_writer(output_file, block_start, block_stop))
  {
    MFATAL("failed to open raw file for write");
    return false;
  }

  for (m_cur_height = block_start; m_cur_height <= block_stop; ++m_cur_height)
  {
    // this method's height refers to 0-based height (genesis block = height 0)
    crypto::hash hash = m_blockchain_storage->get_block_id_by_height(m_cur_height);
    
    m_raw_data_file->write(hash.data, 32);
    
    if (m_cur_height % progress_interval == 0) {
      std::cout << refresh_string;
      std::cout << "block " << m_cur_height << "/" << block_stop << std::flush;
    }
  }

  // print message for last block, which may not have been printed yet due to progress_interval
  std::cout << refresh_string;
  std::cout << "block " << m_cur_height-1 << "/" << block_stop << ENDL;

  return QuickSyncFile::close();
}



