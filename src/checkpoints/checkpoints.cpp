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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "common/dns_config.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <boost/filesystem.hpp>
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    if (m_points.empty())
      return 0;
    return m_points.rbegin()->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    // Hardcoded mainnet checkpoints, spread across history so a node fed a bad
    // chain during sync is rejected at the first divergent checkpoint instead of
    // much later; the highest entry anchors ASSUME_VALID_HEIGHT (enforced below).
    if (nettype == MAINNET)
    {
      ADD_CHECKPOINT(1, "fe2b6c553f136ce46f4716e22d64b07732246dfc245c8f23c41a3eadc888d89d");
      ADD_CHECKPOINT(10, "2fffb6f916a1eb535cd466ecb8022ee1980c81430fe1daaa2b28134355319288");
      ADD_CHECKPOINT(1000, "5de9c560b9e7294cc63c74aadf01edb39ec43fd218def726740d770b558c7097");
      ADD_CHECKPOINT(10000, "992fbc3247e5a6d1b23b67025d8651656d9ecda364878f177ff011ff2f27d64d");
      ADD_CHECKPOINT(100000, "ab33ccdb964c6a39cc57b302b03e7125c212b72fe67cc30e7467229175646d81");
      ADD_CHECKPOINT(200000, "39e1edc050e72ba55dfce0fa9956ad789e3b6dacfabd731f7e469619c019c5bd");
      ADD_CHECKPOINT(300000, "14b59684805db6e87fda7970f7ba4d84e53e382733031101ddaaf61883baa1cc");
      ADD_CHECKPOINT(400000, "cf2afac38a53837927feb7356c369cbf97e3146de51feaa7f8fa833acb9206f7");
      ADD_CHECKPOINT(500000, "892e073423b002da181cd1cc9f423514505dd627f872d2f550ad408643df3d86");
      ADD_CHECKPOINT(600000, "c176fa88d65c87858d77a9bc202e8db57823f4855904c3ce67fb2f374dd83bf0");
      ADD_CHECKPOINT(700000, "acc6e48c254d9ffd1978ca78a5c3b033714c96a2d0bd956962a779fa81eb8a59");
      ADD_CHECKPOINT(800000, "95aea447e43694cf7abcda6153e9f99747ed2fbf2f2975c9af9e876513eed331");
      ADD_CHECKPOINT(900000, "f860dee2a65d38109d223aa804fdb06f0d2a33b6bb7273337c8b28e79fa87a72");
      ADD_CHECKPOINT(1000000, "2f4246adfa484fafff09e367a62ad14bba7440730a471ca335dd0ea76dfb736a");
      ADD_CHECKPOINT(1100000, "8e94d9914b712513c6b563f057ab4d762392fbd84351a04f1d7e63abb1cad06b");
      ADD_CHECKPOINT(1200000, "2b5eae48be279e38a0e395a509f246f1b5e7f746384e9e2f1bce750ed63aa65b");
      ADD_CHECKPOINT(1300000, "363e7e5e7d08574d1f5815d06805081b151af34792ce6dbd22d66ea253b8618d");
      ADD_CHECKPOINT(1400000, "698fc03d367e192bdc6da376c959a9f312e4cd4ab311f4a18ca4fd5a4bcab640");
      ADD_CHECKPOINT(1500000, "783ead46ba80e76f7feb25f7d23acf34a34f8d112fd2dc707e1aacb8261d466d");
      ADD_CHECKPOINT(1600000, "8275b4eb901257080434c659ecdda449b2eea7c2b86cc586e2b3442371223bf7");
      ADD_CHECKPOINT(1700000, "c2f03c5ef2b6b4b27afe0731c5dc556b3a491ace0437cead634e19c59104064c");
      ADD_CHECKPOINT(1800000, "c023301bf056032148c58876c61d2863da1ccc325df8dfc83b3f247923153129");
      ADD_CHECKPOINT(1900000, "e390685e11617caaacadef9d45662f2cf2e82f12ba6f990553898203dfe72897");
      ADD_CHECKPOINT(2000000, "2aad0c92cf4df8799f5307e2ced10921bf70d4144d39b076d7975a70eb401455");
      ADD_CHECKPOINT(2100000, "5ccad0ef7389dcf64ce6d52e3b4f84f7138bab756a3d4238d5d0ec04e162054c");
      ADD_CHECKPOINT(2200000, "bcc96246d6e6fcfdaa0af80cd0050f8cad324934b81e602dfa240bcc2bc52b22");
      ADD_CHECKPOINT(2300000, "b35cc68366383166c559ba6aaaf57863505078164f77ceaa75a04dbe64556f31");
      ADD_CHECKPOINT(2400000, "acdbbd03f3c94cfe71157040e9180db759b8e3351678cfc753681af3324a6fb6");
      ADD_CHECKPOINT(2500000, "0f2edf79d88d9bf0bc2cec40ea7488b8f0f548248b2ffac4d56fd18871ca552a");
      ADD_CHECKPOINT(2600000, "8e3136ee2c0c2f8ec984cef1aed9a73c53b8b454b828ad78e49e243136548014");
      ADD_CHECKPOINT(2700000, "c6d60df64c06f5e2d0a49ecce22dcb453214aeb50d56eb13f4c9466e6832226b");
      ADD_CHECKPOINT(2800000, "35d8220885ed8d5eab35c321c7215c9a1990a0b21256856a1910e16e101f9200");
      ADD_CHECKPOINT(2900000, "debeffd465feccbb7aa94159ee698b6f059673469aa1eb16b37f13f58b09c4a9");
      ADD_CHECKPOINT(3000000, "cab3a91567a86c134a05f078637f736a03d69c427019fdb46e5d6c650edb885a");
      ADD_CHECKPOINT(3100000, "6c05d795ba8060a4b302aa2b5a91dc95fc46a0e5a3d882f601f47f2c59c4a2d5");
      ADD_CHECKPOINT(3200000, "a23310b268022d868eebe810669224bfc4b8296e573e8ab10de5e3de0b530326");
      ADD_CHECKPOINT(3300000, "6b5bb134466c8ca54139ee9ffd422cc26bb8d380b5dc99874fe1c78d69ffd8f7");
      ADD_CHECKPOINT(3400000, "7226372927bd1e27f2d4eac95918db129d02e9a7221b74bc4810f4d31f3d68c7");
      ADD_CHECKPOINT(3500000, "ecced65d0b9577c971b2d92471a39da10bdc398cef1e6231d5714223a59a841a");
      ADD_CHECKPOINT(3600000, "4ee4e483ed91285604a76cd99154cd857ea9d9dfe3ede347979a06a99b2c65bc");
      ADD_CHECKPOINT(3700000, "3abc435c98a3ed81b38c1555c58846d5a3dec412fc1ee553e455062f2232e008");
      ADD_CHECKPOINT(3800000, "d9f5cb1aa289cf1aa8d0e0a68f1524e14b1901c995b6cd0b1cb794ab58224d93");
      ADD_CHECKPOINT(3900000, "a66fe1e2b829080e7b9644ff39c52018c64cebd7c9b3439bf69afe11d70c04e8");
      ADD_CHECKPOINT(4000000, "5b3271eca95fce944086b55c44fa8c26b47e51e508ff272d1228455591f9091d");
      ADD_CHECKPOINT(4100000, "50ededd060ac706e66c013a34bf55adc54d29302833acd9fa0191dd3163be825");
      ADD_CHECKPOINT(4200000, "9e1bbcbf0bd690a59299008e51cfde8403364cde89a1c96bfe173158c3269a8f");
      ADD_CHECKPOINT(4300000, "6ee1e78bd980b5918bf2e7c87b72bb21bc86c7088750bea15e6b0b67a55a93c6");
      ADD_CHECKPOINT(4320000, "45ae8c2a5f5463671ee092adc3f0f786c57369ba5a6fff2119bac0f1a2b86339");   // HF13 activation
    }

    // assume-valid skips PoW below ASSUME_VALID_HEIGHT; that is only safe if a
    // hardcoded checkpoint at or above it anchors the skipped range. Refuse to
    // start otherwise, else an unanchored gap lets an eclipsed node be fed a fake history.
    const uint64_t assume_valid_height = get_config(nettype).ASSUME_VALID_HEIGHT;
    CHECK_AND_ASSERT_MES(nettype == FAKECHAIN || assume_valid_height == 0 || get_max_height() >= assume_valid_height,
        false, "ASSUME_VALID_HEIGHT " << assume_valid_height << " has no anchoring checkpoint at or above it");

    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    if (!tools::dns_utils::load_txt_records_from_dns(records, dns_config::get_config(nettype).CHECKPOINTS))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::hex_to_pod(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
