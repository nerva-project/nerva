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

#pragma once
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include "ringct/rctOps.h"
#include "blockchain_db/blockchain_db.h"

namespace crypto
{
  struct cn_hash_context;
  typedef struct cn_hash_context cn_hash_context_t;
}

namespace cryptonote
{

  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, uint64_t fee, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce = blobdata(), size_t max_outs = 999, uint8_t hard_fork_version = 1);

  bool construct_genesis_tx(transaction& tx, uint64_t amount);

  struct tx_source_entry
  {
    typedef std::pair<uint64_t, rct::ctkey> output_entry;

    std::vector<output_entry> outputs;  //index + key + optional ringct commitment
    size_t real_output;                 //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    std::vector<crypto::public_key> real_out_additional_tx_keys; //incoming real tx additional public keys
    size_t real_output_in_tx_index;     //index in transaction outputs vector
    uint64_t amount;                    //money
    bool rct = true;                    //true if the output is rct (always in NERVA)
    rct::key mask;                      //ringct amount mask
    rct::multisig_kLRki multisig_kLRki; //multisig info

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_additional_tx_keys)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(rct)
      FIELD(mask)
      FIELD(multisig_kLRki)

      if (real_output >= outputs.size())
        return false;
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    std::string original;
    uint64_t amount;                    //money
    account_public_address addr;        //destination address
    bool is_subaddress;
    bool is_integrated;

    tx_destination_entry() : amount(0), addr(AUTO_VAL_INIT(addr)), is_subaddress(false), is_integrated(false) { }
    tx_destination_entry(uint64_t a, const account_public_address &ad, bool is_subaddress) : amount(a), addr(ad), is_subaddress(is_subaddress), is_integrated(false) { }
    tx_destination_entry(const std::string &o, uint64_t a, const account_public_address &ad, bool is_subaddress) : original(o), amount(a), addr(ad), is_subaddress(is_subaddress), is_integrated(false) { }

    std::string address(network_type nettype, const crypto::hash &payment_id) const
    {
      if (!original.empty())
      {
        return original;
      }

      if (is_integrated)
      {
        return get_account_integrated_address_as_str(nettype, addr, reinterpret_cast<const crypto::hash8 &>(payment_id));
      }

      return get_account_address_as_str(nettype, is_subaddress, addr);
    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(original)
      VARINT_FIELD(amount)
      FIELD(addr)
      FIELD(is_subaddress)
      FIELD(is_integrated)
    END_SERIALIZE()
  };

  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr);
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, 
    std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, 
    const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, 
    uint8_t current_tx_version, const rct::RCTConfig &rct_config = { rct::RangeProofBorromean, 0 }, rct::multisig_out *msout = NULL, bool shuffle_outs = true);
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, 
    std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, 
    uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, uint8_t current_tx_version,
    const rct::RCTConfig &rct_config = { rct::RangeProofBorromean, 0 }, rct::multisig_out *msout = NULL);
  bool generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key) ;

  bool generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key) ;

  bool generate_genesis_block(block& bl);
  class Blockchain;


  //todo: could probably get rid of some of these overloads
  bool get_block_longhash(crypto::cn_hash_context_t *context, cryptonote::Blockchain *bc, const block &b, crypto::hash &res, const uint64_t height);
  bool get_block_longhash(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const block &b, crypto::hash &res, const uint64_t height);
  bool get_block_longhash(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const uint8_t major_version, const blobdata &blob, crypto::hash &res, const uint64_t height);
  crypto::hash get_block_longhash(crypto::cn_hash_context_t *context, Blockchain *bc, const block &b, const uint64_t height);
  
  bool get_block_longhash_v11(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const blobdata &blob, crypto::hash &res, uint64_t height);
  bool get_block_longhash_v10(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const blobdata &blob, crypto::hash &res, uint64_t height);
  bool get_block_longhash_v9(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const blobdata &blob, crypto::hash &res, uint64_t height);
  bool get_block_longhash_v7_8(crypto::cn_hash_context_t *context, cryptonote::BlockchainDB &db, const blobdata &blob, crypto::hash &res, uint64_t height, uint64_t data_offset);
}

namespace boost
{
  namespace serialization
  {
    template <class Archive>
    inline void serialize(Archive &a, cryptonote::tx_source_entry &x, const boost::serialization::version_type ver)
    {
      a & x.outputs;
      a & x.real_output;
      a & x.real_out_tx_key;
      a & x.real_output_in_tx_index;
      a & x.amount;
      a & x.rct;
      a & x.mask;
      a & x.multisig_kLRki;
      a & x.real_out_additional_tx_keys;
    }

    template <class Archive>
    inline void serialize(Archive& a, cryptonote::tx_destination_entry& x, const boost::serialization::version_type ver)
    {
      a & x.amount;
      a & x.addr;
      a & x.is_subaddress;
      a & x.original;
      a & x.is_integrated;
    }
  }
}
