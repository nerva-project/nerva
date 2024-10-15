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

#ifndef _XNV_DNS_CONFIG_
#define _XNV_DNS_CONFIG_

#include <vector>
#include <string>
#include "cryptonote_config.h"

namespace dns_config
{
    static const std::vector<std::string> SEED_NODES = { };

    static const std::vector<std::string> TXT_SEED_NODES = {
        "seed.nerva.one",
        "seed.nerva.info"
    };

    static const std::vector<std::string> CHECKPOINTS = {
        "checkpoint.nerva.one"
    };

    static const std::vector<std::string> UPDATE = {
        "update.nerva.one"
    };

    static const std::vector<std::string> DOWNLOAD = {
        "download.nerva.one"
    };

    static const std::vector<std::string> ANALYTICS = {
        "analytics.nerva.one"
    };

    static const std::string ROOT_DOMAIN = "nerva.one";

    namespace testnet
    {
        static const std::vector<std::string> SEED_NODES = { };

        static const std::vector<std::string> TXT_SEED_NODES = {
            "seed-tn.nerva.one",
            "seed-tn.nerva.info"
        };

        static const std::vector<std::string> CHECKPOINTS = {
            "checkpoint-tn.nerva.one"
        };
    }

    void init(const bool testnet);

    std::vector<std::string> get_update_records();
    std::vector<std::string> get_download_records();
    std::vector<std::string> get_seed_node_records();
    std::vector<std::string> get_analytics_records();
    bool has_update_records();
    bool has_download_records();
    bool has_seed_node_records();
    bool has_analytics_records();    
    bool is_dnssec_ok();

    void disable_dns(bool disable);
    bool is_dns_disabled();

    struct dns_config_t
    {
        std::vector<std::string> const SEED_NODES;
        std::vector<std::string> const TXT_SEED_NODES;
        std::vector<std::string> const CHECKPOINTS;
    };

    inline const dns_config_t &get_config(cryptonote::network_type nettype)
    {
        static const dns_config_t mainnet = {
            ::dns_config::SEED_NODES,
            ::dns_config::TXT_SEED_NODES,
            ::dns_config::CHECKPOINTS
        };

        static const dns_config_t testnet = {
            ::dns_config::testnet::SEED_NODES,
            ::dns_config::testnet::TXT_SEED_NODES,
            ::dns_config::testnet::CHECKPOINTS
        };

        static const dns_config_t empty = { {}, {} };

        switch (nettype)
        {
            case cryptonote::MAINNET:
                return mainnet;
            case cryptonote::TESTNET:
                return testnet;
            default:
                return empty;
        }
    }
}
#endif