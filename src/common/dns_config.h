// Copyright (c) 2019, The NERVA Project

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
    bool has_update_records();
    bool has_download_records();
    bool has_seed_node_records();
    bool is_dnssec_ok();

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