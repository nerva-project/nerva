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

#include <vector>
#include <string>
#include "dns_config.h"
#include "dns_utils.h"
#include "misc_log_ex.h"

namespace dns_config
{
    std::vector<std::string> m_seed_nodes;
    std::vector<std::string> m_txt_seed_nodes;
    std::vector<std::string> m_update;
    std::vector<std::string> m_download;
    std::vector<std::string> m_analytics;
    bool m_dnssec_ok;
    bool m_is_dns_disabled = false;

    void init(const bool testnet)
    {
        m_dnssec_ok = false;
        m_seed_nodes.clear();
        m_txt_seed_nodes.clear();
        m_update.clear();
        m_download.clear();
        m_analytics.clear();

        bool dns_avail = false, dns_valid = false;
        std::vector<std::string> result;

        if(is_dns_disabled())
        {
            LOG_PRINT_L0("DNS disabled. Returning from init...");
            return;
        }

        tools::DNSResolver dr = tools::DNSResolver::create();

        dr.get_ipv4(ROOT_DOMAIN, dns_avail, dns_valid);

        if (!dns_avail || !dns_valid) {
            MWARNING("DNS: Cannot resolve A record for " << ROOT_DOMAIN << " (Exists = " << dns_avail << ", DNSSEC Valid = " << dns_valid << ")");
            return;
        }

        std::vector<std::string> seed_nodes = testnet ? testnet::SEED_NODES : SEED_NODES;
        std::vector<std::string> txt_seed_nodes = testnet ? testnet::TXT_SEED_NODES : TXT_SEED_NODES;

        for (auto &s : seed_nodes)
        {
            result = dr.get_ipv4(s, dns_avail, dns_valid);

            if (!dns_avail)
                MERROR("Server side DNS failure for " << s);
            else if (!dns_valid)
                MERROR("Client side DNS failure for " << s);

            if (!dns_avail || !dns_valid)
                continue;

            for (auto &r : result)
                m_seed_nodes.push_back(r);
        }

        tools::dns_utils::load_txt_records_from_dns(dr, m_update, UPDATE);
        tools::dns_utils::load_txt_records_from_dns(dr, m_download, DOWNLOAD);
        tools::dns_utils::load_txt_records_from_dns(dr, m_txt_seed_nodes, txt_seed_nodes);
        tools::dns_utils::load_txt_records_from_dns(dr, m_analytics, ANALYTICS);

        for (auto &s : m_txt_seed_nodes)
            m_seed_nodes.push_back(s);

        if (m_seed_nodes.size() > 0 && m_update.size() > 0)
            m_dnssec_ok = true;
    }

    std::vector<std::string> get_update_records() { return m_update; }
    std::vector<std::string> get_download_records() { return m_download; }
    std::vector<std::string> get_seed_node_records() { return m_seed_nodes; }
    std::vector<std::string> get_analytics_records() { return m_analytics; }
    bool has_update_records() { return m_update.size() > 0; }
    bool has_download_records() { return m_download.size() > 0; }
    bool has_seed_node_records() { return m_seed_nodes.size() > 0; }
    bool has_analytics_records() { return m_analytics.size() > 0; }
    bool is_dnssec_ok() { return m_dnssec_ok; }

    void disable_dns(bool disable) { m_is_dns_disabled = disable; }
    bool is_dns_disabled() { return m_is_dns_disabled; }    
}