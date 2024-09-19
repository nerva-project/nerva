#ifndef _XNV_HTTPS_
#define _XNV_HTTPS_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

namespace xnvhttp
{
    std::string get_host(std::string ip);
};

namespace blacklist
{
    static std::vector<std::string> ip_list;
    const std::vector<std::string> get_ip_list();
    void read_blacklist_from_url();
    std::vector<std::string> split_string(const std::string& str, const std::string& delimiter);
};

namespace analytics
{
    static bool m_enabled = false;

    void enable(bool enabled);
    bool is_enabled();
    std::string get_analytics_url();
    bool contact_server(const bool testnet);
};

#endif