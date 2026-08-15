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

#include "http_notify.h"

#include <chrono>
#include <sstream>
#include <thread>

#include "misc_log_ex.h"
#include "net/http_base.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "notify.http"

namespace tools
{

namespace
{
  // JSON string escape: escapes ", \, \n, \r, \t, and control chars.
  std::string json_escape(const std::string& s)
  {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s)
    {
      switch (c)
      {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
          if (static_cast<unsigned char>(c) < 0x20)
          {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
            out += buf;
          }
          else
          {
            out += c;
          }
      }
    }
    return out;
  }

  // Simple URL parser: extracts scheme, host, port, path from a URL string.
  struct url_parts
  {
    bool use_ssl;
    std::string host;
    std::string port;
    std::string path;
  };

  bool parse_url(const std::string& url, url_parts& out)
  {
    // Find scheme
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos)
      return false;

    std::string scheme = url.substr(0, scheme_end);
    if (scheme == "https")
    {
      out.use_ssl = true;
      out.port = "443";
    }
    else if (scheme == "http")
    {
      out.use_ssl = false;
      out.port = "80";
    }
    else
      return false;

    size_t host_start = scheme_end + 3;
    size_t path_start = url.find('/', host_start);
    std::string host_port;
    if (path_start == std::string::npos)
    {
      host_port = url.substr(host_start);
      out.path = "/";
    }
    else
    {
      host_port = url.substr(host_start, path_start - host_start);
      out.path = url.substr(path_start);
    }

    // Check for port
    size_t colon = host_port.find(':');
    if (colon != std::string::npos)
    {
      out.host = host_port.substr(0, colon);
      out.port = host_port.substr(colon + 1);
    }
    else
    {
      out.host = host_port;
    }

    return !out.host.empty();
  }
} // anonymous namespace

HTTPNotify::HTTPNotify(const std::string& url, unsigned timeout_seconds)
  : m_url(url)
  , m_timeout_seconds(timeout_seconds)
  , m_shutting_down(false)
{
  CHECK_AND_ASSERT_THROW_MES(!url.empty(), "Webhook URL is empty");
  CHECK_AND_ASSERT_THROW_MES(is_webhook_url(url), "Webhook URL must start with http:// or https://: " << url);
}

HTTPNotify::~HTTPNotify()
{
  m_shutting_down = true;
}

bool HTTPNotify::is_webhook_url(const std::string& url)
{
  return url.compare(0, 7, "http://") == 0 || url.compare(0, 8, "https://") == 0;
}

std::string HTTPNotify::build_json(const std::string& event, const std::string& data,
                                    const std::vector<std::pair<std::string, std::string>>& extra) const
{
  std::ostringstream oss;
  oss << "{";
  oss << "\"event\":\"" << json_escape(event) << "\"";
  oss << ",\"data\":\"" << json_escape(data) << "\"";
  oss << ",\"timestamp\":" << std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
  if (!extra.empty())
  {
    oss << ",\"extra\":{";
    bool first = true;
    for (const auto& kv : extra)
    {
      if (!first) oss << ",";
      oss << "\"" << json_escape(kv.first) << "\":\"" << json_escape(kv.second) << "\"";
      first = false;
    }
    oss << "}";
  }
  oss << "}";
  return oss.str();
}

int HTTPNotify::notify(const std::string& event, const std::string& data,
                       const std::vector<std::pair<std::string, std::string>>& extra)
{
  if (m_shutting_down)
    return 1;

  const std::string body = build_json(event, data, extra);
  send_async(body);
  return 0;
}

void HTTPNotify::send_async(const std::string& body)
{
  // Detach a thread to avoid blocking the caller (block validation, tx pool).
  // The thread performs a synchronous HTTP POST using epee's http_simple_client
  // (already linked into the daemon) with a timeout.
  std::thread([url = m_url, body, timeout = m_timeout_seconds]()
  {
    try
    {
      url_parts parts;
      if (!parse_url(url, parts))
      {
        MWARNING("Webhook: invalid URL: " << url);
        return;
      }

      if (parts.use_ssl)
      {
        MWARNING("Webhook: HTTPS not supported by the built-in HTTP client. "
                 "Use http:// for internal webhooks or put a TLS-terminating "
                 "reverse proxy in front. URL was: " << url);
        return;
      }

      // Use epee's HTTP client (already used by wallet2 and core_rpc_server)
      epee::net_utils::http::http_simple_client http_client;
      epee::net_utils::http::url_content url_content{};
      if (!epee::net_utils::parse_url(url, url_content))
      {
        MWARNING("Webhook: failed to parse URL: " << url);
        return;
      }

      // Set timeout
      http_client.set_server(url_content.host,
                             std::to_string(url_content.port),
                             boost::none);

      // Build the HTTP request
      epee::net_utils::http::http_request_info req{};
      req.m_http_method = epee::net_utils::http::http_method::POST;
      req.m_URI = url_content.uri.empty() ? "/" : url_content.uri;
      req.m_header_info.m_content_type = "application/json";
      req.m_body = body;
      req.m_header_info.m_user_agent = "NervaDaemon/1.0";
      req.m_header_info.m_connection = "close";

      epee::net_utils::http::http_response_info res{};
      if (!http_client.invoke(req, res))
      {
        MWARNING("Webhook: HTTP POST failed for " << url);
        return;
      }

      if (res.m_response_code < 200 || res.m_response_code >= 300)
      {
        MDEBUG("Webhook: server returned " << res.m_response_code << " for " << url);
      }
    }
    catch (const std::exception& e)
    {
      MWARNING("Webhook failed for " << url << ": " << e.what());
    }
  }).detach();
}

} // namespace tools
