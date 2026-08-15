// Copyright (c) 2018-2026, The Nerva Project
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

#include "tor_autoconfig.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim.hpp>

#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "tor"

namespace tools
{

namespace
{
  // Read the Tor control auth cookie from the filesystem
  std::string read_cookie(const std::string& path)
  {
    std::ifstream file(path, std::ios::binary);
    if (!file)
      return "";
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
  }

  // Hex-encode a binary string for the Tor control protocol
  std::string hex_encode(const std::string& data)
  {
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(data.size() * 2);
    for (unsigned char c : data)
    {
      out += hex[c >> 4];
      out += hex[c & 0x0F];
    }
    return out;
  }

  // Send a line to the Tor control port and read the response
  bool send_command(boost::asio::ip::tcp::socket& socket, const std::string& cmd, std::string& response)
  {
    namespace net = boost::asio;
    std::string line = cmd + "\r\n";
    net::write(socket, net::buffer(line));

    response.clear();
    char buf[4096];
    boost::system::error_code ec;
    // Read until we get a line starting with a 3-digit code followed by a space (final response)
    while (true)
    {
      std::size_t n = socket.read_some(net::buffer(buf), ec);
      if (n > 0)
      {
        response.append(buf, n);
        // Check if response ends with a final line (code + space)
        size_t pos = response.find("\r\n");
        while (pos != std::string::npos)
        {
          size_t line_start = (pos == 0) ? 0 : response.rfind("\n", pos - 1) + 1;
          if (pos - line_start >= 4 && response[line_start + 3] == ' ')
            return true; // Final response line
          pos = response.find("\r\n", pos + 2);
        }
      }
      if (ec && ec != net::error::would_block)
        break;
    }
    return !response.empty();
  }

  // Extract the ServiceID from a ADD_ONION response
  std::string extract_service_id(const std::string& response)
  {
    // Response looks like: 250-ServiceID=abcdef...56chars\r\n250 OK\r\n
    size_t pos = response.find("ServiceID=");
    if (pos == std::string::npos)
      return "";
    pos += 10; // skip "ServiceID="
    size_t end = response.find("\r\n", pos);
    if (end == std::string::npos)
      end = response.find("\n", pos);
    return response.substr(pos, end - pos);
  }
} // anonymous namespace

bool TorAutoConfig::is_auto(const std::string& value)
{
  std::string lower = value;
  std::transform(lower.begin(), lower.end(), lower.begin(),
    [](unsigned char c) { return std::tolower(c); });
  return lower == "auto";
}

std::string TorAutoConfig::create_onion_service(
  const std::string& control_host,
  uint16_t control_port,
  uint16_t local_port,
  uint16_t onion_port,
  const std::string& cookie_path,
  const std::string& password)
{
  try
  {
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    net::io_context ioc;
    tcp::resolver resolver(ioc);
    tcp::socket socket(ioc);

    MINFO("Tor auto-config: connecting to control port " << control_host << ":" << control_port);
    auto endpoints = resolver.resolve(control_host, std::to_string(control_port));
    net::connect(socket, endpoints);

    // Read the protocol greeting (starts with 250)
    char greeting[1024];
    socket.read_some(net::buffer(greeting));

    // Authenticate
    std::string response;

    if (!cookie_path.empty())
    {
      // Cookie authentication
      std::string cookie = read_cookie(cookie_path);
      if (cookie.empty())
      {
        MERROR("Tor auto-config: failed to read auth cookie from " << cookie_path);
        return "";
      }
      std::string cmd = "AUTHENTICATE " + hex_encode(cookie);
      if (!send_command(socket, cmd, response) || response.substr(0, 3) != "250")
      {
        MERROR("Tor auto-config: authentication failed");
        return "";
      }
    }
    else if (!password.empty())
    {
      // Password authentication (hex-encode the password)
      std::string cmd = "AUTHENTICATE " + hex_encode(password);
      if (!send_command(socket, cmd, response) || response.substr(0, 3) != "250")
      {
        MERROR("Tor auto-config: authentication failed");
        return "";
      }
    }
    else
    {
      // Try SAFECOOKIE first (most secure, default in modern Tor)
      std::string cmd = "AUTHCHALLENGE SAFECOOKIE";
      if (!send_command(socket, cmd, response) || response.substr(0, 3) != "250")
      {
        // Fall back to null authentication (only works if CookieAuthentication
        // is 0 and no auth is configured in torrc -- rare)
        MWARNING("Tor auto-config: SAFECOOKIE challenge failed, trying no-auth");
        if (!send_command(socket, "AUTHENTICATE", response) || response.substr(0, 3) != "250")
        {
          MERROR("Tor auto-config: authentication failed. Configure CookieAuthentication or ControlPort in torrc");
          return "";
        }
      }
      else
      {
        // SAFECOOKIE requires the cookie file -- extract the challenge,
        // compute HMAC, and send back. This is complex and requires reading
        // the cookie file. For simplicity, if we got here without a cookie_path,
        // we can't complete SAFECOOKIE.
        MERROR("Tor auto-config: SAFECOOKIE auth requires --tor-cookie-auth-cookie <path>. "
               "Please provide the cookie path (usually in /var/lib/tor/control_auth_cookie)");
        return "";
      }
    }

    // Create a v3 onion service
    // ADD_ONION NEW:V3 Port=17565,127.0.0.1:17565
    std::ostringstream cmd;
    cmd << "ADD_ONION NEW:V3 Port=" << onion_port << ",127.0.0.1:" << local_port;
    if (!send_command(socket, cmd.str(), response) || response.find("250 OK") == std::string::npos)
    {
      MERROR("Tor auto-config: ADD_ONION failed: " << response);
      return "";
    }

    // Extract the service ID
    std::string service_id = extract_service_id(response);
    if (service_id.empty())
    {
      MERROR("Tor auto-config: failed to extract ServiceID from response: " << response);
      return "";
    }

    std::string onion_address = service_id + ".onion:" + std::to_string(onion_port);
    MINFO("Tor auto-config: created onion service " << onion_address);
    return onion_address;
  }
  catch (const std::exception& e)
  {
    MERROR("Tor auto-config: " << e.what());
    return "";
  }
}

} // namespace tools
