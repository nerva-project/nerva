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

#include "miner_ipc.h"

#include <boost/asio.hpp>
#include <cstdio>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "miner.ipc"

namespace cryptonote
{

namespace
{
  // Simple JSON value extractor (not a full parser, just enough for the miner IPC commands)
  std::string extract_json_string(const std::string& json, const std::string& key)
  {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos)
      return "";
    pos = json.find(':', pos);
    if (pos == std::string::npos)
      return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
      pos++;
    if (pos >= json.size() || json[pos] != '"')
      return "";
    pos++;
    size_t end = json.find('"', pos);
    if (end == std::string::npos)
      return "";
    return json.substr(pos, end - pos);
  }

  int extract_json_int(const std::string& json, const std::string& key, int default_val = 0)
  {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos)
      return default_val;
    pos = json.find(':', pos);
    if (pos == std::string::npos)
      return default_val;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
      pos++;
    return atoi(json.c_str() + pos);
  }

  bool extract_json_bool(const std::string& json, const std::string& key, bool default_val = false)
  {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos)
      return default_val;
    pos = json.find(':', pos);
    if (pos == std::string::npos)
      return default_val;
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
      pos++;
    if (json.compare(pos, 4, "true") == 0)
      return true;
    if (json.compare(pos, 5, "false") == 0)
      return false;
    return default_val;
  }
} // anonymous namespace

class MinerIPCServer::Impl
{
public:
  boost::asio::io_context ioc;
  std::thread io_thread;
  std::atomic<bool> running{false};

#ifdef _WIN32
  // Named pipe on Windows (not yet implemented)
  HANDLE pipe_handle = INVALID_HANDLE_VALUE;
#else
  // Unix domain socket
  boost::asio::local::stream_protocol::acceptor* acceptor = nullptr;
  std::string socket_path;
#endif

  Impl() : ioc() {}

  ~Impl()
  {
    stop();
  }

  void stop()
  {
    if (!running.load())
      return;
    running = false;
    ioc.stop();
    if (io_thread.joinable())
      io_thread.join();
#ifndef _WIN32
    if (acceptor)
    {
      delete acceptor;
      acceptor = nullptr;
    }
    if (!socket_path.empty())
      ::unlink(socket_path.c_str());
#endif
  }
};

MinerIPCServer::MinerIPCServer()
  : m_impl(std::make_unique<Impl>())
{}

MinerIPCServer::~MinerIPCServer()
{
  stop();
}

bool MinerIPCServer::start(const std::string& socket_path)
{
#ifdef _WIN32
  MERROR("Miner IPC server is not yet supported on Windows");
  return false;
#else
  try
  {
    m_impl->socket_path = socket_path;

    // Remove existing socket file
    ::unlink(socket_path.c_str());

    // Create the Unix domain socket acceptor
    m_impl->acceptor = new boost::asio::local::stream_protocol::acceptor(
      m_impl->ioc,
      boost::asio::local::stream_protocol::endpoint(socket_path.c_str())
    );

    // Set socket file permissions to 0600 (owner read/write only)
    ::chmod(socket_path.c_str(), 0600);

    m_impl->running = true;

    // Start accepting connections
    auto do_accept = [this]() {
      auto socket = std::make_shared<boost::asio::local::stream_protocol::socket>(m_impl->ioc);
      m_impl->acceptor->async_accept(*socket,
        [this, socket](const boost::system::error_code& ec) {
          if (ec)
          {
            if (m_impl->running.load())
              MWARNING("Miner IPC: accept error: " << ec.message());
            return;
          }
          // Read a line and handle the command
          auto buf = std::make_shared<boost::asio::streambuf>();
          boost::asio::async_read_until(*socket, *buf, "\n",
            [this, socket, buf](const boost::system::error_code& ec, std::size_t bytes) {
              if (ec)
                return;
              std::istream is(buf.get());
              std::string request;
              std::getline(is, request);
              std::string response = handle_command(request);
              response += "\n";
              boost::asio::write(*socket, boost::asio::buffer(response));
            }
          );
        }
      );
    };
    do_accept();

    // Run the io_context in a dedicated thread
    m_impl->io_thread = std::thread([this]() {
      m_impl->ioc.run();
    });

    m_running = true;
    MINFO("Miner IPC server listening on " << socket_path);
    return true;
  }
  catch (const std::exception& e)
  {
    MERROR("Miner IPC server failed to start: " << e.what());
    return false;
  }
#endif
}

void MinerIPCServer::stop()
{
  m_impl->stop();
  m_running = false;
  MINFO("Miner IPC server stopped");
}

std::string MinerIPCServer::handle_command(const std::string& json_request)
{
  std::string cmd = extract_json_string(json_request, "cmd");
  if (cmd.empty())
  {
    return "{\"error\":\"missing 'cmd' field\"}";
  }

  if (cmd == "start")
  {
    if (!m_start_cb)
      return "{\"error\":\"start callback not registered\"}";
    std::string address = extract_json_string(json_request, "address");
    int threads = extract_json_int(json_request, "threads", 0);
    bool affinity = extract_json_bool(json_request, "affinity", false);
    if (address.empty())
      return "{\"error\":\"missing 'address' field\"}";
    bool ok = m_start_cb(address, threads, affinity);
    return ok ? "{\"status\":\"ok\"}" : "{\"error\":\"start failed\"}";
  }

  if (cmd == "stop")
  {
    if (m_stop_cb)
      m_stop_cb();
    return "{\"status\":\"ok\"}";
  }

  if (cmd == "status")
  {
    if (m_status_cb)
      return m_status_cb();
    return "{\"error\":\"status callback not registered\"}";
  }

  if (cmd == "set_threads")
  {
    if (m_threads_cb)
    {
      int count = extract_json_int(json_request, "count", 1);
      m_threads_cb(count);
      return "{\"status\":\"ok\"}";
    }
    return "{\"error\":\"threads callback not registered\"}";
  }

  if (cmd == "set_affinity")
  {
    if (m_affinity_cb)
    {
      bool enabled = extract_json_bool(json_request, "enabled", false);
      m_affinity_cb(enabled);
      return "{\"status\":\"ok\"}";
    }
    return "{\"error\":\"affinity callback not registered\"}";
  }

  if (cmd == "set_donate_level")
  {
    if (m_donate_cb)
    {
      int level = extract_json_int(json_request, "level", 0);
      m_donate_cb(level);
      return "{\"status\":\"ok\"}";
    }
    return "{\"error\":\"donate callback not registered\"}";
  }

  if (cmd == "get_stats")
  {
    if (m_stats_cb)
      return m_stats_cb();
    return "{\"error\":\"stats callback not registered\"}";
  }

  return "{\"error\":\"unknown command: " + cmd + "\"}";
}

} // namespace cryptonote
