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

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace cryptonote
{

/*!
  \brief IPC (Inter-Process Communication) API for the internal miner.

  This module exposes a Unix domain socket (or named pipe on Windows) that
  allows external processes (like NervaOne GUI) to control the daemon's
  internal miner in real-time. The RPC uses a simple JSON-over-IPC protocol.

  The IPC API is an alternative to the HTTP RPC /start_mining and /stop_mining
  endpoints, with these advantages:
  - No network port needed (Unix socket file-based)
  - No authentication needed (filesystem permissions)
  - Lower latency (no TCP overhead)
  - Can push real-time stats (hashrate, shares found) to the client

  Commands:
    {"cmd":"start","address":"NV...","threads":4,"affinity":true}
    {"cmd":"stop"}
    {"cmd":"status"}                    -> {"running":true,"hashrate":1234.5,...}
    {"cmd":"set_threads","count":4}
    {"cmd":"set_affinity","enabled":true}
    {"cmd":"set_donate_level","level":5}
    {"cmd":"get_stats"}                 -> {"total_hashes":..., "blocks_found":...}

  The server is optional and disabled by default. Enable with:
    nervad --miner-ipc-path /tmp/nerva-miner.sock
*/

class MinerIPCServer
{
public:
  MinerIPCServer();
  ~MinerIPCServer();

  /*!
    \brief Start the IPC server on the given socket path.
    \param socket_path Path for the Unix domain socket file.
    \return true on success.
  */
  bool start(const std::string& socket_path);

  /*!
    \brief Stop the IPC server.
  */
  void stop();

  /*!
    \brief Check if the server is running.
  */
  bool is_running() const { return m_running.load(); }

  // --- Callbacks for the miner to register ---

  using StartCallback = std::function<bool(const std::string& address, int threads, bool affinity)>;
  using StopCallback = std::function<void()>;
  using StatusCallback = std::function<std::string()>;
  using SetThreadsCallback = std::function<void(int)>;
  using SetAffinityCallback = std::function<void(bool)>;
  using SetDonateCallback = std::function<void(int)>;
  using GetStatsCallback = std::function<std::string()>;

  void set_start_callback(StartCallback cb) { m_start_cb = cb; }
  void set_stop_callback(StopCallback cb) { m_stop_cb = cb; }
  void set_status_callback(StatusCallback cb) { m_status_cb = cb; }
  void set_threads_callback(SetThreadsCallback cb) { m_threads_cb = cb; }
  void set_affinity_callback(SetAffinityCallback cb) { m_affinity_cb = cb; }
  void set_donate_callback(SetDonateCallback cb) { m_donate_cb = cb; }
  void set_stats_callback(GetStatsCallback cb) { m_stats_cb = cb; }

private:
  class Impl;
  std::unique_ptr<Impl> m_impl;
  std::atomic<bool> m_running{false};

  StartCallback m_start_cb;
  StopCallback m_stop_cb;
  StatusCallback m_status_cb;
  SetThreadsCallback m_threads_cb;
  SetAffinityCallback m_affinity_cb;
  SetDonateCallback m_donate_cb;
  GetStatsCallback m_stats_cb;

  std::string handle_command(const std::string& json_request);
};

} // namespace cryptonote
