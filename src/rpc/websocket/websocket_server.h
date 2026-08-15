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

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "cryptonote_basic/blobdatatype.h"

namespace cryptonote
{

/*!
  \brief WebSocket subscription server for real-time blockchain updates.

  This module provides a WebSocket server that pushes real-time notifications
  to connected clients when new blocks are added, transactions enter the
  mempool, or reorganizations occur. This eliminates the need for clients
  (explorers, wallets, dashboards) to poll the daemon's REST API every few
  seconds.

  The server is optional and disabled by default. Enable with:
    nervad --ws-bind-port 17568

  Message format (JSON):
    {"type":"new_block","data":{"hash":"...","height":123,"reward":...}}
    {"type":"new_tx","data":{"hash":"...","fee":...}}
    {"type":"reorg","data":{"split_height":...,"new_height":...}}

  Clients connect via: ws://host:port/subscribe
"""

class WebSocketServer
{
public:
  WebSocketServer();
  ~WebSocketServer();

  /*!
    \brief Start the WebSocket server on the given port.
    \param host Bind address (default: 0.0.0.0)
    \param port Bind port (default: 17568)
    \return true on success.
  */
  bool start(const std::string& host = "0.0.0.0", uint16_t port = 17568);

  /*!
    \brief Stop the WebSocket server and disconnect all clients.
  */
  void stop();

  /*!
    \brief Check if the server is running.
  */
  bool is_running() const { return m_running.load(); }

  /*!
    \brief Notify all connected clients of a new block.
    \param block_hash The hex hash of the new block.
    \param height The block height.
    \param reward The block reward in atomic units.
  */
  void notify_new_block(const std::string& block_hash, uint64_t height, uint64_t reward);

  /*!
    \brief Notify all connected clients of a new transaction in the mempool.
    \param tx_hash The hex hash of the transaction.
    \param fee The transaction fee in atomic units.
  */
  void notify_new_tx(const std::string& tx_hash, uint64_t fee);

  /*!
    \brief Notify all connected clients of a chain reorganization.
    \param split_height The height at which the chain split.
    \param new_height The new chain height.
    \param discarded_blocks Number of blocks discarded.
  */
  void notify_reorg(uint64_t split_height, uint64_t new_height, uint64_t discarded_blocks);

  /*!
    \brief Get the number of connected clients.
  */
  size_t client_count() const;

private:
  // Internal implementation (PIMPL to hide boost::asio details from the header)
  class Impl;
  std::unique_ptr<Impl> m_impl;
  std::atomic<bool> m_running{false};
  mutable std::mutex m_clients_mutex;
  std::set<void*> m_clients; ///< Set of client connection pointers

  /*!
    \brief Broadcast a JSON message to all connected clients.
  */
  void broadcast(const std::string& json_message);
};

} // namespace cryptonote
