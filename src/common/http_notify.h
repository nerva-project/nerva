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
//    materials provided the distribution.
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

#include <memory>
#include <string>
#include <thread>
#include <atomic>
#include <vector>

namespace tools
{

/*!
  \brief HTTP webhook notifier.

  Sends a JSON POST request to a URL when a notification fires. This is an
  alternative to the subprocess-based Notify class for environments where
  running an external process is not desirable (containers, managed nodes,
  cloud deployments).

  The JSON payload is built from a simple template system: the spec is a
  URL that may contain %s placeholders, which are substituted with the
  notification values. The body is always a JSON object:

  {
    "event": "<event_type>",
    "data": "<value>",
    "timestamp": <unix_seconds>,
    "extra": { ... }
  }

  Example usage:
    --block-webhook "https://my-server.com/nerva/blocks"
    --tx-webhook "https://my-server.com/nerva/txs"

  The HTTP request is sent in a detached thread to avoid blocking the caller
  (block validation, tx pool, etc.). A timeout of 10 seconds is enforced to
  prevent hanging on unresponsive servers.

  Failed requests are logged at WARNING level but do not block the daemon.
*/
class HTTPNotify
{
public:
  /*!
    \param url The webhook URL (must start with http:// or https://).
    \param timeout_seconds HTTP request timeout (default: 10s).
    \throws std::runtime_error if the URL is invalid.
  */
  explicit HTTPNotify(const std::string& url, unsigned timeout_seconds = 10);
  ~HTTPNotify();

  /*!
    \brief Send a notification.
    \param event The event type (e.g. "new_block", "new_tx", "reorg").
    \param data The primary data value (e.g. block hash hex, tx hash hex).
    \param extra_keys Optional extra key-value pairs to include in the JSON body.
    \param extra_values The values corresponding to extra_keys.
    \return 0 on success, non-zero on failure (matching the convention of
            the subprocess Notify::notify for compatibility).
  */
  int notify(const std::string& event, const std::string& data,
             const std::vector<std::pair<std::string, std::string>>& extra = {});

  /*!
    \brief Check if the URL scheme is supported.
    \return true if url starts with http:// or https://.
  */
  static bool is_webhook_url(const std::string& url);

private:
  std::string m_url;
  unsigned m_timeout_seconds;
  std::atomic<bool> m_shutting_down;

  /*!
    \brief Perform the HTTP POST in a worker thread.
    \param body The JSON body to send.
  */
  void send_async(const std::string& body);

  /*!
    \brief Build the JSON body for a notification.
  */
  std::string build_json(const std::string& event, const std::string& data,
                         const std::vector<std::pair<std::string, std::string>>& extra) const;
};

}
