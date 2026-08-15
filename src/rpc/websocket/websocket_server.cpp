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

#include "websocket_server.h"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <chrono>
#include <sstream>

#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "rpc.websocket"

namespace cryptonote
{

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

namespace
{
  // JSON string escape helper
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
        default:   out += c;
      }
    }
    return out;
  }

  // Build a JSON notification message
  std::string build_message(const std::string& type, const std::string& data_json)
  {
    return "{\"type\":\"" + type + "\",\"data\":" + data_json + "}";
  }

  // Build block notification JSON
  std::string build_block_message(const std::string& hash, uint64_t height, uint64_t reward)
  {
    std::ostringstream oss;
    oss << "{\"hash\":\"" << json_escape(hash) << "\","
        << "\"height\":" << height << ","
        << "\"reward\":" << reward << ","
        << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()).count()
        << "}";
    return build_message("new_block", oss.str());
  }

  // Build tx notification JSON
  std::string build_tx_message(const std::string& hash, uint64_t fee)
  {
    std::ostringstream oss;
    oss << "{\"hash\":\"" << json_escape(hash) << "\","
        << "\"fee\":" << fee << ","
        << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch()).count()
        << "}";
    return build_message("new_tx", oss.str());
  }

  // Build reorg notification JSON
  std::string build_reorg_message(uint64_t split_height, uint64_t new_height, uint64_t discarded_blocks)
  {
    std::ostringstream oss;
    oss << "{\"split_height\":" << split_height << ","
        << "\"new_height\":" << new_height << ","
        << "\"discarded_blocks\":" << discarded_blocks << "}";
    return build_message("reorg", oss.str());
  }

  // WebSocket session: represents a single connected client
  class WebsocketSession : public std::enable_shared_from_this<WebsocketSession>
  {
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    std::vector<std::string> message_queue_;
    std::mutex queue_mutex_;
    bool writing_ = false;

  public:
    explicit WebsocketSession(tcp::socket socket)
      : ws_(std::move(socket))
    {}

    void run()
    {
      // Accept the WebSocket handshake
      ws_.async_accept(
        [self = shared_from_this()](beast::error_code ec)
        {
          if (ec)
          {
            MWARNING("WebSocket: accept failed: " << ec.message());
            return;
          }
          self->do_read();
        }
      );
    }

    void send(const std::string& message)
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      message_queue_.push_back(message);
      if (!writing_)
      {
        writing_ = true;
        do_write();
      }
    }

  private:
    void do_read()
    {
      ws_.async_read(buffer_,
        [self = shared_from_this()](beast::error_code ec, std::size_t bytes)
        {
          if (ec == websocket::error::closed || ec == net::error::eof)
          {
            MDEBUG("WebSocket: client disconnected");
            return;
          }
          if (ec)
          {
            MWARNING("WebSocket: read error: " << ec.message());
            return;
          }
          // Ignore client messages (we only push), keep reading
          self->do_read();
        }
      );
    }

    void do_write()
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      if (message_queue_.empty())
      {
        writing_ = false;
        return;
      }
      std::string msg = std::move(message_queue_.front());
      message_queue_.erase(message_queue_.begin());

      ws_.text(true);
      ws_.async_write(net::buffer(msg),
        [self = shared_from_this()](beast::error_code ec, std::size_t)
        {
          if (ec)
          {
            MWARNING("WebSocket: write error: " << ec.message());
            return;
          }
          self->do_write();
        }
      );
    }
  };
} // anonymous namespace

// PIMPL implementation
class WebSocketServer::Impl
{
public:
  net::io_context ioc;
  tcp::acceptor acceptor;
  std::thread io_thread;
  std::set<std::shared_ptr<WebsocketSession>> sessions;
  std::mutex sessions_mutex;
  std::atomic<bool> running{false};

  Impl()
    : ioc()
    , acceptor(ioc)
  {}

  void do_accept()
  {
    acceptor.async_accept(
      [this](beast::error_code ec, tcp::socket socket)
      {
        if (ec)
        {
          if (running.load())
            MWARNING("WebSocket: accept error: " << ec.message());
          return;
        }
        auto session = std::make_shared<WebsocketSession>(std::move(socket));
        {
          std::lock_guard<std::mutex> lock(sessions_mutex);
          sessions.insert(session);
        }
        MDEBUG("WebSocket: new client connected (" << client_count() << " total)");
        session->run();
        do_accept();
      }
    );
  }

  size_t client_count()
  {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    return sessions.size();
  }

  void broadcast(const std::string& message)
  {
    std::lock_guard<std::mutex> lock(sessions_mutex);
    for (auto& session : sessions)
      session->send(message);
  }
};

WebSocketServer::WebSocketServer()
  : m_impl(std::make_unique<Impl>())
{}

WebSocketServer::~WebSocketServer()
{
  stop();
}

bool WebSocketServer::start(const std::string& host, uint16_t port)
{
  try
  {
    tcp::endpoint endpoint(net::ip::make_address(host), port);
    m_impl->acceptor.open(endpoint.protocol());
    m_impl->acceptor.set_option(net::socket_base::reuse_address(true));
    m_impl->acceptor.bind(endpoint);
    m_impl->acceptor.listen(net::socket_base::max_listen_connections);

    m_impl->running = true;
    m_impl->do_accept();

    m_impl->io_thread = std::thread([this]() { m_impl->ioc.run(); });
    m_running = true;

    MINFO("WebSocket server listening on " << host << ":" << port);
    return true;
  }
  catch (const std::exception& e)
  {
    MERROR("WebSocket server failed to start: " << e.what());
    return false;
  }
}

void WebSocketServer::stop()
{
  if (!m_running.load())
    return;

  m_impl->running = false;
  m_impl->ioc.stop();
  if (m_impl->io_thread.joinable())
    m_impl->io_thread.join();

  std::lock_guard<std::mutex> lock(m_impl->sessions_mutex);
  m_impl->sessions.clear();
  m_running = false;
  MINFO("WebSocket server stopped");
}

void WebSocketServer::notify_new_block(const std::string& block_hash, uint64_t height, uint64_t reward)
{
  if (!m_running.load())
    return;
  broadcast(build_block_message(block_hash, height, reward));
}

void WebSocketServer::notify_new_tx(const std::string& tx_hash, uint64_t fee)
{
  if (!m_running.load())
    return;
  broadcast(build_tx_message(tx_hash, fee));
}

void WebSocketServer::notify_reorg(uint64_t split_height, uint64_t new_height, uint64_t discarded_blocks)
{
  if (!m_running.load())
    return;
  broadcast(build_reorg_message(split_height, new_height, discarded_blocks));
}

size_t WebSocketServer::client_count() const
{
  return m_impl->client_count();
}

void WebSocketServer::broadcast(const std::string& json_message)
{
  m_impl->broadcast(json_message);
}

} // namespace cryptonote
