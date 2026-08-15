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

#include <string>

namespace tools
{

/*!
  \brief Tor v3 onion service auto-configuration helper.

  When the user passes --anonymous-inbound auto (instead of a specific
  onion address), the daemon connects to the Tor control port and requests
  the creation of a new v3 onion service. The onion address is then used
  as the --anonymous-inbound value automatically.

  This simplifies the setup for node operators who want to run a Nerva
  hidden service without manually editing torrc and generating keys.

  Requirements:
  - A running Tor daemon with ControlPort enabled
  - Cookie authentication or password authentication configured

  Usage:
    nervad --anonymous-inbound auto,127.0.0.1:17565

  The Tor control port defaults to 127.0.0.1:9051. Override with:
    --tor-control-host 127.0.0.1 --tor-control-port 9051
*/
class TorAutoConfig
{
public:
  /*!
    \brief Attempt to create a v3 onion service via the Tor control port.
    \param control_host Tor control host (default: 127.0.0.1)
    \param control_port Tor control port (default: 9051)
    \param local_port The local port to expose (the P2P bind port)
    \param onion_port The port to advertise on the onion service (usually same as local)
    \param cookie_path If non-empty, use cookie authentication from this path
    \param password If non-empty, use password authentication
    \return The .onion address (including port), or empty string on failure.
  */
  static std::string create_onion_service(
    const std::string& control_host = "127.0.0.1",
    uint16_t control_port = 9051,
    uint16_t local_port = 17565,
    uint16_t onion_port = 17565,
    const std::string& cookie_path = "",
    const std::string& password = ""
  );

  /*!
    \brief Check if a value is the "auto" keyword for --anonymous-inbound.
    \return true if value equals "auto" (case-insensitive).
  */
  static bool is_auto(const std::string& value);
};

}
