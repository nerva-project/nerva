// Copyright (c) 2018-2019, The NERVA Project
// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#include <stdexcept>
#include <string>
#include <set>
#include <boost/uuid/uuid.hpp>
#include "misc_log_ex.h"

#define CRYPTONOTE_DNS_TIMEOUT_MS                                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                                     500000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                                     0x10000000
#define CRYPTONOTE_MAX_TX_SIZE                                          1000000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER                          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW                            10
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW_V6                         20
#define TRANSACTION_VERSION_V1                                          1
#define TRANSACTION_VERSION_V2                                          2
#define TRANSACTION_VERSION_MAX                                         TRANSACTION_VERSION_V2
#define V2_TX_FORK_HEIGHT                                               12
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT                              60 * 60 * 2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE                             10

#define BULLETPROOF_MAX_OUTPUTS                                         16
#define BULLETPROOF_SIMPLE_FORK_HEIGHT                                  8
#define BULLETPROOF_FULL_FORK_HEIGHT                                    11

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW                               60

#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2                           60 * 24
#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V2                            12

#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V6                           60 * 5

#define MONEY_SUPPLY                                                    ((uint64_t)(-1))
#define EMISSION_SPEED_FACTOR_PER_MINUTE                                (18)
#define FINAL_SUBSIDY_PER_MINUTE                                        ((uint64_t)300000000000)

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE                       300000
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE                          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                                12
#define COIN                                                            ((uint64_t)1000000000000)

#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE                   50000

#define DEFAULT_MIXIN                                                   4
#define DEFAULT_RINGSIZE                                                DEFAULT_MIXIN + 1
#define DYNAMIC_FEE_PER_KB_BASE_FEE                                     ((uint64_t)400000000)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD                            ((uint64_t)10000000000000)

#define DIFFICULTY_TARGET                                               60
#define DIFFICULTY_WINDOW                                               720
#define DIFFICULTY_LAG                                                  15
#define DIFFICULTY_CUT                                                  60
#define DIFFICULTY_BLOCKS_COUNT                                         DIFFICULTY_WINDOW + DIFFICULTY_LAG

#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN                             DIFFICULTY_TARGET
#define DIFFICULTY_WINDOW_V2                                            17
#define DIFFICULTY_CUT_V2                                               6
#define DIFFICULTY_BLOCKS_COUNT_V2                                      DIFFICULTY_WINDOW_V2 + DIFFICULTY_CUT_V2 * 2

#define DIFFICULTY_WINDOW_V3                                            60
#define DIFFICULTY_BLOCKS_COUNT_V3                                      DIFFICULTY_WINDOW_V3

#define DIFFICULTY_WINDOW_V6                                            60
#define DIFFICULTY_BLOCKS_COUNT_V6                                      DIFFICULTY_WINDOW_V6 + 1

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1                   DIFFICULTY_TARGET *CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS                       1

#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT                          10000
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT                              20
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                                  2048

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                                  (86400 * 3)
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME                   604800

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT                           1000

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                                   13
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                                  60
#define P2P_DEFAULT_PACKET_MAX_SIZE                                     50000000
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                                  5000
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT                             2000
#define P2P_DEFAULT_INVOKE_TIMEOUT                                      60 * 2 * 1000
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT                            5000
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT                       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT                            2

#define P2P_FAILED_ADDR_FORGET_SECONDS                                  (60 * 7)
#define P2P_IP_BLOCKTIME_MAINNET                                        (60 * 60 * 24)
#define P2P_IP_BLOCKTIME_TESTNET                                        (60 * 5)
#define P2P_IP_FAILS_BEFORE_BLOCK                                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL                               (5 * 60)
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT                               45
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT                       2
#define P2P_DEFAULT_LIMIT_RATE_UP                                       2048
#define P2P_DEFAULT_LIMIT_RATE_DOWN                                     8192

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                                  0x01
#define P2P_SUPPORT_FLAGS                                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define RPC_IP_FAILS_BEFORE_BLOCK                                       3

#define CRYPTONOTE_PRUNING_STRIPE_SIZE                                  4096
#define CRYPTONOTE_PRUNING_LOG_STRIPES                                  3
#define CRYPTONOTE_PRUNING_TIP_BLOCKS                                   5500

//#define ALLOW_DEBUG_COMMANDS

#define CRYPTONOTE_NAME                                                 "nerva"
#define CRYPTONOTE_POOLDATA_FILENAME                                    "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME                              "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME                         "lock.mdb"
#define P2P_NET_DATA_FILENAME                                           "p2pstate.nerva.v11.bin"
#define MINER_CONFIG_FILE_NAME                                          "miner_conf.json"

#define THREAD_STACK_SIZE                                               5 * 1024 * 1024

#define PER_KB_FEE_QUANTIZATION_DECIMALS                                8

#define HASH_OF_HASHES_STEP                                             256

#define DEFAULT_TXPOOL_MAX_WEIGHT                                       648000000ull

#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT                               12
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR                 50

#define CRYPTONOTE_NOISE_MIN_EPOCH                                      5
#define CRYPTONOTE_NOISE_EPOCH_RANGE                                    30
#define CRYPTONOTE_NOISE_MIN_DELAY                                      10
#define CRYPTONOTE_NOISE_DELAY_RANGE                                    5
#define CRYPTONOTE_NOISE_BYTES                                          3*1024
#define CRYPTONOTE_NOISE_CHANNELS                                       2 

#define CRYPTONOTE_MAX_FRAGMENTS                                        20

#define DONATION_ADDR "NV1aMtARDQjK8j7XeoQ66S7XQe5ZS8CX92XqXmJxSZMpSDf2i11NQyqgHzghmRsDHR1LwYv3bEnE3VoqqbmyRdrR2MMBfdXvY"

struct hard_fork
{
    uint8_t version;
    uint64_t height;
};

namespace config
{
    uint64_t const DEFAULT_DUST_THRESHOLD = 0;
    std::string const P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x3800;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x7081;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x1080;
    uint16_t const P2P_DEFAULT_PORT = 17565;
    uint16_t const RPC_DEFAULT_PORT = 17566;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 17567;
    boost::uuids::uuid const NETWORK_ID = {{0x12, 0x30, 0xF1, 0x71, 0x61, 0x04, 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12}};
    std::string const GENESIS_TX = "010a01ff0001ffffffffffff0f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101abf318a3dc8d66a0263839cffce83daa85963a27635a608a2ba9973055bcc8e400";

    uint32_t const GENESIS_NONCE = 10000;

    std::string const HF_MIN_VERSION = "0.1.7.0";
    std::string const MIN_VERSION    = "0.1.6.4";

    static const hard_fork hard_forks[] = {
        { 1,      1},
        { 2,      2},
        { 3,      3},
        { 4,      4},
        { 5,      5},
        { 6,  44500},
        { 7, 173500},
        { 8, 180000},
        { 9, 240500},
        {10, 341000},
        {11, 500000},
        {12, 930000}
    };

    namespace testnet
    {
        uint16_t const P2P_DEFAULT_PORT = 18565;
        uint16_t const RPC_DEFAULT_PORT = 18566;
        uint16_t const ZMQ_RPC_DEFAULT_PORT = 18567;
        boost::uuids::uuid const NETWORK_ID = {{0x13, 0x22, 0xF0, 0x55, 0x42, 0x18, 0x40, 0x33, 0x16, 0x88, 0x01, 0x92, 0xAA, 0xBC, 0xFF, 0x13}};

        std::string const HF_MIN_VERSION = "0.1.7.0";
        std::string const MIN_VERSION    = "0.1.6.4";

        static const hard_fork hard_forks[] = {
            { 1,   1},
            { 2,   2},
            { 3,   3},
            { 4,   4},
            { 5,   5},
            { 6,   6},
            { 7, 550},
            { 8, 560},
            { 9, 570},
            {10, 580},
            {11, 590},
            {12, 2000}
        };
    }

    namespace stagenet
    {
        uint16_t const P2P_DEFAULT_PORT = 19565;
        uint16_t const RPC_DEFAULT_PORT = 19566;
        uint16_t const ZMQ_RPC_DEFAULT_PORT = 19567;
        boost::uuids::uuid const NETWORK_ID = {{0x14, 0x31, 0xF1, 0x22, 0x54, 0x86, 0x36, 0xFF, 0xAB, 0x51, 0x00, 0x4F, 0x3C, 0x3D, 0xAA, 0x16}};
        
        static const hard_fork hard_forks[] = {
            { 1,   1},
            { 2,   2},
            { 3,   3},
            { 4,   4},
            { 5,   5},
            { 6,   6},
            { 7, 550},
            { 8, 560},
            { 9, 570},
            {10, 580},
            {11, 590},
            {12, 700}
        };
    }
}

#ifndef VERSION_TO_INT
#define VERSION_TO_INT

inline uint32_t version_string_to_integer(std::string data)
{
    const char *v = data.c_str();

    unsigned int byte3;
    unsigned int byte2;
    unsigned int byte1;
    unsigned int byte0;
    char dummyString[2];

    if (sscanf(v, "%u.%u.%u%1s", &byte2, &byte1, &byte0, dummyString) == 3)
        return (byte2 << 24) + (byte1 << 16) + byte0; //3 part versioning scheme
    else if (sscanf(v, "%u.%u.%u.%u%1s", &byte3, &byte2, &byte1, &byte0, dummyString) == 4)
        return (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0; //4 part versioning scheme
    
    MGUSER_RED("Cound not interpret version number");
    return 0;
}

#endif

namespace cryptonote
{
    enum network_type : uint8_t
    {
        MAINNET = 0,
        TESTNET,
        STAGENET,
        FAKECHAIN,
        UNDEFINED = 255
    };

    struct config_t
    {
        uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
        uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
        uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
        uint16_t const P2P_DEFAULT_PORT;
        uint16_t const RPC_DEFAULT_PORT;
        uint16_t const ZMQ_RPC_DEFAULT_PORT;
        boost::uuids::uuid const NETWORK_ID;
        std::string const GENESIS_TX;
        uint32_t const GENESIS_NONCE;
        std::string const HF_MIN_VERSION;
        std::string const MIN_VERSION;
    };

    inline const config_t &get_config(network_type nettype)
    {
        static const config_t mainnet = {
            ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
            ::config::P2P_DEFAULT_PORT,
            ::config::RPC_DEFAULT_PORT,
            ::config::ZMQ_RPC_DEFAULT_PORT,
            ::config::NETWORK_ID,
            ::config::GENESIS_TX,
            ::config::GENESIS_NONCE,
            ::config::HF_MIN_VERSION,
            ::config::MIN_VERSION
            };
        static const config_t testnet = {
            ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
            ::config::testnet::P2P_DEFAULT_PORT,
            ::config::testnet::RPC_DEFAULT_PORT,
            ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
            ::config::testnet::NETWORK_ID,
            ::config::GENESIS_TX,
            ::config::GENESIS_NONCE,
            ::config::testnet::HF_MIN_VERSION,
            ::config::testnet::MIN_VERSION
            };
        static const config_t stagenet = {
            ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
            ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
            ::config::stagenet::P2P_DEFAULT_PORT,
            ::config::stagenet::RPC_DEFAULT_PORT,
            ::config::stagenet::ZMQ_RPC_DEFAULT_PORT,
            ::config::stagenet::NETWORK_ID,
            ::config::GENESIS_TX,
            ::config::GENESIS_NONCE,
            "", ""
            };

        switch (nettype)
        {
            case MAINNET:
                return mainnet;
            case TESTNET:
                return testnet;
            case STAGENET:
                return stagenet;
            case FAKECHAIN:
                return mainnet;
            default:
                throw std::runtime_error("Invalid network type");
        }
    };
}
