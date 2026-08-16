#!/usr/bin/env python3
"""
Nerva RPC API - OpenAPI 3.0 Specification Generator

Generates an OpenAPI 3.0 spec from the endpoint definitions in
src/rpc/core_rpc_server.h. The spec can be imported into Postman,
Insomnia, or swagger-codegen to produce SDK clients.

The endpoint list is extracted from the MAP_URI_AUTO_JON2 / MAP_JON_RPC
macros in core_rpc_server.h. Request/response schemas are written by
hand for the most commonly used endpoints and fall back to a generic
object schema for the rest.

Usage:
    python3 scripts/openapi/generate_openapi.py

Output:
    docs/openapi.yaml (not committed; run the script to generate)
"""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install -r scripts/openapi/requirements.txt", file=sys.stderr)
    sys.exit(1)

# Repository root (parent of scripts/openapi/)
REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_HEADER = REPO_ROOT / "src" / "rpc" / "core_rpc_server.h"
OUTPUT_FILE = REPO_ROOT / "docs" / "openapi.yaml"

# RPC port from src/cryptonote_config.h (mainnet 17566, testnet 18566, stagenet 19566)
MAINNET_RPC_PORT = 17566
TESTNET_RPC_PORT = 18566
STAGENET_RPC_PORT = 19566


def parse_endpoints_from_header():
    """
    Parse src/rpc/core_rpc_server.h to extract the list of REST and
    JSON-RPC endpoints. Returns (rest_endpoints, json_rpc_methods).

    Each REST endpoint is a dict: {path, handler, command, restricted, binary}.
    Each JSON-RPC method is a dict: {method, handler, command, restricted}.
    """
    content = SERVER_HEADER.read_text()

    rest_endpoints = []
    json_rpc_methods = []

    # Match: MAP_URI_AUTO_JON2("/path", on_handler, COMMAND_RPC_X)
    # and:  MAP_URI_AUTO_JON2_IF("/path", on_handler, COMMAND_RPC_X, !m_restricted)
    # and:  MAP_URI_AUTO_BIN2(...) for binary endpoints
    # The _IF variant is used for restricted endpoints (requires !m_restricted).
    rest_pattern = re.compile(
        r'MAP_URI_AUTO_(JON2|BIN2)(?:_IF)?\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*,\s*(\w+)\s*(?:,\s*([^)]+))?\s*\)'
    )
    for m in rest_pattern.finditer(content):
        kind = m.group(1)  # JON2 or BIN2
        path = m.group(2)
        handler = m.group(3)
        command = m.group(4)
        condition = m.group(5) or ""
        restricted = "m_restricted" in condition
        rest_endpoints.append({
            "path": path,
            "handler": handler,
            "command": command,
            "restricted": restricted,
            "binary": kind == "BIN2",
        })

    # Match: MAP_JON_RPC("name", on_handler, COMMAND_RPC_X)
    # and:  MAP_JON_RPC_WE("name", on_handler, COMMAND_RPC_X)
    # and:  MAP_JON_RPC_WE_IF("name", on_handler, COMMAND_RPC_X, !m_restricted)
    rpc_pattern = re.compile(
        r'MAP_JON_RPC(?:_WE)?(?:_IF)?\s*\(\s*"([^"]+)"\s*,\s*(\w+)\s*,\s*(\w+)\s*(?:,\s*([^)]+))?\s*\)'
    )
    for m in rpc_pattern.finditer(content):
        method = m.group(1)
        handler = m.group(2)
        command = m.group(3)
        condition = m.group(4) or ""
        restricted = "m_restricted" in condition
        json_rpc_methods.append({
            "method": method,
            "handler": handler,
            "command": command,
            "restricted": restricted,
        })

    # Deduplicate JSON-RPC methods (the header registers aliases like
    # "get_block_count" and "getblockcount" that point to the same handler)
    seen = set()
    unique_methods = []
    for m in json_rpc_methods:
        if m["method"] not in seen:
            seen.add(m["method"])
            unique_methods.append(m)

    return rest_endpoints, unique_methods


# Human-readable descriptions for the most common endpoints.
# Endpoints not in this dict get a generic description.
ENDPOINT_DESCRIPTIONS = {
    "/get_height": "Returns the current blockchain height and top block hash.",
    "/get_info": "Returns network information: height, difficulty, connections, mempool size, etc.",
    "/get_transactions": "Fetches one or more transactions by their hashes. Returns hex blobs and/or decoded JSON.",
    "/send_raw_transaction": "Submits a signed raw transaction to the network. Returns whether the transaction was accepted and relayed.",
    "/is_key_image_spent": "Checks whether a given key image has been spent on the chain.",
    "/get_transaction_pool": "Returns the full transaction mempool (pending transactions).",
    "/get_transaction_pool_stats": "Returns statistics about the transaction mempool (count, bytes, fee sum, etc.).",
    "/get_blocks.bin": "Binary endpoint for fast block sync. Returns block blobs for a set of requested block hashes.",
    "/get_blocks_by_height.bin": "Binary endpoint. Returns block blobs for a list of heights.",
    "/get_hashes.bin": "Binary endpoint. Returns block hashes for a range of heights (used during sync).",
    "/get_o_indexes.bin": "Binary endpoint. Returns global output indexes for a transaction's outputs.",
    "/get_outs.bin": "Binary endpoint. Returns output keys and commitments for a set of global output indexes.",
    "/get_outs": "Returns output keys and commitments for a set of global output indexes (JSON variant).",
    "/get_alt_blocks_hashes": "Returns the hashes of all alternative (non-mainchain) blocks known to the daemon.",
    "/get_peer_list": "Returns the white and gray peer lists. Restricted.",
    "/get_public_nodes": "Returns a list of public nodes that can be used as peers or bootstrap daemons.",
    "/get_limit": "Returns the current upload and download rate limits.",
    "/start_mining": "Starts the internal miner. Restricted.",
    "/stop_mining": "Stops the internal miner. Restricted.",
    "/mining_status": "Returns the current mining status (hash rate, threads, address). Restricted.",
    "/set_donate_level": "Sets the donation percentage for the internal miner. Nerva-specific. Restricted.",
    "/save_bc": "Forces the blockchain database to be flushed to disk. Restricted.",
    "/pop_blocks": "Pops N blocks from the chain tip. Restricted, for testing only.",
}

# Nerva-specific endpoints (not present in Monero)
NERVA_SPECIFIC = {
    "get_generated_coins", "get_min_version", "get_tx_pubkey",
    "decode_outputs", "add_peer", "set_donate_level",
}


def categorize_endpoint(path, handler, command):
    """Return the tag (category) for an endpoint."""
    if command in NERVA_SPECIFIC or "donate" in path:
        return "Nerva-specific"
    if "transaction_pool" in path or "txpool" in path or "mempool" in handler.lower():
        return "Mempool"
    if "block" in path or "block" in handler.lower():
        return "Blocks"
    if "tx" in path.lower() or "transaction" in path or "tx" in handler.lower():
        return "Transactions"
    if "mining" in path or "miner" in handler.lower() or "donate" in path:
        return "Mining"
    if "peer" in path or "connection" in handler.lower() or "ban" in handler.lower():
        return "Peers"
    if "log" in path:
        return "Logging"
    if "daemon" in handler.lower() or "save" in path or "update" in path or "limit" in path:
        return "Daemon"
    return "Network"


def categorize_json_rpc(method):
    """Return the tag (category) for a JSON-RPC method."""
    if method in NERVA_SPECIFIC:
        return "Nerva-specific"
    if "block" in method:
        return "Blocks"
    if "tx" in method or "transaction" in method:
        return "Transactions"
    if "fee" in method:
        return "Fees"
    if "ban" in method:
        return "Peers"
    if "fork" in method:
        return "Hard Forks"
    if "version" in method:
        return "Version"
    if "output" in method:
        return "Outputs"
    if "txpool" in method or "flush" in method or "relay" in method or "sync" in method:
        return "Mempool"
    if "coinbase" in method:
        return "Blocks"
    if "connection" in method:
        return "Peers"
    if "prune" in method or "cache" in method:
        return "Daemon"
    return "Network"


def build_schema_for_command(command):
    """
    Build an OpenAPI schema reference for a COMMAND_RPC_* struct.
    For now, we return a generic object since auto-parsing the C++ structs
    from commands_defs.h would require a full C++ parser.
    The most common endpoints have hand-written schemas in the components section.
    """
    known_schemas = {
        "COMMAND_RPC_GET_HEIGHT": "GetHeightResponse",
        "COMMAND_RPC_GET_INFO": "GetInfoResponse",
        "COMMAND_RPC_GET_TRANSACTIONS": "GetTransactionsResponse",
        "COMMAND_RPC_SEND_RAW_TX": "SendRawTxResponse",
        "COMMAND_RPC_GET_TRANSACTION_POOL": "GetTransactionPoolResponse",
        "COMMAND_RPC_GET_TRANSACTION_POOL_STATS": "GetTransactionPoolStatsResponse",
        "COMMAND_RPC_IS_KEY_IMAGE_SPENT": "IsKeyImageSpentResponse",
        "COMMAND_RPC_GET_PER_KB_FEE_ESTIMATE": "FeeEstimateResponse",
        "COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT": "BlockHeaderByHeightResponse",
        "COMMAND_RPC_GET_BLOCK_HEADERS_RANGE": "BlockHeadersRangeResponse",
        "COMMAND_RPC_GET_LAST_BLOCK_HEADER": "LastBlockHeaderResponse",
        "COMMAND_RPC_GET_BLOCK": "GetBlockResponse",
        "COMMAND_RPC_HARD_FORK_INFO": "HardForkInfoResponse",
        "COMMAND_RPC_GET_VERSION": "GetVersionResponse",
        "COMMAND_RPC_GET_GENERATED_COINS": "GetGeneratedCoinsResponse",
    }
    schema_name = known_schemas.get(command)
    if schema_name:
        return {"$ref": f"#/components/schemas/{schema_name}"}
    return {"type": "object", "description": "Response schema (see COMMAND_RPC_* in core_rpc_server_commands_defs.h)"}


def build_json_rpc_description(json_rpc_methods):
    """
    Build the /json_rpc description, splitting methods into public and
    restricted groups so integrators know which ones are safe to expose
    on a public node.
    """
    public_methods = sorted(m["method"] for m in json_rpc_methods if not m["restricted"])
    restricted_methods = sorted(m["method"] for m in json_rpc_methods if m["restricted"])

    desc = (
        "Submit a JSON-RPC 2.0 request. The `method` field selects the daemon RPC command.\n\n"
        f"Public methods ({len(public_methods)} total) — safe to expose on a public node:\n"
        + ", ".join(f"`{m}`" for m in public_methods)
        + "\n\n"
        f"Restricted methods ({len(restricted_methods)} total) — require the daemon to be started "
        "without --restricted-rpc, or with --rpc-login authentication. Do NOT expose these on a public node:\n"
        + ", ".join(f"`{m}`" for m in restricted_methods)
    )
    return desc


def build_openapi_spec(rest_endpoints, json_rpc_methods):
    """Build the complete OpenAPI 3.0 specification."""

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Nerva Daemon RPC API",
            "description": (
                "REST and JSON-RPC API for the Nerva (XNV) daemon.\n\n"
                "The daemon exposes two types of endpoints:\n"
                "1. REST-style endpoints (e.g. /get_info, /get_transactions)\n"
                "2. JSON-RPC 2.0 methods under /json_rpc\n\n"
                "Endpoints marked as restricted require the daemon to be started "
                "without --restricted-rpc, or with --rpc-login authentication.\n\n"
                "Default ports: mainnet 17566, testnet 18566, stagenet 19566."
            ),
            "version": "1.0.0",
            "contact": {
                "name": "Nerva Project",
                "url": "https://nerva.one",
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT",
            },
        },
        "servers": [
            {"url": f"http://localhost:{MAINNET_RPC_PORT}", "description": "Local mainnet daemon"},
            {"url": f"http://localhost:{TESTNET_RPC_PORT}", "description": "Local testnet daemon"},
            {"url": f"http://localhost:{STAGENET_RPC_PORT}", "description": "Local stagenet daemon"},
        ],
        "tags": [
            {"name": "Network", "description": "Network info and statistics"},
            {"name": "Blocks", "description": "Block queries and submission"},
            {"name": "Transactions", "description": "Transaction queries and submission"},
            {"name": "Mempool", "description": "Transaction mempool operations"},
            {"name": "Mining", "description": "Mining and block templates"},
            {"name": "Peers", "description": "Peer list and connection management"},
            {"name": "Fees", "description": "Fee estimation"},
            {"name": "Outputs", "description": "Output queries"},
            {"name": "Hard Forks", "description": "Hard fork information"},
            {"name": "Version", "description": "Daemon version info"},
            {"name": "Logging", "description": "Log level management"},
            {"name": "Daemon", "description": "Daemon control and maintenance"},
            {"name": "Nerva-specific", "description": "Endpoints specific to Nerva (not in Monero)"},
            {"name": "Restricted", "description": "Endpoints requiring non-restricted RPC"},
        ],
        "paths": {},
        "components": {
            "schemas": build_component_schemas(),
        },
    }

    # Add REST endpoints
    for ep in rest_endpoints:
        path = ep["path"]
        # All Nerva REST endpoints use POST (the epee framework accepts both
        # GET and POST, but the convention for endpoints with a request body
        # is POST).
        method = "post"
        tag = categorize_endpoint(path, ep["handler"], ep["command"])
        description = ENDPOINT_DESCRIPTIONS.get(path)
        if description is None:
            description = f"RPC endpoint handled by {ep['handler']} ({ep['command']})."
            if ep["binary"]:
                description += " Returns binary data (not JSON)."
            if ep["restricted"]:
                description += " Restricted: requires non-restricted RPC."
            if ep["command"] in NERVA_SPECIFIC or "donate" in path:
                description += " Nerva-specific (not in Monero)."

        tags = [tag]
        if ep["restricted"]:
            tags.append("Restricted")

        operation = {
            "tags": tags,
            "summary": description.split(".")[0] + ".",
            "description": description,
            "operationId": ep["handler"] + "_" + path.replace("/", "_").replace(".", "_"),
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json" if not ep["binary"] else "application/octet-stream": {
                            "schema": build_schema_for_command(ep["command"]) if not ep["binary"]
                                      else {"type": "string", "format": "binary"},
                        },
                    },
                },
            },
        }

        if path not in spec["paths"]:
            spec["paths"][path] = {}
        spec["paths"][path][method] = operation

    # Add the JSON-RPC endpoint
    spec["paths"]["/json_rpc"] = {
        "post": {
            "tags": ["JSON-RPC"],
            "summary": "JSON-RPC 2.0 endpoint",
            "description": build_json_rpc_description(json_rpc_methods),
            "operationId": "json_rpc",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/JsonRpcRequest"},
                    },
                },
            },
            "responses": {
                "200": {
                    "description": "JSON-RPC response",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/JsonRpcResponse"},
                        },
                    },
                },
            },
        }
    }

    return spec


def build_component_schemas():
    """Build reusable schema components for common endpoints."""
    return {
        "JsonRpcRequest": {
            "type": "object",
            "required": ["jsonrpc", "method", "id"],
            "properties": {
                "jsonrpc": {"type": "string", "enum": ["2.0"], "example": "2.0"},
                "method": {"type": "string", "description": "The RPC method name (e.g. get_info, get_block_header_by_height)"},
                "params": {"type": "object", "description": "Method-specific parameters"},
                "id": {"type": "integer", "example": 1},
            },
        },
        "JsonRpcResponse": {
            "type": "object",
            "properties": {
                "jsonrpc": {"type": "string", "example": "2.0"},
                "result": {"type": "object", "description": "Method-specific result. See the C++ COMMAND_RPC_* struct in core_rpc_server_commands_defs.h for the exact fields."},
                "error": {
                    "type": "object",
                    "nullable": True,
                    "properties": {
                        "code": {"type": "integer", "description": "JSON-RPC error code"},
                        "message": {"type": "string", "description": "Error message"},
                    },
                },
                "id": {"type": "integer"},
            },
        },
        "GetHeightResponse": {
            "type": "object",
            "properties": {
                "height": {"type": "integer", "format": "uint64", "description": "Current blockchain height"},
                "hash": {"type": "string", "description": "Top block hash (hex)"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean", "description": "True if response came from a bootstrap daemon"},
            },
        },
        "GetInfoResponse": {
            "type": "object",
            "description": "Network information returned by /get_info",
            "properties": {
                "height": {"type": "integer", "format": "uint64", "description": "Current blockchain height"},
                "target_height": {"type": "integer", "format": "uint64", "description": "Target height (may differ during sync)"},
                "difficulty": {"type": "integer", "format": "uint64", "description": "Current difficulty"},
                "target": {"type": "integer", "format": "uint64", "description": "Block target time in seconds (60)"},
                "tx_count": {"type": "integer", "format": "uint64", "description": "Total transaction count in the chain"},
                "tx_pool_size": {"type": "integer", "format": "uint64", "description": "Number of transactions in the mempool"},
                "alt_blocks_count": {"type": "integer", "format": "uint64"},
                "outgoing_connections_count": {"type": "integer", "format": "uint64"},
                "incoming_connections_count": {"type": "integer", "format": "uint64"},
                "rpc_connections_count": {"type": "integer", "format": "uint64"},
                "white_peerlist_size": {"type": "integer", "format": "uint64"},
                "grey_peerlist_size": {"type": "integer", "format": "uint64"},
                "mainnet": {"type": "boolean"},
                "testnet": {"type": "boolean"},
                "stagenet": {"type": "boolean"},
                "nettype": {"type": "string", "example": "mainnet"},
                "top_block_hash": {"type": "string"},
                "cumulative_difficulty": {"type": "integer", "format": "uint64"},
                "cumulative_difficulty_top64": {"type": "integer", "format": "uint64"},
                "block_size_limit": {"type": "integer", "format": "uint64"},
                "block_weight_limit": {"type": "integer", "format": "uint64"},
                "block_size_median": {"type": "integer", "format": "uint64"},
                "block_weight_median": {"type": "integer", "format": "uint64"},
                "start_time": {"type": "integer", "format": "uint64", "description": "Daemon start time (unix timestamp)"},
                "free_space": {"type": "integer", "format": "uint64", "description": "Free disk space in bytes"},
                "offline": {"type": "boolean"},
                "bootstrap_daemon_address": {"type": "string"},
                "height_without_bootstrap": {"type": "integer", "format": "uint64"},
                "was_bootstrap_ever_used": {"type": "boolean"},
                "database_size": {"type": "integer", "format": "uint64"},
                "update_available": {"type": "boolean"},
                "version": {"type": "string"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetTransactionsResponse": {
            "type": "object",
            "properties": {
                "txs": {
                    "type": "array",
                    "items": {"$ref": "#/components/schemas/TransactionEntry"},
                },
                "txs_as_hex": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Transaction blobs as hex (legacy compat)",
                },
                "txs_as_json": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Transactions decoded as JSON (legacy compat)",
                },
                "missed_tx": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Hashes of transactions that were not found",
                },
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "TransactionEntry": {
            "type": "object",
            "properties": {
                "tx_hash": {"type": "string"},
                "as_hex": {"type": "string", "description": "Full transaction blob as hex"},
                "pruned_as_hex": {"type": "string"},
                "prunable_as_hex": {"type": "string"},
                "prunable_hash": {"type": "string"},
                "as_json": {"type": "string", "description": "Transaction decoded as JSON (if decode_as_json=true)"},
                "in_pool": {"type": "boolean", "description": "True if the transaction is in the mempool"},
                "double_spend_seen": {"type": "boolean"},
                "block_height": {"type": "integer", "format": "uint64", "description": "Block height (only if not in pool)"},
                "block_timestamp": {"type": "integer", "format": "uint64", "description": "Block timestamp (only if not in pool)"},
                "output_indices": {"type": "array", "items": {"type": "integer", "format": "uint64"}},
                "relayed": {"type": "boolean", "description": "Whether the tx was relayed (only if in pool)"},
            },
        },
        "SendRawTxResponse": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "example": "OK"},
                "double_spend": {"type": "boolean"},
                "fee_too_low": {"type": "boolean"},
                "invalid_input": {"type": "boolean"},
                "invalid_output": {"type": "boolean"},
                "too_big": {"type": "boolean"},
                "overspend": {"type": "boolean"},
                "too_few_outputs": {"type": "boolean"},
                "sanity_check_failed": {"type": "boolean"},
                "tx_extra_too_big": {"type": "boolean", "description": "Nerva-specific: tx-extra exceeds MAX_TX_EXTRA_SIZE (1060 bytes)"},
                "not_rct": {"type": "boolean", "description": "Transaction is not RingCT"},
                "reason": {"type": "string", "description": "Comma-separated list of rejection reasons"},
                "not_relayed": {"type": "boolean"},
                "low_mixin": {"type": "boolean"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetTransactionPoolResponse": {
            "type": "object",
            "properties": {
                "transactions": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of mempool transactions",
                },
                "spent_key_images": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Key images spent by mempool transactions",
                },
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetTransactionPoolStatsResponse": {
            "type": "object",
            "properties": {
                "pool_stats": {
                    "type": "object",
                    "properties": {
                        "bytes_total": {"type": "integer", "format": "uint64"},
                        "bytes_min": {"type": "integer", "format": "uint64"},
                        "bytes_max": {"type": "integer", "format": "uint64"},
                        "bytes_med": {"type": "integer", "format": "uint64"},
                        "fee_total": {"type": "integer", "format": "uint64"},
                        "txs_total": {"type": "integer"},
                        "count": {"type": "integer"},
                        "not_relayed": {"type": "integer"},
                        "oldest": {"type": "integer", "format": "uint64"},
                        "histo": {"type": "array", "items": {"type": "object"}},
                    },
                },
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "IsKeyImageSpentResponse": {
            "type": "object",
            "properties": {
                "spent_status": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "0 = unspent, 1 = spent in blockchain, 2 = spent in mempool",
                },
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "FeeEstimateResponse": {
            "type": "object",
            "properties": {
                "fee": {"type": "integer", "format": "uint64", "description": "Estimated fee per kB in atomic units"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "BlockHeaderByHeightResponse": {
            "type": "object",
            "properties": {
                "block_header": {"$ref": "#/components/schemas/BlockHeader"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "BlockHeadersRangeResponse": {
            "type": "object",
            "properties": {
                "headers": {"type": "array", "items": {"$ref": "#/components/schemas/BlockHeader"}},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "LastBlockHeaderResponse": {
            "type": "object",
            "properties": {
                "block_header": {"$ref": "#/components/schemas/BlockHeader"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetBlockResponse": {
            "type": "object",
            "properties": {
                "blob": {"type": "string", "description": "Full block blob as hex"},
                "block_header": {"$ref": "#/components/schemas/BlockHeader"},
                "json": {"type": "string", "description": "Block decoded as JSON"},
                "miner_tx": {"type": "object"},
                "tx_hashes": {"type": "array", "items": {"type": "string"}},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "BlockHeader": {
            "type": "object",
            "properties": {
                "height": {"type": "integer", "format": "uint64"},
                "hash": {"type": "string"},
                "prev_hash": {"type": "string"},
                "timestamp": {"type": "integer", "format": "uint64"},
                "difficulty": {"type": "integer", "format": "uint64"},
                "cumulative_difficulty": {"type": "integer", "format": "uint64"},
                "reward": {"type": "integer", "format": "uint64"},
                "block_size": {"type": "integer", "format": "uint64"},
                "block_weight": {"type": "integer", "format": "uint64"},
                "long_term_weight": {"type": "integer", "format": "uint64"},
                "num_txes": {"type": "integer"},
                "nonce": {"type": "integer", "format": "uint64"},
                "orphan_status": {"type": "boolean"},
                "depth": {"type": "integer"},
                "major_version": {"type": "integer"},
                "minor_version": {"type": "integer"},
                "miner_tx_hash": {"type": "string"},
            },
        },
        "HardForkInfoResponse": {
            "type": "object",
            "properties": {
                "version": {"type": "integer", "description": "Current hard fork version"},
                "enabled": {"type": "boolean", "description": "Whether hard forks are enabled"},
                "window": {"type": "integer", "description": "Voting window size (blocks)"},
                "votes": {"type": "integer"},
                "threshold": {"type": "integer"},
                "voting": {"type": "integer", "description": "Version being voted for"},
                "state": {"type": "integer"},
                "earliest_height": {"type": "integer", "format": "uint64", "description": "Height at which the next fork activates"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetVersionResponse": {
            "type": "object",
            "properties": {
                "version": {"type": "integer", "description": "Daemon version as an integer"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
        "GetGeneratedCoinsResponse": {
            "type": "object",
            "description": "Nerva-specific: returns total coins generated up to a given height",
            "properties": {
                "coins": {"type": "integer", "format": "uint64", "description": "Total emitted coins in atomic units (divide by 10^12 for XNV)"},
                "status": {"type": "string", "example": "OK"},
                "untrusted": {"type": "boolean"},
            },
        },
    }


def main():
    if not SERVER_HEADER.exists():
        print(f"Error: {SERVER_HEADER} not found", file=sys.stderr)
        sys.exit(1)

    rest_endpoints, json_rpc_methods = parse_endpoints_from_header()

    spec = build_openapi_spec(rest_endpoints, json_rpc_methods)

    # Ensure docs directory exists
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        yaml.dump(spec, f, default_flow_style=False, sort_keys=False, width=120)

    # Print summary to stderr so it doesn't interfere with piping the YAML
    public_rpc = [m for m in json_rpc_methods if not m["restricted"]]
    restricted_rpc = [m for m in json_rpc_methods if m["restricted"]]
    restricted_rest = [e for e in rest_endpoints if e["restricted"]]

    print(f"Generated: {OUTPUT_FILE}", file=sys.stderr)
    print(f"  REST endpoints: {len(rest_endpoints)} ({len(restricted_rest)} restricted)", file=sys.stderr)
    print(f"  JSON-RPC methods: {len(json_rpc_methods)} ({len(public_rpc)} public, {len(restricted_rpc)} restricted)", file=sys.stderr)
    print(f"  Schema components: {len(spec['components']['schemas'])}", file=sys.stderr)
    print(f"  Total paths: {len(spec['paths'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
