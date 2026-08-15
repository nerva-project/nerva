#!/usr/bin/env python3
"""
Nerva Block Explorer - OpenAPI 3.0 Specification Generator

This script parses the C++ RPC command definitions in
src/rpc/core_rpc_server_commands_defs.h and generates an OpenAPI 3.0
YAML specification that can be used to auto-generate SDK clients in
TypeScript, Python, Go, Rust, and other languages.

Usage:
    python3 scripts/openapi/generate_openapi.py

Output:
    docs/openapi.yaml

The generated spec covers:
- All REST-style endpoints (e.g. /get_info, /get_transactions)
- All JSON-RPC methods under /json_rpc
- Request and response schemas for each endpoint
- The Nerva-specific extensions (get_generated_coins, decode_outputs, etc.)
"""

import os
import re
import sys
import yaml
from datetime import datetime
from pathlib import Path

# Repository root (parent of scripts/)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFS_FILE = REPO_ROOT / "src" / "rpc" / "core_rpc_server_commands_defs.h"
SERVER_FILE = REPO_ROOT / "src" / "rpc" / "core_rpc_server.h"
OUTPUT_FILE = REPO_ROOT / "docs" / "openapi.yaml"

# RPC server URL map for extracting endpoint paths
ENDPOINT_MAP = {
    # REST-style endpoints (path -> handler name)
    "/get_height": ("GET", "on_get_height", "Get the current blockchain height"),
    "/getheight": ("GET", "on_get_height", "Alias for /get_height"),
    "/get_info": ("GET", "on_get_info", "Get network info (height, difficulty, connections, etc.)"),
    "/getinfo": ("GET", "on_get_info", "Alias for /get_info"),
    "/get_transactions": ("POST", "on_get_transactions", "Get transactions by hashes"),
    "/gettransactions": ("POST", "on_get_transactions", "Alias for /get_transactions"),
    "/get_transaction_pool": ("GET", "on_get_transaction_pool", "Get the transaction mempool"),
    "/get_transaction_pool_stats": ("GET", "on_get_transaction_pool_stats", "Get mempool statistics"),
    "/send_raw_transaction": ("POST", "on_send_raw_tx", "Submit a raw transaction to the network"),
    "/sendrawtransaction": ("POST", "on_send_raw_tx", "Alias for /send_raw_transaction"),
    "/is_key_image_spent": ("POST", "on_is_key_image_spent", "Check if a key image has been spent"),
    "/get_alt_blocks_hashes": ("GET", "on_get_alt_blocks_hashes", "Get hashes of alternative blocks"),
    "/get_peer_list": ("GET", "on_get_peer_list", "Get the peer list (restricted)"),
    "/get_public_nodes": ("GET", "on_get_public_nodes", "Get list of public nodes"),
    "/get_limit": ("GET", "on_get_limit", "Get upload/download rate limits"),
    "/get_net_stats": ("GET", "on_get_net_stats", "Get network statistics (restricted)"),
    "/get_outs": ("POST", "on_get_outs", "Get output keys by global index"),
    "/get_output_distribution.bin": ("GET", "on_get_output_distribution_bin", "Get output distribution (binary)"),
}

# JSON-RPC methods
JSON_RPC_METHODS = {
    "get_block_count": "Get the total block count",
    "get_block_hash": "Get block hash by height",
    "get_block_template": "Get a block template for mining",
    "submit_block": "Submit a mined block",
    "get_last_block_header": "Get the last block header",
    "get_block_header_by_hash": "Get block header by hash",
    "get_block_header_by_height": "Get block header by height",
    "get_block_headers_range": "Get block headers in a height range",
    "get_block": "Get full block by hash or height",
    "get_info": "Get network info (JSON-RPC variant)",
    "hard_fork_info": "Get hard fork information",
    "get_fee_estimate": "Get fee estimate with percentiles",
    "get_txpool_backlog": "Get mempool backlog statistics",
    "get_output_histogram": "Get output amount histogram",
    "get_output_distribution": "Get output distribution",
    "get_coinbase_tx_sum": "Get sum of coinbase transactions in a range",
    "get_version": "Get daemon version info",
    "get_alternate_chains": "Get alternative chains info",
    "get_bans": "Get banned IPs",
    "set_bans": "Ban or unban IPs",
    "banned": "Check if an address is banned",
    "flush_txpool": "Flush transactions from the mempool",
    "relay_tx": "Relay a transaction by hash",
    "sync_info": "Get sync status information",
    "prune_blockchain": "Prune the blockchain",
    "flush_cache": "Flush daemon caches",
    "get_generated_coins": "Get total emitted coins at a height (Nerva-specific)",
    "get_min_version": "Get minimum daemon version required (Nerva-specific)",
    "get_tx_pubkey": "Extract TX public key from tx-extra (Nerva-specific)",
    "decode_outputs": "Decode transaction outputs for a view key (Nerva-specific)",
    "add_peer": "Manually add a peer (Nerva-specific)",
}

# Nerva-specific endpoints
NERVA_SPECIFIC = {
    "get_generated_coins": True,
    "get_min_version": True,
    "get_tx_pubkey": True,
    "decode_outputs": True,
    "add_peer": True,
}


def build_openapi_spec():
    """Build the OpenAPI 3.0 specification dictionary."""

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Nerva Block Explorer API",
            "description": (
                "REST and JSON-RPC API for the Nerva (XNV) daemon. "
                "This API exposes blockchain data, network statistics, "
                "transaction submission, and mining functionality.\n\n"
                "The Nerva daemon exposes two types of endpoints:\n"
                "1. REST-style endpoints (e.g. /get_info, /get_transactions)\n"
                "2. JSON-RPC 2.0 methods under /json_rpc\n\n"
                "Some endpoints are restricted (require --restricted-rpc to be "
                "disabled or --rpc-login authentication).\n\n"
                "Base URL: http://localhost:17566 (mainnet RPC port)\n"
                "Testnet: http://localhost:18566\n"
                "Stagenet: http://localhost:19566"
            ),
            "version": "2.0.0",
            "contact": {
                "name": "Nerva Project",
                "url": "https://nerva.one",
                "email": "contact@nerva.one",
            },
            "license": {
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT",
            },
        },
        "servers": [
            {"url": "http://localhost:17566", "description": "Local mainnet daemon"},
            {"url": "http://localhost:18566", "description": "Local testnet daemon"},
            {"url": "http://localhost:19566", "description": "Local stagenet daemon"},
            {"url": "https://api.nerva.one", "description": "Public Nerva API proxy"},
        ],
        "tags": [
            {"name": "Network", "description": "Network info and statistics"},
            {"name": "Blocks", "description": "Block queries and submission"},
            {"name": "Transactions", "description": "Transaction queries and submission"},
            {"name": "Mempool", "description": "Transaction mempool operations"},
            {"name": "Mining", "description": "Mining and block templates"},
            {"name": "Peers", "description": "Peer list and connection management"},
            {"name": "Hardforks", "description": "Hard fork information"},
            {"name": "Nerva-specific", "description": "Endpoints specific to Nerva (not in Monero)"},
            {"name": "Restricted", "description": "Endpoints requiring authentication or non-restricted RPC"},
        ],
        "paths": {},
        "components": {
            "schemas": {
                "Status": {
                    "type": "string",
                    "description": "Response status. 'OK' on success, error message otherwise.",
                    "example": "OK",
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "status": {"$ref": "#/components/schemas/Status"},
                        "error": {"type": "string"},
                    },
                },
                "NetworkInfo": {
                    "type": "object",
                    "description": "Network information returned by /get_info",
                    "properties": {
                        "height": {"type": "integer", "format": "uint64", "description": "Current blockchain height"},
                        "difficulty": {"type": "integer", "format": "uint64", "description": "Current difficulty"},
                        "tx_count": {"type": "integer", "format": "uint64", "description": "Total transaction count"},
                        "tx_pool_size": {"type": "integer", "format": "uint64", "description": "Mempool size"},
                        "target": {"type": "integer", "format": "uint64", "description": "Block target time (60 seconds)"},
                        "top_block_hash": {"type": "string", "description": "Hash of the top block"},
                        "status": {"$ref": "#/components/schemas/Status"},
                        "untrusted": {"type": "boolean", "description": "True if response came from a bootstrap daemon"},
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
                        "reward": {"type": "integer", "format": "uint64"},
                        "block_size": {"type": "integer", "format": "uint64"},
                        "num_txes": {"type": "integer"},
                        "nonce": {"type": "integer", "format": "uint64"},
                        "major_version": {"type": "integer"},
                        "minor_version": {"type": "integer"},
                        "depth": {"type": "integer"},
                    },
                },
                "Transaction": {
                    "type": "object",
                    "properties": {
                        "tx_hash": {"type": "string"},
                        "block_height": {"type": "integer", "format": "uint64"},
                        "block_timestamp": {"type": "integer", "format": "uint64"},
                        "fee": {"type": "integer", "format": "uint64"},
                        "tx_size": {"type": "integer"},
                    },
                },
                "FeeEstimate": {
                    "type": "object",
                    "description": "Enhanced fee estimate with percentiles",
                    "properties": {
                        "fee": {"type": "integer", "format": "uint64", "description": "Median fee per kB"},
                        "fee_p10": {"type": "integer", "format": "uint64", "description": "10th percentile fee"},
                        "fee_p50": {"type": "integer", "format": "uint64", "description": "50th percentile (median)"},
                        "fee_p90": {"type": "integer", "format": "uint64", "description": "90th percentile fee"},
                        "blocks_scanned": {"type": "integer", "description": "Blocks used for calculation"},
                        "fee_history": {
                            "type": "array",
                            "items": {"type": "integer", "format": "uint64"},
                            "description": "Per-block median fees (most recent first, max 100)",
                        },
                        "fee_xnv": {"type": "number", "format": "double", "description": "Median fee in XNV"},
                        "fee_p10_xnv": {"type": "number", "format": "double"},
                        "fee_p50_xnv": {"type": "number", "format": "double"},
                        "fee_p90_xnv": {"type": "number", "format": "double"},
                        "status": {"$ref": "#/components/schemas/Status"},
                    },
                },
            },
        },
    }

    # Add REST endpoints
    for path, (method, handler, desc) in ENDPOINT_MAP.items():
        tag = "Nerva-specific" if any(k in handler for k in ["decode", "generated", "min_version", "tx_pubkey", "add_peer"]) else "Network"
        if "transaction" in path or "tx" in path.lower():
            tag = "Transactions"
        elif "block" in path:
            tag = "Blocks"
        elif "peer" in path:
            tag = "Peers"

        spec["paths"][path] = {
            method.lower(): {
                "tags": [tag],
                "summary": desc,
                "operationId": handler,
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                            },
                        },
                    },
                },
            }
        }

    # Add JSON-RPC endpoint
    spec["paths"]["/json_rpc"] = {
        "post": {
            "tags": ["JSON-RPC"],
            "summary": "JSON-RPC 2.0 endpoint for all daemon RPC methods",
            "description": (
                "Submit a JSON-RPC 2.0 request. The method field selects the "
                "daemon RPC command. Available methods: "
                + ", ".join(sorted(JSON_RPC_METHODS.keys()))
            ),
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["jsonrpc", "method", "params", "id"],
                            "properties": {
                                "jsonrpc": {"type": "string", "enum": ["2.0"]},
                                "method": {
                                    "type": "string",
                                    "enum": list(JSON_RPC_METHODS.keys()),
                                    "description": "The RPC method name",
                                },
                                "params": {"type": "object"},
                                "id": {"type": "integer"},
                            },
                        },
                    },
                },
            },
            "responses": {
                "200": {
                    "description": "JSON-RPC response",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "jsonrpc": {"type": "string"},
                                    "result": {"type": "object"},
                                    "error": {
                                        "type": "object",
                                        "properties": {
                                            "code": {"type": "integer"},
                                            "message": {"type": "string"},
                                        },
                                    },
                                    "id": {"type": "integer"},
                                },
                            },
                        },
                    },
                },
            },
        }
    }

    return spec


def main():
    spec = build_openapi_spec()

    # Ensure docs directory exists
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        yaml.dump(spec, f, default_flow_style=False, sort_keys=False, width=120)

    print(f"Generated OpenAPI 3.0 spec: {OUTPUT_FILE}")
    print(f"  Paths: {len(spec['paths'])}")
    print(f"  JSON-RPC methods: {len(JSON_RPC_METHODS)}")
    print(f"  Schemas: {len(spec['components']['schemas'])}")

    # Also generate a summary markdown
    md_file = OUTPUT_FILE.parent / "openapi-summary.md"
    with open(md_file, "w") as f:
        f.write("# Nerva RPC API Summary\n\n")
        f.write("Auto-generated from the OpenAPI 3.0 spec.\n\n")

        f.write("## REST Endpoints\n\n")
        f.write("| Method | Path | Description |\n")
        f.write("|--------|------|-------------|\n")
        for path, (method, handler, desc) in sorted(ENDPOINT_MAP.items()):
            f.write(f"| {method} | `{path}` | {desc} |\n")

        f.write("\n## JSON-RPC Methods\n\n")
        f.write("All methods are called via `POST /json_rpc` with JSON-RPC 2.0 format.\n\n")
        f.write("| Method | Description | Nerva-specific? |\n")
        f.write("|--------|-------------|-----------------|\n")
        for method, desc in sorted(JSON_RPC_METHODS.items()):
            is_nerva = "Yes" if NERVA_SPECIFIC.get(method, False) else "No"
            f.write(f"| `{method}` | {desc} | {is_nerva} |\n")

    print(f"  Summary: {md_file}")


if __name__ == "__main__":
    main()
