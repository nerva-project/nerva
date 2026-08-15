# Nerva RPC API Summary

Auto-generated from the OpenAPI 3.0 spec.

## REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/get_alt_blocks_hashes` | Get hashes of alternative blocks |
| GET | `/get_height` | Get the current blockchain height |
| GET | `/get_info` | Get network info (height, difficulty, connections, etc.) |
| GET | `/get_limit` | Get upload/download rate limits |
| GET | `/get_net_stats` | Get network statistics (restricted) |
| GET | `/get_output_distribution.bin` | Get output distribution (binary) |
| POST | `/get_outs` | Get output keys by global index |
| GET | `/get_peer_list` | Get the peer list (restricted) |
| GET | `/get_public_nodes` | Get list of public nodes |
| GET | `/get_transaction_pool` | Get the transaction mempool |
| GET | `/get_transaction_pool_stats` | Get mempool statistics |
| POST | `/get_transactions` | Get transactions by hashes |
| GET | `/getheight` | Alias for /get_height |
| GET | `/getinfo` | Alias for /get_info |
| POST | `/gettransactions` | Alias for /get_transactions |
| POST | `/is_key_image_spent` | Check if a key image has been spent |
| POST | `/send_raw_transaction` | Submit a raw transaction to the network |
| POST | `/sendrawtransaction` | Alias for /send_raw_transaction |

## JSON-RPC Methods

All methods are called via `POST /json_rpc` with JSON-RPC 2.0 format.

| Method | Description | Nerva-specific? |
|--------|-------------|-----------------|
| `add_peer` | Manually add a peer (Nerva-specific) | Yes |
| `banned` | Check if an address is banned | No |
| `decode_outputs` | Decode transaction outputs for a view key (Nerva-specific) | Yes |
| `flush_cache` | Flush daemon caches | No |
| `flush_txpool` | Flush transactions from the mempool | No |
| `get_alternate_chains` | Get alternative chains info | No |
| `get_bans` | Get banned IPs | No |
| `get_block` | Get full block by hash or height | No |
| `get_block_count` | Get the total block count | No |
| `get_block_hash` | Get block hash by height | No |
| `get_block_header_by_hash` | Get block header by hash | No |
| `get_block_header_by_height` | Get block header by height | No |
| `get_block_headers_range` | Get block headers in a height range | No |
| `get_block_template` | Get a block template for mining | No |
| `get_coinbase_tx_sum` | Get sum of coinbase transactions in a range | No |
| `get_fee_estimate` | Get fee estimate with percentiles | No |
| `get_generated_coins` | Get total emitted coins at a height (Nerva-specific) | Yes |
| `get_info` | Get network info (JSON-RPC variant) | No |
| `get_last_block_header` | Get the last block header | No |
| `get_min_version` | Get minimum daemon version required (Nerva-specific) | Yes |
| `get_output_distribution` | Get output distribution | No |
| `get_output_histogram` | Get output amount histogram | No |
| `get_tx_pubkey` | Extract TX public key from tx-extra (Nerva-specific) | Yes |
| `get_txpool_backlog` | Get mempool backlog statistics | No |
| `get_version` | Get daemon version info | No |
| `hard_fork_info` | Get hard fork information | No |
| `prune_blockchain` | Prune the blockchain | No |
| `relay_tx` | Relay a transaction by hash | No |
| `set_bans` | Ban or unban IPs | No |
| `submit_block` | Submit a mined block | No |
| `sync_info` | Get sync status information | No |
