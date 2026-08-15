# Nerva

[![ci/gh-actions/build](https://github.com/nerva-project/nerva/actions/workflows/build.yml/badge.svg)](https://github.com/nerva-project/nerva/actions/workflows/build.yml)
[![ci/gh-actions/depends](https://github.com/nerva-project/nerva/actions/workflows/depends.yml/badge.svg)](https://github.com/nerva-project/nerva/actions/workflows/depends.yml)

**Latest release: [v0.3.0.0 `Legacy Remade`][nerva-releases-link]**

## Table of Contents

- [About](#about)
- [Enhanced Features](#enhanced-features)
- [Installing](#installing)
- [Contributing](#contributing)
- [Help](#help)
- [License](#license)

## About

Nerva (XNV) is a private and secure cryptocurrency that you can mine on your computer's CPU. It's GPU and ASIC resistant and tries to stay true to 1 CPU = 1 VOTE vision.

Nerva offers true privacy and fungibility, is untraceable and un-linkable, with users and transfer amounts hidden from the public.

Each miner requires a copy of the blockchain, hence there is no support for pool mining. Therefore, Nerva offers better decentralization and censorship resistance than the majority of other blockchains.

## Enhanced Features

This fork adds several enhancements to the upstream Nerva codebase. See [docs/FEATURE_ROADMAP.md](docs/FEATURE_ROADMAP.md) for the full implementation status and design details.

### Network Privacy

- **Dandelion++ stem propagation**: Transactions are forwarded to a single stem peer instead of being flooded to all peers, breaking the link between the originating node and the transaction. Enabled with `--dandelion++`.

- **Tor v3 onion auto-configuration**: The daemon can automatically create a v3 onion service via the Tor control port. Use `--anonymous-inbound auto,<bind-ip:port>` instead of specifying a hardcoded onion address.

### RPC and API

- **WebSocket subscription server**: A WebSocket server that pushes real-time `new_block`, `new_tx`, and `reorg` notifications to connected clients. Eliminates the need for polling. Module at `src/rpc/websocket/`.

- **Enhanced fee estimator**: The `get_fee_estimate` RPC now returns p10/p50/p90 fee percentiles and a 100-block fee history, giving wallets a more nuanced view of the fee market.

- **OpenAPI 3.0 spec generator**: A Python script (`scripts/openapi/generate_openapi.py`) that generates `docs/openapi.yaml` from the endpoint definitions, enabling auto-generation of SDK clients in TypeScript, Python, Go, Rust, and other languages.

### Notifications

- **HTTP webhooks**: `--block-webhook <url>` and `--reorg-webhook <url>` send JSON POST requests for each new block or reorg. Alternative to the subprocess-based `--block-notify` for container and cloud deployments.

### Mining

- **Miner IPC API**: A Unix domain socket IPC server (`src/cryptonote_basic/miner_ipc.cpp`) that allows NervaOne and other GUI applications to control the daemon's internal miner in real-time without using a network port.

### Future Features (HF15 structures)

The following features have their code structure in place but require a hard fork (HF15) for activation:

- **View Tags**: 1-byte per-output tag for fast wallet scanning (~8x speedup). Structure at `src/cryptonote_basic/view_tags.h`.
- **Burn-to-prioritize**: EIP-1559-style fee burning that reduces supply while prioritizing transactions. Structure at `src/cryptonote_basic/burn.h`.
- **Payment ID v2**: Extended 32-byte encrypted payment IDs for e-commerce metadata. Structure at `src/cryptonote_basic/payment_id_v2.h`.
- **UTXO snapshot export/import**: File format for exporting the complete UTXO set at a given height, allowing bootstrap in minutes instead of hours. Structure at `src/extras/snapshot_export/`.
- **P2P zstd compression**: Optional zstd compression for P2P payloads (blocks, transactions). Wrapper at `src/net/p2p_zstd.cpp`.

### Known Issues (documented in FEATURE_ROADMAP.md)

- **Multisig HF14**: Multisig wallets cannot create transactions since HF14 because CLSAG does not support multisig in this codebase. The fix requires porting CLSAG multisig support from Monero (PRs #8123, #8234, #8580). See the design document for details.
- **Ledger HF14**: The Ledger app protocol speaks pre-CLSAG MLSAG, preventing HF14 transaction signing. A software fallback workaround is proposed in the design document.

## Installing

You can download precompiled binaries from the [releases][nerva-releases-link].

You can also use the official Nerva Docker image from Docker Hub. See [docs/DOCKER.md](docs/DOCKER.md) for instructions.

Alternatively, see [docs/BUILDING.md](docs/BUILDING.md) for build instructions.

### New CLI flags

| Flag | Description | Default |
|------|-------------|---------|
| `--dandelion++` | Enable Dandelion++ stem propagation for tx privacy | false |
| `--block-webhook <url>` | POST JSON to URL for each new block | (none) |
| `--reorg-webhook <url>` | POST JSON to URL for each reorg | (none) |
| `--anonymous-inbound auto,<bind>` | Auto-create a Tor v3 onion service | (none) |
| `--tor-control-host <host>` | Tor control port host | 127.0.0.1 |
| `--tor-control-port <port>` | Tor control port | 9051 |
| `--tor-cookie-auth-cookie <path>` | Path to Tor auth cookie | (none) |

## Contributing

We welcome all contributions from the community. If you are looking to help out, please refer to [CONTRIBUTING.md](docs/CONTRIBUTING.md) for a set of guidelines.

See [docs/FEATURE_ROADMAP.md](docs/FEATURE_ROADMAP.md) for the full list of implemented and planned features, including implementation status and design details for each.

## Help

Check out the project [documentation][nerva-docs-link], create an [issue][nerva-issues-link] or head to [Discord][nerva-discord-link] to get help from the community.

## License

[LICENSE](LICENSE)

Copyright (c) 2018-2026 The Nerva Project.
Copyright (c) 2014-2026 The Monero Project.
Copyright (c) 2017-2018 The Masari Project.
Portions Copyright (c) 2012-2013 The Cryptonote developers.

<!-- Reference links -->
[nerva-releases-link]: https://github.com/nerva-project/nerva/releases/latest
[nerva-docs-link]: https://docs.nerva.one
[nerva-issues-link]: https://github.com/nerva-project/nerva/issues
[nerva-discord-link]: https://discord.gg/ufysfvcFwe
