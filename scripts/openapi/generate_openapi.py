#!/usr/bin/env python3
# Copyright (c) 2018-2026, The Nerva Project
# Copyright (c) 2014-2026, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Nerva Daemon RPC API - OpenAPI 3.0 specification generator.

The spec is derived from the source of truth rather than kept by hand: the
routing table in src/rpc/core_rpc_server.h (MAP_URI_AUTO_* and MAP_JON_RPC
macros) provides every REST path and JSON-RPC method together with its
restricted status, and the request and response schemas are derived from the
KV_SERIALIZE maps of the corresponding structs in
src/rpc/core_rpc_server_commands_defs.h and
src/cryptonote_protocol/cryptonote_protocol_defs.h. A field or type that
cannot be resolved is a hard error, so the generator fails loudly instead of
silently emitting an incomplete spec.

The output, docs/openapi.yaml, is committed. The CI job in
.github/workflows/openapi.yml regenerates it and fails on drift, so a change
to the RPC surface has to be committed together with a regenerated spec.

Usage:
    python3 scripts/openapi/generate_openapi.py

Optional check that the generated spec is valid OpenAPI 3.0:
    pip install openapi-spec-validator
    openapi-spec-validator docs/openapi.yaml
"""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required. Install with: pip install -r scripts/openapi/requirements.txt",
          file=sys.stderr)
    sys.exit(1)

# Repository root (parent of scripts/openapi/)
REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_HEADER = REPO_ROOT / "src" / "rpc" / "core_rpc_server.h"
COMMANDS_HEADER = REPO_ROOT / "src" / "rpc" / "core_rpc_server_commands_defs.h"
PROTOCOL_HEADER = REPO_ROOT / "src" / "cryptonote_protocol" / "cryptonote_protocol_defs.h"
OUTPUT_FILE = REPO_ROOT / "docs" / "openapi.yaml"

# RPC bind ports from src/cryptonote_config.h
MAINNET_RPC_PORT = 17566
TESTNET_RPC_PORT = 18566
STAGENET_RPC_PORT = 19566

# Text used wherever restricted access matters. The wording is deliberate:
# --rpc-login never lifts restricted mode, and --rpc-restricted-bind-port
# implies restricted mode on its own listener.
RESTRICTED_NOTE = (
    "Restricted endpoints and methods are only registered when the daemon runs "
    "without --restricted-rpc and without --rpc-restricted-bind-port. --rpc-login "
    "adds HTTP digest authentication but does not re-enable restricted methods."
)

# Plausibility floors. If the parsers return fewer items than this, the source
# layout changed in a way the generator does not understand, and it must fail
# rather than emit a plausible-looking but empty spec.
MIN_REST_ENDPOINTS = 20
MIN_JSON_RPC_METHODS = 35
MIN_UNIQUE_METHOD_NAMES = 35


class ParseError(Exception):
    """Raised when the C++ sources cannot be parsed unambiguously."""


# ---------------------------------------------------------------------------
# Lexical helpers
# ---------------------------------------------------------------------------

def strip_comments(text, preserve=False):
    """Remove // and /* */ comments while respecting string literals.

    With preserve=True the removed text is replaced by spaces of the same
    length (newlines kept), so offsets in the cleaned text still line up with
    the original and member comments can be recovered separately.
    """
    out = []
    i = 0
    n = len(text)
    in_string = None  # ' or " while inside a literal
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_string:
            out.append(ch)
            if ch == "\\" and nxt:
                out.append(nxt)
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_string = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            j = text.find("\n", i)
            if j == -1:
                j = n
            if preserve:
                out.append(" " * (j - i))
            i = j  # the newline itself is copied on the next pass
            continue
        if ch == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                raise ParseError("unterminated block comment")
            if preserve:
                blanks = []
                for k in range(i, j + 2):
                    blanks.append("\n" if text[k] == "\n" else " ")
                out.append("".join(blanks))
            else:
                out.append(" ")
            i = j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def find_matching_brace(text, open_idx):
    """Return the index of the '}' matching the '{' at open_idx (deep aware of strings)."""
    depth = 0
    i = open_idx
    n = len(text)
    in_string = None
    while i < n:
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_string = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ParseError("unbalanced braces")


def find_matching_paren(text, open_idx):
    """Return the index of the ')' matching the '(' at open_idx."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ParseError("unbalanced parentheses")


# ---------------------------------------------------------------------------
# Routing table: src/rpc/core_rpc_server.h
# ---------------------------------------------------------------------------

# Order matters: the alternation is matched left to right, so the longer
# macro names must come first.
REST_MACRO_RE = re.compile(
    r"\bMAP_URI_AUTO_(JON2|BIN2)(?:_IF)?\s*\(\s*\"([^\"]+)\"\s*,\s*(\w+)\s*,\s*(\w+)\s*(?:,\s*([^)]+))?\s*\)"
)
JSON_RPC_MACRO_RE = re.compile(
    r"\bMAP_JON_RPC(?:_WE)?(?:_IF)?\s*\(\s*\"([^\"]+)\"\s*,\s*(\w+)\s*,\s*(\w+)\s*(?:,\s*([^)]+))?\s*\)"
)
# Every MAP_* routing macro invocation, successful or not, for the coverage
# check. No trailing word boundary: variants like MAP_JON_RPC_WE_IF must
# count, and no other identifier in the header starts with MAP_.
ANY_ROUTE_MACRO_RE = re.compile(r"\bMAP_")


def parse_routing():
    """Extract REST endpoints and JSON-RPC methods from the routing table.

    Returns (rest_endpoints, json_rpc_methods) where each REST endpoint is
    {path, handler, command, restricted, binary} and each JSON-RPC method is
    {method, handler, command, restricted}. Raises ParseError when the number
    of parsed entries does not match the number of macro invocations present
    in the file, which catches macro renames and format drift.
    """
    raw = SERVER_HEADER.read_text(encoding="utf-8")
    body = strip_comments(raw)

    rest_endpoints = []
    for m in REST_MACRO_RE.finditer(body):
        condition = m.group(5) or ""
        if condition and "m_restricted" not in condition:
            raise ParseError(
                f"unexpected routing condition {condition.strip()!r} for {m.group(2)}"
            )
        rest_endpoints.append({
            "path": m.group(2),
            "handler": m.group(3),
            "command": m.group(4),
            "restricted": "m_restricted" in condition,
            "binary": m.group(1) == "BIN2",
        })

    json_rpc_methods = []
    for m in JSON_RPC_MACRO_RE.finditer(body):
        condition = m.group(4) or ""
        if condition and "m_restricted" not in condition:
            raise ParseError(
                f"unexpected routing condition {condition.strip()!r} for {m.group(1)}"
            )
        json_rpc_methods.append({
            "method": m.group(1),
            "handler": m.group(2),
            "command": m.group(3),
            "restricted": "m_restricted" in condition,
        })

    # Coverage check: every routing macro in the file must have been parsed.
    total_macros = len(ANY_ROUTE_MACRO_RE.findall(body))
    total_parsed = len(rest_endpoints) + len(json_rpc_methods)
    if total_macros != total_parsed:
        raise ParseError(
            f"routing table parse mismatch: {total_macros} MAP_* macros in "
            f"{SERVER_HEADER.name} but only {total_parsed} were parsed; the "
            "macro format may have changed"
        )

    if len(rest_endpoints) < MIN_REST_ENDPOINTS:
        raise ParseError(f"only {len(rest_endpoints)} REST endpoints parsed")
    if len(json_rpc_methods) < MIN_JSON_RPC_METHODS:
        raise ParseError(f"only {len(json_rpc_methods)} JSON-RPC methods parsed")

    return rest_endpoints, json_rpc_methods

# ---------------------------------------------------------------------------
# Struct parsing: commands_defs.h and cryptonote_protocol_defs.h
# ---------------------------------------------------------------------------

STRUCT_HEAD_RE = re.compile(r"\bstruct\s+(\w+)\s*(?::\s*(?:public\s+)?(\w+)\s*)?\{")
MEMBER_RE = re.compile(
    r"^\s*([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*(?:\s*<[^;=]+>)?)\s+([A-Za-z_]\w*)\s*;"
    r"(?:\s*//\s*(.*?)\s*)?$"
)
# KV_SERIALIZE macros, longest names first so the alternation cannot truncate.
KV_MACRO_RE = re.compile(
    r"\bKV_SERIALIZE"
    r"(?:_VAL_POD_AS_BLOB_FORCE|_VAL_POD_AS_BLOB_OPT|_VAL_POD_AS_BLOB"
    r"|_CONTAINER_POD_AS_BLOB_OPT|_CONTAINER_POD_AS_BLOB"
    r"|_OPT|_PARENT)?"
    r"(?:_N)?"
    r"\s*\("
)


def extract_top_level_structs(text):
    """Yield (name, parent, body) for every struct definition in text."""
    structs = []
    for m in STRUCT_HEAD_RE.finditer(text):
        name = m.group(1)
        parent = m.group(2)
        open_idx = m.end() - 1
        close_idx = find_matching_brace(text, open_idx)
        body = text[open_idx + 1:close_idx]
        structs.append((name, parent, body))
    return structs


def parse_kv_entries(struct_body):
    """Parse the KV_SERIALIZE map of one struct body.

    Returns a list of entries:
      {kind, field, json_name, optional, conditional}
    kind is one of "field", "opt", "parent", "pod_blob", "container_blob".
    Entries emitted inside an if(...) block are marked conditional, since
    their presence on the wire depends on other fields.
    """
    begin = struct_body.find("BEGIN_KV_SERIALIZE_MAP()")
    end = struct_body.find("END_KV_SERIALIZE_MAP()")
    if begin == -1 or end == -1:
        raise ParseError("struct without KV_SERIALIZE map")
    region = struct_body[begin:end]

    # Neutralise if(...) conditions but keep their braces so the depth scan
    # below tracks which entries are conditional.
    def _blank_if(m):
        return "IF(" + " " * (len(m.group(0)) - 3) + ")"
    region = re.sub(r"\bif\s*\([^()]*\)", _blank_if, region)

    entries = []
    depth = 0
    i = 0
    n = len(region)
    while i < n:
        ch = region[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth = max(0, depth - 1)
            i += 1
            continue
        m = KV_MACRO_RE.match(region, i)
        if not m:
            i += 1
            continue
        macro_name = m.group(0).strip()[:-1]  # without the opening paren
        open_paren = m.end() - 1
        close_paren = find_matching_paren(region, open_paren)
        args = region[open_paren + 1:close_paren]
        i = close_paren + 1

        entry = {
            "kind": "field",
            "field": None,
            "json_name": None,
            "optional": False,
            "conditional": depth > 0,
        }
        pieces = _split_top_level(args)
        if not pieces:
            raise ParseError(f"empty macro {macro_name}() in KV map")

        if macro_name == "KV_SERIALIZE_PARENT":
            entry["kind"] = "parent"
            entry["field"] = pieces[0]
        elif macro_name in ("KV_SERIALIZE", "KV_SERIALIZE_N"):
            entry["field"] = pieces[0]
        elif macro_name in ("KV_SERIALIZE_VAL_POD_AS_BLOB", "KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE",
                            "KV_SERIALIZE_VAL_POD_AS_BLOB_N"):
            entry["kind"] = "pod_blob"
            entry["field"] = pieces[0]
        elif macro_name in ("KV_SERIALIZE_OPT", "KV_SERIALIZE_OPT_N"):
            entry["field"] = pieces[0]
            entry["optional"] = True
        elif macro_name == "KV_SERIALIZE_VAL_POD_AS_BLOB_OPT_N":
            entry["kind"] = "pod_blob"
            entry["field"] = pieces[0]
            entry["optional"] = True
        elif macro_name in ("KV_SERIALIZE_CONTAINER_POD_AS_BLOB",
                            "KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N"):
            entry["kind"] = "container_blob"
            entry["field"] = pieces[0]
        elif macro_name == "KV_SERIALIZE_CONTAINER_POD_AS_BLOB_OPT_N":
            entry["kind"] = "container_blob"
            entry["field"] = pieces[0]
            entry["optional"] = True
        else:
            raise ParseError(f"unhandled KV_SERIALIZE macro {macro_name}")

        # _N variants carry an explicit JSON name: (expr, "json_name", ...)
        if macro_name.endswith("_N") and entry["kind"] != "parent":
            if len(pieces) < 2:
                raise ParseError(f"missing JSON name in {macro_name}({args})")
            name_match = re.fullmatch(r'"([^"]*)"', pieces[1])
            if not name_match:
                raise ParseError(f"non literal JSON name in {macro_name}({args})")
            entry["json_name"] = name_match.group(1)
        # json_name defaults to the last path segment of the field expression
        if entry["json_name"] is None and entry["field"]:
            entry["json_name"] = entry["field"].split(".")[-1]
        entries.append(entry)
    return entries


def _split_top_level(text):
    """Split a macro argument list on top-level commas only."""
    parts = []
    depth = 0
    current = []
    in_string = None
    for ch in text:
        if in_string:
            current.append(ch)
            if ch == in_string:
                in_string = None
            continue
        if ch in ("'", '"'):
            in_string = ch
            current.append(ch)
        elif ch in "(<":
            depth += 1
            current.append(ch)
        elif ch in ")>":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return [p for p in (p.strip() for p in parts) if p]


def parse_members(struct_body):
    """Collect member declarations declared before the KV_SERIALIZE map.

    Returns {name: {"type": str, "comment": str}}. Declaration-style lines
    (constructors, typedefs, nested structs, enums) are ignored.
    """
    cut = struct_body.find("BEGIN_KV_SERIALIZE_MAP()")
    zone = struct_body[:cut] if cut != -1 else struct_body
    # Remove nested struct bodies from the zone; their members belong to them.
    while True:
        m = STRUCT_HEAD_RE.search(zone)
        if not m:
            break
        open_idx = m.end() - 1
        close_idx = find_matching_brace(zone, open_idx)
        zone = zone[:m.start()] + zone[close_idx + 1:]
    members = {}
    for line in zone.splitlines():
        m = MEMBER_RE.match(line)
        if not m:
            continue
        members[m.group(2)] = {
            "type": re.sub(r"\s+", " ", m.group(1)).strip(),
            "comment": (m.group(3) or "").strip(),
        }
    return members


# ---------------------------------------------------------------------------
# C++ type to OpenAPI schema mapping
# ---------------------------------------------------------------------------

# Scalar types, mapped to the closest OpenAPI format. Unsigned 64-bit values
# that can exceed the signed 64-bit or the JavaScript safe integer range are
# documented per field below in FIELD_NOTES rather than invented formats,
# which OpenAPI does not define.
SCALAR_TYPES = {
    "uint64_t": {"type": "integer", "format": "int64"},
    "int64_t": {"type": "integer", "format": "int64"},
    "uint32_t": {"type": "integer", "format": "int32"},
    "int32_t": {"type": "integer", "format": "int32"},
    "uint16_t": {"type": "integer", "format": "int32"},
    "int16_t": {"type": "integer", "format": "int32"},
    "uint8_t": {"type": "integer", "format": "int32"},
    "int8_t": {"type": "integer", "format": "int32"},
    "size_t": {"type": "integer", "format": "int64"},
    "ssize_t": {"type": "integer", "format": "int64"},
    "int": {"type": "integer", "format": "int32"},
    "unsigned int": {"type": "integer", "format": "int32"},
    "bool": {"type": "boolean"},
    "std::string": {"type": "string"},
    "blobdata": {"type": "string"},
    "cryptonote::blobdata": {"type": "string"},
    "std::wstring": {"type": "string"},
}

# Fixed-size binary PODs. On JSON endpoints they travel as binary blob
# strings; on .bin endpoints the whole body is binary transport.
POD_BLOB_TYPES = {
    "crypto::hash": "32-byte hash, serialized as a blob",
    "crypto::hash8": "8-byte hash, serialized as a blob",
    "crypto::public_key": "32-byte public key, serialized as a blob",
    "crypto::secret_key": "32-byte secret key, serialized as a blob",
    "crypto::key_image": "32-byte key image, serialized as a blob",
    "crypto::ec_point": "32-byte point, serialized as a blob",
    "rct::key": "32-byte key, serialized as a blob",
}

# Field-level notes for values whose JSON representation deserves a warning
# or an explanation that cannot be derived from the C++ type alone.
FIELD_NOTES = {
    "cumulative_difficulty": (
        "Low 64 bits of the 128-bit cumulative difficulty. Serialized as a "
        "JSON number, which exceeds the JavaScript safe integer range on long "
        "chains; parse it losslessly (the high 64 bits are in "
        "cumulative_difficulty_top64)."
    ),
    "cumulative_difficulty_top64": (
        "High 64 bits of the 128-bit cumulative difficulty (see "
        "cumulative_difficulty for the low bits)."
    ),
    "difficulty": (
        "Current difficulty. Serialized as a JSON number; on very long chains "
        "it can exceed the JavaScript safe integer range."
    ),
    "spent_status": (
        "0 = unspent, 1 = spent in the blockchain, 2 = spent in the mempool."
    ),
    "height": "Block height.",
    "start_height": "Starting height of the range.",
}

# Names that indicate hex-encoded binary content on JSON endpoints.
HEX_NAME_RE = re.compile(r"(_blob|_hex|as_hex|_hash|blob$|^hash$|_pubkey|key$|mask$|^tx$)")


def type_to_schema(cpp_type, field_name=None, known_components=None, where=""):
    """Map a C++ member type to an OpenAPI schema fragment.

    Raises ParseError for unmapped types instead of degrading silently; a
    mapping that is not understood is a source change that needs human eyes.
    """
    cpp_type = re.sub(r"\s+", " ", cpp_type).strip()
    known_components = known_components or {}

    if cpp_type in SCALAR_TYPES:
        schema = dict(SCALAR_TYPES[cpp_type])
    elif cpp_type in POD_BLOB_TYPES:
        schema = {"type": "string", "description": POD_BLOB_TYPES[cpp_type]}
    elif cpp_type.endswith("blobdata") and cpp_type != "blobdata":
        schema = {"type": "string"}
    else:
        vector = re.fullmatch(r"std::(vector|list)\s*<\s*(.+)\s*>", cpp_type)
        if vector:
            item_type = re.sub(r"\s+", " ", vector.group(2)).strip()
            items = type_to_schema(item_type, field_name, known_components, where)
            schema = {"type": "array", "items": items}
        elif cpp_type in known_components:
            schema = {"$ref": f"#/components/schemas/{known_components[cpp_type]}"}
        else:
            raise ParseError(f"unmapped C++ type {cpp_type!r} for field "
                             f"{field_name!r} in {where}")

    if field_name and schema.get("type") == "string" and "description" not in schema:
        if HEX_NAME_RE.search(field_name):
            schema = dict(schema)
            schema["description"] = "Hex-encoded binary data."
    if field_name and field_name in FIELD_NOTES and "description" not in schema:
        schema = dict(schema)
        schema["description"] = FIELD_NOTES[field_name]
    return schema

# ---------------------------------------------------------------------------
# Handler descriptions, keyed by handler rather than by path so alias
# endpoints (/getheight for /get_height, ...) share the real description.
# ---------------------------------------------------------------------------

HANDLER_DESCRIPTIONS = {
    "on_get_height": "Returns the current chain height and the hash of the top block.",
    "on_get_blocks": "Retrieves block blobs for sync. The request lists the first ten block ids sequentially, then ids at exponentially growing offsets up to the genesis block, and the daemon answers with the blocks needed to advance the chain.",
    "on_get_blocks_by_height": "Retrieves raw block blobs for an explicit list of heights.",
    "on_get_hashes": "Retrieves block hashes for a height range, used during chain sync.",
    "on_get_indexes": "Retrieves the global output indexes of every output of a transaction.",
    "on_get_outs_bin": "Retrieves output keys and commitments for a set of global output indexes, in binary form.",
    "on_get_transactions": "Fetches one or more transactions by hash, as hex blobs and, on request, decoded JSON.",
    "on_get_alt_blocks_hashes": "Returns the hashes of the alternative (non-mainchain) blocks known to the daemon.",
    "on_is_key_image_spent": "Checks whether each given key image is spent on the chain or in the mempool.",
    "on_send_raw_tx": "Submits a signed raw transaction to the network and reports whether it was accepted, relayed, or rejected with reasons.",
    "on_start_mining": "Starts the internal CPU miner for a given address and thread count.",
    "on_set_donation_level": "Sets the developer donation percentage used by the internal miner. Nerva-specific.",
    "on_stop_mining": "Stops the internal miner.",
    "on_mining_status": "Reports whether the internal miner is running, with its thread count, hashrate and address.",
    "on_save_bc": "Flushes the blockchain database to disk.",
    "on_get_peer_list": "Returns the white and grey peer lists with per-peer state and statistics.",
    "on_get_public_nodes": "Returns the nodes that announced themselves as public RPC peers, usable as remote nodes.",
    "on_set_log_hash_rate": "Toggles periodic logging of the miner hashrate. Only meaningful while mining.",
    "on_set_log_level": "Sets the daemon log verbosity, from 0 (errors only) to 4 (trace).",
    "on_set_log_categories": "Sets the active log categories, a comma-separated list of names with optional regex filters.",
    "on_get_transaction_pool": "Returns the full contents of the transaction mempool.",
    "on_get_transaction_pool_hashes_bin": "Returns the mempool transaction hashes as a binary blob.",
    "on_get_transaction_pool_hashes": "Returns the mempool transaction hashes as hex strings.",
    "on_get_transaction_pool_stats": "Returns aggregate statistics about the mempool: counts, bytes, fee totals and a time histogram.",
    "on_set_bootstrap_daemon": "Sets, replaces or clears the bootstrap daemon used for delegated sync.",
    "on_stop_daemon": "Requests a clean daemon shutdown.",
    "on_get_info": "Returns the network status summary: height, difficulty, connection counts, version, and related statistics.",
    "on_get_net_stats": "Returns cumulative network traffic counters since daemon start.",
    "on_get_limit": "Returns the current download and upload rate limits.",
    "on_set_limit": "Sets the download and upload rate limits in kB/s.",
    "on_out_peers": "Sets the target number of outgoing peer connections.",
    "on_in_peers": "Sets the target number of incoming peer connections.",
    "on_get_outs": "Retrieves output keys and commitments for a set of global output indexes, in JSON.",
    "on_update": "Checks whether a daemon update is available and can download and verify one.",
    "on_get_output_distribution_bin": "Retrieves the output amount distribution histogram, in binary form.",
    "on_pop_blocks": "Pops a number of blocks from the chain tip. Intended for testing, not production use.",
    # JSON-RPC handlers
    "on_getblockcount": "Returns the current chain height.",
    "on_getblockhash": "Returns the hash of the block at the requested height, directly as the result string.",
    "on_getblocktemplate": "Returns a block template to mine on, including the blob to extend, the difficulty, the expected reward and the reserved offset.",
    "on_submitblock": "Submits a mined block blob for validation and chain inclusion.",
    "on_get_last_block_header": "Returns the header of the current chain tip block.",
    "on_get_block_header_by_hash": "Returns the header of the block identified by its hash.",
    "on_get_block_header_by_height": "Returns the header of the block at the given height.",
    "on_get_block_headers_range": "Returns the headers of all blocks in an inclusive height range.",
    "on_get_block": "Returns a full block, by height or by hash: header, raw blob, decoded JSON, miner transaction and transaction hashes.",
    "on_get_connections": "Returns the live peer connections with their state, traffic counters and sync status.",
    "on_get_info_json": "Returns the network status summary: height, difficulty, connection counts, version, and related statistics.",
    "on_hard_fork_info": "Returns the state of the current hard fork: version, votes, threshold and earliest height of the next fork.",
    "on_set_bans": "Bans or unbans a host, with a duration in seconds.",
    "on_get_bans": "Returns the current ban list with remaining time per host.",
    "on_banned": "Checks whether a given host is currently banned.",
    "on_flush_txpool": "Flushes the given transaction hashes, or the whole mempool, from the transaction pool.",
    "on_get_output_histogram": "Returns a histogram of output amounts, optionally restricted to a height range and to unused outputs.",
    "on_get_version": "Returns the daemon RPC version, and whether the daemon is a release build.",
    "on_get_coinbase_tx_sum": "Returns the sum of coinbase amounts and fees emitted over a height range.",
    "on_get_per_kb_fee_estimate": "Returns the estimated fee per kB for the given confirmation weight.",
    "on_get_alternate_chains": "Returns the alternative chains known to the daemon, with their heights, difficulties and block hashes.",
    "on_relay_tx": "Rebroadcasts the given transactions to the peer network.",
    "on_sync_info": "Returns the current sync spans, the peers serving them, and a one line overview.",
    "on_get_txpool_backlog": "Returns the mempool backlog as a binary blob of backlog entries.",
    "on_get_output_distribution": "Returns the output amount distribution histogram in JSON, with optional binary and compressed forms.",
    "on_prune_blockchain": "Prunes the blockchain, or reports the prunable size when called with check=true.",
    "on_flush_cache": "Flushes the bad block cache and, optionally, the transaction pool cache.",
    "on_get_generated_coins": "Returns the total coins emitted up to a given height. Nerva-specific.",
    "on_get_min_version": "Returns the minimal daemon version accepted by this network. Nerva-specific.",
    "on_get_tx_pubkey": "Extracts the transaction public key and additional keys from a transaction extra blob. Nerva-specific.",
    "on_decode_outputs": "Decodes transaction outputs for a given address and view key. Nerva-specific.",
    "on_add_peer": "Adds a peer to the peer list by host.",
}

# Nerva-specific commands (no Monero equivalent).
NERVA_SPECIFIC_COMMANDS = {
    "COMMAND_RPC_GET_GENERATED_COINS", "COMMAND_RPC_MIN_VERSION",
    "COMMAND_RPC_GET_TX_PUBKEY", "COMMAND_RPC_DECODE_OUTPUTS",
    "COMMAND_RPC_ADD_PEER", "COMMAND_RPC_DONATE_MINING",
}

TAGS = [
    {"name": "Network", "description": "Network wide information and statistics."},
    {"name": "Blocks", "description": "Block queries, headers and submission."},
    {"name": "Transactions", "description": "Transaction queries and submission."},
    {"name": "Mempool", "description": "Transaction mempool contents and management."},
    {"name": "Mining", "description": "Mining, block templates and emission."},
    {"name": "Peers", "description": "Peer lists, connections and bans."},
    {"name": "Outputs", "description": "Output keys, indexes and distributions."},
    {"name": "Logging", "description": "Log level and category management."},
    {"name": "Daemon", "description": "Daemon control and maintenance."},
    {"name": "Nerva-specific", "description": "Commands specific to Nerva, absent from Monero."},
    {"name": "JSON-RPC", "description": "The JSON-RPC 2.0 transport endpoint."},
    {"name": "Restricted", "description": "Only registered on a non-restricted daemon. " + RESTRICTED_NOTE},
]


def categorize(name, command):
    """Return the tag for a path or a JSON-RPC method name."""
    n = name.lower()
    if command in NERVA_SPECIFIC_COMMANDS or "donate" in n:
        return "Nerva-specific"
    # Mining first: getblocktemplate and submitblock contain "block" and
    # must not be filed under Blocks.
    if ("mining" in n or "miner" in n or "blocktemplate" in n
            or "submitblock" in n or "coinbase" in n):
        return "Mining"
    if "transaction_pool" in n or "txpool" in n or "flush_txpool" in n or "mempool" in n:
        return "Mempool"
    if "block" in n or "hashes" in n or "chain" in n:
        return "Blocks"
    if "tx" in n or "transaction" in n or "key_image" in n:
        return "Transactions"
    if "fee" in n:
        return "Fees"
    if "output" in n or "outs" in n or "index" in n:
        return "Outputs"
    if ("peer" in n or "ban" in n or "connection" in n or "node" in n):
        return "Peers"
    if "fork" in n:
        return "Hard Forks"
    if "version" in n:
        return "Version"
    if "log" in n:
        return "Logging"
    if ("daemon" in n or "save" in n or "update" in n or "limit" in n
            or "prune" in n or "cache" in n or "sync" in n or "bootstrap" in n
            or "net_stats" in n or "netstat" in n):
        return "Daemon"
    return "Network"


# ---------------------------------------------------------------------------
# Component schema construction
# ---------------------------------------------------------------------------

def to_camel(name):
    parts = [p for p in name.replace("COMMAND_RPC_", "").split("_") if p]
    return "".join(p[0].upper() + p[1:].lower() for p in parts)


def collect_structs(path):
    """Return every struct of a header as {name, parent, clean_body, raw_body, start, end}."""
    raw = path.read_text(encoding="utf-8")
    clean = strip_comments(raw, preserve=True)
    structs = []
    for m in STRUCT_HEAD_RE.finditer(clean):
        name = m.group(1)
        parent = m.group(2)
        open_idx = m.end() - 1
        close_idx = find_matching_brace(clean, open_idx)
        structs.append({
            "name": name,
            "parent": parent,
            "clean_body": clean[open_idx + 1:close_idx],
            "raw_body": raw[open_idx + 1:close_idx],
            "start": m.start(),
            "end": close_idx + 1,
        })
    return structs


# Structs whose schema is written by hand because the C++ serialization is
# conditional on flags in ways a struct-by-struct derivation cannot express:
# COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::distribution serializes its array as a
# plain array, a binary blob or a compressed string depending on the binary
# and compress request flags.
HAND_WRITTEN_SCHEMAS = {
    "GetOutputDistributionDistribution": {
        "type": "object",
        "required": ["amount", "start_height"],
        "properties": {
            "amount": {"type": "integer", "format": "int64", "description": "Amount whose distribution follows."},
            "start_height": {"type": "integer", "format": "int64", "description": "Height the distribution starts at."},
            "binary": {"type": "boolean", "description": "True when the distribution is serialized as a binary blob."},
            "compress": {"type": "boolean", "description": "True when the distribution is compressed."},
            "distribution": {
                "description": "Output counts per height. A plain array of integers when binary is false; a binary blob string when binary is true and compress false; and the compressed form is carried by compressed_data when compress is true.",
                "oneOf": [
                    {"type": "array", "items": {"type": "integer", "format": "int64"}},
                    {"type": "string", "description": "Binary blob of uint64 values."},
                ],
            },
            "compressed_data": {"type": "string", "description": "Compressed distribution, present when compress is true."},
            "base": {"type": "integer", "format": "int64", "description": "Population base of the distribution."},
        },
    },
}


def build_struct_schema(struct, role, command_name, scope):
    """Derive one OpenAPI object schema from a request_t/response_t struct."""
    kv = parse_kv_entries(struct["clean_body"])
    members = parse_members(struct["raw_body"])
    properties = {}
    required = []
    for entry in kv:
        if entry["kind"] == "parent":
            if entry["field"] == "rpc_response_base":
                properties["status"] = {
                    "type": "string",
                    "description": "RPC status string, \"OK\" on success.",
                }
                required.append("status")
                properties["untrusted"] = {
                    "type": "boolean",
                    "description": "True when the answer came from a bootstrap daemon.",
                }
            elif entry["field"] == "rpc_request_base":
                continue
            else:
                raise ParseError(f"unknown KV_SERIALIZE_PARENT base {entry['field']!r} "
                                 f"in {command_name}")
            continue

        member_name = entry["field"].split(".")[0]
        json_name = entry["json_name"]
        if member_name not in members:
            raise ParseError(
                f"serialized field {member_name!r} has no matching member in "
                f"{command_name} ({role}); the struct layout may have changed"
            )
        member = members[member_name]

        if entry["kind"] == "container_blob":
            prop = {
                "type": "string",
                "description": f"Binary blob: {member['type']} serialized as raw bytes.",
            }
        else:
            prop = type_to_schema(
                member["type"], json_name, scope, f"{command_name} ({role})"
            )
            if not isinstance(prop, dict) or "$ref" not in prop:
                prop = dict(prop)

        desc = member["comment"] or ""
        if entry["conditional"]:
            desc = (desc + " " if desc else "") + (
                "Conditional: presence on the wire depends on the sibling fields."
            )
        elif not entry["optional"] and role == "response":
            required.append(json_name)
        if desc:
            prop.setdefault("description", desc)
        properties[json_name] = prop

    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    if not properties:
        schema["description"] = "This command takes no parameters."
    return schema


# ---------------------------------------------------------------------------
# Spec assembly
# ---------------------------------------------------------------------------

def build_spec(rest_endpoints, json_rpc_methods):
    commands_structs = collect_structs(COMMANDS_HEADER)
    protocol_structs = collect_structs(PROTOCOL_HEADER)

    # Command blocks and the structs nested inside them.
    command_blocks = [s for s in commands_structs if s["name"].startswith("COMMAND_RPC_")]
    nested_of = {}
    for blk in command_blocks:
        nested_of[blk["name"]] = [
            s for s in commands_structs
            if not s["name"].startswith("COMMAND_RPC_")
            and blk["start"] <= s["start"] and s["end"] <= blk["end"]
        ]
    namespace_structs = [
        s for s in commands_structs
        if not s["name"].startswith("COMMAND_RPC_")
        and not any(blk["start"] <= s["start"] and s["end"] <= blk["end"]
                    for blk in command_blocks)
    ]

    # Namespace-level helper types resolve to components by their own name.
    global_scope = {}
    for s in namespace_structs:
        global_scope[s["name"]] = to_camel(s["name"])
    # Protocol-level helpers (connection_info, ...).
    for s in protocol_structs:
        global_scope.setdefault(s["name"], to_camel(s["name"]))

    referenced_commands = {}
    for ep in rest_endpoints:
        referenced_commands.setdefault(ep["command"], ep)
    for m in json_rpc_methods:
        referenced_commands.setdefault(m["command"], m)

    # A command is answered in binary only when every registration is a .bin
    # REST path and it has no JSON-RPC method.
    command_registrations = {}
    for ep in rest_endpoints:
        command_registrations.setdefault(ep["command"], []).append(("rest", ep["binary"]))
    for m in json_rpc_methods:
        command_registrations.setdefault(m["command"], []).append(("jsonrpc", False))

    def binary_only(cmd):
        regs = command_registrations.get(cmd, [])
        return bool(regs) and all(kind == "rest" and is_bin for kind, is_bin in regs)

    candidates = {}  # component name -> schema, built eagerly for requests
    lazy_registry = {}  # component name -> (struct, command, scope) built on demand

    def register_nested(cmd_name, nested, local_scope):
        comp = to_camel(cmd_name) + to_camel(nested["name"])
        lazy_registry[comp] = (nested, cmd_name, {**global_scope, **local_scope})
        local_scope[nested["name"]] = comp
        return comp

    def process_command(cmd_name):
        blk = next((b for b in command_blocks if b["name"] == cmd_name), None)
        if blk is None:
            raise ParseError(f"command {cmd_name} referenced by the routing table "
                             f"has no struct in {COMMANDS_HEADER.name}")

        local_scope = dict(global_scope)
        for nested in nested_of[cmd_name]:
            register_nested(cmd_name, nested, local_scope)

        scope = {**global_scope, **local_scope}
        camel = to_camel(cmd_name)

        request_struct = next(
            (n for n in nested_of[cmd_name] if n["name"] == "request_t"), None)
        response_struct = next(
            (n for n in nested_of[cmd_name] if n["name"] == "response_t"), None)

        req_name = camel + "Request"
        resp_name = camel + "Response"

        # Typedef-based requests/responses (get_block_count, on_get_block_hash).
        # findall returns (type, name) pairs; index them by name.
        typedefs = {
            name: ctype.strip()
            for ctype, name in re.findall(
                r"typedef\s+([\w:<>,\s]+?)\s+(\w+)\s*;", blk["raw_body"])
        }
        # --- request -----------------------------------------------------
        has_request_params = True
        if request_struct is None:
            # Typedef-based request (get_block_count, on_get_block_hash).
            req_type = typedefs.get("request")
            if req_type is None:
                raise ParseError(f"{cmd_name} has neither request_t nor a request typedef")
            candidates[req_name] = type_to_schema(
                re.sub(r"\s+", " ", req_type), None, scope, cmd_name)
            if req_type.strip() in ("std::list<std::string>", "std::vector<uint64_t>"):
                candidates[req_name] = dict(candidates[req_name])
                candidates[req_name].setdefault("description",
                                                "Legacy positional parameter list.")
        else:
            request_schema = build_struct_schema(
                request_struct, "request", cmd_name, scope)
            if not request_schema.get("properties"):
                # No parameters at all: share one component instead of one
                # empty object schema per command.
                req_name = "RpcEmptyRequest"
                has_request_params = False
            else:
                candidates[req_name] = request_schema

        # --- response ----------------------------------------------------
        if response_struct is None:
            # Typedef-based response (the hash itself for on_get_block_hash).
            resp_type = typedefs.get("response")
            if resp_type is None:
                raise ParseError(f"{cmd_name} has neither response_t nor a response typedef")
            candidates[resp_name] = type_to_schema(
                re.sub(r"\s+", " ", resp_type), None, scope, cmd_name)
            if resp_type.strip() == "std::string":
                candidates[resp_name] = dict(candidates[resp_name])
                candidates[resp_name]["description"] = (
                    "The requested value, returned directly as the JSON-RPC result."
                )
        elif not binary_only(cmd_name):
            lazy_registry[resp_name] = (response_struct, cmd_name, scope)
        return req_name, resp_name, has_request_params

    command_request_ref = {}
    command_response_ref = {}
    command_has_params = {}
    for cmd in sorted(referenced_commands):
        req_name, resp_name, has_params = process_command(cmd)
        command_request_ref[cmd] = req_name
        command_response_ref[cmd] = resp_name
        command_has_params[cmd] = has_params

    # --- envelope schemas -------------------------------------------------
    unique_methods = {}
    for m in json_rpc_methods:
        unique_methods.setdefault(m["method"], m)

    request_refs = []
    seen_request_refs = set()
    for m in sorted(unique_methods.values(), key=lambda x: x["method"]):
        name = command_request_ref[m["command"]]
        if name not in seen_request_refs:
            seen_request_refs.add(name)
            request_refs.append({"$ref": f"#/components/schemas/{name}"})
    response_refs = [
        {"$ref": f"#/components/schemas/{command_response_ref[m['command']]}"}
        for m in sorted(unique_methods.values(), key=lambda x: x["method"])
        if not binary_only(m["command"])
    ]

    public_methods = sorted(
        (m for m in unique_methods.values() if not m["restricted"]),
        key=lambda m: m["method"])
    restricted_methods = sorted(
        (m for m in unique_methods.values() if m["restricted"]),
        key=lambda m: m["method"])

    def method_lines(methods):
        return "\n".join(
            f"`{m['method']}` ({categorize(m['method'], m['command'])})"
            for m in methods
        )

    method_description = (
        "RPC method name. Public methods "
        f"({len(public_methods)}), safe to expose on a public node:\n"
        + method_lines(public_methods)
        + f"\n\nRestricted methods ({len(restricted_methods)}), only registered on a "
        "non-restricted daemon:\n"
        + method_lines(restricted_methods)
    )

    json_rpc_description = (
        "Submits a JSON-RPC 2.0 request. The `method` field selects the command "
        "and `params` carries its parameters; the request schema of every "
        "method is a component named after it and `params` accepts any of them."
        "\n\n"
        f"Public methods ({len(public_methods)}) are safe to expose on a public "
        "node. Restricted methods "
        f"({len(restricted_methods)}) are only registered when the daemon runs "
        "without --restricted-rpc and without --rpc-restricted-bind-port. "
        "--rpc-login adds HTTP digest authentication but does not re-enable "
        "restricted methods.\n\n"
        "Method lists, grouped by category:\n"
        + method_lines(public_methods)
        + "\n\nRestricted (grouped by category):\n"
        + method_lines(restricted_methods)
    )

    envelope = {
        "RpcEmptyRequest": {
            "type": "object",
            "description": "This command takes no parameters; params may be omitted or sent as an empty object.",
        },
        "JsonRpcRequest": {
            "type": "object",
            "required": ["jsonrpc", "method"],
            "properties": {
                "jsonrpc": {"type": "string", "enum": ["2.0"], "example": "2.0"},
                "method": {
                    "type": "string",
                    "enum": sorted(unique_methods.keys()),
                    "description": method_description,
                },
                "params": {
                    "description": "Method-specific parameters. The schema for each method is the matching *Request component.",
                    "anyOf": request_refs,
                },
                "id": {
                    "description": "Client request id, echoed back in the response.",
                    "oneOf": [
                        {"type": "integer"},
                        {"type": "string"},
                    ],
                },
            },
        },
        "JsonRpcResponse": {
            "type": "object",
            "properties": {
                "jsonrpc": {"type": "string", "example": "2.0"},
                "id": {
                    "oneOf": [{"type": "integer"}, {"type": "string"}],
                },
                "result": {
                    "description": "Method-specific result. The schema for each method is the matching *Response component.",
                    "anyOf": response_refs,
                },
                "error": {
                    "type": "object",
                    "nullable": True,
                    "properties": {
                        "code": {"type": "integer", "description": "JSON-RPC error code."},
                        "message": {"type": "string", "description": "Human readable error."},
                    },
                },
            },
        },
    }

    # --- REST paths --------------------------------------------------------
    paths = {}
    seen_handlers = {}
    for ep in rest_endpoints:
        if ep["handler"] not in HANDLER_DESCRIPTIONS:
            raise ParseError(f"no description written for handler {ep['handler']}")
        path = ep["path"]
        if path in paths:
            raise ParseError(f"duplicate REST path {path}")
        handler_desc = HANDLER_DESCRIPTIONS[ep["handler"]]
        alias_of = seen_handlers.get(ep["handler"])
        seen_handlers.setdefault(ep["handler"], path)

        op_id = re.sub(r"[^0-9a-zA-Z_]", "_", path.lstrip("/")).lower()
        notes = []
        if alias_of:
            summary = f"Legacy alias of {alias_of}."
            notes.append(f"This path is a legacy alias of {alias_of} and behaves identically.")
        else:
            summary = handler_desc.split(". ")[0] + "."
        if ep["restricted"]:
            notes.append(RESTRICTED_NOTE)
        if ep["binary"]:
            notes.append(
                "The response is a binary epee serialization, not JSON. The "
                "request is still a JSON object and may also be sent in the "
                "binary epee encoding."
            )
        else:
            notes.append(
                "The epee framework also accepts these fields as URL query "
                "parameters on GET; POST with a JSON body is the portable form."
            )
        description = handler_desc
        if notes:
            description += "\n\n" + "\n\n".join(notes)

        operation = {
            "tags": [categorize(path, ep["command"])] + (["Restricted"] if ep["restricted"] else []),
            "summary": summary,
            "description": description,
            "operationId": op_id,
        }

        req_schema = {"$ref": f"#/components/schemas/{command_request_ref[ep['command']]}"}
        if command_has_params[ep["command"]]:
            operation["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": req_schema}},
            }

        if ep["binary"]:
            content_type = "application/octet-stream"
            schema = {"type": "string", "format": "binary"}
        else:
            content_type = "application/json"
            schema = {"$ref": f"#/components/schemas/{command_response_ref[ep['command']]}"}
        operation["responses"] = {
            "200": {
                "description": "Successful response.",
                "content": {content_type: {"schema": schema}},
            },
        }
        paths[path] = {"post": operation}

    paths["/json_rpc"] = {
        "post": {
            "tags": ["JSON-RPC"],
            "summary": "JSON-RPC 2.0 endpoint.",
            "description": json_rpc_description,
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
                    "description": "JSON-RPC response envelope; carries either result or error.",
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/JsonRpcResponse"},
                        },
                    },
                },
            },
        },
    }

    # --- reachability closure over $refs ------------------------------------
    def iter_refs(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    yield value
                else:
                    yield from iter_refs(value)
        elif isinstance(node, list):
            for item in node:
                yield from iter_refs(item)

    # Namespace and protocol helpers build on demand too, so that structs
    # used only by binary-only responses are never even parsed.
    namespace_by_camel = {}
    for s in namespace_structs + protocol_structs:
        namespace_by_camel.setdefault(to_camel(s["name"]), s)

    def materialize(name):
        """Build one lazily registered schema, hand-written or derived."""
        if name in HAND_WRITTEN_SCHEMAS:
            candidates[name] = dict(HAND_WRITTEN_SCHEMAS[name])
            return
        if name in lazy_registry:
            struct, cmd_name, scope = lazy_registry[name]
            candidates[name] = build_struct_schema(struct, "response", cmd_name, scope)
            return
        if name in namespace_by_camel:
            struct = namespace_by_camel[name]
            candidates[name] = build_struct_schema(
                struct, "response", struct["name"], global_scope)
            return
        raise ParseError(f"dangling schema reference #/components/schemas/{name}")

    roots = set(iter_refs({"paths": paths, "envelope": envelope}))
    components = dict(envelope)
    reachable = set()
    frontier = list(roots)
    while frontier:
        ref = frontier.pop()
        if ref in reachable:
            continue
        reachable.add(ref)
        name = ref.split("/")[-1]
        if name not in candidates and name not in components:
            materialize(name)
        source = components if name in components else candidates
        frontier.extend(iter_refs(source[name]))
    for name, schema in candidates.items():
        ref = f"#/components/schemas/{name}"
        if ref in reachable:
            components[name] = schema

    # Nothing eagerly or lazily built may end up unreferenced.
    orphaned = sorted(set(candidates) - {n.split("/")[-1] for n in reachable})
    if orphaned:
        raise ParseError(f"orphaned component schemas (nothing references them): {orphaned}")

    # RPC version from the header, so the spec version tracks the wire version.
    raw_commands = COMMANDS_HEADER.read_text(encoding="utf-8")
    major = int(re.search(r"#define\s+CORE_RPC_VERSION_MAJOR\s+(\d+)", raw_commands).group(1))
    minor = int(re.search(r"#define\s+CORE_RPC_VERSION_MINOR\s+(\d+)", raw_commands).group(1))

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Nerva Daemon RPC API",
            "description": (
                "REST and JSON-RPC API of the Nerva (XNV) daemon.\n\n"
                "The daemon serves two kinds of endpoints: REST style paths "
                "such as /get_info, and JSON-RPC 2.0 methods called by "
                "POSTing to /json_rpc. Paths ending in .bin answer with a "
                "binary epee serialization instead of JSON.\n\n"
                + RESTRICTED_NOTE + "\n\n"
                "Default RPC ports: mainnet 17566, testnet 18566, stagenet "
                "19566. The security scheme below applies when the daemon is "
                "started with --rpc-login.\n\n"
                "This document is generated from the daemon source by "
                "scripts/openapi/generate_openapi.py and is checked for drift "
                "in CI."
            ),
            "version": f"{major}.{minor}.0",
            "contact": {
                "name": "Nerva Project",
                "url": "https://nerva.one",
            },
            "license": {
                "name": "BSD-3-Clause",
                "url": "https://opensource.org/licenses/BSD-3-Clause",
            },
        },
        "servers": [
            {"url": f"http://127.0.0.1:{MAINNET_RPC_PORT}", "description": "Local mainnet daemon."},
            {"url": f"http://127.0.0.1:{TESTNET_RPC_PORT}", "description": "Local testnet daemon."},
            {"url": f"http://127.0.0.1:{STAGENET_RPC_PORT}", "description": "Local stagenet daemon."},
        ],
        "security": [{"rpcLogin": []}],
        "tags": TAGS,
        "paths": {p: paths[p] for p in sorted(paths)},
        "components": {
            "securitySchemes": {
                "rpcLogin": {
                    "type": "http",
                    "scheme": "digest",
                    "description": "HTTP digest authentication, enabled by --rpc-login user:pass.",
                },
            },
            "schemas": {k: components[k] for k in sorted(components)},
        },
    }

    # --- final assertions ----------------------------------------------------
    op_ids = []
    for path_item in spec["paths"].values():
        for method, op in path_item.items():
            if "operationId" not in op:
                raise ParseError(f"operation without operationId at {method} {op.get('summary')}")
            op_ids.append(op["operationId"])
            if "responses" not in op:
                raise ParseError(f"operation without responses: {op['operationId']}")
    if len(op_ids) != len(set(op_ids)):
        dupes = sorted({o for o in op_ids if op_ids.count(o) > 1})
        raise ParseError(f"duplicate operationIds: {dupes}")

    method_enum = spec["components"]["schemas"]["JsonRpcRequest"]["properties"]["method"]["enum"]
    if len(method_enum) < MIN_UNIQUE_METHOD_NAMES:
        raise ParseError(f"only {len(method_enum)} unique JSON-RPC method names")
    if len(set(method_enum)) != len(method_enum):
        raise ParseError("duplicate JSON-RPC method names in the envelope enum")

    if len(spec["components"]["schemas"]) < 40:
        raise ParseError(f"only {len(spec['components']['schemas'])} component schemas")

    stats = {
        "rest": len(rest_endpoints),
        "json_rpc_registrations": len(json_rpc_methods),
        "json_rpc_unique": len(unique_methods),
        "public_methods": len(public_methods),
        "restricted_methods": len(restricted_methods),
        "restricted_rest": sum(1 for e in rest_endpoints if e["restricted"]),
        "schemas": len(spec["components"]["schemas"]),
        "paths": len(spec["paths"]),
    }
    return spec, stats


def main():
    for path in (SERVER_HEADER, COMMANDS_HEADER, PROTOCOL_HEADER):
        if not path.exists():
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)

    try:
        rest_endpoints, json_rpc_methods = parse_routing()
        spec, stats = build_spec(rest_endpoints, json_rpc_methods)
    except ParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print("The generator refuses to emit an incomplete or wrong spec; "
              "adjust it for the new source layout.", file=sys.stderr)
        sys.exit(1)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(spec, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True, width=100)

    print(f"Generated: {OUTPUT_FILE}", file=sys.stderr)
    print(f"  REST endpoints: {stats['rest']} ({stats['restricted_rest']} restricted)", file=sys.stderr)
    print(f"  JSON-RPC methods: {stats['json_rpc_unique']} unique registrations "
          f"({stats['json_rpc_registrations']} including aliases; "
          f"{stats['public_methods']} public, {stats['restricted_methods']} restricted)",
          file=sys.stderr)
    print(f"  Paths: {stats['paths']}", file=sys.stderr)
    print(f"  Component schemas: {stats['schemas']}", file=sys.stderr)


if __name__ == "__main__":
    main()


