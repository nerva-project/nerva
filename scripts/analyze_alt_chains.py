import json
import datetime
import requests

DAEMON_HOST = 'http://127.0.0.1:17566/json_rpc'

def get_block(block_hash:str) -> dict:
    r = requests.post(DAEMON_HOST, json={'method': 'get_block', 'params': {'hash': block_hash}})
    return json.loads(r.json()['result']['json'])

def get_block_by_height(height:int) -> dict:
    r = requests.post(DAEMON_HOST, json={'method': 'get_block', 'params': {'height': height}})
    return json.loads(r.json()['result']['json'])

def get_alt_chains():
    r = requests.post(DAEMON_HOST, json={'method': 'get_alternate_chains'})
    chains = r.json()['result']['chains']
    sorted_chains = sorted(chains, key=lambda alt_chain: alt_chain['height'])
    return sorted_chains

if __name__ == '__main__':
    prev_alt_chain_height = None
    for alt_chain in get_alt_chains():
        alt_block_timestamp = get_block(alt_chain['block_hashes'][-1])['timestamp']
        main_chain_sibling_timestamp = get_block_by_height(alt_chain['height'])['timestamp']
        print(f'Alt chain found at height {alt_chain["height"]} with head {alt_chain["block_hashes"][-1]}')
        print(f'  Alt chain length: {alt_chain["length"]}')
        print(f'  Timestamp: {datetime.datetime.fromtimestamp(alt_block_timestamp)}; Difference from mainchain: {abs(alt_block_timestamp - main_chain_sibling_timestamp)}s')
        print(f'  Height difference from previous alt chain head: {None if not prev_alt_chain_height else alt_chain["height"] - prev_alt_chain_height}')
        prev_alt_chain_height = alt_chain["height"]