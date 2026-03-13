import os
import json
import requests

DAEMON_HOST = 'http://127.0.0.1:17566/json_rpc'

def get_top_block() -> (str, int):
    r = requests.post(DAEMON_HOST, json={'method': 'get_info'})
    return r.json()['result']['top_block_hash'], r.json()['result']['height']

def get_block(block_hash:str) -> dict:
    r = requests.post(DAEMON_HOST, json={'method': 'get_block', 'params': {'hash': block_hash}})
    return json.loads(r.json()['result']['json'])

if __name__ == '__main__':
    top_block_hash, top_block_height = get_top_block()


    empty_block_counter = 0
    blocks_found = 0
    total_blocks_scanned = 0

    non_miner_txs = []
    height = top_block_height
    next_block_hash = top_block_hash
    while height > 1: # speed could be improved by batching the network requests
        block = get_block(next_block_hash)
        non_miner_txs = block['tx_hashes']
        next_block_hash = block['prev_id']
        total_blocks_scanned += 1
    
        if block['tx_hashes']:
            blocks_found += 1
            # print(block)
            height = block['miner_tx']['vin'][0]['gen']['height']
            print(f'{empty_block_counter} block searched since last block')
            print(f'{blocks_found} / {total_blocks_scanned} are not empty ({(float(blocks_found)/float(total_blocks_scanned))*100.0}%)')
            empty_block_counter = 0 # reset counter to get gap until next non-empty block
        else:
            empty_block_counter += 1

    print(f'{blocks_found} / {total_blocks_scanned} are not empty ({(float(blocks_found)/float(total_blocks_scanned))*100.0}%)')