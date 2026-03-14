import json
import requests

DAEMON_HOST = 'http://127.0.0.1:17566/json_rpc'

class BlockchainRPCIterator:
    '''
    Iterate from the top of the chain to the origin block via RPC
    '''
    def __init__(self):
        self.session = requests.Session()
        self.next_block_hash, self.height = self.get_top_block()

    def __iter__(self):
        return self

    def __next__(self):
        block = self.get_block(self.next_block_hash)
        self.next_block_hash = block['prev_id']
        self.height = block['miner_tx']['vin'][0]['gen']['height']
        return block

    def get_top_block(self) -> (str, int):
        r = self.session.post(DAEMON_HOST, json={'method': 'get_info'})
        return r.json()['result']['top_block_hash'], r.json()['result']['height']

    def get_block(self, block_hash:str) -> dict:
        r = self.session.post(DAEMON_HOST, json={'method': 'get_block', 'params': {'hash': block_hash}})
        return json.loads(r.json()['result']['json'])

if __name__ == '__main__':

    empty_block_counter = 0
    blocks_found = 0
    total_blocks_scanned = 0

    for block in BlockchainRPCIterator():
        non_miner_txs = block['tx_hashes']
        total_blocks_scanned += 1

        if block['tx_hashes']:
            blocks_found += 1
            # print(block)
            print(f'{empty_block_counter} block searched since last block')
            print(f'{blocks_found} / {total_blocks_scanned} are not empty ({(float(blocks_found)/float(total_blocks_scanned))*100.0}%)')
            empty_block_counter = 0 # reset counter to get gap until next non-empty block
        else:
            empty_block_counter += 1

    print(f'{100.0 - ((float(blocks_found)/float(total_blocks_scanned))*100.0)}% blocks are empty')