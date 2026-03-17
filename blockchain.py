import hashlib
import json
import time
from pathlib import Path
from typing import List, Dict, Any

class Block:
    def __init__(self, index: int, timestamp: float, incident_data: Dict[str, Any], playbook_path: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.incident_data = incident_data
        self.playbook_path = playbook_path
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        # We hash the string representation of our data
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "incident_data": self.incident_data,
            "playbook_path": self.playbook_path,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
        
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "incident_data": self.incident_data,
            "playbook_path": self.playbook_path,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self, storage_file: Path = Path("data/blockchain.json")):
        self.storage_file = storage_file
        self.chain: List[Block] = []
        self.load_chain()

    def load_chain(self):
        if self.storage_file.exists():
            try:
                with open(self.storage_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for item in data:
                        block = Block(
                            index=item['index'],
                            timestamp=item['timestamp'],
                            incident_data=item['incident_data'],
                            playbook_path=item['playbook_path'],
                            previous_hash=item['previous_hash']
                        )
                        # We override the calculated hash to strictly match what was saved
                        # (in case someone tampered with the file, we want calculate_hash later to fail vs this hash)
                        block.hash = item.get('hash', block.hash)
                        self.chain.append(block)
            except Exception as e:
                print(f"[Blockchain] Error loading chain: {e}")
                self.create_genesis_block()
        else:
            self.create_genesis_block()

    def save_chain(self):
        self.storage_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.storage_file, 'w', encoding='utf-8') as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=4)

    def create_genesis_block(self):
        genesis = Block(0, time.time(), {"info": "Genesis Block"}, "None", "0")
        self.chain.append(genesis)
        self.save_chain()

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, incident_data: Dict[str, Any], playbook_path: str):
        latest = self.get_latest_block()
        new_block = Block(
            index=latest.index + 1,
            timestamp=time.time(),
            incident_data=incident_data,
            playbook_path=playbook_path,
            previous_hash=latest.hash
        )
        self.chain.append(new_block)
        self.save_chain()

    def is_chain_valid(self) -> bool:
        # We must recalculate from scratch and ensure all links are unbroken
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # Recalculate hash internally using current data
            recalculated_hash = current_block.calculate_hash()

            # 1. Did the data inside the block change?
            if current_block.hash != recalculated_hash:
                return False

            # 2. Did the link to the previous block break?
            if current_block.previous_hash != previous_block.hash:
                return False

        return True
