from typing import Any, Dict, Optional
from datetime import datetime, timedelta
import hashlib
import json

class CacheManager:
    def __init__(self, ttl: int = 3600, max_size: int = 1000, strategy: str = 'LRU'):
        self.ttl = ttl
        self.max_size = max_size
        self.strategy = strategy
        self.cache: Dict[str, Dict] = {}
        self.access_count: Dict[str, int] = {}
        self.access_time: Dict[str, datetime] = {}
    
    def set(self, key: str, value: Any):
        if len(self.cache) >= self.max_size:
            self._evict()
        
        hash_key = hashlib.md5(key.encode()).hexdigest()
        self.cache[hash_key] = {
            'value': value,
            'expiry': datetime.now() + timedelta(seconds=self.ttl)
        }
        self.access_time[hash_key] = datetime.now()
        self.access_count[hash_key] = 0
    
    def get(self, key: str) -> Optional[Any]:
        hash_key = hashlib.md5(key.encode()).hexdigest()
        
        if hash_key not in self.cache:
            return None
        
        entry = self.cache[hash_key]
        if datetime.now() > entry['expiry']:
            del self.cache[hash_key]
            return None
        
        self.access_count[hash_key] += 1
        self.access_time[hash_key] = datetime.now()
        
        return entry['value']
    
    def delete(self, key: str):
        hash_key = hashlib.md5(key.encode()).hexdigest()
        if hash_key in self.cache:
            del self.cache[hash_key]
    
    def clear(self):
        self.cache.clear()
        self.access_count.clear()
        self.access_time.clear()
    
    def _evict(self):
        if self.strategy == 'LRU':
            lru_key = min(self.access_time, key=self.access_time.get)
            del self.cache[lru_key]
            del self.access_time[lru_key]
        
        elif self.strategy == 'LFU':
            lfu_key = min(self.access_count, key=self.access_count.get)
            del self.cache[lfu_key]
            del self.access_count[lfu_key]
        
        elif self.strategy == 'FIFO':
            fifo_key = list(self.cache.keys())[0]
            del self.cache[fifo_key]
    
    def get_stats(self) -> Dict:
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'ttl': self.ttl,
            'strategy': self.strategy
        }