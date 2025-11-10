from typing import Dict, Optional, Any, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict
import time
import threading
import hashlib
import pickle
from abc import ABC, abstractmethod
import json


class CacheStrategy(Enum):
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"
    ARC = "arc"


class EvictionPolicy(Enum):
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    RANDOM = "random"
    SIZE_BASED = "size_based"


@dataclass
class CacheEntry:
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: Optional[float] = None
    size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def update_access(self):
        self.last_accessed = time.time()
        self.access_count += 1
    
    def get_age(self) -> float:
        return time.time() - self.created_at
    
    def get_idle_time(self) -> float:
        return time.time() - self.last_accessed


@dataclass
class CacheStatistics:
    total_puts: int = 0
    total_gets: int = 0
    total_hits: int = 0
    total_misses: int = 0
    total_evictions: int = 0
    total_expirations: int = 0
    current_size: int = 0
    max_size: int = 0
    
    def get_hit_rate(self) -> float:
        total = self.total_hits + self.total_misses
        if total == 0:
            return 0.0
        return (self.total_hits / total) * 100
    
    def get_miss_rate(self) -> float:
        return 100.0 - self.get_hit_rate()


class LRUCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)
            
            self.cache[key] = CacheEntry(
                key=key,
                value=value,
                ttl=ttl,
                size=self._estimate_size(value)
            )
            
            if len(self.cache) > self.max_size:
                evicted_key, _ = self.cache.popitem(last=False)
                return True
            
            return False
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            
            if entry.is_expired():
                del self.cache[key]
                return None
            
            entry.update_access()
            self.cache.move_to_end(key)
            
            return entry.value
    
    def _estimate_size(self, obj: Any) -> int:
        try:
            return len(pickle.dumps(obj))
        except:
            return 1
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def size(self) -> int:
        with self.lock:
            return len(self.cache)
    
    def contains(self, key: str) -> bool:
        with self.lock:
            return key in self.cache


class LFUCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        with self.lock:
            self.cache[key] = CacheEntry(
                key=key,
                value=value,
                ttl=ttl,
                size=self._estimate_size(value)
            )
            
            if len(self.cache) > self.max_size:
                lfu_key = min(self.cache.keys(), 
                             key=lambda k: self.cache[k].access_count)
                del self.cache[lfu_key]
                return True
            
            return False
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            
            if entry.is_expired():
                del self.cache[key]
                return None
            
            entry.update_access()
            return entry.value
    
    def _estimate_size(self, obj: Any) -> int:
        try:
            return len(pickle.dumps(obj))
        except:
            return 1
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class FIFOCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        with self.lock:
            if key in self.cache:
                self.cache[key] = CacheEntry(
                    key=key,
                    value=value,
                    ttl=ttl,
                    size=self._estimate_size(value)
                )
                return False
            
            self.cache[key] = CacheEntry(
                key=key,
                value=value,
                ttl=ttl,
                size=self._estimate_size(value)
            )
            
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)
                return True
            
            return False
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            
            if entry.is_expired():
                del self.cache[key]
                return None
            
            entry.update_access()
            return entry.value
    
    def _estimate_size(self, obj: Any) -> int:
        try:
            return len(pickle.dumps(obj))
        except:
            return 1
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class ARCCache:
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.t1: OrderedDict[str, None] = OrderedDict()
        self.t2: OrderedDict[str, None] = OrderedDict()
        self.b1: OrderedDict[str, None] = OrderedDict()
        self.b2: OrderedDict[str, None] = OrderedDict()
        self.p = 0
        self.lock = threading.RLock()
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        with self.lock:
            entry = CacheEntry(
                key=key,
                value=value,
                ttl=ttl,
                size=self._estimate_size(value)
            )
            
            if key in self.cache:
                self.cache[key] = entry
                if key in self.t1:
                    self.t1.pop(key)
                    self.t2[key] = None
                return False
            
            self.cache[key] = entry
            self.t1[key] = None
            
            if len(self.cache) > self.max_size:
                self._evict()
                return True
            
            return False
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            if key not in self.cache:
                return None
            
            entry = self.cache[key]
            
            if entry.is_expired():
                self._remove_expired(key)
                return None
            
            entry.update_access()
            
            if key in self.t1:
                self.t1.pop(key)
                self.t2[key] = None
            
            return entry.value
    
    def _evict(self):
        if len(self.t1) >= max(1, self.p):
            evict_key = next(iter(self.t1))
            self.t1.pop(evict_key)
            self.b1[evict_key] = None
            del self.cache[evict_key]
        else:
            evict_key = next(iter(self.t2))
            self.t2.pop(evict_key)
            self.b2[evict_key] = None
            del self.cache[evict_key]
    
    def _remove_expired(self, key: str):
        if key in self.t1:
            self.t1.pop(key)
        elif key in self.t2:
            self.t2.pop(key)
        del self.cache[key]
    
    def _estimate_size(self, obj: Any) -> int:
        try:
            return len(pickle.dumps(obj))
        except:
            return 1
    
    def clear(self):
        with self.lock:
            self.cache.clear()
            self.t1.clear()
            self.t2.clear()
            self.b1.clear()
            self.b2.clear()
            self.p = 0
    
    def size(self) -> int:
        with self.lock:
            return len(self.cache)


class CacheKeyGenerator:
    @staticmethod
    def generate_key(prefix: str, *args, **kwargs) -> str:
        key_parts = [prefix]
        
        for arg in args:
            key_parts.append(str(arg))
        
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}={v}")
        
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    @staticmethod
    def generate_from_url(url: str, method: str = "GET") -> str:
        key_string = f"{method}:{url}"
        return hashlib.md5(key_string.encode()).hexdigest()


class CacheWarmer:
    def __init__(self, cache: 'CacheManager'):
        self.cache = cache
        self.warm_data: Dict[str, Any] = {}
        self.lock = threading.Lock()
    
    def add_warm_entry(self, key: str, value: Any, ttl: Optional[float] = None):
        with self.lock:
            self.warm_data[key] = (value, ttl)
    
    def warm_cache(self):
        with self.lock:
            for key, (value, ttl) in self.warm_data.items():
                self.cache.put(key, value, ttl)
    
    def clear_warm_data(self):
        with self.lock:
            self.warm_data.clear()


class CacheInvalidator:
    def __init__(self, cache: 'CacheManager'):
        self.cache = cache
        self.rules: List[Callable[[str], bool]] = []
        self.lock = threading.Lock()
    
    def add_invalidation_rule(self, rule: Callable[[str], bool]):
        with self.lock:
            self.rules.append(rule)
    
    def invalidate(self):
        with self.lock:
            keys_to_remove = []
            for key in self.cache.cache.keys():
                for rule in self.rules:
                    if rule(key):
                        keys_to_remove.append(key)
            
            for key in keys_to_remove:
                self.cache.remove(key)
    
    def clear_rules(self):
        with self.lock:
            self.rules.clear()


class CacheManager:
    def __init__(self, strategy: CacheStrategy = CacheStrategy.LRU, 
                 max_size: int = 1000, ttl: int = 3600):
        self.strategy = strategy
        self.max_size = max_size
        self.ttl = ttl
        self.statistics = CacheStatistics(max_size=max_size)
        
        if strategy == CacheStrategy.LRU:
            self.cache = LRUCache(max_size)
        elif strategy == CacheStrategy.LFU:
            self.cache = LFUCache(max_size)
        elif strategy == CacheStrategy.FIFO:
            self.cache = FIFOCache(max_size)
        elif strategy == CacheStrategy.ARC:
            self.cache = ARCCache(max_size)
        else:
            self.cache = LRUCache(max_size)
        
        self.key_generator = CacheKeyGenerator()
        self.warmer = CacheWarmer(self)
        self.invalidator = CacheInvalidator(self)
        self.lock = threading.RLock()
        
        self.cleanup_thread = None
        self.cleanup_running = False
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        with self.lock:
            actual_ttl = ttl or self.ttl
            evicted = self.cache.put(key, value, actual_ttl)
            
            self.statistics.total_puts += 1
            self.statistics.current_size = self.cache.size()
            
            return evicted
    
    def get(self, key: str) -> Optional[Any]:
        with self.lock:
            value = self.cache.get(key)
            
            self.statistics.total_gets += 1
            
            if value is not None:
                self.statistics.total_hits += 1
            else:
                self.statistics.total_misses += 1
            
            return value
    
    def contains(self, key: str) -> bool:
        if hasattr(self.cache, 'contains'):
            return self.cache.contains(key)
        
        with self.lock:
            return self.get(key) is not None
    
    def remove(self, key: str) -> bool:
        with self.lock:
            if isinstance(self.cache, (LRUCache, FIFOCache)):
                if self.cache.contains(key):
                    del self.cache.cache[key]
                    return True
            elif isinstance(self.cache, LFUCache):
                if key in self.cache.cache:
                    del self.cache.cache[key]
                    return True
            elif isinstance(self.cache, ARCCache):
                if key in self.cache.cache:
                    self.cache._remove_expired(key)
                    return True
            
            return False
    
    def clear(self):
        with self.lock:
            self.cache.clear()
    
    def size(self) -> int:
        return self.cache.size()
    
    def cleanup_expired(self):
        with self.lock:
            expired_keys = []
            
            if isinstance(self.cache, (LRUCache, FIFOCache)):
                for key, entry in list(self.cache.cache.items()):
                    if entry.is_expired():
                        expired_keys.append(key)
            elif isinstance(self.cache, LFUCache):
                for key, entry in list(self.cache.cache.items()):
                    if entry.is_expired():
                        expired_keys.append(key)
            elif isinstance(self.cache, ARCCache):
                for key, entry in list(self.cache.cache.items()):
                    if entry.is_expired():
                        expired_keys.append(key)
            
            for key in expired_keys:
                self.remove(key)
                self.statistics.total_expirations += 1
            
            self.statistics.current_size = self.cache.size()
    
    def start_cleanup_thread(self, interval: int = 60):
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
        
        self.cleanup_running = True
        
        def cleanup_worker():
            while self.cleanup_running:
                time.sleep(interval)
                self.cleanup_expired()
        
        self.cleanup_thread = threading.Thread(daemon=True, target=cleanup_worker)
        self.cleanup_thread.start()
    
    def stop_cleanup_thread(self):
        self.cleanup_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
    
    def get_statistics(self) -> Dict[str, Any]:
        with self.lock:
            return {
                'strategy': self.strategy.value,
                'total_puts': self.statistics.total_puts,
                'total_gets': self.statistics.total_gets,
                'total_hits': self.statistics.total_hits,
                'total_misses': self.statistics.total_misses,
                'hit_rate': f"{self.statistics.get_hit_rate():.2f}%",
                'miss_rate': f"{self.statistics.get_miss_rate():.2f}%",
                'current_size': self.statistics.current_size,
                'max_size': self.statistics.max_size,
                'total_evictions': self.statistics.total_evictions,
                'total_expirations': self.statistics.total_expirations,
            }
    
    def get_entries(self) -> List[Dict]:
        with self.lock:
            entries = []
            
            if isinstance(self.cache, (LRUCache, FIFOCache)):
                for key, entry in self.cache.cache.items():
                    entries.append({
                        'key': key,
                        'created_at': entry.created_at,
                        'last_accessed': entry.last_accessed,
                        'access_count': entry.access_count,
                        'age': entry.get_age(),
                        'idle_time': entry.get_idle_time(),
                        'size': entry.size,
                    })
            elif isinstance(self.cache, LFUCache):
                for key, entry in self.cache.cache.items():
                    entries.append({
                        'key': key,
                        'created_at': entry.created_at,
                        'last_accessed': entry.last_accessed,
                        'access_count': entry.access_count,
                        'age': entry.get_age(),
                        'idle_time': entry.get_idle_time(),
                        'size': entry.size,
                    })
            
            return entries
    
    def generate_key(self, prefix: str, *args, **kwargs) -> str:
        return self.key_generator.generate_key(prefix, *args, **kwargs)
    
    def generate_key_from_url(self, url: str, method: str = "GET") -> str:
        return self.key_generator.generate_from_url(url, method)
    
    def warm_cache(self):
        self.warmer.warm_cache()
    
    def add_warm_entry(self, key: str, value: Any, ttl: Optional[int] = None):
        self.warmer.add_warm_entry(key, value, ttl)
    
    def invalidate(self):
        self.invalidator.invalidate()
    
    def add_invalidation_rule(self, rule: Callable[[str], bool]):
        self.invalidator.add_invalidation_rule(rule)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        with self.lock:
            stats = self.get_statistics()
            entries = self.get_entries()
            
            avg_age = sum(e['age'] for e in entries) / len(entries) if entries else 0
            avg_idle = sum(e['idle_time'] for e in entries) / len(entries) if entries else 0
            total_size = sum(e['size'] for e in entries)
            
            return {
                'statistics': stats,
                'average_entry_age': f"{avg_age:.2f}s",
                'average_idle_time': f"{avg_idle:.2f}s",
                'total_cache_size_bytes': total_size,
                'entry_count': len(entries),
            }
    
    def __enter__(self):
        self.start_cleanup_thread()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_cleanup_thread()
        self.clear()