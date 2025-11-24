from typing import Dict, Optional, Any, List, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict
import time
import threading
import hashlib
import pickle
import logging
from pathlib import Path
from abc import ABC, abstractmethod
import json

logger = logging.getLogger("cache_manager")
if not logger.handlers:
    log_dir = Path.home() / ".mod" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(log_dir / "cache_manager.log")
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
logger.setLevel(logging.DEBUG)


class CacheStrategy(Enum):
    """Enumeration of cache eviction strategies."""
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    TTL = "ttl"
    ARC = "arc"


class EvictionPolicy(Enum):
    """Enumeration of eviction policies."""
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"
    RANDOM = "random"
    SIZE_BASED = "size_based"


@dataclass
class CacheEntry:
    """Single cache entry with lifecycle and access tracking."""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: Optional[float] = None
    size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if entry exceeded TTL."""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def update_access(self) -> None:
        """Update access time and count."""
        self.last_accessed = time.time()
        self.access_count += 1
    
    def get_age(self) -> float:
        """Return seconds since creation."""
        return time.time() - self.created_at
    
    def get_idle_time(self) -> float:
        """Return seconds since last access."""
        return time.time() - self.last_accessed


@dataclass
class CacheStatistics:
    """Cache performance metrics."""
    total_puts: int = 0
    total_gets: int = 0
    total_hits: int = 0
    total_misses: int = 0
    total_evictions: int = 0
    total_expirations: int = 0
    current_size: int = 0
    max_size: int = 0
    
    def get_hit_rate(self) -> float:
        """Return hit rate as percentage."""
        total = self.total_hits + self.total_misses
        if total == 0:
            return 0.0
        return (self.total_hits / total) * 100
    
    def get_miss_rate(self) -> float:
        """Return miss rate as percentage."""
        return 100.0 - self.get_hit_rate()


class LRUCache:
    """Least Recently Used cache using OrderedDict."""

    def __init__(self, max_size: int = 1000) -> None:
        """Initialize with validation.
        
        Args:
            max_size: Maximum cache entries.
            
        Raises:
            ValueError: If max_size <= 0.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be positive int, got {max_size}")
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        logger.debug(f"LRUCache initialized with max_size={max_size}")
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Store value; return True if entry was evicted."""
        with self.lock:
            try:
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
                    logger.debug(f"LRU evicted {evicted_key}")
                    return True
                
                return False
            except Exception as e:
                logger.exception(f"LRUCache.put error: {e}")
                raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value; return None if expired or missing."""
        with self.lock:
            try:
                if key not in self.cache:
                    return None
                
                entry = self.cache[key]
                
                if entry.is_expired():
                    del self.cache[key]
                    logger.debug(f"LRU entry {key} expired")
                    return None
                
                entry.update_access()
                self.cache.move_to_end(key)
                
                return entry.value
            except Exception as e:
                logger.exception(f"LRUCache.get error: {e}")
                return None
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size via pickle."""
        try:
            return len(pickle.dumps(obj))
        except Exception as e:
            logger.debug(f"Size estimate failed for {type(obj).__name__}: {e}")
            return 1
    
    def clear(self) -> None:
        """Remove all entries."""
        with self.lock:
            self.cache.clear()
            logger.debug("LRU cache cleared")
    
    def size(self) -> int:
        """Return entry count."""
        with self.lock:
            return len(self.cache)
    
    def contains(self, key: str) -> bool:
        """Check if key exists (ignores expiration)."""
        with self.lock:
            return key in self.cache


class LFUCache:
    """Least Frequently Used cache."""

    def __init__(self, max_size: int = 1000) -> None:
        """Initialize LFU cache.
        
        Args:
            max_size: Maximum cache entries.
            
        Raises:
            ValueError: If max_size <= 0.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be positive int, got {max_size}")
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.RLock()
        logger.debug(f"LFUCache initialized with max_size={max_size}")
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Store value; evict least frequently used if full."""
        with self.lock:
            try:
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
                    logger.debug(f"LFU evicted {lfu_key}")
                    return True
                
                return False
            except Exception as e:
                logger.exception(f"LFUCache.put error: {e}")
                raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value; return None if expired or missing."""
        with self.lock:
            try:
                if key not in self.cache:
                    return None
                
                entry = self.cache[key]
                
                if entry.is_expired():
                    del self.cache[key]
                    logger.debug(f"LFU entry {key} expired")
                    return None
                
                entry.update_access()
                return entry.value
            except Exception as e:
                logger.exception(f"LFUCache.get error: {e}")
                return None
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size via pickle."""
        try:
            return len(pickle.dumps(obj))
        except Exception as e:
            logger.debug(f"Size estimate failed for {type(obj).__name__}: {e}")
            return 1
    
    def clear(self) -> None:
        """Remove all entries."""
        with self.lock:
            self.cache.clear()
            logger.debug("LFU cache cleared")
    
    def size(self) -> int:
        """Return entry count."""
        with self.lock:
            return len(self.cache)
    
    def contains(self, key: str) -> bool:
        """Check if key exists (ignores expiration)."""
        with self.lock:
            return key in self.cache


class FIFOCache:
    """First In First Out cache."""

    def __init__(self, max_size: int = 1000) -> None:
        """Initialize FIFO cache.
        
        Args:
            max_size: Maximum cache entries.
            
        Raises:
            ValueError: If max_size <= 0.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be positive int, got {max_size}")
        self.max_size = max_size
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        logger.debug(f"FIFOCache initialized with max_size={max_size}")
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Store value; evict oldest if full."""
        with self.lock:
            try:
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
                    evicted_key, _ = self.cache.popitem(last=False)
                    logger.debug(f"FIFO evicted {evicted_key}")
                    return True
                
                return False
            except Exception as e:
                logger.exception(f"FIFOCache.put error: {e}")
                raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value; return None if expired or missing."""
        with self.lock:
            try:
                if key not in self.cache:
                    return None
                
                entry = self.cache[key]
                
                if entry.is_expired():
                    del self.cache[key]
                    logger.debug(f"FIFO entry {key} expired")
                    return None
                
                entry.update_access()
                return entry.value
            except Exception as e:
                logger.exception(f"FIFOCache.get error: {e}")
                return None
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size via pickle."""
        try:
            return len(pickle.dumps(obj))
        except Exception as e:
            logger.debug(f"Size estimate failed for {type(obj).__name__}: {e}")
            return 1
    
    def clear(self) -> None:
        """Remove all entries."""
        with self.lock:
            self.cache.clear()
            logger.debug("FIFO cache cleared")
    
    def size(self) -> int:
        """Return entry count."""
        with self.lock:
            return len(self.cache)
    
    def contains(self, key: str) -> bool:
        """Check if key exists (ignores expiration)."""
        with self.lock:
            return key in self.cache


class ARCCache:
    """Adaptive Replacement Cache combining recency and frequency."""

    def __init__(self, max_size: int = 1000) -> None:
        """Initialize ARC cache.
        
        Args:
            max_size: Maximum cache entries.
            
        Raises:
            ValueError: If max_size <= 0.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be positive int, got {max_size}")
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.t1: OrderedDict[str, None] = OrderedDict()
        self.t2: OrderedDict[str, None] = OrderedDict()
        self.b1: OrderedDict[str, None] = OrderedDict()
        self.b2: OrderedDict[str, None] = OrderedDict()
        self.p = 0
        self.lock = threading.RLock()
        logger.debug(f"ARCCache initialized with max_size={max_size}")
    
    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Store value; evict using ARC policy if full."""
        with self.lock:
            try:
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
                    logger.debug(f"ARC evicted based on policy")
                    return True
                
                return False
            except Exception as e:
                logger.exception(f"ARCCache.put error: {e}")
                raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value; return None if expired or missing."""
        with self.lock:
            try:
                if key not in self.cache:
                    return None
                
                entry = self.cache[key]
                
                if entry.is_expired():
                    self._remove_expired(key)
                    logger.debug(f"ARC entry {key} expired")
                    return None
                
                entry.update_access()
                
                if key in self.t1:
                    self.t1.pop(key)
                    self.t2[key] = None
                
                return entry.value
            except Exception as e:
                logger.exception(f"ARCCache.get error: {e}")
                return None
    
    def _evict(self) -> None:
        """Evict entry using ARC policy."""
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
    
    def _remove_expired(self, key: str) -> None:
        """Remove expired entry from tracking."""
        if key in self.t1:
            self.t1.pop(key)
        elif key in self.t2:
            self.t2.pop(key)
        del self.cache[key]
    
    def _estimate_size(self, obj: Any) -> int:
        """Estimate object size via pickle."""
        try:
            return len(pickle.dumps(obj))
        except Exception as e:
            logger.debug(f"Size estimate failed for {type(obj).__name__}: {e}")
            return 1
    
    def clear(self) -> None:
        """Remove all entries."""
        with self.lock:
            self.cache.clear()
            self.t1.clear()
            self.t2.clear()
            self.b1.clear()
            self.b2.clear()
            self.p = 0
            logger.debug("ARC cache cleared")
    
    def size(self) -> int:
        """Return entry count."""
        with self.lock:
            return len(self.cache)
    
    def contains(self, key: str) -> bool:
        """Check if key exists (ignores expiration)."""
        with self.lock:
            return key in self.cache


class CacheKeyGenerator:
    """Generate cache keys from various input formats."""
    
    @staticmethod
    def generate_key(prefix: str, *args, **kwargs) -> str:
        """Generate cache key from prefix, args, and kwargs.
        
        Args:
            prefix: Key prefix.
            *args: Positional arguments.
            **kwargs: Keyword arguments.
            
        Returns:
            MD5 hashed cache key.
        """
        try:
            key_parts = [prefix]
            
            for arg in args:
                key_parts.append(str(arg))
            
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")
            
            key_string = ":".join(key_parts)
            return hashlib.md5(key_string.encode()).hexdigest()
        except Exception as e:
            logger.exception(f"Key generation error: {e}")
            return hashlib.md5(prefix.encode()).hexdigest()
    
    @staticmethod
    def generate_from_url(url: str, method: str = "GET") -> str:
        """Generate cache key from HTTP request.
        
        Args:
            url: Request URL.
            method: HTTP method.
            
        Returns:
            MD5 hashed cache key.
        """
        try:
            key_string = f"{method}:{url}"
            return hashlib.md5(key_string.encode()).hexdigest()
        except Exception as e:
            logger.exception(f"URL key generation error: {e}")
            return hashlib.md5(url.encode()).hexdigest()


class CacheWarmer:
    """Pre-populate cache with warm data."""
    
    def __init__(self, cache: 'CacheManager') -> None:
        """Initialize warmer.
        
        Args:
            cache: CacheManager instance.
        """
        self.cache = cache
        self.warm_data: Dict[str, tuple] = {}
        self.lock = threading.Lock()
        logger.debug("CacheWarmer initialized")
    
    def add_warm_entry(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Add entry to warm cache on next warm_cache() call.
        
        Args:
            key: Cache key.
            value: Value to store.
            ttl: Time-to-live in seconds.
        """
        with self.lock:
            self.warm_data[key] = (value, ttl)
    
    def warm_cache(self) -> None:
        """Load all warm entries into cache."""
        with self.lock:
            try:
                for key, (value, ttl) in self.warm_data.items():
                    self.cache.put(key, value, ttl)
                logger.info(f"Cache warmed with {len(self.warm_data)} entries")
            except Exception as e:
                logger.exception(f"Cache warming error: {e}")
    
    def clear_warm_data(self) -> None:
        """Clear warm data."""
        with self.lock:
            self.warm_data.clear()
            logger.debug("Warm data cleared")


class CacheInvalidator:
    """Invalidate cache entries based on rules."""
    
    def __init__(self, cache: 'CacheManager') -> None:
        """Initialize invalidator.
        
        Args:
            cache: CacheManager instance.
        """
        self.cache = cache
        self.rules: List[Callable[[str], bool]] = []
        self.lock = threading.Lock()
        logger.debug("CacheInvalidator initialized")
    
    def add_invalidation_rule(self, rule: Callable[[str], bool]) -> None:
        """Add rule function that returns True to invalidate key.
        
        Args:
            rule: Predicate function accepting key string.
        """
        with self.lock:
            self.rules.append(rule)
    
    def invalidate(self) -> None:
        """Apply all rules and remove matching keys."""
        with self.lock:
            try:
                keys_to_remove = []
                cache_impl = self.cache.cache
                
                if isinstance(cache_impl, (LRUCache, FIFOCache)):
                    for key in list(cache_impl.cache.keys()):
                        for rule in self.rules:
                            if rule(key):
                                keys_to_remove.append(key)
                elif isinstance(cache_impl, LFUCache):
                    for key in list(cache_impl.cache.keys()):
                        for rule in self.rules:
                            if rule(key):
                                keys_to_remove.append(key)
                elif isinstance(cache_impl, ARCCache):
                    for key in list(cache_impl.cache.keys()):
                        for rule in self.rules:
                            if rule(key):
                                keys_to_remove.append(key)
                
                for key in keys_to_remove:
                    self.cache.remove(key)
                logger.debug(f"Invalidated {len(keys_to_remove)} entries")
            except Exception as e:
                logger.exception(f"Invalidation error: {e}")
    
    def clear_rules(self) -> None:
        """Remove all rules."""
        with self.lock:
            self.rules.clear()
            logger.debug("Invalidation rules cleared")


class CacheManager:
    """Central cache manager supporting multiple strategies."""
    
    def __init__(self, strategy: CacheStrategy = CacheStrategy.LRU, 
                 max_size: int = 1000, ttl: int = 3600) -> None:
        """Initialize cache manager.
        
        Args:
            strategy: Cache eviction strategy.
            max_size: Maximum entries.
            ttl: Default time-to-live in seconds.
            
        Raises:
            ValueError: If parameters invalid.
        """
        if not isinstance(max_size, int) or max_size <= 0:
            raise ValueError(f"max_size must be positive int, got {max_size}")
        if not isinstance(ttl, int) or ttl <= 0:
            raise ValueError(f"ttl must be positive int, got {ttl}")
        
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
            logger.warning(f"Unknown strategy {strategy}, using LRU")
            self.cache = LRUCache(max_size)
        
        self.key_generator = CacheKeyGenerator()
        self.warmer = CacheWarmer(self)
        self.invalidator = CacheInvalidator(self)
        self.lock = threading.RLock()
        
        self.cleanup_thread: Optional[threading.Thread] = None
        self.cleanup_running = False
        logger.info(f"CacheManager initialized: strategy={strategy.value}, max_size={max_size}, ttl={ttl}s")
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Store value in cache.
        
        Args:
            key: Cache key.
            value: Value to store.
            ttl: Optional TTL override in seconds.
            
        Returns:
            True if entry was evicted, False otherwise.
        """
        with self.lock:
            try:
                actual_ttl = ttl or self.ttl
                evicted = self.cache.put(key, value, actual_ttl)
                
                self.statistics.total_puts += 1
                if evicted:
                    self.statistics.total_evictions += 1
                self.statistics.current_size = self.cache.size()
                
                return evicted
            except Exception as e:
                logger.exception(f"CacheManager.put error: {e}")
                raise
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache.
        
        Args:
            key: Cache key.
            
        Returns:
            Cached value if found and not expired, None otherwise.
        """
        with self.lock:
            try:
                value = self.cache.get(key)
                
                self.statistics.total_gets += 1
                
                if value is not None:
                    self.statistics.total_hits += 1
                else:
                    self.statistics.total_misses += 1
                
                return value
            except Exception as e:
                logger.exception(f"CacheManager.get error: {e}")
                return None
    
    def contains(self, key: str) -> bool:
        """Check if key exists in cache (ignores expiration).
        
        Args:
            key: Cache key.
            
        Returns:
            True if key exists, False otherwise.
        """
        with self.lock:
            try:
                return self.cache.contains(key)
            except Exception as e:
                logger.exception(f"CacheManager.contains error: {e}")
                return False
    
    def remove(self, key: str) -> bool:
        """Remove entry from cache.
        
        Args:
            key: Cache key.
            
        Returns:
            True if entry was removed, False if not found.
        """
        with self.lock:
            try:
                cache_impl = self.cache
                
                if isinstance(cache_impl, (LRUCache, FIFOCache, LFUCache)):
                    if key in cache_impl.cache:
                        del cache_impl.cache[key]
                        logger.debug(f"Removed {key}")
                        return True
                elif isinstance(cache_impl, ARCCache):
                    if key in cache_impl.cache:
                        cache_impl._remove_expired(key)
                        logger.debug(f"Removed {key}")
                        return True
                
                return False
            except Exception as e:
                logger.exception(f"CacheManager.remove error: {e}")
                return False
    
    def clear(self) -> None:
        """Remove all entries from cache."""
        with self.lock:
            try:
                self.cache.clear()
                logger.info("Cache cleared")
            except Exception as e:
                logger.exception(f"CacheManager.clear error: {e}")
    
    def size(self) -> int:
        """Return current entry count."""
        return self.cache.size()
    
    def cleanup_expired(self) -> None:
        """Remove all expired entries."""
        with self.lock:
            try:
                expired_keys = []
                cache_impl = self.cache
                
                if isinstance(cache_impl, (LRUCache, FIFOCache, LFUCache)):
                    for key, entry in list(cache_impl.cache.items()):
                        if entry.is_expired():
                            expired_keys.append(key)
                elif isinstance(cache_impl, ARCCache):
                    for key, entry in list(cache_impl.cache.items()):
                        if entry.is_expired():
                            expired_keys.append(key)
                
                for key in expired_keys:
                    self.remove(key)
                    self.statistics.total_expirations += 1
                
                if expired_keys:
                    logger.debug(f"Cleaned up {len(expired_keys)} expired entries")
                self.statistics.current_size = self.cache.size()
            except Exception as e:
                logger.exception(f"CacheManager.cleanup_expired error: {e}")
    
    def start_cleanup_thread(self, interval: int = 60) -> None:
        """Start background cleanup thread.
        
        Args:
            interval: Cleanup interval in seconds.
        """
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            logger.debug("Cleanup thread already running")
            return
        
        self.cleanup_running = True
        
        def cleanup_worker() -> None:
            while self.cleanup_running:
                time.sleep(interval)
                self.cleanup_expired()
        
        self.cleanup_thread = threading.Thread(daemon=True, target=cleanup_worker)
        self.cleanup_thread.start()
        logger.info(f"Cleanup thread started with {interval}s interval")
    
    def stop_cleanup_thread(self) -> None:
        """Stop background cleanup thread."""
        self.cleanup_running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("Cleanup thread stopped")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Return cache performance statistics.
        
        Returns:
            Dictionary with stats.
        """
        with self.lock:
            try:
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
            except Exception as e:
                logger.exception(f"Error getting statistics: {e}")
                return {}
    
    def get_entries(self) -> List[Dict]:
        """Return list of cache entries with metadata.
        
        Returns:
            List of entry dictionaries.
        """
        with self.lock:
            try:
                entries = []
                cache_impl = self.cache
                
                if isinstance(cache_impl, (LRUCache, FIFOCache)):
                    for key, entry in cache_impl.cache.items():
                        entries.append({
                            'key': key,
                            'created_at': entry.created_at,
                            'last_accessed': entry.last_accessed,
                            'access_count': entry.access_count,
                            'age': entry.get_age(),
                            'idle_time': entry.get_idle_time(),
                            'size': entry.size,
                        })
                elif isinstance(cache_impl, LFUCache):
                    for key, entry in cache_impl.cache.items():
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
            except Exception as e:
                logger.exception(f"Error getting entries: {e}")
                return []
    
    def generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from inputs.
        
        Args:
            prefix: Key prefix.
            *args: Positional arguments.
            **kwargs: Keyword arguments.
            
        Returns:
            Generated cache key.
        """
        return self.key_generator.generate_key(prefix, *args, **kwargs)
    
    def generate_key_from_url(self, url: str, method: str = "GET") -> str:
        """Generate cache key from HTTP request.
        
        Args:
            url: Request URL.
            method: HTTP method.
            
        Returns:
            Generated cache key.
        """
        return self.key_generator.generate_from_url(url, method)
    
    def warm_cache(self) -> None:
        """Load pre-configured warm entries."""
        self.warmer.warm_cache()
    
    def add_warm_entry(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Add entry to warm on next warm_cache() call.
        
        Args:
            key: Cache key.
            value: Value to store.
            ttl: Optional TTL in seconds.
        """
        self.warmer.add_warm_entry(key, value, ttl)
    
    def invalidate(self) -> None:
        """Apply invalidation rules and remove matching entries."""
        self.invalidator.invalidate()
    
    def add_invalidation_rule(self, rule: Callable[[str], bool]) -> None:
        """Add rule for cache invalidation.
        
        Args:
            rule: Predicate returning True to invalidate.
        """
        self.invalidator.add_invalidation_rule(rule)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Return detailed performance metrics.
        
        Returns:
            Dictionary with statistics and entry metrics.
        """
        with self.lock:
            try:
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
            except Exception as e:
                logger.exception(f"Error computing metrics: {e}")
                return {}
    
    def __enter__(self):
        """Context manager entry."""
        self.start_cleanup_thread()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_cleanup_thread()
        self.clear()
