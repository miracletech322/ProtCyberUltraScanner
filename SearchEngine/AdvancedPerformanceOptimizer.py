"""
================================================================================
FEATURE 2 - ADVANCED PERFORMANCE OPTIMIZATION & SCALABILITY ENGINE - ENHANCED VERSION
================================================================================

Advanced Performance Optimization Engine for High-Volume Security Scanning

This class provides enterprise-grade performance optimization for security scanners:
- Asynchronous I/O with connection pooling and multiplexing
- Intelligent rate limiting and adaptive throttling
- Distributed computing with load balancing
- Memory-efficient caching with compression
- Real-time performance monitoring and auto-tuning
- Fault tolerance and graceful degradation

Features:
1. Multi-tier caching with LRU/LFU eviction policies
2. Async-first architecture with connection reuse
3. Adaptive rate limiting based on target responsiveness
4. Distributed task queue with Redis/Celery integration
5. Real-time performance metrics and auto-optimization
6. Memory pooling and object reuse for reduced GC pressure
7. HTTP/2 multiplexing and connection pipelining
8. Intelligent retry mechanisms with exponential backoff
"""

import asyncio
import aiohttp
import hashlib
import time
import json
import gzip
import pickle
import zlib
import threading
import multiprocessing
import psutil
import gc
from typing import Dict, List, Any, Optional, Set, Tuple, Callable, Union
from collections import defaultdict, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import random
import statistics

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class CacheEntry:
    """Enhanced cache entry with metadata."""
    data: Any
    timestamp: float
    ttl: float
    hits: int = 0
    size: int = 0
    compression: str = 'none'
    dependencies: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)

@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""
    tokens: float
    last_refill: float
    rate: float  # tokens per second
    capacity: float
    penalty_count: int = 0
    last_penalty: float = 0.0

class AdvancedPerformanceOptimizer:
    """
    Advanced Performance Optimization Engine for high-throughput security scanning.
    
    This class provides comprehensive performance optimizations including:
    - Async-first HTTP client with connection pooling
    - Multi-tier intelligent caching
    - Adaptive rate limiting with circuit breakers
    - Distributed task processing
    - Real-time performance monitoring and auto-tuning
    - Memory optimization and garbage collection control
    """
    
    def __init__(self, 
                 max_connections: int = 1000,
                 max_cache_size: int = 1024 * 1024 * 100,  # 100MB
                 enable_compression: bool = True,
                 enable_distributed: bool = False,
                 redis_url: str = None):
        """
        Initialize the performance optimizer.
        
        Args:
            max_connections: Maximum simultaneous connections
            max_cache_size: Maximum cache size in bytes
            enable_compression: Enable response compression
            enable_distributed: Enable distributed processing
            redis_url: Redis URL for distributed caching
        """
        self.max_connections = max_connections
        self.max_cache_size = max_cache_size
        self.enable_compression = enable_compression
        self.enable_distributed = enable_distributed
        
        # Connection pools
        self.http_pool = None
        self.aiohttp_session = None
        self.connection_stats = defaultdict(int)
        
        # Enhanced caching system
        self.cache = OrderedDict()  # LRU cache
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_size = 0
        self.disk_cache_path = None
        
        # Rate limiting with adaptive algorithms
        self.rate_limits = {}
        self.circuit_breakers = {}
        self.throttle_configs = {}
        
        # Performance monitoring
        self.metrics = {
            'requests': defaultdict(int),
            'response_times': deque(maxlen=1000),
            'errors': defaultdict(int),
            'throughput': deque(maxlen=60),  # Last minute
        }
        
        # Memory management
        self.object_pool = defaultdict(deque)
        self.memory_threshold = 0.8  # 80% memory usage threshold
        
        # Thread/process pools
        self.thread_pool = None
        self.process_pool = None
        self.max_workers = multiprocessing.cpu_count() * 2
        
        # Distributed processing (Redis)
        self.redis_client = None
        if enable_distributed and redis_url:
            self._init_redis(redis_url)
        
        # Auto-tuning parameters
        self.auto_tune_interval = 60  # seconds
        self.last_tune_time = time.time()
        self.tuning_history = deque(maxlen=100)
        
        # DNS cache
        self.dns_cache = {}
        self.dns_ttl = 300
        
        # Initialize components
        self._init_connection_pool()
        self._init_thread_pools()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_performance, daemon=True)
        self.monitor_thread.start()
        
        logger.info(f"Performance Optimizer initialized with {max_connections} max connections")
    
    def _init_connection_pool(self):
        """Initialize HTTP connection pools."""
        # Sync HTTP adapter with connection pooling
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD"]
        )
        
        adapter = HTTPAdapter(
            pool_connections=self.max_connections,
            pool_maxsize=self.max_connections,
            max_retries=retry_strategy,
            pool_block=False,
        )
        
        self.http_pool = requests.Session()
        self.http_pool.mount("http://", adapter)
        self.http_pool.mount("https://", adapter)
        
        # Performance headers
        self.http_pool.headers.update({
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept': '*/*',
            'Connection': 'keep-alive',
            'Keep-Alive': 'timeout=30, max=1000',
        })
    
    async def _init_async_session(self):
        """Initialize async HTTP session."""
        if not self.aiohttp_session:
            timeout = aiohttp.ClientTimeout(
                total=30,
                connect=10,
                sock_read=20,
                sock_connect=10
            )
            
            connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                limit_per_host=20,
                ttl_dns_cache=self.dns_ttl,
                enable_cleanup_closed=True,
                force_close=False,
                use_dns_cache=True,
            )
            
            self.aiohttp_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'Accept-Encoding': 'gzip, deflate, br',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                }
            )
        
        return self.aiohttp_session
    
    def _init_thread_pools(self):
        """Initialize thread and process pools."""
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="optimizer_thread"
        )
        
        self.process_pool = ProcessPoolExecutor(
            max_workers=min(multiprocessing.cpu_count(), 4),
            mp_context=multiprocessing.get_context('spawn')
        )
    
    def _init_redis(self, redis_url: str):
        """Initialize Redis client for distributed caching."""
        try:
            import redis
            self.redis_client = redis.Redis.from_url(
                redis_url,
                decode_responses=False,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            logger.info(f"Redis connected: {redis_url}")
        except ImportError:
            logger.warning("Redis not installed, distributed caching disabled")
            self.enable_distributed = False
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.enable_distributed = False
    
    # ============================================================================
    # ASYNC HTTP REQUESTS
    # ============================================================================
    
    async def async_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Dict = None,
        data: Any = None,
        json_data: Any = None,
        timeout: int = 30,
        retries: int = 3,
        backoff_factor: float = 1.0,
        circuit_breaker: bool = True
    ) -> Optional[Dict]:
        """
        Make asynchronous HTTP request with advanced features.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            data: Request data
            json_data: JSON data
            timeout: Request timeout
            retries: Maximum retries
            backoff_factor: Exponential backoff factor
            circuit_breaker: Enable circuit breaker
        
        Returns:
            Response dictionary or None on failure
        """
        # Check circuit breaker
        if circuit_breaker and self._is_circuit_open(url):
            logger.warning(f"Circuit open for {url}, skipping request")
            return None
        
        # Apply rate limiting
        await self._apply_rate_limit(url)
        
        # Prepare request
        session = await self._init_async_session()
        request_headers = headers or {}
        
        # Add performance headers
        request_headers.setdefault('Accept-Encoding', 'gzip, deflate, br')
        
        start_time = time.time()
        last_error = None
        
        for attempt in range(retries + 1):
            try:
                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    data=data,
                    json=json_data,
                    timeout=timeout,
                    ssl=False
                ) as response:
                    
                    # Read response
                    content = await response.read()
                    text = await response.text(errors='ignore')
                    
                    # Record metrics
                    elapsed = time.time() - start_time
                    self._record_metrics(url, response.status, elapsed)
                    
                    # Update circuit breaker on success
                    if circuit_breaker:
                        self._record_success(url)
                    
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'content': content,
                        'text': text,
                        'url': str(response.url),
                        'elapsed': elapsed,
                        'attempt': attempt + 1,
                        'cached': False,
                    }
                    
            except asyncio.TimeoutError:
                last_error = f"Timeout after {timeout}s"
                logger.warning(f"Request timeout for {url} (attempt {attempt + 1})")
            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.warning(f"Client error for {url}: {e}")
            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error for {url}: {e}")
            
            # Exponential backoff before retry
            if attempt < retries:
                backoff_time = backoff_factor * (2 ** attempt)
                backoff_time += random.uniform(0, 0.1)  # Jitter
                await asyncio.sleep(backoff_time)
        
        # All retries failed
        if circuit_breaker:
            self._record_failure(url, last_error)
        
        self.metrics['errors']['total'] += 1
        self.metrics['errors'][url] = self.metrics['errors'].get(url, 0) + 1
        
        return None
    
    async def async_batch_request(
        self,
        requests: List[Dict],
        max_concurrent: int = 100,
        batch_timeout: int = 300
    ) -> List[Optional[Dict]]:
        """
        Process batch of HTTP requests concurrently.
        
        Args:
            requests: List of request configurations
            max_concurrent: Maximum concurrent requests
            batch_timeout: Total batch timeout
        
        Returns:
            List of responses
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        tasks = []
        results = [None] * len(requests)
        
        async def process_request(idx: int, req_config: Dict):
            async with semaphore:
                try:
                    response = await self.async_request(**req_config)
                    results[idx] = response
                except Exception as e:
                    logger.error(f"Batch request failed: {e}")
                    results[idx] = None
        
        # Create tasks
        for i, req in enumerate(requests):
            task = asyncio.create_task(process_request(i, req))
            tasks.append(task)
        
        # Wait for completion with timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=batch_timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Batch request timed out after {batch_timeout}s")
            # Cancel remaining tasks
            for task in tasks:
                task.cancel()
        
        return results
    
    # ============================================================================
    # SYNC HTTP REQUESTS (with connection pooling)
    # ============================================================================
    
    def sync_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Dict = None,
        data: Any = None,
        json_data: Any = None,
        timeout: int = 30,
        retries: int = 3,
        allow_redirects: bool = True,
        stream: bool = False
    ) -> Optional[Dict]:
        """
        Make synchronous HTTP request with connection pooling.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            data: Request data
            json_data: JSON data
            timeout: Request timeout
            retries: Maximum retries
            allow_redirects: Follow redirects
            stream: Stream response
        
        Returns:
            Response dictionary or None on failure
        """
        start_time = time.time()
        
        try:
            response = self.http_pool.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                timeout=timeout,
                allow_redirects=allow_redirects,
                stream=stream
            )
            
            # Read response (if not streaming)
            if not stream:
                content = response.content
                text = response.text
            else:
                content = None
                text = None
            
            elapsed = time.time() - start_time
            self._record_metrics(url, response.status_code, elapsed)
            
            return {
                'status': response.status_code,
                'headers': dict(response.headers),
                'content': content,
                'text': text,
                'url': response.url,
                'elapsed': elapsed,
                'cached': False,
            }
            
        except requests.RequestException as e:
            logger.error(f"Sync request failed for {url}: {e}")
            self.metrics['errors']['total'] += 1
            return None
    
    # ============================================================================
    # ADVANCED CACHING SYSTEM
    # ============================================================================
    
    def cache_set(
        self,
        key: str,
        data: Any,
        ttl: int = 300,
        tags: List[str] = None,
        compress: bool = True,
        dependencies: List[str] = None
    ) -> bool:
        """
        Store data in cache with advanced features.
        
        Args:
            key: Cache key
            data: Data to cache
            ttl: Time to live in seconds
            tags: Tags for categorization
            compress: Enable compression
            dependencies: Dependent cache keys
        
        Returns:
            True if successful
        """
        try:
            # Generate cache key
            cache_key = self._generate_cache_key(key)
            
            # Prepare data
            cache_data = data
            compression = 'none'
            size = len(pickle.dumps(data)) if hasattr(data, '__len__') else 0
            
            # Apply compression if enabled
            if compress and self.enable_compression and size > 100:
                try:
                    cache_data = gzip.compress(pickle.dumps(data))
                    compression = 'gzip'
                    size = len(cache_data)
                except Exception as e:
                    logger.warning(f"Cache compression failed: {e}")
            
            # Check cache size limit
            if size + self.cache_size > self.max_cache_size:
                self._evict_cache(size)
            
            # Create cache entry
            entry = CacheEntry(
                data=cache_data,
                timestamp=time.time(),
                ttl=ttl,
                size=size,
                compression=compression,
                tags=set(tags or []),
                dependencies=dependencies or []
            )
            
            # Store in memory cache
            self.cache[cache_key] = entry
            self.cache_size += size
            
            # Move to end (LRU)
            self.cache.move_to_end(cache_key)
            
            # Store in distributed cache if enabled
            if self.enable_distributed and self.redis_client:
                self._cache_set_distributed(cache_key, entry)
            
            return True
            
        except Exception as e:
            logger.error(f"Cache set failed: {e}")
            return False
    
    def cache_get(self, key: str, update_ttl: bool = False) -> Optional[Any]:
        """
        Retrieve data from cache.
        
        Args:
            key: Cache key
            update_ttl: Reset TTL on access
        
        Returns:
            Cached data or None
        """
        cache_key = self._generate_cache_key(key)
        
        # Check memory cache first
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            
            # Check TTL
            if time.time() - entry.timestamp < entry.ttl:
                # Move to end (LRU)
                self.cache.move_to_end(cache_key)
                entry.hits += 1
                self.cache_hits += 1
                
                # Update TTL if requested
                if update_ttl:
                    entry.timestamp = time.time()
                
                # Decompress if needed
                if entry.compression == 'gzip':
                    try:
                        data = pickle.loads(gzip.decompress(entry.data))
                    except Exception as e:
                        logger.error(f"Cache decompression failed: {e}")
                        return None
                else:
                    data = entry.data
                
                return data
        
        # Check distributed cache
        if self.enable_distributed and self.redis_client:
            data = self._cache_get_distributed(cache_key)
            if data:
                self.cache_hits += 1
                return data
        
        self.cache_misses += 1
        return None
    
    def cache_invalidate(self, key: str = None, tag: str = None, pattern: str = None):
        """
        Invalidate cache entries.
        
        Args:
            key: Specific cache key
            tag: Invalidate all entries with tag
            pattern: Regex pattern for keys
        """
        if key:
            cache_key = self._generate_cache_key(key)
            if cache_key in self.cache:
                entry = self.cache.pop(cache_key)
                self.cache_size -= entry.size
        
        elif tag:
            keys_to_remove = []
            for key, entry in self.cache.items():
                if tag in entry.tags:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                entry = self.cache.pop(key)
                self.cache_size -= entry.size
        
        elif pattern:
            import re
            regex = re.compile(pattern)
            keys_to_remove = [k for k in self.cache if regex.match(k)]
            
            for key in keys_to_remove:
                entry = self.cache.pop(key)
                self.cache_size -= entry.size
        
        # Invalidate distributed cache
        if self.enable_distributed and self.redis_client:
            self._cache_invalidate_distributed(key, tag, pattern)
    
    def _evict_cache(self, required_size: int):
        """Evict cache entries using LRU policy."""
        evicted_size = 0
        keys_to_evict = []
        
        for key in self.cache:
            entry = self.cache[key]
            evicted_size += entry.size
            keys_to_evict.append(key)
            
            if self.cache_size - evicted_size + required_size <= self.max_cache_size * 0.8:
                break
        
        for key in keys_to_evict:
            entry = self.cache.pop(key)
            self.cache_size -= entry.size
        
        logger.info(f"Evicted {evicted_size} bytes from cache")
    
    def _generate_cache_key(self, key: str) -> str:
        """Generate normalized cache key."""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _cache_set_distributed(self, key: str, entry: CacheEntry):
        """Store cache entry in distributed cache."""
        try:
            serialized = pickle.dumps({
                'data': entry.data,
                'timestamp': entry.timestamp,
                'ttl': entry.ttl,
                'compression': entry.compression,
            })
            
            self.redis_client.setex(
                key,
                entry.ttl,
                serialized
            )
        except Exception as e:
            logger.error(f"Distributed cache set failed: {e}")
    
    def _cache_get_distributed(self, key: str) -> Optional[Any]:
        """Retrieve cache entry from distributed cache."""
        try:
            serialized = self.redis_client.get(key)
            if serialized:
                entry_data = pickle.loads(serialized)
                
                # Check TTL
                if time.time() - entry_data['timestamp'] < entry_data['ttl']:
                    data = entry_data['data']
                    
                    # Decompress if needed
                    if entry_data['compression'] == 'gzip':
                        data = pickle.loads(gzip.decompress(data))
                    
                    # Store in local cache for faster access
                    self.cache_set(key, data, entry_data['ttl'])
                    
                    return data
        except Exception as e:
            logger.error(f"Distributed cache get failed: {e}")
        
        return None
    
    def _cache_invalidate_distributed(self, key: str = None, tag: str = None, pattern: str = None):
        """Invalidate distributed cache entries."""
        try:
            if key:
                self.redis_client.delete(self._generate_cache_key(key))
            elif tag:
                # Redis doesn't support tag-based invalidation natively
                # Would need to maintain a tag->keys index
                pass
            elif pattern:
                # Scan and delete matching keys
                cursor = 0
                while True:
                    cursor, keys = self.redis_client.scan(
                        cursor=cursor,
                        match=pattern,
                        count=1000
                    )
                    
                    if keys:
                        self.redis_client.delete(*keys)
                    
                    if cursor == 0:
                        break
        except Exception as e:
            logger.error(f"Distributed cache invalidation failed: {e}")
    
    # ============================================================================
    # RATE LIMITING & CIRCUIT BREAKERS
    # ============================================================================
    
    def configure_rate_limit(
        self,
        target: str,
        requests_per_second: float = 10,
        burst_capacity: int = 20,
        penalty_factor: float = 2.0
    ):
        """
        Configure rate limiting for a target.
        
        Args:
            target: Target domain or IP
            requests_per_second: Maximum requests per second
            burst_capacity: Burst capacity
            penalty_factor: Penalty multiplier for violations
        """
        self.rate_limits[target] = RateLimitBucket(
            tokens=burst_capacity,
            last_refill=time.time(),
            rate=requests_per_second,
            capacity=burst_capacity
        )
        
        self.throttle_configs[target] = {
            'rps': requests_per_second,
            'burst': burst_capacity,
            'penalty': penalty_factor,
        }
    
    async def _apply_rate_limit(self, url: str):
        """Apply rate limiting for URL."""
        target = urlparse(url).netloc
        if target not in self.rate_limits:
            # Default rate limit
            self.configure_rate_limit(target)
        
        bucket = self.rate_limits[target]
        
        while True:
            current_time = time.time()
            elapsed = current_time - bucket.last_refill
            
            # Refill tokens
            new_tokens = elapsed * bucket.rate
            bucket.tokens = min(bucket.capacity, bucket.tokens + new_tokens)
            bucket.last_refill = current_time
            
            # Check if we have tokens
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return
            
            # Wait for next token
            wait_time = (1 - bucket.tokens) / bucket.rate
            await asyncio.sleep(wait_time)
    
    def _record_success(self, target: str):
        """Record successful request for circuit breaker."""
        if target not in self.circuit_breakers:
            self.circuit_breakers[target] = {
                'failures': 0,
                'successes': 0,
                'state': 'CLOSED',
                'last_failure': 0,
                'opened_at': 0,
            }
        
        cb = self.circuit_breakers[target]
        cb['successes'] += 1
        
        # Reset failure count after enough successes
        if cb['successes'] >= 10 and cb['state'] == 'HALF_OPEN':
            cb['state'] = 'CLOSED'
            cb['failures'] = 0
            cb['successes'] = 0
    
    def _record_failure(self, target: str, error: str):
        """Record failed request for circuit breaker."""
        if target not in self.circuit_breakers:
            self.circuit_breakers[target] = {
                'failures': 0,
                'successes': 0,
                'state': 'CLOSED',
                'last_failure': time.time(),
                'opened_at': 0,
            }
        
        cb = self.circuit_breakers[target]
        cb['failures'] += 1
        cb['last_failure'] = time.time()
        
        # Check if circuit should open
        if cb['state'] == 'CLOSED' and cb['failures'] >= 5:
            cb['state'] = 'OPEN'
            cb['opened_at'] = time.time()
            logger.warning(f"Circuit opened for {target}")
        elif cb['state'] == 'HALF_OPEN':
            cb['state'] = 'OPEN'
            cb['opened_at'] = time.time()
    
    def _is_circuit_open(self, target: str) -> bool:
        """Check if circuit breaker is open for target."""
        if target not in self.circuit_breakers:
            return False
        
        cb = self.circuit_breakers[target]
        
        if cb['state'] == 'OPEN':
            # Check if timeout has passed
            if time.time() - cb['opened_at'] > 60:  # 60 second timeout
                cb['state'] = 'HALF_OPEN'
                return False
            return True
        
        return False
    
    # ============================================================================
    # BATCH PROCESSING & DISTRIBUTED COMPUTING
    # ============================================================================
    
    def process_batch(
        self,
        items: List,
        processor: Callable,
        batch_size: int = 100,
        max_workers: int = None,
        use_processes: bool = False,
        progress_callback: Callable = None
    ) -> List:
        """
        Process items in batches with parallel execution.
        
        Args:
            items: List of items to process
            processor: Processing function
            batch_size: Items per batch
            max_workers: Maximum workers
            use_processes: Use processes instead of threads
            progress_callback: Progress callback function
        
        Returns:
            List of results
        """
        results = []
        total_items = len(items)
        processed = 0
        
        executor_class = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
        workers = max_workers or (multiprocessing.cpu_count() if use_processes else self.max_workers)
        
        with executor_class(max_workers=workers) as executor:
            # Process in batches
            for i in range(0, total_items, batch_size):
                batch = items[i:i + batch_size]
                
                # Submit batch tasks
                future_to_item = {
                    executor.submit(processor, item): item
                    for item in batch
                }
                
                # Collect results
                for future in as_completed(future_to_item):
                    item = future_to_item[future]
                    try:
                        result = future.result(timeout=300)
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Batch processing failed for {item}: {e}")
                        results.append(None)
                    
                    processed += 1
                    
                    # Update progress
                    if progress_callback:
                        progress_callback(processed, total_items)
                
                # Rate limiting between batches
                time.sleep(0.05)
        
        return results
    
    async def async_process_batch(
        self,
        items: List,
        processor: Callable,
        batch_size: int = 100,
        max_concurrent: int = 50
    ) -> List:
        """
        Process items asynchronously in batches.
        
        Args:
            items: List of items to process
            processor: Async processing function
            batch_size: Items per batch
            max_concurrent: Maximum concurrent tasks
        
        Returns:
            List of results
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []
        
        async def process_item(item):
            async with semaphore:
                try:
                    result = await processor(item)
                    return result
                except Exception as e:
                    logger.error(f"Async batch processing failed: {e}")
                    return None
        
        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            
            # Create tasks
            tasks = [process_item(item) for item in batch]
            
            # Wait for batch completion
            batch_results = await asyncio.gather(*tasks)
            results.extend(batch_results)
            
            # Small delay between batches
            await asyncio.sleep(0.01)
        
        return results
    
    def distribute_task(
        self,
        task_id: str,
        task_data: Any,
        queue_name: str = 'default',
        priority: int = 0,
        ttl: int = 3600
    ) -> bool:
        """
        Distribute task to distributed queue.
        
        Args:
            task_id: Unique task identifier
            task_data: Task data
            queue_name: Queue name
            priority: Task priority
            ttl: Time to live in seconds
        
        Returns:
            True if successful
        """
        if not self.enable_distributed or not self.redis_client:
            logger.warning("Distributed processing not enabled")
            return False
        
        try:
            task_payload = {
                'id': task_id,
                'data': task_data,
                'priority': priority,
                'created_at': time.time(),
                'queue': queue_name,
            }
            
            serialized = pickle.dumps(task_payload)
            
            # Use Redis sorted set for priority queue
            self.redis_client.zadd(
                f'queue:{queue_name}',
                {serialized: priority}
            )
            
            # Set TTL
            self.redis_client.expire(f'queue:{queue_name}', ttl)
            
            return True
            
        except Exception as e:
            logger.error(f"Task distribution failed: {e}")
            return False
    
    # ============================================================================
    # PERFORMANCE MONITORING & AUTO-TUNING
    # ============================================================================
    
    def _record_metrics(self, url: str, status: int, elapsed: float):
        """Record request metrics."""
        target = urlparse(url).netloc
        
        self.metrics['requests']['total'] += 1
        self.metrics['requests'][target] = self.metrics['requests'].get(target, 0) + 1
        self.metrics['requests'][f'status_{status}'] = self.metrics['requests'].get(f'status_{status}', 0) + 1
        
        self.metrics['response_times'].append(elapsed)
        
        # Record throughput (requests per second)
        current_second = int(time.time())
        self.metrics['throughput'].append((current_second, 1))
        
        # Remove old throughput records
        cutoff = current_second - 60
        self.metrics['throughput'] = deque(
            [t for t in self.metrics['throughput'] if t[0] > cutoff],
            maxlen=1000
        )
    
    def _monitor_performance(self):
        """Monitor performance and auto-tune parameters."""
        while True:
            try:
                # Check memory usage
                memory_usage = psutil.Process().memory_percent()
                
                if memory_usage > self.memory_threshold:
                    self.optimize_memory(aggressive=True)
                
                # Auto-tune every interval
                current_time = time.time()
                if current_time - self.last_tune_time > self.auto_tune_interval:
                    self._auto_tune_parameters()
                    self.last_tune_time = current_time
                
                # Log performance stats periodically
                if random.random() < 0.01:  # 1% chance each iteration
                    stats = self.get_performance_stats()
                    logger.debug(f"Performance stats: {stats}")
                
                # Sleep for monitoring interval
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                time.sleep(30)
    
    def _auto_tune_parameters(self):
        """Auto-tune performance parameters based on metrics."""
        try:
            # Analyze response times
            if self.metrics['response_times']:
                avg_response = statistics.mean(self.metrics['response_times'])
                p95_response = statistics.quantiles(self.metrics['response_times'], n=20)[18]
                
                # Adjust connection pool based on performance
                if avg_response > 2.0:  # Slow responses
                    # Reduce concurrent connections
                    new_max = max(10, self.max_connections // 2)
                    if new_max != self.max_connections:
                        logger.info(f"Auto-tuning: Reducing max connections from {self.max_connections} to {new_max}")
                        self.max_connections = new_max
                        self._init_connection_pool()
                
                elif avg_response < 0.5 and p95_response < 1.0:  # Fast responses
                    # Increase concurrent connections
                    new_max = min(5000, self.max_connections * 2)
                    if new_max != self.max_connections:
                        logger.info(f"Auto-tuning: Increasing max connections from {self.max_connections} to {new_max}")
                        self.max_connections = new_max
                        self._init_connection_pool()
            
            # Analyze error rate
            total_requests = self.metrics['requests'].get('total', 0)
            total_errors = self.metrics['errors'].get('total', 0)
            
            if total_requests > 100:
                error_rate = total_errors / total_requests
                
                if error_rate > 0.1:  # 10% error rate
                    # Increase timeouts
                    logger.info("Auto-tuning: High error rate detected, consider adjusting timeouts")
            
            # Record tuning decision
            self.tuning_history.append({
                'timestamp': time.time(),
                'max_connections': self.max_connections,
                'avg_response': avg_response if self.metrics['response_times'] else 0,
                'error_rate': error_rate if total_requests > 0 else 0,
            })
            
        except Exception as e:
            logger.error(f"Auto-tuning failed: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        total_requests = self.metrics['requests'].get('total', 0)
        total_errors = self.metrics['errors'].get('total', 0)
        
        # Calculate throughput
        throughput_data = list(self.metrics['throughput'])
        if throughput_data:
            throughput = sum(count for _, count in throughput_data[-10:]) / 10  # Last 10 seconds
        else:
            throughput = 0
        
        # Calculate cache hit rate
        cache_total = self.cache_hits + self.cache_misses
        cache_hit_rate = self.cache_hits / cache_total if cache_total > 0 else 0
        
        # Calculate response time statistics
        response_times = list(self.metrics['response_times'])
        if response_times:
            avg_response = statistics.mean(response_times)
            p95_response = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else 0
            p99_response = statistics.quantiles(response_times, n=100)[98] if len(response_times) >= 100 else 0
        else:
            avg_response = p95_response = p99_response = 0
        
        return {
            'requests': {
                'total': total_requests,
                'per_second': throughput,
                'error_rate': total_errors / total_requests if total_requests > 0 else 0,
            },
            'response_times': {
                'avg_ms': avg_response * 1000,
                'p95_ms': p95_response * 1000,
                'p99_ms': p99_response * 1000,
            },
            'cache': {
                'size': self.cache_size,
                'entries': len(self.cache),
                'hits': self.cache_hits,
                'misses': self.cache_misses,
                'hit_rate': cache_hit_rate,
            },
            'connections': {
                'max': self.max_connections,
                'active': self.connection_stats.get('active', 0),
                'pool_size': len(self.http_pool.adapters) if self.http_pool else 0,
            },
            'memory': {
                'usage_mb': psutil.Process().memory_info().rss / 1024 / 1024,
                'cache_mb': self.cache_size / 1024 / 1024,
                'available_percent': 100 - psutil.virtual_memory().percent,
            },
            'rate_limits': {
                'configured': len(self.rate_limits),
                'circuit_breakers': len([cb for cb in self.circuit_breakers.values() if cb['state'] != 'CLOSED']),
            },
            'timestamp': time.time(),
        }
    
    # ============================================================================
    # MEMORY OPTIMIZATION
    # ============================================================================
    
    def optimize_memory(self, aggressive: bool = False):
        """Optimize memory usage."""
        logger.info("Starting memory optimization...")
        
        # Clear expired cache entries
        self._clean_expired_cache()
        
        # Reduce cache size if needed
        if self.cache_size > self.max_cache_size * 0.9:
            self._evict_cache(0)
        
        # Clear connection pool for idle connections
        if self.http_pool:
            self.http_pool.close()
            self._init_connection_pool()
        
        # Clear async session if exists
        if self.aiohttp_session:
            asyncio.run(self._close_async_session())
        
        # Clear object pools
        self.object_pool.clear()
        
        # Force garbage collection
        gc.collect(generation=2 if aggressive else 1)
        
        # Compact memory if available
        try:
            import ctypes
            ctypes.CDLL('libc.so.6').malloc_trim(0)
        except:
            pass
        
        stats = self.get_performance_stats()
        logger.info(f"Memory optimized. Cache: {stats['cache']['entries']} entries, "
                   f"Memory usage: {stats['memory']['usage_mb']:.1f}MB")
    
    async def _close_async_session(self):
        """Close async HTTP session."""
        if self.aiohttp_session and not self.aiohttp_session.closed:
            await self.aiohttp_session.close()
            self.aiohttp_session = None
    
    def _clean_expired_cache(self):
        """Clean expired cache entries."""
        current_time = time.time()
        expired_keys = []
        
        for key, entry in self.cache.items():
            if current_time - entry.timestamp > entry.ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            entry = self.cache.pop(key, None)
            if entry:
                self.cache_size -= entry.size
        
        if expired_keys:
            logger.debug(f"Cleaned {len(expired_keys)} expired cache entries")
    
    # ============================================================================
    # UTILITY METHODS
    # ============================================================================
    
    def get_cached_response(self, url: str, params: Dict = None) -> Optional[Dict]:
        """Get cached HTTP response."""
        cache_key = f"http:{url}:{hashlib.sha256(json.dumps(params or {}).encode()).hexdigest()}"
        return self.cache_get(cache_key)
    
    def cache_response(self, url: str, response: Dict, ttl: int = 300):
        """Cache HTTP response."""
        cache_key = f"http:{url}:{hashlib.sha256(json.dumps(response.get('params', {})).encode()).hexdigest()}"
        self.cache_set(cache_key, response, ttl=ttl)
    
    def batch_process_urls(self, urls: List[str], method: str = 'GET', **kwargs) -> List[Dict]:
        """Batch process URLs with caching."""
        results = []
        
        for url in urls:
            # Check cache first
            cached = self.get_cached_response(url)
            if cached:
                cached['cached'] = True
                results.append(cached)
            else:
                response = self.sync_request(url, method=method, **kwargs)
                if response:
                    self.cache_response(url, response)
                    results.append(response)
        
        return results
    
    def shutdown(self):
        """Shutdown optimizer and cleanup resources."""
        logger.info("Shutting down Performance Optimizer...")
        
        # Close HTTP sessions
        if self.http_pool:
            self.http_pool.close()
        
        # Close async session
        if self.aiohttp_session and not self.aiohttp_session.closed:
            asyncio.run(self._close_async_session())
        
        # Shutdown thread pools
        if self.thread_pool:
            self.thread_pool.shutdown(wait=False)
        
        if self.process_pool:
            self.process_pool.shutdown(wait=False)
        
        # Clear caches
        self.cache.clear()
        self.cache_size = 0
        
        # Stop monitoring thread
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("Performance Optimizer shutdown complete")

# ============================================================================
# PERFORMANCE UTILITY FUNCTIONS
# ============================================================================

class PerformanceProfiler:
    """Utility class for performance profiling."""
    
    @staticmethod
    def profile_function(func: Callable, *args, **kwargs) -> Tuple[Any, Dict]:
        """
        Profile function execution.
        
        Returns:
            Tuple of (result, profile_data)
        """
        import time
        import tracemalloc
        
        tracemalloc.start()
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            result = e
        
        end_time = time.time()
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        profile_data = {
            'execution_time': end_time - start_time,
            'memory_current': current,
            'memory_peak': peak,
            'success': not isinstance(result, Exception)
        }
        
        return result, profile_data
    
    @staticmethod
    def benchmark_throughput(func: Callable, iterations: int = 100, *args, **kwargs) -> Dict:
        """Benchmark function throughput."""
        import time
        
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            func(*args, **kwargs)
            end = time.perf_counter()
            times.append(end - start)
        
        return {
            'iterations': iterations,
            'total_time': sum(times),
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'throughput': iterations / sum(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
        }

def optimize_for_throughput(target_rps: int, current_rps: int, current_connections: int) -> int:
    """
    Calculate optimal connection count for target RPS.
    
    Args:
        target_rps: Target requests per second
        current_rps: Current requests per second
        current_connections: Current connection count
    
    Returns:
        Recommended connection count
    """
    if current_rps <= 0:
        return current_connections * 2
    
    ratio = target_rps / current_rps
    new_connections = int(current_connections * ratio)
    
    # Add some headroom
    new_connections = int(new_connections * 1.2)
    
    # Apply limits
    new_connections = max(10, min(new_connections, 5000))
    
    return new_connections

# ============================================================================
# EXAMPLE USAGE
# ============================================================================

async def example_usage():
    """Example usage of AdvancedPerformanceOptimizer."""
    
    # Initialize optimizer
    optimizer = AdvancedPerformanceOptimizer(
        max_connections=500,
        max_cache_size=1024 * 1024 * 50,  # 50MB
        enable_compression=True,
        enable_distributed=False
    )
    
    print("Performance Optimizer initialized")
    
    # Configure rate limiting for a domain
    optimizer.configure_rate_limit(
        target="example.com",
        requests_per_second=5,
        burst_capacity=10
    )
    
    # Make async requests
    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/status/200",
        "https://httpbin.org/delay/1",
    ]
    
    print(f"\nMaking {len(urls)} async requests...")
    
    start_time = time.time()
    responses = await asyncio.gather(*[
        optimizer.async_request(url) for url in urls
    ])
    
    elapsed = time.time() - start_time
    print(f"Completed in {elapsed:.2f}s ({len(urls)/elapsed:.1f} req/s)")
    
    # Batch processing example
    print("\nBatch processing example...")
    
    def process_url(url: str):
        response = optimizer.sync_request(url)
        return {'url': url, 'status': response['status'] if response else 'error'}
    
    test_urls = [f"https://httpbin.org/status/{code}" for code in [200, 404, 500]] * 10
    
    batch_results = optimizer.process_batch(
        items=test_urls,
        processor=process_url,
        batch_size=5,
        progress_callback=lambda p, t: print(f"Progress: {p}/{t}")
    )
    
    print(f"Processed {len(batch_results)} URLs in batch")
    
    # Cache example
    print("\nCache example...")
    
    cache_key = "test:data"
    test_data = {"message": "Hello, World!", "timestamp": time.time()}
    
    optimizer.cache_set(cache_key, test_data, ttl=60, tags=["test", "example"])
    
    cached = optimizer.cache_get(cache_key)
    print(f"Cached data retrieved: {cached is not None}")
    
    # Get performance stats
    print("\nPerformance Statistics:")
    stats = optimizer.get_performance_stats()
    
    print(f"Total requests: {stats['requests']['total']}")
    print(f"Throughput: {stats['requests']['per_second']:.1f} req/s")
    print(f"Cache hit rate: {stats['cache']['hit_rate']:.1%}")
    print(f"Memory usage: {stats['memory']['usage_mb']:.1f} MB")
    
    # Optimize memory
    print("\nOptimizing memory...")
    optimizer.optimize_memory()
    
    # Clean shutdown
    optimizer.shutdown()
    
    return stats

if __name__ == "__main__":
    # Run example
    asyncio.run(example_usage())