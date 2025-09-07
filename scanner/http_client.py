"""
http_client.py
--------------
This module provides a stealthy HTTP client for making web requests with randomized headers,
delays, and retry logic. It supports GET, POST, and HEAD methods and can optionally route traffic
through a proxy.

Enhanced with human-like browsing patterns:
- Contextual headers (referer, accept variations)
- Adaptive timing based on request history
- Occasional innocent browsing behavior
- Session state tracking for realistic patterns

Severity:
- Network request failure = Warning
- Successful request with stealth = Info
"""

import time
import random
import requests
from typing import List, Tuple, Optional, Dict, Any
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, urljoin
import concurrent.futures

USER_AGENTS = [
    # More diverse and recent UAs
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
]

# Common innocent paths users might visit
INNOCENT_PATHS = [
    '/favicon.ico',
    '/robots.txt', 
    '/sitemap.xml',
    '/about',
    '/contact',
    '/privacy',
    '/terms',
    '/help',
    '/support'
]

def _random_headers():
    """Generate basic randomized headers"""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
    }

def _get_contextual_headers(base_headers: Dict[str, str], url: str, last_url: Optional[str] = None, request_count: int = 0) -> Dict[str, str]:
    """
    Generate contextual headers that mimic real browser behavior
    """
    headers = base_headers.copy()
    parsed = urlparse(url)
    
    # Add realistic referer patterns after first request
    if last_url and request_count > 0:
        # Sometimes use the actual last URL as referer
        if random.random() < 0.7:  # 70% of the time
            headers["Referer"] = last_url
        else:
            # Sometimes use other realistic referers
            potential_referers = [
                f"{parsed.scheme}://{parsed.netloc}/",
                f"https://www.google.com/search?q={parsed.netloc}",
                f"{parsed.scheme}://{parsed.netloc}/home"
            ]
            headers["Referer"] = random.choice(potential_referers)
    
    # Vary Accept headers occasionally to simulate different request types
    if random.random() < 0.2:  # 20% chance
        accept_variations = [
            "application/json, text/plain, */*",
            "text/css,*/*;q=0.1",
            "image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            "*/*"
        ]
        headers["Accept"] = random.choice(accept_variations)
    
    # Sometimes add Accept-Encoding (browsers always do this)
    if random.random() < 0.8:  # 80% chance
        headers["Accept-Encoding"] = "gzip, deflate, br"
    
    # Occasionally add DNT header (privacy-conscious users)
    if random.random() < 0.3:  # 30% chance
        headers["DNT"] = "1"
    
    # Sometimes add Sec-Fetch headers (modern browsers)
    if random.random() < 0.6:  # 60% chance
        headers.update({
            "Sec-Fetch-Dest": random.choice(["document", "empty", "image"]),
            "Sec-Fetch-Mode": "navigate" if "document" in headers.get("Sec-Fetch-Dest", "") else "cors",
            "Sec-Fetch-Site": "same-origin" if last_url and urlparse(last_url).netloc == parsed.netloc else "none"
        })
    
    return headers

class HTTPClient:
    """
    Enhanced stealthy HTTP client with human-like browsing patterns:
      - Reuses a single requests.Session (cookie/TCP reuse).
      - Rotates realistic headers per request with context awareness.
      - Adaptive timing based on request history and patterns.
      - Occasional innocent browsing to blend malicious requests.
      - Session state tracking for realistic referer chains.
      - Retries transient failures with backoff.
      - Optional proxy support for both http/https.
    """

    def __init__(
        self,
        delay_range: Tuple[float, float] = (1.0, 3.0),
        stealth: bool = True,
        fast_mode: bool = False,  
        timeout: float = 8.0,
        retries: int = 2,
        backoff_factor: float = 0.3,
        proxy_url: Optional[str] = None,
        quiet: bool = True,
        innocent_browsing_chance: float = 0.15,
    ):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay_range = delay_range
        self.stealth = stealth
        self.quiet = quiet
        self.innocent_browsing_chance = innocent_browsing_chance
        
        # Session state for realistic browsing patterns
        self.request_count = 0
        self.last_url = None
        self.session_start = time.time()
        self.target_domain = None
        self.last_request_time = None
        self.consecutive_test_requests = 0  # Track how many test requests in a row

        # Retries on idempotent methods by default
        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=20,    # Increased from 10
            pool_maxsize=100,       # Increased from 10
            pool_block=False        # Don't block when pool is full
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if proxy_url:
            self.session.proxies.update({"http": proxy_url, "https": proxy_url})
        
        self.fast_mode = fast_mode
        if fast_mode:
            self.stealth = False
            self.delay_range = (0.1, 0.3)
            self.innocent_browsing_chance = 0

    def _determine_target_domain(self, url: str):
        """Extract and remember the target domain for innocent browsing"""
        if not self.target_domain:
            parsed = urlparse(url)
            self.target_domain = f"{parsed.scheme}://{parsed.netloc}"

    def _should_make_innocent_request(self, url: str) -> bool:
        """
        Decide if we should make an innocent request before the actual request.
        More likely after consecutive test requests or if URL looks suspicious.
        """
        # Don't make innocent requests for already innocent-looking URLs
        if self.fast_mode:
            return False

        if any(path in url for path in INNOCENT_PATHS):
            return False
            
        # Higher chance after several test requests in a row
        if self.consecutive_test_requests >= 3:
            return random.random() < 0.4  # 40% chance
        elif self.consecutive_test_requests >= 2:
            return random.random() < 0.25  # 25% chance
        else:
            return random.random() < self.innocent_browsing_chance

    def _make_innocent_request(self):
        """Make an innocent-looking request to blend in"""
        if not self.target_domain:
            return
            
        try:
            innocent_path = random.choice(INNOCENT_PATHS)
            innocent_url = self.target_domain + innocent_path
            
            # Use basic headers for innocent requests
            headers = _random_headers()
            if self.last_url:
                headers["Referer"] = self.last_url
                
            # Make the innocent request (don't update last_url tracking)
            self.session.request("GET", innocent_url, headers=headers, timeout=self.timeout)
            
            # Small delay after innocent request
            if self.stealth:
                time.sleep(random.uniform(0.5, 1.5))
                
        except:
            pass  # Silently ignore failures for innocent requests

    def _adaptive_sleep(self, url: str):
        """
        Implement adaptive timing that mimics human browsing patterns
        """
        if self.fast_mode:
            time.sleep(random.uniform(0.05, 0.15))
            return

        if not self.stealth or not self.delay_range:
            return
            
        base_min, base_max = self.delay_range
        
        # Adjust timing based on request patterns
        if self.consecutive_test_requests >= 4:
            # Longer delays after many consecutive tests
            multiplier = 2.0
        elif self.consecutive_test_requests >= 2:
            multiplier = 1.5
        else:
            multiplier = 1.0
            
        # Add some human-like variation
        if random.random() < 0.1:  # 10% chance of longer "reading" pause
            multiplier *= random.uniform(3, 6)  # 3-6x longer delay
        elif random.random() < 0.2:  # 20% chance of quick browsing
            multiplier *= 0.5  # Shorter delay
            
        min_delay = base_min * multiplier
        max_delay = base_max * multiplier
        
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        
        self.last_request_time = time.time()

    def _is_test_request(self, url: str, **kwargs) -> bool:
        """
        Heuristic to determine if this looks like a security test request
        """
        # Check URL for suspicious patterns
        suspicious_patterns = [
            "'", '"', '<script', '<img', 'alert(', 'UNION', 'SELECT',
            'OR 1=1', 'javascript:', 'onerror=', '../../', '../',
            'evil.com', 'WAITFOR', 'SLEEP(', 'pg_sleep'
        ]
        
        if any(pattern in url for pattern in suspicious_patterns):
            return True
            
        # Check POST data for suspicious patterns
        if kwargs.get('data') or kwargs.get('json'):
            data_str = str(kwargs.get('data', '')) + str(kwargs.get('json', ''))
            if any(pattern in data_str for pattern in suspicious_patterns):
                return True
                
        return False

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Enhanced request method with human-like browsing simulation
        """
        self._determine_target_domain(url)
        
        # Track if this looks like a test request
        is_test = self._is_test_request(url, **kwargs)
        
        if is_test:
            self.consecutive_test_requests += 1
            # Maybe make an innocent request first
            if self._should_make_innocent_request(url):
                self._make_innocent_request()
        else:
            self.consecutive_test_requests = 0
        
        # Generate contextual headers
        headers = kwargs.pop("headers", {}) or {}
        base_headers = _random_headers()
        contextual_headers = _get_contextual_headers(
            base_headers, url, self.last_url, self.request_count
        )
        contextual_headers.update(headers)  # User headers override defaults

        # Adaptive delay before request
        self._adaptive_sleep(url)
        
        # Make the actual request
        try:
            response = self.session.request(
                method, url, headers=contextual_headers, timeout=self.timeout, **kwargs
            )
            
            # Update session state
            self.request_count += 1
            self.last_url = url
            
            return response
            
        except Exception as e:
            # Still update counters even on failure
            self.request_count += 1
            self.last_url = url
            raise e

    # Handy shortcuts (unchanged interface for compatibility)
    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    # Additional utility methods for advanced usage
    def make_innocent_browsing_session(self, target_url: str, num_requests: int = 3):
        """
        Explicitly create some innocent browsing traffic before starting tests.
        Useful to establish a "normal" session before vulnerability testing.
        """
        self._determine_target_domain(target_url)
        
        # Make some innocent requests
        innocent_requests = min(num_requests, len(INNOCENT_PATHS))
        selected_paths = random.sample(INNOCENT_PATHS, innocent_requests)
        
        for path in selected_paths:
            try:
                innocent_url = self.target_domain + path
                self.get(innocent_url)
            except:
                pass  # Ignore failures
                
    def reset_session_state(self):
        """Reset session tracking (useful for testing multiple targets)"""
        self.request_count = 0
        self.last_url = None
        self.target_domain = None
        self.last_request_time = None
        self.consecutive_test_requests = 0
        self.session_start = time.time()

    def batch_get(self, urls: List[str], max_workers: int = 5) -> List[Tuple[str, int, str]]:
        """
        Batch process multiple URLs concurrently
        Returns list of (url, status_code, response_text) tuples
        """
        results = []
    
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(self.get, url): url 
                for url in urls
            }
        
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    response = future.result()
                    results.append((url, response.status_code, response.text))
                except Exception as e:
                    results.append((url, 0, str(e)))
                
        return results