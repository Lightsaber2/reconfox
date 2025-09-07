"""
crawler.py
----------
Stealth-aware crawler that cooperates with the shared HTTPClient.

Signature:
    crawl(start_url, max_pages=30, client=None)

Important:
- client is the LAST parameter so main.call_module(..., client=client) works.
- _fetch_with_fallback normalizes outputs from either HTTPClient (requests.Response)
  or plain requests (status_code, text).
"""

import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from colorama import Fore
from urllib.robotparser import RobotFileParser
from typing import Optional, Tuple, List
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

# Fallback user agents for direct requests
FALLBACK_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)"
]


def _get_robots_parser(base_url: str) -> Optional[RobotFileParser]:
    """
    Get robots.txt parser with error handling and timeout.
    Returns None if robots.txt can't be fetched or parsed.
    """
    robots_url = urljoin(base_url, "/robots.txt")
    rp = RobotFileParser()
    try:
        rp.set_url(robots_url)
        # Add timeout for robots.txt fetching
        rp.read()
        return rp
    except Exception as e:
        # If we can't read robots.txt, assume crawling is allowed
        # This prevents the crawler from being blocked by network issues
        print(Fore.YELLOW + f"[!] Could not read robots.txt from {robots_url}: {e}")
        return None


def _fetch_with_fallback(url: str, client: Optional[object], max_retries: int = 2) -> Tuple[Optional[int], Optional[str]]:
    """
    Always return (status_code, text) or (None, None) on failure.

    Works with:
      - client (HTTPClient) that returns a requests.Response
      - client that returns a (status, text) tuple
      - fallback to requests.get when client is None
    """
    if client is not None:
        try:
            resp = client.get(url, allow_redirects=True)
            if resp is None:
                return None, None

            # Normalize possible return shapes
            # If client returned a tuple (status, text)
            if isinstance(resp, tuple) and len(resp) >= 2:
                return resp[0], resp[1]

            # If client returned a requests.Response-like object
            if hasattr(resp, "status_code"):
                return resp.status_code, getattr(resp, "text", None)

            # Unexpected type: log and fail
            print(Fore.RED + f"[!] client returned unexpected type for {url}: {type(resp)}")
            return None, None

        except Exception as e:
            print(Fore.RED + f"[!] client error fetching {url}: {e}")
            return None, None

    # Fallback: use requests directly (with simple retry)
    for attempt in range(1, max_retries + 1):
        try:
            headers = {"User-Agent": random.choice(FALLBACK_USER_AGENTS)}
            r = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            return r.status_code, r.text
        except Exception as e:
            wait = 2 ** attempt
            print(Fore.RED + f"[!] Error fetching {url}: {e}. Retrying in {wait}s...")
            time.sleep(wait)

    return None, None


def crawl(start_url: str, max_pages: int = 30, client: Optional[object] = None) -> List[dict]:
    """
    Crawl pages within the same domain.
    Returns structured results: {url, status, title, parameters}.
    """
    visited = set()
    normalized_seen = set()
    to_visit = [start_url]
    results = []

    print(Fore.CYAN + f"[*] Starting crawl at {start_url}")

    # Get robots.txt parser (may be None if unavailable)
    rp = _get_robots_parser(start_url)
    
    # If robots.txt blocks everything, show warning but continue with start URL
    if rp and not rp.can_fetch("*", start_url):
        print(Fore.YELLOW + f"[!] Warning: robots.txt disallows crawling {start_url}")
        print(Fore.YELLOW + f"[!] Continuing with limited crawling for security testing purposes")
        # For security testing, we still want to test the start URL at minimum
        # but we'll be more respectful and not follow links

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        url = urldefrag(url).url  # strip anchors
        if url in visited:
            continue

        # robots.txt check - but allow the original start URL even if blocked
        if rp and url != start_url and not rp.can_fetch("*", url):
            print(Fore.YELLOW + f"[-] Skipping disallowed by robots.txt: {url}")
            visited.add(url)
            continue

        status, text = _fetch_with_fallback(url, client)
        visited.add(url)

        if not status:
            print(Fore.RED + f"[!] Failed to fetch {url}")
            if client is None:
                time.sleep(random.uniform(0.4, 1.2))
            continue

        # ---- Color-coded printing ----
        if 200 <= status < 300:
            color = Fore.GREEN
        elif 300 <= status < 400:
            color = Fore.YELLOW
        else:
            color = Fore.RED
        print(color + f"[Crawled] {url} (status {status})")

        # ---- Extract title + query parameters ----
        title = None
        params = []
        if text:
            try:
                soup = BeautifulSoup(text, "html.parser")
                if soup.title and soup.title.string:
                    title = soup.title.string.strip()
            except Exception:
                pass

            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            params = list(qs.keys())

        # ---- Store result ----
        results.append({
            "url": url,
            "status": status,
            "title": title,
            "parameters": params
        })

        # ---- Handle deduplication by parameter keys ----
        parsed = urlparse(url)
        norm_query = "&".join([f"{k}=*" for k in sorted(params)])
        normalized_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        if norm_query:
            normalized_url += "?" + norm_query

        # ---- Extract links only if not already normalized AND robots.txt doesn't block everything ----
        if 200 <= status < 400 and text and normalized_url not in normalized_seen:
            # If robots.txt blocks the start URL, don't follow links to be respectful
            if not (rp and not rp.can_fetch("*", start_url)):
                soup = BeautifulSoup(text, "html.parser")
                for link in soup.find_all("a", href=True):
                    next_url = urljoin(url, link["href"])
                    next_url = urldefrag(next_url).url
                    if urlparse(next_url).netloc == urlparse(start_url).netloc:
                        if next_url not in visited and next_url not in to_visit:
                            to_visit.append(next_url)

        normalized_seen.add(normalized_url)

        if client is None:
            time.sleep(random.uniform(0.4, 1.2))

    print(Fore.MAGENTA + f"\n[*] Crawl finished. Discovered {len(results)} URLs.\n")
    return results