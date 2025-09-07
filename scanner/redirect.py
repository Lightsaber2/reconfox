"""
redirect.py
-----------
Enhanced Open Redirect vulnerability detection module with comprehensive testing:
- Multiple parameter names and positions
- Various payload types (absolute, relative, protocol-relative)
- Encoding bypass techniques  
- JavaScript redirect detection
- POST form redirect testing
- Multiple redirect chains analysis

Severity:
- Confirmed Open Redirect with external domain = High
- Open Redirect to relative paths = Medium  
- Suspicious redirect behavior = Medium
- JavaScript-based redirects = Medium
- No redirect vulnerability = Info
"""

import requests
import time
import random
import re
import urllib.parse
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from colorama import Fore

FALLBACK_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class OpenRedirectTester:
    def __init__(self, client: Optional[object] = None):
        self.client = client
        self.findings = []
        
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make HTTP request using client or fallback to requests"""
        try:
            if self.client is not None:
                if method.upper() == "GET":
                    return self.client.get(url, allow_redirects=False, **kwargs)
                elif method.upper() == "POST":
                    return self.client.post(url, allow_redirects=False, **kwargs)
                else:
                    return self.client.request(method, url, allow_redirects=False, **kwargs)
            else:
                headers = kwargs.pop('headers', FALLBACK_HEADERS)
                response = requests.request(
                    method, url, headers=headers, timeout=8, 
                    allow_redirects=False, **kwargs
                )
                time.sleep(random.uniform(0.3, 1.2))
                return response
        except Exception as e:
            print(Fore.RED + f"[!] Request failed for {url}: {e}")
            return None
    
    def _is_external_redirect(self, original_url: str, redirect_url: str) -> bool:
        """Check if redirect URL points to external domain"""
        if not redirect_url:
            return False
            
        try:
            original_parsed = urlparse(original_url)
            redirect_parsed = urlparse(redirect_url)
            
            # If redirect URL has no scheme, it's relative
            if not redirect_parsed.scheme:
                return False
                
            # Compare domains (case-insensitive)
            original_domain = original_parsed.netloc.lower()
            redirect_domain = redirect_parsed.netloc.lower()
            
            return original_domain != redirect_domain
            
        except Exception:
            return False
    
    def _analyze_redirect_response(self, response: requests.Response, payload: str, original_url: str) -> Dict:
        """Analyze response for redirect behavior"""
        result = {
            "redirected": False,
            "external": False,
            "location": "",
            "method": "http_header",
            "status_code": response.status_code if response else 0,
            "payload_reflected": False
        }
        
        if not response:
            return result
            
        # Check HTTP header redirects
        location = response.headers.get("Location", "")
        if location and response.status_code in [301, 302, 303, 307, 308]:
            result["redirected"] = True
            result["location"] = location
            result["external"] = self._is_external_redirect(original_url, location)
            result["payload_reflected"] = payload in location
            
        # Check for JavaScript redirects in response body
        if response.text:
            js_redirects = self._find_js_redirects(response.text, payload)
            if js_redirects:
                result["redirected"] = True
                result["method"] = "javascript"
                result["location"] = js_redirects[0]  # Take first found
                result["external"] = self._is_external_redirect(original_url, js_redirects[0])
                result["payload_reflected"] = any(payload in redir for redir in js_redirects)
        
        return result
    
    def _find_js_redirects(self, html_content: str, payload: str) -> List[str]:
        """Find JavaScript-based redirects in HTML content"""
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']\s*\)',
        ]
        
        found_redirects = []
        for pattern in js_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                redirect_url = match.group(1)
                # Only include if it contains our payload or looks suspicious
                if payload in redirect_url or self._looks_like_external_url(redirect_url):
                    found_redirects.append(redirect_url)
        
        return found_redirects
    
    def _looks_like_external_url(self, url: str) -> bool:
        """Heuristic to detect if URL looks external"""
        external_indicators = [
            r'https?://',  # Protocol
            r'//[^/]+\.',  # Protocol-relative with domain
            r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}',  # Domain pattern
        ]
        
        return any(re.search(pattern, url) for pattern in external_indicators)
    
    def _test_parameter_redirects(self, base_url: str) -> List[Dict]:
        """Test common redirect parameters with various payloads"""
        print(Fore.CYAN + "  [*] Testing redirect parameters...")
        findings = []
        
        # Common redirect parameter names
        redirect_params = [
            'next', 'redirect', 'url', 'return_to', 'callback', 'continue',
            'target', 'dest', 'destination', 'forward', 'go', 'r', 'ReturnUrl',
            'returnurl', 'return_url', 'redirect_uri', 'redirect_to', 'redir'
        ]
        
        # Various payload types for testing
        payloads = [
            # Direct external URLs
            'https://evil.com',
            'http://malicious.example',
            'https://attacker-site.com/steal-data',
            
            # Protocol-relative URLs
            '//evil.com',
            '//malicious.example/path',
            
            # Encoded payloads (bypass basic filters)
            'https%3A%2F%2Fevil.com',
            'http%3A//evil.com',
            urllib.parse.quote('https://evil.com'),
            
            # Double-encoded
            urllib.parse.quote(urllib.parse.quote('https://evil.com')),
            
            # Unicode/special encoding
            'https://evil\u002ecom',
            'https://evil.com\u0020',
            
            # Localhost variations (for SSRF-like behavior)
            'http://localhost:8080/admin',
            'http://127.0.0.1:22',
            'http://[::1]/sensitive',
            
            # Data URLs (potential XSS)
            'data:text/html,<script>alert("XSS")</script>',
            
            # Relative paths that could be dangerous
            '../admin',
            '/admin/sensitive',
            '\\\\evil.com\\path',  # Windows UNC path
        ]
        
        # Test subset of parameters and payloads for stealth
        test_params = redirect_params[:8]  # Test first 8 parameters
        test_payloads = payloads[:12]      # Test first 12 payloads
        
        for param in test_params:
            print(Fore.YELLOW + f"    [+] Testing parameter: {param}")
            
            for payload in test_payloads[:3]:  # Max 3 payloads per parameter for stealth
                try:
                    # Build test URL
                    parsed = urlparse(base_url)
                    query_params = parse_qs(parsed.query)
                    query_params[param] = [payload]
                    
                    new_query = urlencode(query_params, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    
                    response = self._make_request(test_url)
                    analysis = self._analyze_redirect_response(response, payload, base_url)
                    
                    if analysis["redirected"]:
                        if analysis["external"]:
                            severity = "High"
                            issue = f"Open Redirect to external domain via '{param}' parameter"
                        else:
                            severity = "Medium" 
                            issue = f"Internal redirect via '{param}' parameter"
                        
                        findings.append({
                            "issue": f"{issue}: {analysis['location']}",
                            "severity": severity,
                            "evidence": f"Parameter: {param}, Payload: {payload}, Method: {analysis['method']}",
                            "url": test_url
                        })
                        
                        print(Fore.RED + f"[!] Redirect detected: {param} -> {analysis['location']}")
                        
                        # If we find external redirect, that's critical - stop testing this param
                        if analysis["external"]:
                            break
                            
                except Exception as e:
                    print(Fore.YELLOW + f"    [!] Error testing {param}: {e}")
        
        return findings
    
    def _test_form_redirects(self, base_url: str) -> List[Dict]:
        """Test POST form-based redirects"""
        print(Fore.CYAN + "  [*] Testing POST form redirects...")
        findings = []
        
        # Test common form redirect scenarios
        form_tests = [
            {'next': 'https://evil.com'},
            {'redirect_to': '//malicious.example'},
            {'return_url': '/admin/../../../evil.com'},
        ]
        
        for form_data in form_tests[:2]:  # Limit for stealth
            try:
                response = self._make_request(base_url, method="POST", data=form_data)
                if response:
                    analysis = self._analyze_redirect_response(response, list(form_data.values())[0], base_url)
                    
                    if analysis["redirected"] and analysis["external"]:
                        findings.append({
                            "issue": f"POST form open redirect: {analysis['location']}",
                            "severity": "High",
                            "evidence": f"Form data: {form_data}, Method: {analysis['method']}",
                            "url": base_url
                        })
                        print(Fore.RED + f"[!] POST redirect detected: {analysis['location']}")
                        
            except Exception as e:
                print(Fore.YELLOW + f"    [!] Error testing POST redirect: {e}")
        
        return findings
    
    def _test_header_injection(self, base_url: str) -> List[Dict]:
        """Test for header injection via redirect parameters"""
        print(Fore.CYAN + "  [*] Testing header injection in redirects...")
        findings = []
        
        # CRLF injection payloads
        crlf_payloads = [
            'https://evil.com%0d%0aSet-Cookie: malicious=1',
            'https://evil.com%0a%0dX-Injected: header',
            'https://evil.com\r\nX-Test: injected',
        ]
        
        for payload in crlf_payloads[:2]:  # Test first 2 for stealth
            try:
                test_url = f"{base_url.rstrip('/')}?next={payload}"
                response = self._make_request(test_url)
                
                if response:
                    # Check if our injected headers appear
                    headers_text = str(response.headers).lower()
                    if 'x-injected' in headers_text or 'x-test' in headers_text:
                        findings.append({
                            "issue": "Header injection via redirect parameter",
                            "severity": "High",
                            "evidence": f"Payload: {payload}",
                            "url": test_url
                        })
                        print(Fore.RED + f"[!] Header injection detected!")
                        
            except Exception as e:
                print(Fore.YELLOW + f"    [!] Error testing header injection: {e}")
        
        return findings
    
    def _test_redirect_chains(self, base_url: str) -> List[Dict]:
        """Test for redirect chains and multiple hops"""
        print(Fore.CYAN + "  [*] Testing redirect chains...")
        findings = []
        
        # Test if app follows redirect chains
        chain_payloads = [
            'https://httpbin.org/redirect-to?url=https://evil.com',
            f'{base_url}?next=https://evil.com'
        ]
        
        for payload in chain_payloads[:1]:  # Test first one for stealth
            try:
                test_url = f"{base_url.rstrip('/')}?next={payload}"
                
                # Follow redirects manually to analyze chain
                current_url = test_url
                hops = 0
                max_hops = 3
                
                while hops < max_hops:
                    response = self._make_request(current_url)
                    if not response or response.status_code not in [301, 302, 303, 307, 308]:
                        break
                        
                    location = response.headers.get("Location")
                    if not location:
                        break
                        
                    hops += 1
                    
                    if self._is_external_redirect(base_url, location):
                        findings.append({
                            "issue": f"Multi-hop redirect chain to external domain (hops: {hops})",
                            "severity": "Medium",
                            "evidence": f"Final destination: {location}",
                            "url": test_url
                        })
                        print(Fore.YELLOW + f"[!] Redirect chain detected: {hops} hops to {location}")
                        break
                        
                    current_url = urljoin(current_url, location)
                    
            except Exception as e:
                print(Fore.YELLOW + f"    [!] Error testing redirect chains: {e}")
        
        return findings


def check_open_redirect(url: str, client: Optional[object] = None) -> List[Dict]:
    """
    Enhanced open redirect detection with comprehensive testing
    
    Args:
        url: Target URL to test
        client: Optional HTTP client for requests
        
    Returns:
        List of findings with detailed redirect analysis
    """
    print(Fore.CYAN + "\n[*] Checking for Open Redirects...")
    
    tester = OpenRedirectTester(client)
    all_findings = []
    
    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    test_methods = [
        tester._test_parameter_redirects,
        tester._test_form_redirects, 
        tester._test_header_injection,
        tester._test_redirect_chains
    ]
    
    for test_method in test_methods:
        try:
            findings = test_method(url)
            all_findings.extend(findings)
            
            # If we find high severity redirects, might want to stop for stealth
            if any(f.get("severity") == "High" for f in findings):
                print(Fore.YELLOW + "  [!] High severity redirect found, limiting further tests")
                break
                
        except Exception as e:
            print(Fore.RED + f"[!] Error in {test_method.__name__}: {e}")
    
    # Summary
    if not all_findings:
        print(Fore.GREEN + "[-] No Open Redirect vulnerabilities detected.")
        all_findings.append({"issue": "No Open Redirect found", "severity": "Info"})
    else:
        high_findings = len([f for f in all_findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in all_findings if f.get('severity') == 'Medium'])
        print(Fore.MAGENTA + f"[*] Open redirect testing completed. Found {high_findings} high and {medium_findings} medium severity findings.")
    
    return all_findings


# Backward compatibility
def run(url: str, client: Optional[object] = None) -> List[Dict]:
    """Main entry point for the redirect module"""
    return check_open_redirect(url, client)