"""
cors.py
-------
Enhanced CORS (Cross-Origin Resource Sharing) misconfiguration detection module:
- Comprehensive origin testing (malicious, null, subdomain bypass)
- Preflight OPTIONS request analysis
- Credential-enabled CORS testing
- Multiple HTTP methods testing
- Header reflection analysis
- Subdomain and protocol bypass detection
- Advanced origin manipulation techniques

Severity:
- Wildcard with credentials = Critical
- Origin reflection with credentials = High
- Insecure wildcard CORS = High
- Origin reflection without credentials = Medium
- Overly permissive methods/headers = Medium
- Subdomain bypass = Medium
- Properly configured CORS = Info
"""

import requests
import time
import random
import re
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, urljoin
from colorama import Fore

FALLBACK_HEADERS_BASE = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class CORSAnalyzer:
    def __init__(self, client: Optional[object] = None):
        self.client = client
        self.findings = []
        self.target_domain = None
        
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """Make HTTP request using client or fallback to requests"""
        try:
            if self.client is not None:
                if method.upper() == "GET":
                    return self.client.get(url, allow_redirects=True, **kwargs)
                elif method.upper() == "OPTIONS":
                    return self.client.request("OPTIONS", url, allow_redirects=True, **kwargs)
                else:
                    return self.client.request(method, url, allow_redirects=True, **kwargs)
            else:
                headers = kwargs.pop('headers', FALLBACK_HEADERS_BASE.copy())
                response = requests.request(
                    method, url, headers=headers, timeout=8, 
                    allow_redirects=True, **kwargs
                )
                time.sleep(random.uniform(0.3, 1.0))
                return response
        except Exception as e:
            print(Fore.RED + f"[!] Request failed for {url}: {e}")
            return None
    
    def _extract_domain_info(self, url: str):
        """Extract domain information for targeted testing"""
        parsed = urlparse(url)
        self.target_domain = parsed.netloc
        return {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'subdomain': parsed.netloc.split('.')[0] if '.' in parsed.netloc else None,
            'root_domain': '.'.join(parsed.netloc.split('.')[-2:]) if '.' in parsed.netloc else parsed.netloc
        }
    
    def _generate_test_origins(self, target_info: Dict[str, str]) -> List[Tuple[str, str]]:
        """Generate various malicious origins for testing"""
        origins = []
        
        # Basic malicious origins
        malicious_domains = [
            ("http://evil.com", "Basic malicious domain"),
            ("https://attacker.com", "HTTPS malicious domain"),
            ("http://malicious.example", "Alternative malicious domain"),
        ]
        origins.extend(malicious_domains)
        
        # Null origin (common bypass)
        origins.append(("null", "Null origin bypass"))
        
        # Data URLs and other schemes
        origins.extend([
            ("data:", "Data URL scheme"),
            ("file://", "File URL scheme"),
            ("ftp://evil.com", "FTP scheme"),
        ])
        
        # Target domain variations (subdomain bypass attempts)
        if target_info['domain']:
            domain = target_info['domain']
            root_domain = target_info['root_domain']
            
            subdomain_tests = [
                (f"http://evil.{root_domain}", "Subdomain injection"),
                (f"https://{domain}.evil.com", "Domain suffix attack"),
                (f"http://{domain}evil.com", "Domain concatenation"),
                (f"https://evil{domain}", "Domain prefix attack"),
            ]
            origins.extend(subdomain_tests)
            
            # Protocol variations
            if target_info['scheme'] == 'https':
                origins.append((f"http://{domain}", "Protocol downgrade"))
        
        return origins
    
    def _test_simple_cors(self, url: str, origins: List[Tuple[str, str]]) -> List[Dict]:
        """Test basic CORS with different origins"""
        print(Fore.CYAN + "  [*] Testing simple CORS requests...")
        findings = []
        
        for origin, description in origins[:10]:  # Limit to first 10 for stealth
            print(Fore.YELLOW + f"    [+] Testing origin: {origin}")
            
            headers = {"Origin": origin}
            response = self._make_request(url, headers=headers)
            
            if not response:
                continue
            
            cors_analysis = self._analyze_cors_response(response, origin, description)
            if cors_analysis:
                findings.extend(cors_analysis)
                
                # If we find critical issues, stop testing more origins
                if any(f.get("severity") == "Critical" for f in cors_analysis):
                    print(Fore.RED + "  [!] Critical CORS issue found, stopping origin enumeration")
                    break
        
        return findings
    
    def _test_preflight_cors(self, url: str, origins: List[Tuple[str, str]]) -> List[Dict]:
        """Test CORS preflight (OPTIONS) requests"""
        print(Fore.CYAN + "  [*] Testing CORS preflight requests...")
        findings = []
        
        # Test with dangerous methods and headers
        test_scenarios = [
            {
                "method": "PUT",
                "headers": "Content-Type,X-Custom-Header",
                "description": "PUT method with custom headers"
            },
            {
                "method": "DELETE", 
                "headers": "Authorization,X-API-Key",
                "description": "DELETE method with auth headers"
            },
            {
                "method": "PATCH",
                "headers": "X-Requested-With,X-CSRF-Token",
                "description": "PATCH method with CSRF headers"
            }
        ]
        
        for origin, origin_desc in origins[:5]:  # Test first 5 origins
            for scenario in test_scenarios[:2]:  # Test first 2 scenarios per origin
                print(Fore.YELLOW + f"    [+] Preflight test: {origin} -> {scenario['method']}")
                
                preflight_headers = {
                    "Origin": origin,
                    "Access-Control-Request-Method": scenario["method"],
                    "Access-Control-Request-Headers": scenario["headers"]
                }
                
                response = self._make_request(url, method="OPTIONS", headers=preflight_headers)
                
                if response:
                    preflight_analysis = self._analyze_preflight_response(
                        response, origin, scenario, origin_desc
                    )
                    findings.extend(preflight_analysis)
        
        return findings
    
    def _test_credentials_cors(self, url: str, origins: List[Tuple[str, str]]) -> List[Dict]:
        """Test CORS with credentials enabled"""
        print(Fore.CYAN + "  [*] Testing CORS with credentials...")
        findings = []
        
        for origin, description in origins[:6]:  # Test first 6 origins
            print(Fore.YELLOW + f"    [+] Testing credentials with origin: {origin}")
            
            headers = {
                "Origin": origin,
                "Cookie": "test=value",  # Simulate credential
                "Authorization": "Bearer test-token"
            }
            
            response = self._make_request(url, headers=headers)
            
            if response:
                cred_analysis = self._analyze_credentials_cors(response, origin, description)
                findings.extend(cred_analysis)
                
                # Critical finding if wildcard with credentials
                if any(f.get("severity") == "Critical" for f in cred_analysis):
                    print(Fore.RED + "  [!] Critical credentials CORS issue detected!")
                    break
        
        return findings
    
    def _analyze_cors_response(self, response: requests.Response, test_origin: str, origin_desc: str) -> List[Dict]:
        """Analyze CORS response headers for misconfigurations"""
        findings = []
        cors_headers = {}
        
        # Extract all CORS-related headers
        for header, value in response.headers.items():
            if header.lower().startswith('access-control-'):
                cors_headers[header.lower()] = value
        
        if not cors_headers:
            return findings  # No CORS headers, nothing to analyze
        
        # Analyze Access-Control-Allow-Origin
        allow_origin = cors_headers.get('access-control-allow-origin', '')
        if allow_origin:
            if allow_origin == "*":
                findings.append({
                    "issue": "Wildcard CORS policy allows any origin",
                    "severity": "High",
                    "evidence": f"Access-Control-Allow-Origin: {allow_origin}",
                    "recommendation": "Restrict to specific trusted origins"
                })
                print(Fore.RED + f"[!] Wildcard CORS detected: {allow_origin}")
                
            elif allow_origin == test_origin:
                severity = "High" if test_origin not in ["null", "data:"] else "Medium"
                findings.append({
                    "issue": f"CORS origin reflection - {origin_desc}",
                    "severity": severity,
                    "evidence": f"Origin: {test_origin} → Access-Control-Allow-Origin: {allow_origin}",
                    "recommendation": "Implement proper origin validation"
                })
                print(Fore.RED + f"[!] Origin reflection detected: {test_origin}")
                
            elif test_origin in allow_origin:
                findings.append({
                    "issue": f"Partial origin match in CORS policy",
                    "severity": "Medium",
                    "evidence": f"Test origin '{test_origin}' found in '{allow_origin}'",
                    "recommendation": "Ensure exact origin matching"
                })
        
        return findings
    
    def _analyze_preflight_response(self, response: requests.Response, origin: str, scenario: Dict, origin_desc: str) -> List[Dict]:
        """Analyze preflight OPTIONS response"""
        findings = []
        
        allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
        allow_methods = response.headers.get('Access-Control-Allow-Methods', '')
        allow_headers = response.headers.get('Access-Control-Allow-Headers', '')
        
        # Check if preflight was accepted
        if allow_origin and (allow_origin == "*" or allow_origin == origin):
            
            # Check for dangerous methods
            if allow_methods:
                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
                allowed_methods = [m.strip().upper() for m in allow_methods.split(',')]
                
                found_dangerous = [m for m in dangerous_methods if m in allowed_methods]
                if found_dangerous:
                    findings.append({
                        "issue": f"Dangerous HTTP methods allowed via CORS: {', '.join(found_dangerous)}",
                        "severity": "Medium",
                        "evidence": f"Access-Control-Allow-Methods: {allow_methods}",
                        "recommendation": "Restrict allowed methods to necessary ones only"
                    })
                    print(Fore.YELLOW + f"[!] Dangerous methods allowed: {found_dangerous}")
            
            # Check for permissive headers
            if allow_headers:
                if allow_headers == "*":
                    findings.append({
                        "issue": "Wildcard headers allowed in CORS preflight",
                        "severity": "Medium", 
                        "evidence": f"Access-Control-Allow-Headers: {allow_headers}",
                        "recommendation": "Specify exact headers instead of wildcard"
                    })
                else:
                    dangerous_headers = ['authorization', 'x-api-key', 'x-auth-token']
                    allowed_headers_lower = [h.strip().lower() for h in allow_headers.split(',')]
                    
                    found_dangerous_headers = [h for h in dangerous_headers if h in allowed_headers_lower]
                    if found_dangerous_headers:
                        findings.append({
                            "issue": f"Sensitive headers allowed via CORS: {', '.join(found_dangerous_headers)}",
                            "severity": "Medium",
                            "evidence": f"Access-Control-Allow-Headers: {allow_headers}",
                            "recommendation": "Carefully review allowed headers"
                        })
        
        return findings
    
    def _analyze_credentials_cors(self, response: requests.Response, origin: str, origin_desc: str) -> List[Dict]:
        """Analyze CORS response when credentials are involved"""
        findings = []
        
        allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
        allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        # Critical: Wildcard with credentials (impossible but check for developer errors)
        if allow_origin == "*" and allow_credentials == "true":
            findings.append({
                "issue": "CRITICAL: Wildcard CORS with credentials enabled (invalid configuration)",
                "severity": "Critical",
                "evidence": f"Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                "recommendation": "This is invalid - browsers will block this. Fix CORS configuration."
            })
            print(Fore.RED + "[!] CRITICAL: Invalid wildcard + credentials CORS!")
        
        # High risk: Origin reflection with credentials
        elif allow_origin == origin and allow_credentials == "true":
            findings.append({
                "issue": f"High risk: CORS credentials enabled with origin reflection - {origin_desc}",
                "severity": "High",
                "evidence": f"Origin: {origin}, Credentials: true, Reflected: {allow_origin}",
                "recommendation": "Implement strict origin validation when credentials are enabled"
            })
            print(Fore.RED + f"[!] High risk: Credentials + reflection for {origin}")
        
        return findings
    
    def _test_advanced_bypasses(self, url: str) -> List[Dict]:
        """Test advanced CORS bypass techniques"""
        print(Fore.CYAN + "  [*] Testing advanced CORS bypass techniques...")
        findings = []
        
        if not self.target_domain:
            return findings
        
        # Test common bypass patterns
        bypass_origins = [
            # Subdomain wildcards that might be overly permissive
            f"https://evil.{self.target_domain}",
            f"https://{self.target_domain}.evil.com",
            
            # URL-encoded bypasses (safer than raw Unicode)
            f"https://{self.target_domain}%20",  # URL-encoded space
            f"https://{self.target_domain}.%00",  # Null byte (URL-encoded)
            
            # IP address variations
            "http://127.0.0.1",
            "http://localhost",
            
            # Special schemes
            "chrome-extension://fake-extension-id",
            "moz-extension://fake-extension-id",
        ]
        
        for bypass_origin in bypass_origins[:5]:  # Test first 5
            try:
                # Ensure the origin can be safely encoded
                safe_origin = bypass_origin.encode('ascii', errors='ignore').decode('ascii')
                if not safe_origin:
                    print(Fore.YELLOW + f"    [!] Skipping non-ASCII origin: {bypass_origin}")
                    continue
                    
                headers = {"Origin": safe_origin}
                response = self._make_request(url, headers=headers)
                
                if response:
                    allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
                    if allow_origin == safe_origin:
                        findings.append({
                            "issue": f"CORS bypass detected: {safe_origin}",
                            "severity": "High",
                            "evidence": f"Bypass origin accepted: {safe_origin}",
                            "recommendation": "Implement strict origin validation"
                        })
                        print(Fore.RED + f"[!] CORS bypass successful: {safe_origin}")
            
            except Exception as e:
                print(Fore.YELLOW + f"    [!] Error testing bypass {bypass_origin}: {e}")
        
        return findings


def check_cors(url: str, client: Optional[object] = None) -> List[Dict]:
    """
    Enhanced CORS misconfiguration detection with comprehensive testing
    
    Args:
        url: Target URL to test
        client: Optional HTTP client for requests
        
    Returns:
        List of findings with detailed CORS analysis
    """
    print(Fore.CYAN + "\n[*] Analyzing CORS Configuration...")
    
    analyzer = CORSAnalyzer(client)
    all_findings = []
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    # Extract domain information for targeted testing
    target_info = analyzer._extract_domain_info(url)
    
    # Generate test origins based on target domain
    test_origins = analyzer._generate_test_origins(target_info)
    
    print(Fore.YELLOW + f"  [+] Target: {target_info['domain']}")
    print(Fore.YELLOW + f"  [+] Testing {len(test_origins)} origin variations")
    
    # Run different CORS tests
    test_methods = [
        lambda: analyzer._test_simple_cors(url, test_origins),
        lambda: analyzer._test_preflight_cors(url, test_origins),
        lambda: analyzer._test_credentials_cors(url, test_origins),
        lambda: analyzer._test_advanced_bypasses(url)
    ]
    
    for test_method in test_methods:
        try:
            findings = test_method()
            all_findings.extend(findings)
            
            # Stop if we find critical issues for stealth
            if any(f.get("severity") == "Critical" for f in findings):
                print(Fore.YELLOW + "  [!] Critical CORS issues found, limiting further testing")
                break
                
        except Exception as e:
            print(Fore.RED + f"[!] Error in CORS testing: {e}")
    
    # Summary
    if not all_findings:
        print(Fore.GREEN + "[-] No CORS misconfigurations detected.")
        all_findings.append({"issue": "CORS appears properly configured", "severity": "Info"})
    else:
        critical_count = len([f for f in all_findings if f.get('severity') == 'Critical'])
        high_count = len([f for f in all_findings if f.get('severity') == 'High'])
        medium_count = len([f for f in all_findings if f.get('severity') == 'Medium'])
        
        print(Fore.MAGENTA + f"[*] CORS analysis completed: {critical_count} critical, {high_count} high, {medium_count} medium findings")
    
    return all_findings


# Backward compatibility
def run(url: str, client: Optional[object] = None) -> List[Dict]:
    """Main entry point for the CORS module"""
    return check_cors(url, client)