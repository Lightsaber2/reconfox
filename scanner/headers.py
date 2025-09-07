"""
headers.py
----------
Enhanced HTTP security headers analysis module with comprehensive testing:
- Complete security header coverage (15+ headers)
- Header value validation and best practice analysis
- Information disclosure detection
- Context-aware severity assessment
- HTTPS vs HTTP appropriate recommendations
- Security policy analysis (CSP, HSTS, etc.)

Severity:
- Critical security headers missing/misconfigured = High
- Important headers missing = Medium
- Minor headers missing/suboptimal = Low
- Information disclosure = Medium/High
- Headers properly configured = Info
"""

import requests
import time
import random
import re
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse
from colorama import Fore

FALLBACK_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class SecurityHeadersAnalyzer:
    def __init__(self, client: Optional[object] = None):
        self.client = client
        self.findings = []
        
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request using client or fallback to requests"""
        try:
            if self.client is not None:
                return self.client.get(url, allow_redirects=True, **kwargs)
            else:
                response = requests.get(
                    url, headers=FALLBACK_HEADERS, timeout=8, 
                    allow_redirects=True, **kwargs
                )
                time.sleep(random.uniform(0.3, 1.0))
                return response
        except Exception as e:
            print(Fore.RED + f"[!] Request failed: {e}")
            return None
    
    def _analyze_csp(self, csp_value: str) -> Dict:
        """Analyze Content Security Policy header for security issues"""
        analysis = {
            "secure": True,
            "issues": [],
            "recommendations": []
        }
        
        if not csp_value:
            return analysis
        
        csp_lower = csp_value.lower()
        
        # Check for dangerous directives
        dangerous_patterns = [
            ("'unsafe-inline'", "Allows inline JavaScript/CSS - major XSS risk"),
            ("'unsafe-eval'", "Allows eval() - enables code injection"),
            ("data:", "Data URLs can bypass CSP protections"),
            ("*", "Wildcard allows any domain - too permissive"),
            ("http:", "HTTP sources vulnerable to MITM attacks"),
        ]
        
        for pattern, issue in dangerous_patterns:
            if pattern in csp_lower:
                analysis["secure"] = False
                analysis["issues"].append(issue)
        
        # Check for missing important directives
        important_directives = [
            ("default-src", "Base policy for loading resources"),
            ("script-src", "JavaScript source restrictions"),
            ("style-src", "CSS source restrictions"),
            ("img-src", "Image source restrictions"),
            ("frame-ancestors", "Clickjacking protection")
        ]
        
        for directive, purpose in important_directives:
            if directive not in csp_lower:
                analysis["recommendations"].append(f"Consider adding {directive} for {purpose}")
        
        return analysis
    
    def _analyze_hsts(self, hsts_value: str) -> Dict:
        """Analyze HTTP Strict Transport Security header"""
        analysis = {
            "secure": True,
            "issues": [],
            "max_age": 0,
            "includes_subdomains": False,
            "preload": False
        }
        
        if not hsts_value:
            return analysis
        
        # Parse max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
        if max_age_match:
            analysis["max_age"] = int(max_age_match.group(1))
            
            # Check if max-age is too short (less than 6 months)
            if analysis["max_age"] < 15552000:  # 6 months in seconds
                analysis["secure"] = False
                analysis["issues"].append(f"max-age too short ({analysis['max_age']}s), recommend 31536000s (1 year)")
        else:
            analysis["secure"] = False
            analysis["issues"].append("Missing or invalid max-age directive")
        
        # Check for includeSubDomains
        if "includesubdomains" in hsts_value.lower():
            analysis["includes_subdomains"] = True
        else:
            analysis["issues"].append("Missing includeSubDomains - subdomains not protected")
        
        # Check for preload
        if "preload" in hsts_value.lower():
            analysis["preload"] = True
        
        return analysis
    
    def _analyze_x_frame_options(self, xfo_value: str) -> Dict:
        """Analyze X-Frame-Options header"""
        analysis = {
            "secure": True,
            "issues": []
        }
        
        if not xfo_value:
            return analysis
        
        xfo_lower = xfo_value.lower().strip()
        
        if xfo_lower not in ["deny", "sameorigin"]:
            if xfo_lower.startswith("allow-from"):
                analysis["issues"].append("ALLOW-FROM is deprecated, use CSP frame-ancestors instead")
            else:
                analysis["secure"] = False
                analysis["issues"].append(f"Invalid value '{xfo_value}', use DENY or SAMEORIGIN")
        
        return analysis
    
    def _check_information_disclosure(self, headers: Dict[str, str]) -> List[Dict]:
        """Check for information disclosure in headers"""
        findings = []
        
        # Headers that can reveal sensitive information
        disclosure_headers = {
            'server': {
                'name': 'Server',
                'severity': 'Medium',
                'patterns': [
                    (r'apache/(\d+\.\d+\.\d+)', 'Apache version disclosed'),
                    (r'nginx/(\d+\.\d+\.\d+)', 'Nginx version disclosed'),
                    (r'microsoft-iis/(\d+\.\d+)', 'IIS version disclosed'),
                    (r'php/(\d+\.\d+\.\d+)', 'PHP version disclosed'),
                ]
            },
            'x-powered-by': {
                'name': 'Technology Stack',
                'severity': 'Medium',
                'patterns': [
                    (r'php/(\d+\.\d+)', 'PHP version disclosed'),
                    (r'asp\.net', 'ASP.NET technology disclosed'),
                ]
            },
            'x-aspnet-version': {
                'name': 'ASP.NET Version',
                'severity': 'High',
                'patterns': [(r'(\d+\.\d+)', 'Detailed ASP.NET version disclosed')]
            },
            'x-aspnetmvc-version': {
                'name': 'ASP.NET MVC Version', 
                'severity': 'Medium',
                'patterns': [(r'(\d+\.\d+)', 'ASP.NET MVC version disclosed')]
            }
        }
        
        for header_key, config in disclosure_headers.items():
            header_value = headers.get(header_key, '')
            if header_value:
                # Check for version patterns
                version_found = False
                for pattern, description in config['patterns']:
                    if re.search(pattern, header_value, re.IGNORECASE):
                        findings.append({
                            "issue": f"{description}: {header_value}",
                            "severity": config['severity'],
                            "evidence": f"{config['name']}: {header_value}",
                            "recommendation": f"Remove or obfuscate {config['name']} header"
                        })
                        version_found = True
                        break
                
                # If no specific version pattern but header exists
                if not version_found:
                    findings.append({
                        "issue": f"{config['name']} header disclosed: {header_value}",
                        "severity": "Low",
                        "evidence": f"{header_key}: {header_value}",
                        "recommendation": f"Consider removing {config['name']} header"
                    })
        
        return findings
    
    def _analyze_security_headers(self, headers: Dict[str, str], url: str) -> List[Dict]:
        """Comprehensive security headers analysis"""
        findings = []
        is_https = url.startswith('https://')
        
        # Define all security headers with their importance and context
        security_headers = {
            'content-security-policy': {
                'name': 'Content-Security-Policy',
                'severity_missing': 'High',
                'description': 'Prevents XSS and data injection attacks',
                'required_context': 'all',
                'analyzer': self._analyze_csp
            },
            'strict-transport-security': {
                'name': 'Strict-Transport-Security', 
                'severity_missing': 'High',
                'description': 'Enforces HTTPS connections',
                'required_context': 'https',
                'analyzer': self._analyze_hsts
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'severity_missing': 'Medium',
                'description': 'Prevents clickjacking attacks',
                'required_context': 'all',
                'analyzer': self._analyze_x_frame_options
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'severity_missing': 'Medium', 
                'description': 'Prevents MIME type sniffing',
                'required_context': 'all',
                'expected_value': 'nosniff'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'severity_missing': 'Low',
                'description': 'Controls referrer information leakage',
                'required_context': 'all',
                'secure_values': ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
            },
            'permissions-policy': {
                'name': 'Permissions-Policy',
                'severity_missing': 'Low',
                'description': 'Controls browser feature access',
                'required_context': 'all'
            },
            'x-xss-protection': {
                'name': 'X-XSS-Protection',
                'severity_missing': 'Low',
                'description': 'Legacy XSS filter (mostly deprecated)',
                'required_context': 'all',
                'expected_value': '1; mode=block'
            },
            'cache-control': {
                'name': 'Cache-Control',
                'severity_missing': 'Low',
                'description': 'Controls caching behavior',
                'required_context': 'all'
            }
        }
        
        print(Fore.CYAN + "[*] Comprehensive Security Headers Analysis:")
        
        for header_key, config in security_headers.items():
            # Skip HTTPS-only headers if we're on HTTP
            if config['required_context'] == 'https' and not is_https:
                continue
                
            header_value = headers.get(header_key, '') or headers.get(config['name'], '')
            
            if header_value:
                print(Fore.GREEN + f"[+] {config['name']} present: {header_value}")
                
                # Analyze header value if analyzer exists
                if 'analyzer' in config:
                    analysis = config['analyzer'](header_value)
                    if not analysis['secure']:
                        for issue in analysis['issues']:
                            findings.append({
                                "issue": f"{config['name']} misconfigured: {issue}",
                                "severity": "Medium",
                                "evidence": f"{config['name']}: {header_value}",
                                "recommendation": "Review and strengthen header configuration"
                            })
                    else:
                        findings.append({
                            "issue": f"{config['name']} properly configured",
                            "severity": "Info",
                            "evidence": f"{config['name']}: {header_value}"
                        })
                
                # Check expected values
                elif 'expected_value' in config:
                    if header_value.lower().strip() != config['expected_value'].lower():
                        findings.append({
                            "issue": f"{config['name']} suboptimal value: {header_value}",
                            "severity": "Low",
                            "evidence": f"Expected: {config['expected_value']}, Got: {header_value}",
                            "recommendation": f"Set {config['name']} to {config['expected_value']}"
                        })
                    else:
                        findings.append({
                            "issue": f"{config['name']} properly configured",
                            "severity": "Info"
                        })
                
                # Check secure values list
                elif 'secure_values' in config:
                    if header_value.lower().strip() not in [v.lower() for v in config['secure_values']]:
                        findings.append({
                            "issue": f"{config['name']} weak policy: {header_value}",
                            "severity": "Low",
                            "evidence": f"Recommended: {', '.join(config['secure_values'])}",
                            "recommendation": f"Use more restrictive {config['name']} policy"
                        })
                    else:
                        findings.append({
                            "issue": f"{config['name']} properly configured",
                            "severity": "Info"
                        })
                
                else:
                    # Header present but no specific validation
                    findings.append({
                        "issue": f"{config['name']} present",
                        "severity": "Info"
                    })
                    
            else:
                print(Fore.RED + f"[-] {config['name']} missing!")
                findings.append({
                    "issue": f"{config['name']} missing - {config['description']}",
                    "severity": config['severity_missing'],
                    "recommendation": f"Implement {config['name']} header"
                })
        
        return findings
    
    def _check_deprecated_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """Check for deprecated or problematic headers"""
        findings = []
        
        deprecated_headers = {
            'x-webkit-csp': 'Use Content-Security-Policy instead',
            'x-content-security-policy': 'Use Content-Security-Policy instead', 
            'public-key-pins': 'HPKP is deprecated due to security risks',
            'expect-ct': 'Expect-CT is deprecated, use Certificate Transparency monitoring'
        }
        
        for deprecated, message in deprecated_headers.items():
            if deprecated in [k.lower() for k in headers.keys()]:
                findings.append({
                    "issue": f"Deprecated header in use: {deprecated}",
                    "severity": "Low",
                    "recommendation": message
                })
        
        return findings


def check_security_headers(url: str, client: Optional[object] = None) -> List[Dict]:
    """
    Enhanced security headers analysis with comprehensive testing
    
    Args:
        url: Target URL to analyze
        client: Optional HTTP client for requests
        
    Returns:
        List of findings with detailed header analysis
    """
    print(Fore.CYAN + "\n[*] Analyzing Security Headers...")
    
    analyzer = SecurityHeadersAnalyzer(client)
    all_findings = []
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    try:
        response = analyzer._make_request(url)
        
        if not response:
            return [{"issue": "Failed to retrieve headers for analysis", "severity": "Info"}]
        
        headers = response.headers
        
        # Convert headers to case-insensitive dict for easier processing
        headers_dict = {k.lower(): v for k, v in headers.items()}
        
        # Main security headers analysis
        security_findings = analyzer._analyze_security_headers(headers_dict, url)
        all_findings.extend(security_findings)
        
        # Information disclosure analysis
        disclosure_findings = analyzer._check_information_disclosure(headers_dict)
        all_findings.extend(disclosure_findings)
        
        # Deprecated headers check
        deprecated_findings = analyzer._check_deprecated_headers(headers_dict)
        all_findings.extend(deprecated_findings)
        
    except Exception as e:
        print(Fore.RED + f"[!] Error analyzing headers: {e}")
        return [{"issue": f"Header analysis failed: {e}", "severity": "Info"}]
    
    # Summary
    if all_findings:
        high_count = len([f for f in all_findings if f.get('severity') == 'High'])
        medium_count = len([f for f in all_findings if f.get('severity') == 'Medium']) 
        low_count = len([f for f in all_findings if f.get('severity') == 'Low'])
        info_count = len([f for f in all_findings if f.get('severity') == 'Info'])
        
        print(Fore.MAGENTA + f"\n[*] Header analysis completed: {high_count} high, {medium_count} medium, {low_count} low, {info_count} info findings")
    
    return all_findings


# Backward compatibility
def run(url: str, client: Optional[object] = None) -> List[Dict]:
    """Main entry point for the headers module"""
    return check_security_headers(url, client)