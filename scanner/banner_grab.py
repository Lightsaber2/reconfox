"""
banner_grab.py
--------------
Enhanced banner grabbing module that performs comprehensive service fingerprinting
across multiple protocols and ports. Identifies software versions, technologies,
and potential security information disclosure issues.

Features:
- Multi-protocol banner grabbing (HTTP/HTTPS, SSH, FTP, SMTP, POP3, IMAP, etc.)
- Advanced HTTP header analysis and technology fingerprinting
- Service version detection and CVE correlation potential
- SSL/TLS certificate information extraction
- Comprehensive header security analysis
- Stealth mode with timing randomization
- Detailed information leakage assessment

Severity:
- Detailed version info with known vulnerabilities = Critical
- Server software versions exposed = High
- Technology stack fingerprinting possible = Medium  
- Basic service identification = Low
- Secure headers present, minimal info disclosed = Info
- Banner not retrieved = Info
"""

import socket
import ssl
import time
import random
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from colorama import Fore
import base64

class ServiceBannerGrabber:
    """Enhanced banner grabbing with multi-protocol support"""
    
    # Service definitions with banner grab techniques
    SERVICES = {
        21: {
            "name": "FTP",
            "method": "connect_only",
            "expected_banner": r"220.*FTP",
            "version_patterns": [
                r"220.*?(vsftpd|ProFTPD|Pure-FTPd|FileZilla|WS_FTP|Microsoft FTP)\s*([\d.]+)?",
                r"220.*?FTP.*?(\d+\.\d+[\.\d]*)"
            ],
            "risk_indicators": ["anonymous", "welcome", "ready"]
        },
        22: {
            "name": "SSH", 
            "method": "connect_only",
            "expected_banner": r"SSH-",
            "version_patterns": [
                r"SSH-([\d.]+)-OpenSSH_([\d.]+\w*)",
                r"SSH-([\d.]+)-([\w\-_.]+)",
                r"SSH-([\d.]+)"
            ],
            "risk_indicators": ["OpenSSH_4", "OpenSSH_5", "SSH-1"]
        },
        25: {
            "name": "SMTP",
            "method": "connect_only", 
            "expected_banner": r"220.*SMTP",
            "version_patterns": [
                r"220.*?(Postfix|Exim|Sendmail|Microsoft ESMTP|qmail)\s*([\d.]+)?",
                r"220.*?ESMTP\s+([^\s]+)\s*([\d.]+)?"
            ],
            "risk_indicators": ["VRFY", "EXPN", "relay"]
        },
        53: {
            "name": "DNS",
            "method": "dns_query",
            "expected_banner": None,
            "version_patterns": [],
            "risk_indicators": ["version.bind"]
        },
        80: {
            "name": "HTTP",
            "method": "http_request",
            "expected_banner": r"HTTP/",
            "version_patterns": [
                r"Server:\s*([^/\r\n]+?)(?:/([^\s\r\n]+))?",
                r"X-Powered-By:\s*([^\r\n]+)",
                r"X-AspNet-Version:\s*([\d.]+)"
            ],
            "risk_indicators": ["admin", "test", "debug", "php", "asp"]
        },
        110: {
            "name": "POP3",
            "method": "connect_only",
            "expected_banner": r"\+OK",
            "version_patterns": [
                r"\+OK.*?(Dovecot|Courier|UW-IMAP|Cyrus)\s*v?([\d.]+)?"
            ],
            "risk_indicators": ["ready", "pop3"]
        },
        143: {
            "name": "IMAP",
            "method": "connect_only", 
            "expected_banner": r"\* OK",
            "version_patterns": [
                r"\* OK.*?(Dovecot|Courier|UW-IMAP|Cyrus|Exchange)\s*v?([\d.]+)?"
            ],
            "risk_indicators": ["ready", "imap4"]
        },
        443: {
            "name": "HTTPS",
            "method": "https_request",
            "expected_banner": r"HTTP/",
            "version_patterns": [
                r"Server:\s*([^/\r\n]+?)(?:/([^\s\r\n]+))?",
                r"X-Powered-By:\s*([^\r\n]+)"
            ],
            "risk_indicators": ["admin", "test", "debug"]
        },
        993: {
            "name": "IMAPS",
            "method": "ssl_connect",
            "expected_banner": r"\* OK",
            "version_patterns": [
                r"\* OK.*?(Dovecot|Courier|Exchange)\s*v?([\d.]+)?"
            ],
            "risk_indicators": ["ready"]
        },
        995: {
            "name": "POP3S", 
            "method": "ssl_connect",
            "expected_banner": r"\+OK",
            "version_patterns": [
                r"\+OK.*?(Dovecot|Courier)\s*v?([\d.]+)?"
            ],
            "risk_indicators": ["ready"]
        }
    }
    
    def __init__(self, timeout: float = 5.0, stealth: bool = False):
        self.timeout = timeout
        self.stealth = stealth
        self.results = []
        
    def _stealth_delay(self):
        """Add random delay for stealth mode"""
        if self.stealth:
            time.sleep(random.uniform(0.2, 1.0))
    
    def _normalize_target(self, target: str) -> str:
        """Extract hostname/IP from target"""
        target = target.replace("http://", "").replace("https://", "")
        if ":" in target:
            target = target.split(":")[0]
        return target.strip()
    
    def _grab_basic_banner(self, host: str, port: int) -> Optional[str]:
        """Grab banner by connecting and reading initial response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Wait a moment for banner
            time.sleep(0.1)
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _grab_http_banner(self, host: str, port: int = 80, use_ssl: bool = False) -> Optional[Dict]:
        """Grab HTTP/HTTPS banner with detailed header analysis"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if use_ssl:
                # Wrap socket with SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Security Scanner)\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Receive response
            response = b""
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if b"\r\n\r\n" in response:  # End of headers
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            if response:
                response_str = response.decode(errors="ignore")
                headers = self._parse_http_headers(response_str)
                
                return {
                    "raw_response": response_str,
                    "headers": headers,
                    "status_line": response_str.split('\n')[0].strip(),
                    "ssl_used": use_ssl
                }
                
        except Exception as e:
            return None
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """Parse HTTP headers from response"""
        headers = {}
        lines = response.split('\n')
        
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            elif line.strip() == "":
                break  # End of headers
                
        return headers
    
    def _grab_ssl_certificate_info(self, host: str, port: int) -> Optional[Dict]:
        """Extract SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])), 
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', []),
                        "cipher_suite": cipher[0] if cipher else None,
                        "tls_version": cipher[1] if cipher else None,
                        "key_bits": cipher[2] if cipher else None
                    }
                    
        except Exception:
            return None
    
    def _analyze_service_banner(self, service_name: str, port: int, banner_data: Any) -> List[Dict]:
        """Analyze banner data for security implications"""
        findings = []
        service_info = self.SERVICES.get(port, {})
        
        if not banner_data:
            findings.append({
                "issue": f"{service_name} on port {port} - No banner retrieved",
                "severity": "Info",
                "port": port,
                "service": service_name
            })
            return findings
        
        # Handle different types of banner data
        if isinstance(banner_data, dict):
            # HTTP/HTTPS response
            findings.extend(self._analyze_http_response(service_name, port, banner_data))
        else:
            # Plain text banner
            findings.extend(self._analyze_text_banner(service_name, port, str(banner_data), service_info))
        
        return findings
    
    def _analyze_http_response(self, service_name: str, port: int, response_data: Dict) -> List[Dict]:
        """Analyze HTTP/HTTPS response for security information"""
        findings = []
        headers = response_data.get("headers", {})
        status_line = response_data.get("status_line", "")
        
        print(Fore.GREEN + f"[+] {service_name} Banner (Port {port}):")
        print(Fore.YELLOW + f"    Status: {status_line}")
        
        # Check for server information disclosure
        server_header = headers.get("server", "")
        if server_header:
            print(Fore.YELLOW + f"    Server: {server_header}")
            
            # Detailed server analysis
            if any(version in server_header.lower() for version in ["apache/2.2", "apache/2.0", "nginx/1.0", "iis/6.0", "iis/7.0"]):
                findings.append({
                    "issue": f"Outdated server version detected: {server_header}",
                    "severity": "High",
                    "port": port,
                    "service": service_name,
                    "evidence": server_header
                })
            elif "/" in server_header:
                findings.append({
                    "issue": f"Server version disclosed: {server_header}",
                    "severity": "Medium", 
                    "port": port,
                    "service": service_name,
                    "evidence": server_header
                })
        
        # Check for technology disclosure
        tech_headers = [
            ("x-powered-by", "Technology stack"),
            ("x-aspnet-version", "ASP.NET version"),
            ("x-aspnetmvc-version", "ASP.NET MVC version"),
            ("x-php-version", "PHP version"),
            ("x-framework", "Framework"),
            ("x-generator", "CMS/Generator")
        ]
        
        for header, description in tech_headers:
            value = headers.get(header, "")
            if value:
                print(Fore.YELLOW + f"    {header.title()}: {value}")
                findings.append({
                    "issue": f"{description} disclosed: {value}",
                    "severity": "Medium",
                    "port": port,
                    "service": service_name,
                    "evidence": f"{header}: {value}"
                })
        
        # Security header analysis
        security_headers = {
            "strict-transport-security": ("HSTS", "Info"),
            "x-frame-options": ("Clickjacking protection", "Info"),
            "x-content-type-options": ("MIME sniffing protection", "Info"),
            "content-security-policy": ("CSP", "Info"),
            "x-xss-protection": ("XSS protection", "Info")
        }
        
        missing_security_headers = []
        for header, (name, severity) in security_headers.items():
            if header in headers:
                print(Fore.GREEN + f"    {name}: Present")
            else:
                missing_security_headers.append(name)
        
        if missing_security_headers:
            findings.append({
                "issue": f"Missing security headers: {', '.join(missing_security_headers)}",
                "severity": "Low",
                "port": port,
                "service": service_name,
                "evidence": f"Missing: {', '.join(missing_security_headers)}"
            })
        
        # Check for information disclosure headers
        risky_headers = ["server", "x-powered-by", "x-aspnet-version", "x-php-version"]
        disclosed_info = [headers.get(h) for h in risky_headers if headers.get(h)]
        
        if not disclosed_info:
            findings.append({
                "issue": f"{service_name} headers properly configured - minimal information disclosure",
                "severity": "Info",
                "port": port,
                "service": service_name
            })
        
        return findings
    
    def _analyze_text_banner(self, service_name: str, port: int, banner: str, service_info: Dict) -> List[Dict]:
        """Analyze plain text service banners"""
        findings = []
        
        print(Fore.GREEN + f"[+] {service_name} Banner (Port {port}):")
        print(Fore.YELLOW + f"    {banner[:200]}...")  # Show first 200 chars
        
        # Look for version patterns
        version_patterns = service_info.get("version_patterns", [])
        version_found = False
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version_info = " ".join(match.groups())
                print(Fore.YELLOW + f"    Version detected: {version_info}")
                
                # Check for known vulnerable versions
                if self._is_vulnerable_version(service_name, version_info):
                    findings.append({
                        "issue": f"Potentially vulnerable {service_name} version: {version_info}",
                        "severity": "High",
                        "port": port,
                        "service": service_name,
                        "evidence": version_info
                    })
                else:
                    findings.append({
                        "issue": f"{service_name} version disclosed: {version_info}",
                        "severity": "Medium",
                        "port": port,
                        "service": service_name,
                        "evidence": version_info
                    })
                version_found = True
                break
        
        # Check for risk indicators
        risk_indicators = service_info.get("risk_indicators", [])
        found_risks = []
        
        for indicator in risk_indicators:
            if indicator.lower() in banner.lower():
                found_risks.append(indicator)
        
        if found_risks:
            findings.append({
                "issue": f"{service_name} banner contains risk indicators: {', '.join(found_risks)}",
                "severity": "Medium",
                "port": port,
                "service": service_name,
                "evidence": f"Indicators: {', '.join(found_risks)}"
            })
        
        # If no version found but banner exists
        if not version_found:
            findings.append({
                "issue": f"{service_name} service identified - banner retrieved but no version info",
                "severity": "Low",
                "port": port,
                "service": service_name
            })
        
        return findings
    
    def _is_vulnerable_version(self, service: str, version_info: str) -> bool:
        """Check if version is known to be vulnerable (simplified)"""
        vulnerable_versions = {
            "SSH": ["OpenSSH_4", "OpenSSH_5.0", "OpenSSH_5.1"],
            "FTP": ["vsftpd 2.3.4", "ProFTPD 1.3.0"],
            "HTTP": ["Apache/2.2.0", "Apache/2.2.1", "nginx/1.0.0"],
            "SMTP": ["Exim 4.41", "Postfix 2.1.0"]
        }
        
        known_vulns = vulnerable_versions.get(service, [])
        return any(vuln in version_info for vuln in known_vulns)
    
    def grab_banner(self, host: str, port: int) -> List[Dict]:
        """Main banner grabbing method for a specific port"""
        self._stealth_delay()
        
        service_info = self.SERVICES.get(port, {"name": f"Port-{port}", "method": "connect_only"})
        service_name = service_info["name"]
        method = service_info["method"]
        
        banner_data = None
        
        try:
            if method == "connect_only":
                banner_data = self._grab_basic_banner(host, port)
            elif method == "http_request":
                banner_data = self._grab_http_banner(host, port, use_ssl=False)
            elif method == "https_request":
                banner_data = self._grab_http_banner(host, port, use_ssl=True)
            elif method == "ssl_connect":
                # Try SSL banner grab
                banner_data = self._grab_basic_banner(host, port)
                # Also get certificate info
                cert_info = self._grab_ssl_certificate_info(host, port)
                if cert_info:
                    banner_data = {"banner": banner_data, "certificate": cert_info}
            
        except Exception as e:
            print(Fore.RED + f"[!] Error grabbing banner for {service_name} on port {port}: {e}")
        
        return self._analyze_service_banner(service_name, port, banner_data)


def run(target: str, ports: Optional[List[int]] = None, stealth: bool = False) -> List[Dict]:
    """
    Enhanced banner grabbing function with multi-protocol support
    
    Args:
        target: Target hostname or IP
        ports: List of ports to check (default: common service ports)
        stealth: Enable stealth mode with delays
        
    Returns:
        List of findings with detailed banner analysis
    """
    print(Fore.CYAN + "[*] Running Enhanced Banner Grabbing...")
    
    grabber = ServiceBannerGrabber(timeout=5.0, stealth=stealth)
    host = grabber._normalize_target(target)
    
    # Use provided ports or default common service ports
    if ports is None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995]
    
    print(Fore.YELLOW + f"  [+] Target: {host}")
    print(Fore.YELLOW + f"  [+] Checking {len(ports)} service ports for banners")
    print(Fore.YELLOW + f"  [+] Stealth mode: {'Enabled' if stealth else 'Disabled'}")
    
    all_findings = []
    services_found = 0
    
    # Check each port for banner information
    for port in ports:
        try:
            findings = grabber.grab_banner(host, port)
            if findings:
                # Filter out "no banner" findings for cleaner output
                meaningful_findings = [f for f in findings if "No banner retrieved" not in f.get("issue", "")]
                if meaningful_findings:
                    services_found += 1
                    all_findings.extend(findings)
                    print()  # Spacing between services
                    
        except Exception as e:
            print(Fore.RED + f"[!] Error scanning port {port}: {e}")
    
    # Summary
    if services_found == 0:
        print(Fore.GREEN + "[-] No service banners retrieved")
        all_findings.append({
            "issue": "No service banners retrieved from common ports",
            "severity": "Info"
        })
    else:
        print(Fore.MAGENTA + f"\n[*] Banner grabbing completed: {services_found} services analyzed")
    
    return all_findings


# Backwards compatibility function
def run_basic(target: str) -> List[Dict]:
    """Basic banner grab for HTTP only (maintains original interface)"""
    return run(target, ports=[80], stealth=False)


if __name__ == "__main__":
    # Test the enhanced banner grabber
    test_targets = [
        "scanme.nmap.org",
        "testphp.vulnweb.com"
    ]
    
    for target in test_targets[:1]:
        print(f"\n{'='*60}")
        print(f"Testing enhanced banner grabbing on: {target}")
        print('='*60)
        
        results = run(target, stealth=True)
        print(f"\nFound {len(results)} banner-related findings")