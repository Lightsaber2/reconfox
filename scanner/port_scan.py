"""
port_scan.py
------------
Enhanced TCP port scanning module with improved performance, stealth capabilities,
and comprehensive port coverage. Performs intelligent port scanning with adaptive
timing and detailed service identification.

Features:
- Multi-threaded scanning for improved performance
- Comprehensive port lists (top ports + full range options)
- Adaptive timeout based on network conditions
- Stealth mode with randomized delays
- Service name resolution and risk assessment
- IPv6 support detection
- Detailed timing and statistics

Severity:
- Critical services (e.g. Telnet, unencrypted databases) = Critical
- High-risk services (e.g. SSH with weak config, MySQL) = High  
- Medium-risk services (e.g. HTTP, FTP) = Medium
- Low-risk services (e.g. SMTP, DNS) = Low
- Secure/standard services (e.g. HTTPS) = Info
- No open ports found = Info
"""

import socket
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set
from colorama import Fore
import ipaddress


class PortScanner:
    """Enhanced port scanner with threading and stealth capabilities"""
    
    # Comprehensive port database with service names and risk levels
    PORT_DATABASE = {
        # Critical Risk - Unencrypted/Legacy protocols
        21: ("FTP", "Critical"),           # Often allows anonymous access
        23: ("Telnet", "Critical"),       # Unencrypted remote access
        69: ("TFTP", "Critical"),         # Trivial File Transfer Protocol
        135: ("MS-RPC", "Critical"),      # Microsoft RPC endpoint mapper
        139: ("NetBIOS-SSN", "Critical"), # NetBIOS Session Service
        445: ("SMB", "Critical"),         # Server Message Block
        512: ("Rexec", "Critical"),       # Remote execution
        513: ("Rlogin", "Critical"),      # Remote login
        514: ("Rshell", "Critical"),      # Remote shell
        1433: ("MSSQL", "Critical"),      # Microsoft SQL Server
        1521: ("Oracle", "Critical"),     # Oracle database
        2049: ("NFS", "Critical"),        # Network File System
        3389: ("RDP", "Critical"),        # Remote Desktop Protocol
        5432: ("PostgreSQL", "Critical"), # PostgreSQL database
        5900: ("VNC", "Critical"),        # Virtual Network Computing
        6379: ("Redis", "Critical"),      # Redis database
        
        # High Risk - Network services that need hardening
        22: ("SSH", "High"),              # Secure Shell
        25: ("SMTP", "High"),             # Simple Mail Transfer Protocol
        53: ("DNS", "High"),              # Domain Name System
        110: ("POP3", "High"),            # Post Office Protocol v3
        111: ("RPC", "High"),             # Remote Procedure Call
        143: ("IMAP", "High"),            # Internet Message Access Protocol
        161: ("SNMP", "High"),            # Simple Network Management Protocol
        389: ("LDAP", "High"),            # Lightweight Directory Access Protocol
        636: ("LDAPS", "High"),           # LDAP over SSL
        993: ("IMAPS", "High"),           # IMAP over SSL
        995: ("POP3S", "High"),           # POP3 over SSL
        1723: ("PPTP", "High"),           # Point-to-Point Tunneling Protocol
        3306: ("MySQL", "High"),          # MySQL database
        5432: ("PostgreSQL", "High"),     # PostgreSQL database
        5984: ("CouchDB", "High"),        # CouchDB database
        6667: ("IRC", "High"),            # Internet Relay Chat
        8080: ("HTTP-Alt", "High"),       # Alternative HTTP port
        8443: ("HTTPS-Alt", "High"),      # Alternative HTTPS port
        9200: ("Elasticsearch", "High"),  # Elasticsearch
        11211: ("Memcached", "High"),     # Memcached
        27017: ("MongoDB", "High"),       # MongoDB database
        
        # Medium Risk - Common web/application services
        80: ("HTTP", "Medium"),           # Hypertext Transfer Protocol
        443: ("HTTPS", "Medium"),         # HTTP over SSL/TLS
        993: ("IMAPS", "Medium"),         # IMAP over SSL
        3000: ("Node.js", "Medium"),      # Common Node.js development port
        5000: ("Flask", "Medium"),        # Common Flask development port
        8000: ("HTTP-Alt", "Medium"),     # Alternative HTTP port
        8008: ("HTTP-Alt", "Medium"),     # Alternative HTTP port
        8888: ("HTTP-Alt", "Medium"),     # Alternative HTTP port
        9000: ("HTTP-Alt", "Medium"),     # Alternative HTTP port
        
        # Low Risk - Standard services, typically well-secured
        20: ("FTP-Data", "Low"),          # FTP Data Transfer
        119: ("NNTP", "Low"),             # Network News Transfer Protocol
        443: ("HTTPS", "Info"),           # HTTPS is generally secure
        465: ("SMTPS", "Info"),           # SMTP over SSL
        587: ("SMTP-Submission", "Info"), # SMTP Submission
        631: ("IPP", "Low"),              # Internet Printing Protocol
        993: ("IMAPS", "Info"),           # IMAP over SSL
        995: ("POP3S", "Info"),           # POP3 over SSL
    }
    
    # Port ranges for different scan types
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443]
    TOP_1000_PORTS = list(range(1, 1001))  # Simplified - in practice would be actual top 1000
    
    def __init__(self, stealth_mode: bool = False, max_threads: int = 50):
        self.stealth_mode = stealth_mode
        self.max_threads = max_threads
        self.scan_start = None
        self.scan_duration = None
        self.ports_scanned = 0
        self.open_ports = []
        self.closed_ports = 0
        self.timeout_base = 1.0
        self.adaptive_timeout = 1.0
        
    def _normalize_target(self, target: str) -> str:
        """Clean and normalize target hostname/IP"""
        target = target.replace("http://", "").replace("https://", "")
        # Remove port if specified in target
        if ":" in target:
            target = target.split(":")[0]
        return target.strip()
    
    def _detect_target_type(self, target: str) -> str:
        """Detect if target is IPv4, IPv6, or hostname"""
        try:
            ip = ipaddress.ip_address(target)
            return "ipv6" if ip.version == 6 else "ipv4"
        except ValueError:
            return "hostname"
    
    def _adaptive_timeout_calculation(self, target: str) -> float:
        """Calculate adaptive timeout based on network conditions"""
        print(Fore.CYAN + "  [*] Calculating optimal timeout...")
        
        test_ports = [22, 80, 443]  # Fast test on common ports
        response_times = []
        
        for port in test_ports:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)  # Initial timeout for testing
            try:
                result = sock.connect_ex((target, port))
                elapsed = time.time() - start_time
                response_times.append(elapsed)
            except:
                response_times.append(2.0)  # Max timeout if failed
            finally:
                sock.close()
                
            if self.stealth_mode:
                time.sleep(random.uniform(0.1, 0.3))
        
        if response_times:
            avg_response = sum(response_times) / len(response_times)
            # Set timeout to 3x average response time, min 0.5s, max 5s
            self.adaptive_timeout = max(0.5, min(5.0, avg_response * 3))
        else:
            self.adaptive_timeout = self.timeout_base
            
        print(Fore.YELLOW + f"    [+] Adaptive timeout set to {self.adaptive_timeout:.2f}s")
        return self.adaptive_timeout
    
    def _scan_port(self, target: str, port: int) -> Optional[Dict]:
        """Scan a single port and return result"""
        try:
            # Stealth delay
            if self.stealth_mode:
                time.sleep(random.uniform(0.05, 0.2))
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.adaptive_timeout)
            
            start_time = time.time()
            result = sock.connect_ex((target, port))
            response_time = time.time() - start_time
            
            if result == 0:
                # Port is open
                service_name, risk_level = self.PORT_DATABASE.get(port, ("Unknown", "Low"))
                
                sock.close()
                return {
                    "port": port,
                    "status": "open",
                    "service": service_name,
                    "severity": risk_level,
                    "response_time": round(response_time * 1000, 2)  # Convert to ms
                }
            else:
                sock.close()
                self.closed_ports += 1
                return None
                
        except socket.timeout:
            try:
                sock.close()
            except:
                pass
            return None
        except Exception:
            try:
                sock.close()
            except:
                pass
            return None
    
    def _threaded_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """Perform threaded port scan"""
        print(Fore.CYAN + f"  [*] Scanning {len(ports)} ports with {self.max_threads} threads...")
        
        results = []
        self.ports_scanned = 0
        
        # Adjust thread count for stealth mode
        thread_count = min(5, self.max_threads) if self.stealth_mode else self.max_threads
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self._scan_port, target, port): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                self.ports_scanned += 1
                
                # Progress indicator
                if self.ports_scanned % max(1, len(ports) // 20) == 0:
                    progress = (self.ports_scanned / len(ports)) * 100
                    print(Fore.YELLOW + f"    [+] Progress: {progress:.1f}% ({self.ports_scanned}/{len(ports)})")
                
                result = future.result()
                if result:
                    results.append(result)
                    
        return results
    
    def _get_port_list(self, scan_type: str = "common") -> List[int]:
        """Get list of ports to scan based on scan type"""
        if scan_type == "common":
            return self.COMMON_PORTS
        elif scan_type == "top1000":
            # For demo purposes, using a realistic top ports selection
            top_ports = []
            top_ports.extend(self.COMMON_PORTS)  # Include common ports
            # Add additional ports that are commonly found open
            additional = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 11211, 27017]
            for port in additional:
                if port not in top_ports:
                    top_ports.append(port)
            return sorted(top_ports[:100])  # Limit to 100 for performance
        elif scan_type == "full":
            return list(range(1, 65536))  # Full port range
        else:
            return self.COMMON_PORTS
    
    def _format_scan_results(self, results: List[Dict], target: str) -> Tuple[List[Dict], str]:
        """Format scan results for output"""
        if not results:
            summary = f"No open ports found on {target}"
            findings = [{"issue": summary, "severity": "Info"}]
            return findings, summary
        
        findings = []
        open_ports_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
        
        for result in results:
            port = result["port"]
            service = result["service"]
            severity = result["severity"]
            response_time = result["response_time"]
            
            # Create detailed finding
            issue = f"Port {port} open ({service}) - Response: {response_time}ms"
            findings.append({
                "issue": issue,
                "severity": severity,
                "port": port,
                "service": service,
                "response_time": response_time
            })
            
            open_ports_by_severity[severity].append(f"{port}/{service}")
        
        # Create summary
        total_open = len(results)
        summary_parts = [f"{total_open} open ports found"]
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            count = len(open_ports_by_severity[severity])
            if count > 0:
                summary_parts.append(f"{severity}: {count}")
        
        summary = " | ".join(summary_parts)
        
        return findings, summary
    
    def _print_detailed_results(self, results: List[Dict], target: str):
        """Print detailed scan results with color coding"""
        if not results:
            print(Fore.GREEN + f"[-] No open ports found on {target}")
            return
        
        print(Fore.GREEN + f"\n[+] Open ports found on {target}:")
        
        # Group by severity for organized output
        severity_colors = {
            "Critical": Fore.RED + "[CRITICAL]",
            "High": Fore.MAGENTA + "[HIGH]",
            "Medium": Fore.YELLOW + "[MEDIUM]", 
            "Low": Fore.CYAN + "[LOW]",
            "Info": Fore.WHITE + "[INFO]"
        }
        
        by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
        
        for result in results:
            by_severity[result["severity"]].append(result)
        
        for severity in ["Critical", "High", "Medium", "Low", "Info"]:
            ports = by_severity[severity]
            if ports:
                print(f"\n{severity_colors[severity]}")
                for port_info in ports:
                    port = port_info["port"]
                    service = port_info["service"]
                    response_time = port_info["response_time"]
                    print(f"    {port:>5} | {service:<15} | {response_time:>6}ms")
    
    def _print_scan_statistics(self, results: List[Dict]):
        """Print scan timing and statistics"""
        print(Fore.CYAN + f"\n[*] Scan Statistics:")
        print(f"    Duration: {self.scan_duration:.2f} seconds")
        print(f"    Ports scanned: {self.ports_scanned}")
        print(f"    Open ports: {len(results)}")
        print(f"    Closed/filtered: {self.closed_ports}")
        print(f"    Scan rate: {self.ports_scanned/self.scan_duration:.1f} ports/second")
        print(f"    Adaptive timeout: {self.adaptive_timeout:.2f}s")


def run(target: str, scan_type: str = "common", stealth: bool = False) -> List[Dict]:
    """
    Enhanced port scanning function with multiple improvements:
    
    Args:
        target: Target hostname or IP address
        scan_type: 'common', 'top1000', or 'full' (default: 'common')  
        stealth: Enable stealth mode with delays and reduced threads
        
    Returns:
        List of findings with detailed port information
    """
    print(Fore.CYAN + "[*] Running Enhanced Port Scan...")
    
    # Initialize scanner
    scanner = PortScanner(stealth_mode=stealth, max_threads=50 if not stealth else 10)
    
    # Normalize target
    clean_target = scanner._normalize_target(target)
    target_type = scanner._detect_target_type(clean_target)
    
    print(Fore.YELLOW + f"  [+] Target: {clean_target} (Type: {target_type})")
    print(Fore.YELLOW + f"  [+] Scan type: {scan_type}")
    print(Fore.YELLOW + f"  [+] Stealth mode: {'Enabled' if stealth else 'Disabled'}")
    
    # Get port list
    ports_to_scan = scanner._get_port_list(scan_type)
    
    # Calculate adaptive timeout
    scanner._adaptive_timeout_calculation(clean_target)
    
    # Perform scan
    scanner.scan_start = time.time()
    scan_results = scanner._threaded_scan(clean_target, ports_to_scan)
    scanner.scan_duration = time.time() - scanner.scan_start
    
    # Format and display results
    findings, summary = scanner._format_scan_results(scan_results, clean_target)
    scanner._print_detailed_results(scan_results, clean_target)
    scanner._print_scan_statistics(scan_results)
    
    print(Fore.MAGENTA + f"\n[*] Port scan completed: {summary}")
    
    return findings


# Compatibility function for the existing interface
def run_basic(target: str) -> List[Dict]:
    """
    Basic port scan function that maintains compatibility with existing code
    """
    return run(target, scan_type="common", stealth=False)


# Example usage and testing
if __name__ == "__main__":
    # Test the enhanced port scanner
    test_targets = [
        "scanme.nmap.org",
        "testphp.vulnweb.com", 
        "127.0.0.1"
    ]
    
    for target in test_targets[:1]:  # Test only first target
        print(f"\n{'='*60}")
        print(f"Testing enhanced port scan on: {target}")
        print('='*60)
        
        results = run(target, scan_type="common", stealth=True)
        
        print(f"\nFound {len([r for r in results if 'open' in r.get('issue', '')])} open ports")