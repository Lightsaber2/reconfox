"""
dirlisting.py
-------------
Enhanced directory listing detection module with comprehensive testing:
- Extensive path coverage (50+ common directories)
- Multi-server detection (Apache, Nginx, IIS, etc.)
- Sensitive file enumeration and categorization
- Risk-based severity assessment
- Recursive directory exploration
- File extension analysis and content type detection

Severity:
- Critical files exposed (configs, databases) = High
- Sensitive directories with valuable content = Medium  
- Basic directory listing with low-risk files = Low
- No directory listing = Info
"""

import requests
import time
import random
import re
from typing import Optional, List, Dict, Set, Tuple
from urllib.parse import urljoin, urlparse
from colorama import Fore

FALLBACK_HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

class DirectoryListingScanner:
    def __init__(self, client: Optional[object] = None):
        self.client = client
        self.findings = []
        self.discovered_files = []
        self.tested_paths = set()
        
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
            print(Fore.RED + f"[!] Request failed for {url}: {e}")
            return None
    
    def _get_comprehensive_paths(self) -> List[Tuple[str, str, str]]:
        """Generate comprehensive list of paths to test"""
        # Format: (path, description, risk_level)
        paths = [
            # Root and common directories
            ("/", "Root directory", "medium"),
            ("/test/", "Test directory", "low"), 
            ("/tests/", "Tests directory", "low"),
            ("/tmp/", "Temporary files", "medium"),
            ("/temp/", "Temporary files", "medium"),
            
            # Administrative paths
            ("/admin/", "Admin directory", "high"),
            ("/administrator/", "Administrator directory", "high"),
            ("/management/", "Management interface", "high"),
            ("/manager/", "Manager interface", "medium"),
            
            # Upload and media directories
            ("/uploads/", "Upload directory", "medium"),
            ("/upload/", "Upload directory", "medium"),
            ("/files/", "Files directory", "medium"),
            ("/media/", "Media files", "low"),
            ("/images/", "Images directory", "low"),
            ("/img/", "Images directory", "low"),
            ("/photos/", "Photos directory", "low"),
            ("/documents/", "Documents directory", "medium"),
            ("/docs/", "Documentation", "low"),
            
            # Configuration and sensitive directories
            ("/config/", "Configuration files", "high"),
            ("/configuration/", "Configuration files", "high"),
            ("/conf/", "Config directory", "high"),
            ("/etc/", "System configuration", "high"),
            ("/settings/", "Settings directory", "high"),
            
            # Backup directories
            ("/backup/", "Backup files", "high"),
            ("/backups/", "Backup files", "high"),
            ("/bak/", "Backup files", "high"),
            ("/old/", "Old files", "medium"),
            ("/archive/", "Archive files", "medium"),
            
            # Development directories
            ("/dev/", "Development files", "medium"),
            ("/development/", "Development files", "medium"),
            ("/src/", "Source code", "high"),
            ("/source/", "Source code", "high"),
            ("/git/", "Git repository", "high"),
            ("/.git/", "Git repository", "high"),
            ("/.svn/", "SVN repository", "high"),
            
            # Database directories
            ("/db/", "Database files", "high"),
            ("/database/", "Database files", "high"),
            ("/data/", "Data files", "high"),
            ("/sql/", "SQL files", "high"),
            
            # Log directories
            ("/logs/", "Log files", "medium"),
            ("/log/", "Log files", "medium"),
            ("/access-logs/", "Access logs", "medium"),
            
            # Library and includes
            ("/lib/", "Library files", "low"),
            ("/libs/", "Library files", "low"),
            ("/includes/", "Include files", "medium"),
            ("/inc/", "Include files", "medium"),
            
            # Cache directories
            ("/cache/", "Cache files", "low"),
            ("/cached/", "Cached files", "low"),
            
            # Private directories
            ("/private/", "Private files", "high"),
            ("/protected/", "Protected files", "high"),
            ("/secure/", "Secure files", "high"),
            
            # Web application specific
            ("/wp-content/", "WordPress content", "low"),
            ("/wp-admin/", "WordPress admin", "medium"),
            ("/wp-includes/", "WordPress includes", "low"),
            ("/assets/", "Web assets", "low"),
            ("/static/", "Static files", "low"),
            ("/public/", "Public files", "low"),
        ]
        
        return paths
    
    def _detect_directory_listing(self, response: requests.Response, url: str) -> Tuple[bool, str, List[str]]:
        """
        Detect directory listing and extract file information
        Returns: (is_listing, server_type, files_found)
        """
        if not response or not response.text:
            return False, "", []
        
        content = response.text.lower()
        files_found = []
        server_type = "unknown"
        
        # Server-specific directory listing patterns
        listing_patterns = {
            'apache': [
                r'<title>index of /',
                r'<h1>index of /',
                r'parent directory',
                r'<img[^>]*alt="\[dir\]"',
                r'<img[^>]*alt="\[   \]"'  # Apache file icon
            ],
            'nginx': [
                r'<title>index of /',
                r'<h1>index of /',
                r'<a href="\.\.">\.\./</a>'
            ],
            'iis': [
                r'directory listing.*denied',
                r'<title>[^<]*- /</title>',
                r'<pre><a href="\[to parent directory\]">',
                r'microsoft-iis'
            ],
            'lighttpd': [
                r'<title>index of /',
                r'lighttpd'
            ],
            'python': [
                r'directory listing for /',
                r'<title>directory listing for /',
                r'<code>directory listing</code>'
            ]
        }
        
        # Check for directory listing patterns
        is_listing = False
        for server, patterns in listing_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    is_listing = True
                    server_type = server
                    break
            if is_listing:
                break
        
        # Additional generic patterns
        if not is_listing:
            generic_patterns = [
                r'index of /',
                r'directory listing',
                r'parent directory',
                r'<a href="\.\."',
                r'\[to parent directory\]',
                r'<title>[^<]*directory[^<]*</title>'
            ]
            
            for pattern in generic_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    is_listing = True
                    break
        
        # Extract file links if directory listing detected
        if is_listing:
            files_found = self._extract_files_from_listing(response.text, url)
        
        return is_listing, server_type, files_found
    
    def _extract_files_from_listing(self, html_content: str, base_url: str) -> List[str]:
        """Extract file and directory names from directory listing HTML"""
        files = []
        
        # Common patterns for extracting links in directory listings
        link_patterns = [
            r'<a href="([^"]*)"[^>]*>([^<]*)</a>',  # Standard HTML links
            r'href="([^"]*)"[^>]*>([^<]*)<',        # Alternative format
        ]
        
        for pattern in link_patterns:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                href = match.group(1)
                text = match.group(2).strip()
                
                # Skip parent directory links and empty entries
                if href in ['..', '../', '/', ''] or 'parent' in text.lower():
                    continue
                
                # Skip query parameters and fragments
                if '?' in href or '#' in href:
                    continue
                
                # Add to files list if it looks like a valid file/directory
                if href and not href.startswith(('http://', 'https://', 'mailto:', 'javascript:')):
                    files.append(href)
        
        return list(set(files))  # Remove duplicates
    
    def _analyze_exposed_files(self, files: List[str], base_path: str) -> Dict[str, List[str]]:
        """Categorize exposed files by risk level"""
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        # File patterns by risk level
        risk_patterns = {
            'critical': [
                r'\.key$', r'\.pem$', r'\.crt$', r'\.p12$',  # Certificates/keys
                r'\.sql$', r'\.db$', r'\.sqlite$', r'\.mdb$',  # Databases
                r'password', r'passwd', r'secret', r'private',  # Sensitive keywords
                r'\.env$', r'\.config$', r'web\.config$',  # Config files
            ],
            'high': [
                r'\.bak$', r'\.backup$', r'\.old$', r'\.orig$',  # Backups
                r'\.php$', r'\.asp$', r'\.jsp$', r'\.py$', r'\.rb$',  # Source code
                r'\.log$', r'\.error$', r'access\.log',  # Log files
                r'admin', r'administrator', r'root',  # Admin-related
            ],
            'medium': [
                r'\.txt$', r'\.doc$', r'\.pdf$', r'\.xls$',  # Documents
                r'\.xml$', r'\.json$', r'\.yml$', r'\.yaml$',  # Data files
                r'readme', r'install', r'setup', r'todo',  # Info files
            ],
            'low': [
                r'\.jpg$', r'\.png$', r'\.gif$', r'\.css$',  # Media/assets
                r'\.js$', r'\.html$', r'\.htm$',  # Web files
            ]
        }
        
        for filename in files:
            filename_lower = filename.lower()
            categorized_file = False
            
            for risk_level, patterns in risk_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, filename_lower, re.IGNORECASE):
                        categorized[risk_level].append(filename)
                        categorized_file = True
                        break
                if categorized_file:
                    break
            
            # If file doesn't match any pattern, categorize as low
            if not categorized_file:
                categorized['low'].append(filename)
        
        return categorized
    
    def _test_directory_paths(self, base_url: str, max_paths: int = 30) -> List[Dict]:
        """Test directory paths for listings"""
        print(Fore.CYAN + "  [*] Testing directory paths for listings...")
        findings = []
        
        paths = self._get_comprehensive_paths()
        # Limit paths for stealth - prioritize high-risk paths
        high_risk_paths = [p for p in paths if p[2] == 'high'][:15]
        medium_risk_paths = [p for p in paths if p[2] == 'medium'][:10]
        low_risk_paths = [p for p in paths if p[2] == 'low'][:5]
        
        test_paths = high_risk_paths + medium_risk_paths + low_risk_paths
        
        for path, description, risk_level in test_paths:
            if len(findings) >= max_paths:  # Limit total tests
                break
                
            target_url = base_url.rstrip('/') + path
            
            if target_url in self.tested_paths:
                continue
                
            self.tested_paths.add(target_url)
            print(Fore.YELLOW + f"    [+] Testing: {target_url}")
            
            response = self._make_request(target_url)
            
            if not response:
                continue
                
            # Check for directory listing
            is_listing, server_type, files_found = self._detect_directory_listing(response, target_url)
            
            if is_listing:
                # Analyze exposed files
                categorized_files = self._analyze_exposed_files(files_found, path)
                
                # Determine severity based on files found
                if categorized_files['critical']:
                    severity = "High"
                    issue = f"CRITICAL files exposed in directory listing: {description}"
                elif categorized_files['high']:
                    severity = "High" 
                    issue = f"Sensitive files exposed in directory listing: {description}"
                elif categorized_files['medium']:
                    severity = "Medium"
                    issue = f"Directory listing enabled with potentially sensitive files: {description}"
                else:
                    severity = "Low"
                    issue = f"Directory listing enabled: {description}"
                
                # Create detailed finding
                file_summary = []
                for risk, files in categorized_files.items():
                    if files:
                        file_summary.append(f"{risk}: {len(files)} files")
                
                findings.append({
                    "issue": issue,
                    "severity": severity,
                    "evidence": f"Server: {server_type}, Files found: {len(files_found)}",
                    "url": target_url,
                    "files_summary": ", ".join(file_summary) if file_summary else "No files categorized",
                    "critical_files": categorized_files.get('critical', [])[:5],  # Show first 5
                    "high_risk_files": categorized_files.get('high', [])[:5]
                })
                
                print(Fore.RED + f"[!] Directory listing detected: {target_url}")
                print(Fore.RED + f"    Server: {server_type}, Files: {len(files_found)}")
                
                # Show critical files immediately
                if categorized_files['critical']:
                    print(Fore.RED + f"    CRITICAL FILES: {', '.join(categorized_files['critical'][:3])}")
                
            else:
                print(Fore.GREEN + f"[-] {target_url} protected")
                # Don't add "safe" findings to reduce noise unless explicitly requested
                
        return findings
    
    def _test_recursive_listing(self, base_url: str, discovered_dirs: List[str], max_depth: int = 2) -> List[Dict]:
        """Test discovered directories recursively"""
        print(Fore.CYAN + "  [*] Testing discovered directories recursively...")
        findings = []
        
        if max_depth <= 0 or not discovered_dirs:
            return findings
        
        # Test first few discovered directories to avoid excessive requests
        for directory in discovered_dirs[:5]:  # Limit to first 5 directories
            if not directory.endswith('/'):
                directory += '/'
                
            recursive_url = urljoin(base_url, directory)
            
            if recursive_url in self.tested_paths:
                continue
                
            print(Fore.YELLOW + f"    [+] Recursive test: {recursive_url}")
            
            response = self._make_request(recursive_url)
            
            if response:
                is_listing, server_type, files_found = self._detect_directory_listing(response, recursive_url)
                
                if is_listing:
                    categorized_files = self._analyze_exposed_files(files_found, directory)
                    
                    severity = "Medium"
                    if categorized_files['critical'] or categorized_files['high']:
                        severity = "High"
                    
                    findings.append({
                        "issue": f"Recursive directory listing in subdirectory: {directory}",
                        "severity": severity,
                        "evidence": f"Nested listing found, Files: {len(files_found)}",
                        "url": recursive_url,
                        "depth": max_depth
                    })
                    
                    print(Fore.YELLOW + f"[!] Recursive listing: {recursive_url}")
        
        return findings


def check_dir_listing(url: str, client: Optional[object] = None) -> List[Dict]:
    """
    Enhanced directory listing detection with comprehensive analysis
    
    Args:
        url: Target URL to test
        client: Optional HTTP client for requests
        
    Returns:
        List of findings with detailed directory analysis
    """
    print(Fore.CYAN + "\n[*] Checking for Directory Listings...")
    
    scanner = DirectoryListingScanner(client)
    all_findings = []
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    try:
        # Main directory listing tests
        directory_findings = scanner._test_directory_paths(url)
        all_findings.extend(directory_findings)
        
        # Extract discovered directories for recursive testing
        discovered_dirs = []
        for finding in directory_findings:
            if finding.get("severity") in ["High", "Medium"]:
                # Extract directory path from URL for recursive testing
                path = urlparse(finding.get("url", "")).path
                if path and path.endswith('/'):
                    discovered_dirs.append(path)
        
        # Recursive testing if directories were found
        if discovered_dirs:
            recursive_findings = scanner._test_recursive_listing(url, discovered_dirs, max_depth=1)
            all_findings.extend(recursive_findings)
        
    except Exception as e:
        print(Fore.RED + f"[!] Error in directory listing detection: {e}")
        return [{"issue": f"Directory listing test failed: {e}", "severity": "Info"}]
    
    # Summary
    if not all_findings:
        print(Fore.GREEN + "[-] No directory listings detected.")
        all_findings.append({"issue": "No directory listings found", "severity": "Info"})
    else:
        high_count = len([f for f in all_findings if f.get('severity') == 'High'])
        medium_count = len([f for f in all_findings if f.get('severity') == 'Medium'])
        low_count = len([f for f in all_findings if f.get('severity') == 'Low'])
        
        print(Fore.MAGENTA + f"[*] Directory listing scan completed: {high_count} high, {medium_count} medium, {low_count} low severity findings")
        
        # Show summary of critical files if found
        critical_files = []
        for finding in all_findings:
            critical_files.extend(finding.get('critical_files', []))
        
        if critical_files:
            print(Fore.RED + f"[!] CRITICAL FILES EXPOSED: {', '.join(critical_files[:5])}")
    
    return all_findings


# Backward compatibility
def run(url: str, client: Optional[object] = None) -> List[Dict]:
    """Main entry point for the directory listing module"""
    return check_dir_listing(url, client)