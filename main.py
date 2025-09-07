# main.py
"""

Vulnerability Scanner - Main Entry Point
----------------------------------------

This script orchestrates the scanning process:
1. Normalizes the user-provided target (domain/IP/URL).
2. Runs multiple security modules (port scanning, SQLi, XSS, etc.).
3. Collects findings from all modules in a structured way.
4. Displays a final severity-based summary report (like Vega/Nessus).
"""


"""
a few domains which are deliberately vulnerable test sites, set up for training/security research:

1) http://testphp.vulnweb.com/c (Acunetix demo site)

2) http://testasp.vulnweb.com/

3) http://zero.webappsecurity.com/

4) http://www.webscantest.com/

5) https://juice-shop.herokuapp.com/ (OWASP Juice Shop)

6) http://xss-game.appspot.com/ (Google's XSS game)
"""

import os
import argparse
import json
import time
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import inspect
from colorama import init, Fore, Style
import concurrent.futures
import threading
from typing import List, Dict, Any

# Import scanner modules
from scanner import (
    port_scan,
    banner_grab,
    sql_injection,
    xss,
    redirect,
    headers,
    cors,
    dirlisting,
    crawler,
)

# Try to import the shared HTTPClient (must be created in scanner/http_client.py)
try:
    from scanner.http_client import HTTPClient
except Exception:
    HTTPClient = None  # we'll handle this later

# Initialize colorama
init(autoreset=True)


# ---------- Utility Functions ----------

def normalize_url(raw: str) -> str:
    """
    Ensure the input has a proper scheme (http:// or https://).
    If a bare domain/IP is provided, default to http://.
    """
    raw = (raw or "").strip()
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        return "http:" + raw
    return "http://" + raw


def extract_host(url: str) -> str:
    """
    Extract just the hostname from a URL (no scheme, path, or port).
    Used by modules like port scan and banner grab.
    """
    p = urlparse(url)
    host = p.netloc or p.path
    if "@" in host:
        host = host.split("@", 1)[1]
    if host.startswith("[") and "]" in host:
        host = host[1: host.index("]")]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def print_summary(findings):
    """
    Print a final severity-based summary of all findings.
    Findings are grouped into Critical, High, Medium, Low, Info.
    """
    if not findings:
        print(Fore.GREEN + Style.BRIGHT + "\n[+] No findings reported.")
        return

    # All 5 severity levels that the scanner modules can return
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    grouped = defaultdict(list)

    for f in findings:
        # safety: ensure keys exist and normalize severity levels
        sev = f.get("severity", "Info")
        # Ensure severity is one of the expected values
        if sev not in severity_order:
            sev = "Info"  # Default unknown severities to Info
        issue = f.get("issue", str(f))
        grouped[sev].append(issue)

    print(Fore.MAGENTA + Style.BRIGHT + "\n=== Final Scan Report ===")
    
    # Print summary counts first - only show levels that have findings
    total_findings = sum(len(issues) for issues in grouped.values())
    if total_findings > 0:
        summary_parts = []
        for level in severity_order:
            count = len(grouped.get(level, []))
            if count > 0:
                summary_parts.append(f"{level}: {count}")
        
        if summary_parts:
            print(Fore.WHITE + f"Total findings: {total_findings} ({', '.join(summary_parts)})")
    
    # Print detailed findings by severity level - only show levels that have findings
    for level in severity_order:
        issues = grouped.get(level, [])
        if issues:  # Only print sections that have findings
            # Color mapping for all 5 severity levels
            color_map = {
                "Critical": Fore.RED + Style.BRIGHT,
                "High": Fore.RED,
                "Medium": Fore.YELLOW,
                "Low": Fore.CYAN,
                "Info": Fore.WHITE,
            }
            color = color_map.get(level, Fore.WHITE)  # Fallback to white if unknown
            print(color + f"\n{level} Findings ({len(issues)}):")
            for issue in issues:
                print(color + "   - " + issue)


def save_json(findings, target, start_time, duration):
    """
    Save findings JSON into the ./results directory with a timestamped filename.
    """
    # Ensure results directory exists
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)

    # Build a unique filename with target + timestamp
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{safe_target}_{timestamp}.json"
    filepath = os.path.join(results_dir, filename)

    # Construct the JSON report with severity summary
    severity_summary = defaultdict(int)
    for finding in findings:
        severity = finding.get("severity", "Info")
        severity_summary[severity] += 1

    report = {
        "target": target,
        "scan_started": datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S"),
        "report_generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": round(duration, 2),
        "total_findings": len(findings),
        "severity_summary": dict(severity_summary),
        "findings": findings,
    }

    # Save the file
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    # flush print to avoid terminal buffering oddities
    print(Fore.CYAN + f"\n[+] Results saved to {filepath}", flush=True)


# ---------- Module call helper ----------

def _normalize_module_result(result):
    """
    Convert result from a module into a list of finding dicts:
    - If module returns a list of dicts, return as-is
    - If returns a list of strings (URLs), convert to {"issue": "...", "severity": "Info"}
    - If returns a single dict, wrap it
    - Else return empty list
    """
    if result is None:
        return []
    if isinstance(result, list):
        if not result:
            return []
        first = result[0]
        if isinstance(first, dict):
            return result
        elif isinstance(first, str):
            return [{"issue": str(u), "severity": "Info"} for u in result]
        else:
            # unknown list content
            return []
    if isinstance(result, dict):
        return [result]
    return []


def call_module(func, args_list, client=None, module_name=None):
    """
    Call module function with either (args...) or (args..., client) depending on what it accepts.
    Returns a normalized list of findings (list of dicts).
    """
    module_name = module_name or (getattr(func, "__name__", "module"))
    # Try calling with client if provided
    try:
        if client is not None:
            try:
                result = func(*args_list, client)
            except TypeError:
                # function doesn't accept client, call without
                result = func(*args_list)
        else:
            result = func(*args_list)
    except Exception as e:
        print(Fore.RED + f"[!] {module_name} error: {e}")
        return []

    return _normalize_module_result(result)


# ---------- Main Logic ----------

def main():
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    parser.add_argument("--target", "-t", help="Target domain or IP (with or without http/https)")
    parser.add_argument("--json", "-j", action="store_true", help="Export results to a JSON file in ./results/")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (random delays + UA rotation)")
    parser.add_argument("--fast", action="store_true", help="Fast mode - minimal delays, no stealth")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads for HTTP tests")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout (seconds)")
    parser.add_argument("--skip-modules", nargs='+', help="Skip specific modules (port, banner, sqli, xss, etc.)")
    parser.add_argument("--only-modules", nargs='+', help="Only run specific modules")
    parser.add_argument("--delay-min", type=float, default=1.0, help="Minimum delay (seconds) between HTTP requests in stealth mode")
    parser.add_argument("--delay-max", type=float, default=3.0, help="Maximum delay (seconds) between HTTP requests in stealth mode")
    parser.add_argument("--proxy", help="Optional proxy URL to use for HTTP requests (e.g. http://127.0.0.1:8080)")
    args = parser.parse_args()

    print(Fore.CYAN + Style.BRIGHT + "=== Simple Vulnerability Scanner ===\n")

    # If CLI target present use it, otherwise prompt interactively
    if args.target:
        user_input = args.target.strip()
    else:
        user_input = input(Fore.YELLOW + "Enter the target IP or domain (with or without http/https): ").strip()

    if not user_input:
        print(Fore.RED + "[-] No target provided. Exiting...")
        return

    target = normalize_url(user_input)
    target_host = extract_host(target)

    if target != user_input:
        print(Fore.BLUE + f"[*] Normalized target to: {target}")

    # Create shared HTTP client if available (http_client.py must exist in scanner/)
    client = None
    if HTTPClient is not None:
        if args.fast:
            args.stealth = False
            delay_range = (0.05, 0.15)
            timeout = 3.0
        else:
            delay_range = (args.delay_min, args.delay_max)
            timeout = args.timeout

        client = HTTPClient(
            delay_range=delay_range,
            stealth=args.stealth and not args.fast,
            fast_mode=args.fast,
            timeout=timeout,
            retries=1 if args.fast else 2,
            backoff_factor=0.3,
            proxy_url=args.proxy,
            quiet=True,
        )
    else:
        # If HTTPClient is not present, warn and modules will fallback to using requests directly
        print(Fore.YELLOW + "[!] scanner.http_client.HTTPClient not found — HTTP modules will be called without the shared client.")

    print(Fore.GREEN + f"\n[+] Starting scan on target: {target}\n")
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(Fore.MAGENTA + f"[*] Scan started at: {timestamp}\n")

    findings = []

    # ----------------- Run Scanner Modules -----------------
    # Define module execution plan
    modules_config = {
        'port': {'func': port_scan.run, 'args': [target_host], 'use_client': False, 'parallel': False},
        'banner': {'func': banner_grab.run, 'args': [target_host], 'use_client': False, 'parallel': False},
        'sqli': {'func': sql_injection.run, 'args': [target], 'use_client': True, 'parallel': True},
        'xss': {'func': xss.run, 'args': [target], 'use_client': True, 'parallel': True},
        'redirect': {'func': redirect.check_open_redirect, 'args': [target], 'use_client': True, 'parallel': True},
        'headers': {'func': headers.check_security_headers, 'args': [target], 'use_client': True, 'parallel': True},
        'cors': {'func': cors.check_cors, 'args': [target], 'use_client': True, 'parallel': True},
        'dirlisting': {'func': dirlisting.check_dir_listing, 'args': [target], 'use_client': True, 'parallel': True},
        'crawler': {'func': crawler.crawl, 'args': [target, 10 if args.fast else 20], 'use_client': True, 'parallel': False},
    }

    # Filter modules based on command line args
    if args.skip_modules:
        modules_config = {k: v for k, v in modules_config.items() if k not in args.skip_modules}
    if args.only_modules:
      modules_config = {k: v for k, v in modules_config.items() if k in args.only_modules}

    # Run non-parallel modules first (port scan, banner grab)
    sequential_modules = {k: v for k, v in modules_config.items() if not v['parallel']}
    parallel_modules = {k: v for k, v in modules_config.items() if v['parallel']}

    # Sequential execution
    for module_name, config in sequential_modules.items():
        print(Fore.CYAN + f"[*] Running {module_name.title()}...")
        module_start_time = time.time()  # CHANGED: Use module-specific timer
    
        module_findings = call_module(
            config['func'], 
            config['args'], 
            client=client if config['use_client'] else None,
            module_name=module_name
        )
        findings.extend(module_findings)
    
    module_duration = time.time() - module_start_time  # CHANGED: Use module-specific timer
    print(Fore.GREEN + f"[+] {module_name.title()} completed in {module_duration:.2f}s")

    # Parallel execution for HTTP-based modules
    if parallel_modules and not args.fast:
        print(Fore.CYAN + f"\n[*] Running {len(parallel_modules)} HTTP modules in parallel...")
    
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_module = {}
        
            for module_name, config in parallel_modules.items():
                future = executor.submit(
                    call_module,
                    config['func'],
                    config['args'],
                    client if config['use_client'] else None,
                    module_name
                )
                future_to_module[future] = module_name
        
            for future in concurrent.futures.as_completed(future_to_module):
                module_name = future_to_module[future]
                try:
                    module_findings = future.result()
                    findings.extend(module_findings)
                    print(Fore.GREEN + f"[+] {module_name.title()} completed")
                except Exception as e:
                    print(Fore.RED + f"[!] {module_name.title()} failed: {e}")
    else:
        # Sequential fallback for fast mode
        for module_name, config in parallel_modules.items():
            print(Fore.CYAN + f"[*] Running {module_name.title()}...")
            module_start_time = time.time()  # CHANGED: Use module-specific timer
    
            module_findings = call_module(
            config['func'],
            config['args'],
            client=client if config['use_client'] else None,
            module_name=module_name
            )
            findings.extend(module_findings)
    
            module_duration = time.time() - module_start_time  # CHANGED: Use module-specific timer
            print(Fore.GREEN + f"[+] {module_name.title()} completed in {module_duration:.2f}s")


    # ----------------- Wrap Up -----------------
    total_duration = time.time() - start_time  # Uses the original start_time from line ~160
    print(Fore.GREEN + Style.BRIGHT + f"\n[+] Scan completed in {total_duration:.2f} seconds.")

    print_summary(findings)

    # Save JSON if requested
    if args.json:
        save_json(findings, target, start_time, module_duration)


if __name__ == "__main__":
    main()