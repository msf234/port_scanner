#!/usr/bin/env python3
"""
scanner.py — A fast, multi-threaded port scanner with service detection.
Author: Michael Fletez
Usage:
    python scanner.py <target> [options]

Examples:
    python scanner.py 192.168.1.1
    python scanner.py scanme.nmap.org -p 1-1000 -t 200 -o results.txt
    python scanner.py 10.0.0.1 --top-ports
"""

import socket
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
# Common service names for well-known ports
# ──────────────────────────────────────────────
COMMON_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    135: "RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker",
    3000: "Dev-Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6443: "Kubernetes", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 514, 587, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000,
    3306, 3389, 5432, 5900, 6379, 6443, 8080, 8443, 8888, 9200, 27017,
    # Additional common ports
    20, 67, 68, 119, 123, 137, 161, 194, 389, 636, 2375,
]

# ──────────────────────────────────────────────
# Color helpers (ANSI codes)
# ──────────────────────────────────────────────
class Color:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def colored(text, color):
    return f"{color}{text}{Color.RESET}"

# ──────────────────────────────────────────────
# Core scanning logic
# ──────────────────────────────────────────────
def resolve_target(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(colored(f"[ERROR] Cannot resolve host: {target}", Color.RED))
        sys.exit(1)

def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:80] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""

def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> dict | None:
    """
    Attempt TCP connection to a single port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = grab_banner(ip, port, timeout) if grab_banners else ""
            return {"port": port, "service": service, "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def parse_port_range(port_str: str) -> list[int]:
    """Parse port range string like '1-1000' or '80,443,22'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

# ──────────────────────────────────────────────
# Output formatting
# ──────────────────────────────────────────────
def print_header(target: str, ip: str, port_count: int, threads: int):
    print()
    print(colored("=" * 60, Color.CYAN))
    print(colored("  SCANNER.PY — Python Port Scanner", Color.BOLD))
    print(colored("=" * 60, Color.CYAN))
    print(f"  Target   : {colored(target, Color.YELLOW)}", end="")
    if target != ip:
        print(f"  ({ip})", end="")
    print()
    print(f"  Ports    : {port_count} ports")
    print(f"  Threads  : {threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(colored("=" * 60, Color.CYAN))
    print()

def print_result(result: dict):
    port_str  = colored(f"{result['port']:>5}/tcp", Color.GREEN)
    state_str = colored("OPEN", Color.GREEN)
    svc_str   = colored(result['service'], Color.CYAN)
    line = f"  {port_str}  {state_str}  {svc_str}"
    if result['banner']:
        line += f"\n           Banner: {result['banner']}"
    print(line)

def print_summary(open_ports: list[dict], start_time: datetime):
    elapsed = (datetime.now() - start_time).total_seconds()
    print()
    print(colored("=" * 60, Color.CYAN))
    print(f"  {colored(str(len(open_ports)), Color.GREEN)} open port(s) found in {elapsed:.2f}s")
    print(colored("=" * 60, Color.CYAN))
    print()

def save_results(filepath: str, target: str, ip: str, open_ports: list[dict]):
    with open(filepath, "w") as f:
        f.write(f"Scan Results — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Target: {target} ({ip})\n")
        f.write("-" * 40 + "\n")
        if open_ports:
            for r in open_ports:
                f.write(f"{r['port']:>5}/tcp  OPEN  {r['service']}\n")
                if r['banner']:
                    f.write(f"        Banner: {r['banner']}\n")
        else:
            f.write("No open ports found.\n")
    print(colored(f"\n  Results saved to: {filepath}", Color.YELLOW))

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="scanner.py — Fast multi-threaded TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range or list (e.g. '1-1000' or '22,80,443'). Default: 1-1024"
    )
    parser.add_argument(
        "--top-ports", action="store_true",
        help="Scan top 100 common ports (overrides -p)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-b", "--banners", action="store_true",
        help="Attempt to grab service banners (slower)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save results to a file"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Only print open ports, no header/summary"
    )

    args = parser.parse_args()

    # Resolve target
    ip = resolve_target(args.target)

    # Build port list
    if args.top_ports:
        ports = sorted(set(TOP_100_PORTS))
    else:
        try:
            ports = parse_port_range(args.ports)
        except ValueError:
            print(colored("[ERROR] Invalid port range format.", Color.RED))
            sys.exit(1)

    if not args.quiet:
        print_header(args.target, ip, len(ports), args.threads)

    # Scan
    open_ports = []
    lock = threading.Lock()
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, args.timeout, args.banners): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                with lock:
                    open_ports.append(result)
                    if not args.quiet:
                        print_result(result)

    # Sort by port number
    open_ports.sort(key=lambda r: r["port"])

    if not args.quiet:
        print_summary(open_ports, start_time)
    else:
        for r in open_ports:
            print(f"{r['port']}/tcp  {r['service']}")

    # Save output
    if args.output:
        save_results(args.output, args.target, ip, open_ports)

if __name__ == "__main__":
    main()
