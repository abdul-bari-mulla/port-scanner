#!/usr/bin/env python3
"""
Advanced Port Scanner
A multi-threaded port scanner with service detection, banner grabbing, and multiple output formats
"""

import socket
import argparse
import sys
import threading
import json
import csv
from datetime import datetime
from queue import Queue
from typing import List, Dict
import ipaddress

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Common port to service mapping
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 1433: 'MSSQL', 139: 'NetBIOS', 161: 'SNMP',
    389: 'LDAP', 636: 'LDAPS', 873: 'Rsync', 1521: 'Oracle',
    2049: 'NFS', 2181: 'Zookeeper', 5000: 'Docker', 5672: 'RabbitMQ',
    6379: 'Redis', 8000: 'HTTP-Alt', 9200: 'Elasticsearch', 9300: 'Elasticsearch'
}


class PortScanner:
    def __init__(self, targets: List[str], ports: List[int], threads: int = 100, 
                 timeout: float = 1.0, grab_banner: bool = False, verbose: bool = False):
        self.targets = targets
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.grab_banner = grab_banner
        self.verbose = verbose
        self.results = {}
        self.queue = Queue()
        self.lock = threading.Lock()
        self.scan_start_time = None
        self.scan_end_time = None

    def resolve_target(self, target: str) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def grab_banner_from_port(self, ip: str, port: int) -> str:
        """Attempt to grab banner from service"""
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Try to receive banner
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else "No banner"
        except:
            return "No banner"

    def scan_port(self, ip: str, port: int) -> Dict:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner = None
                
                if self.grab_banner:
                    banner = self.grab_banner_from_port(ip, port)
                
                port_info = {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
                
                if self.verbose:
                    banner_info = f" - {banner}" if banner else ""
                    print(f"{Colors.GREEN}[+] {ip}:{port} OPEN - {service}{banner_info}{Colors.RESET}")
                
                return port_info
            return None
            
        except socket.error:
            return None

    def worker(self):
        """Worker thread for scanning ports"""
        while True:
            target, port = self.queue.get()
            if target is None:
                break
                
            result = self.scan_port(target, port)
            
            if result:
                with self.lock:
                    if target not in self.results:
                        self.results[target] = []
                    self.results[target].append(result)
            
            self.queue.task_done()

    def scan(self):
        """Main scanning function"""
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  Port Scanner{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        self.scan_start_time = datetime.now()
        
        # Resolve all targets
        resolved_targets = {}
        for target in self.targets:
            ip = self.resolve_target(target)
            if ip:
                resolved_targets[ip] = target
                print(f"{Colors.BLUE}[*] Target: {target} ({ip}){Colors.RESET}")
            else:
                print(f"{Colors.RED}[!] Could not resolve: {target}{Colors.RESET}")
        
        if not resolved_targets:
            print(f"{Colors.RED}[!] No valid targets to scan{Colors.RESET}")
            return
        
        print(f"{Colors.BLUE}[*] Ports to scan: {len(self.ports)}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Threads: {self.threads}{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Timeout: {self.timeout}s{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Banner grabbing: {'Enabled' if self.grab_banner else 'Disabled'}{Colors.RESET}\n")
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Add tasks to queue
        total_scans = 0
        for ip in resolved_targets.keys():
            for port in self.ports:
                self.queue.put((ip, port))
                total_scans += 1
        
        # Wait for all tasks to complete
        self.queue.join()
        
        # Stop workers
        for _ in range(self.threads):
            self.queue.put((None, None))
        
        for t in threads:
            t.join()
        
        self.scan_end_time = datetime.now()
        self.print_summary(resolved_targets)

    def print_summary(self, resolved_targets: Dict[str, str]):
        """Print scan summary"""
        duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  Scan Results{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        if not self.results:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.RESET}\n")
        else:
            for ip, original_target in resolved_targets.items():
                if ip in self.results:
                    print(f"{Colors.BOLD}{Colors.MAGENTA}Target: {original_target} ({ip}){Colors.RESET}")
                    print(f"{Colors.MAGENTA}{'-'*70}{Colors.RESET}")
                    
                    for port_info in sorted(self.results[ip], key=lambda x: x['port']):
                        port = port_info['port']
                        service = port_info['service']
                        banner = port_info.get('banner')
                        
                        print(f"  {Colors.GREEN}Port {port:5d}/tcp{Colors.RESET}  |  "
                              f"{Colors.CYAN}Service: {service:15s}{Colors.RESET}", end="")
                        
                        if banner and banner != "No banner":
                            print(f"  |  Banner: {banner[:50]}")
                        else:
                            print()
                    
                    print()
        
        print(f"{Colors.BLUE}[*] Scan completed in {duration:.2f} seconds{Colors.RESET}")
        print(f"{Colors.BLUE}[*] Total open ports: {sum(len(ports) for ports in self.results.values())}{Colors.RESET}\n")

    def save_results_json(self, filename: str):
        """Save results to JSON file"""
        output = {
            'scan_info': {
                'start_time': self.scan_start_time.isoformat(),
                'end_time': self.scan_end_time.isoformat(),
                'duration': (self.scan_end_time - self.scan_start_time).total_seconds(),
                'targets': self.targets,
                'ports_scanned': len(self.ports),
                'threads': self.threads
            },
            'results': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")

    def save_results_csv(self, filename: str):
        """Save results to CSV file"""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Port', 'State', 'Service', 'Banner'])
            
            for target, ports in self.results.items():
                for port_info in ports:
                    writer.writerow([
                        target,
                        port_info['port'],
                        port_info['state'],
                        port_info['service'],
                        port_info.get('banner', '')
                    ])
        
        print(f"{Colors.GREEN}[+] Results saved to {filename}{Colors.RESET}")


def parse_ports(port_string: str) -> List[int]:
    """Parse port string (e.g., '80,443,8000-8100')"""
    ports = []
    
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner with multi-threading and service detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 1-1000
  %(prog)s -t scanme.nmap.org,example.com -p 22,80,443
  %(prog)s -t 10.0.0.1 -p 1-65535 -T 200 -b -o results.json
  %(prog)s -t target.com --top-ports -v
        """
    )
    
    parser.add_argument('-t', '--targets', required=True,
                        help='Target IP addresses or hostnames (comma-separated)')
    parser.add_argument('-p', '--ports',
                        help='Ports to scan (e.g., 80,443,8000-8100)')
    parser.add_argument('--top-ports', action='store_true',
                        help='Scan top 100 common ports')
    parser.add_argument('-T', '--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('-b', '--banner', action='store_true',
                        help='Grab service banners')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (show results in real-time)')
    parser.add_argument('-o', '--output',
                        help='Save results to file (JSON or CSV based on extension)')
    
    args = parser.parse_args()
    
    # Parse targets
    targets = [t.strip() for t in args.targets.split(',')]
    
    # Parse ports - default to top ports if not specified
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(f"{Colors.RED}[!] Invalid port format{Colors.RESET}")
            sys.exit(1)
    else:
        # Default to top common ports (like nmap)
        ports = sorted(COMMON_PORTS.keys())
        if not args.top_ports:
            print(f"{Colors.YELLOW}[*] No ports specified, scanning top {len(ports)} common ports{Colors.RESET}")
    
    # Validate port range
    if any(p < 1 or p > 65535 for p in ports):
        print(f"{Colors.RED}[!] Ports must be between 1 and 65535{Colors.RESET}")
        sys.exit(1)
    
    # Create scanner and run
    try:
        scanner = PortScanner(
            targets=targets,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            grab_banner=args.banner,
            verbose=args.verbose
        )
        
        scanner.scan()
        
        # Save results if output file specified
        if args.output:
            if args.output.endswith('.json'):
                scanner.save_results_json(args.output)
            elif args.output.endswith('.csv'):
                scanner.save_results_csv(args.output)
            else:
                print(f"{Colors.YELLOW}[!] Unsupported output format. Use .json or .csv{Colors.RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()