import csv
import nmap
import socket
import asyncio
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import sys
from typing import Dict
import argparse

# Optional dependencies
try:
    import netifaces
    HAVE_NETIFACES = True
except ImportError:
    HAVE_NETIFACES = False

try:
    from tqdm import tqdm
    HAVE_TQDM = True
except ImportError:
    HAVE_TQDM = False

# Add timeout constants before any function definitions
DEFAULT_PORT_TIMEOUT = 2
DEFAULT_HOST_TIMEOUT = 30
DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes max per host

# Simple progress bar fallback
class SimpleProgress:
    def __init__(self, total, desc, **kwargs):
        self.total = total
        self.current = 0
        self.desc = desc
    
    def update(self, n=1):
        self.current += n
        print(f"\rProgress: {self.current}/{self.total} {self.desc}", end='')
    
    def close(self):
        print()
    
    def clear(self):
        print('\r' + ' ' * 80 + '\r', end='')
    
    def refresh(self):
        self.update(0)
    
    def set_description(self, desc):
        self.desc = desc
        self.refresh()

class SimpleLogger:
    def __init__(self):
        pass
    
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

# Define VULNERABLE_PORTS at module level
VULNERABLE_PORTS = {
    '21': 'FTP',
    '22': 'SSH',
    '23': 'Telnet',
    '25': 'SMTP',
    '53': 'DNS',
    '80': 'HTTP',
    '110': 'POP3',
    '111': 'RPC',
    '135': 'Microsoft RPC',
    '139': 'NetBIOS',
    '143': 'IMAP',
    '443': 'HTTPS',
    '445': 'Microsoft-DS (SMB)',
    '993': 'IMAP SSL',
    '995': 'POP3 SSL',
    '1433': 'MSSQL',
    '1723': 'PPTP VPN',
    '3306': 'MySQL',
    '3389': 'RDP',
    '5432': 'PostgreSQL',
    '5900': 'VNC',
    '8080': 'HTTP Proxy',
    '8443': 'HTTPS Alt'
}

# Add hostname cache
hostname_cache: Dict[str, str] = {}

async def resolve_hostname(ip: str) -> str:
    """Asynchronously resolve hostname with caching"""
    if ip in hostname_cache:
        return hostname_cache[ip]
    
    try:
        # Run DNS resolution in a thread to avoid blocking
        loop = asyncio.get_event_loop()
        hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        resolved = hostname[0]
        hostname_cache[ip] = resolved
        return resolved
    except (socket.herror, socket.gaierror):
        hostname_cache[ip] = ip
        return ip

class ProgressLogger:
    def __init__(self, progress_bar):
        self.progress_bar = progress_bar

    def log(self, message):
        # Save cursor position, move to beginning of line, clear line, print message
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.progress_bar.clear()
        # Use carriage return to ensure clean line
        sys.stdout.write(f"\r[{timestamp}] {message}\n")
        sys.stdout.flush()
        # Refresh progress bar on its own line
        self.progress_bar.refresh()
    
    def update_description(self, desc):
        """Update progress bar description"""
        self.progress_bar.set_description(desc)
        self.progress_bar.refresh()

def log_message(message):
    # This will be replaced when we have a progress bar
    if hasattr(log_message, 'logger'):
        log_message.logger.log(message)
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

# Add port scanner function
async def check_port(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return port, result == 0
    except:
        return port, False

def try_connect(host, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        return result == 0
    except:
        return False

async def resolve_hostnames(hosts):
    """Resolve all hostnames concurrently"""
    tasks = [resolve_hostname(host) for host in hosts]
    return await asyncio.gather(*tasks)

def discover_hosts(subnet, scanner):
    """Perform initial host discovery and yield results as they come in"""
    log_message(f"Starting initial host discovery on {subnet}")
    scanner.scan(subnet, arguments="-sn")
    initial_hosts = scanner.all_hosts()
    
    # Create and run event loop for hostname resolution
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        # Resolve all hostnames
        hostnames = loop.run_until_complete(resolve_hostnames(initial_hosts))
        
        # Yield results with resolved hostnames
        for host, hostname in zip(initial_hosts, hostnames):
            log_message(f"🔍 Discovered host: {host} ({hostname})")
            yield host
    finally:
        loop.close()

def scan_ports_for_host(host, scanner, timeout=30):
    """Perform detailed port scan for a single host"""
    # Scan the specific ports we're interested in
    port_range = ",".join(VULNERABLE_PORTS.keys())
    scanner.scan(host, arguments=f"-sV -p{port_range} -T4 --host-timeout {timeout}s --min-rate 100")
    return scanner[host]

async def scan_port_async(host, port, scanner):
    """Async port scanning function"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            service_info = scanner[host]['tcp'][int(port)]
            log_message(f"🔓 Host {host}: Port {port} ({service_info.get('name', 'unknown')}) is OPEN")
            return port, True, service_info
        return port, False, {}
    except:
        return port, False, {}

def format_host_display(host, hostname):
    """Helper function for consistent host:hostname display"""
    return f"{host} ({hostname})"

def scan_single_host(host, hostname, scanner, writer, write_lock, total_hosts, current, timeout=DEFAULT_PORT_TIMEOUT):
    start_time = time.time()
    host_display = format_host_display(host, hostname)
    
    if hasattr(log_message, 'logger'):
        log_message.logger.update_description(f"Scanning {host_display}")
    
    log_message(f"🎯 Starting scan of host {host_display} [{current}/{total_hosts}]")
    
    try:
        # First perform the port scan with timeout
        host_info = scan_ports_for_host(host, scanner)
        ports_checked = []
        port_details = []
        
        # Now check each port that was found
        if 'tcp' in host_info:
            for port in VULNERABLE_PORTS.keys():
                if time.time() - start_time > DEFAULT_SCAN_TIMEOUT:
                    log_message(f"⚠️  Host {host_display} scan timed out after {DEFAULT_SCAN_TIMEOUT} seconds")
                    break
                    
                port_int = int(port)
                if port_int in host_info['tcp'] and host_info['tcp'][port_int]['state'] == 'open':
                    service_info = host_info['tcp'][port_int]
                    service_name = service_info.get('name', 'unknown')
                    service_version = service_info.get('version', 'unknown')
                    service_product = service_info.get('product', 'unknown')
                    
                    ports_checked.append(port)
                    
                    # Enhanced port information logging
                    log_message(
                        f"🔓 Host {host_display}: "
                        f"Port {port} ({service_name}) is OPEN\n"
                        f"   └─ Product: {service_product}\n"
                        f"   └─ Version: {service_version}"
                    )
                    
                    # Try to connect to verify accessibility
                    state = 'Accessible' if try_connect(host, port, timeout) else 'Inaccessible'
                    port_details.append({
                        'port': port,
                        'service': service_name,
                        'product': service_product,
                        'version': service_version,
                        'state': state
                    })

        # Report findings for this host
        log_message(f"📊 Host {host_display}: Found {len(ports_checked)} open ports")

        # Write results for this host immediately with enhanced details
        with write_lock:
            writer.writerow([
                host,
                hostname,
                len(ports_checked),
                ' | '.join([
                    f"{p['port']}({p['service']}/{p['product']} {p['version']}) - {p['state']}"
                    for p in port_details
                ]) if port_details else 'No open ports'
            ])
        
        return len(ports_checked), port_details
    except Exception as e:
        log_message(f"❌ Error scanning host {host_display}: {str(e)}")
        return 0, []

def get_default_subnet():
    """Detect default interface and subnet with fallback"""
    if not HAVE_NETIFACES:
        return None
        
    try:
        # Get default gateway interface
        default_gateway = netifaces.gateways()['default']
        if not default_gateway or not default_gateway.get(netifaces.AF_INET):
            return None
            
        default_interface = default_gateway[netifaces.AF_INET][1]
        
        # Get interface addresses
        addrs = netifaces.ifaddresses(default_interface)
        if netifaces.AF_INET not in addrs:
            return None
            
        # Get IP address and netmask
        ip = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0]['netmask']
        
        # Convert to CIDR notation
        import ipaddress
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        
        return str(network)
    except Exception as e:
        log_message(f"Warning: Could not detect default subnet: {e}")
        return None

def parse_arguments():
    """Parse command line arguments"""
    default_subnet = get_default_subnet()
    default_subnet_msg = f" (default: {default_subnet})" if default_subnet else ""
    
    parser = argparse.ArgumentParser(
        description="""
Network port scanner with service detection
-----------------------------------------
Scans one or more subnets for open ports and running services.
Outputs results to scan_results.csv in the current directory.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Scan default subnet
    python3 scan.py

    # Scan a single subnet
    python3 scan.py -s 192.168.1.0/24

    # Scan multiple subnets
    python3 scan.py -s 192.168.1.0/24 -s 10.0.0.0/24 -s 172.16.0.0/24

    # Show this help message
    python3 scan.py --help
        """
    )
    
    parser.add_argument(
        '-s', '--subnet',
        action='append',
        help=f'Subnet to scan (CIDR notation, e.g., 192.168.1.0/24). Can be specified multiple times.{default_subnet_msg}'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=DEFAULT_PORT_TIMEOUT,
        help=f'Timeout in seconds for individual port checks (default: {DEFAULT_PORT_TIMEOUT})'
    )
    
    parser.add_argument(
        '--host-timeout',
        type=int,
        default=DEFAULT_HOST_TIMEOUT,
        help=f'Maximum time in seconds to spend scanning each host (default: {DEFAULT_HOST_TIMEOUT})'
    )
    
    args = parser.parse_args()
    
    # Use default subnet if none provided
    if not args.subnet and default_subnet:
        args.subnet = [default_subnet]
        log_message(f"No subnet specified, using default: {default_subnet}")
    elif not args.subnet:
        parser.print_help()
        sys.exit(0)
        
    return args

def create_progress_bar(total, desc, **kwargs):
    """Create appropriate progress bar based on available modules"""
    if HAVE_TQDM:
        return tqdm(total=total, desc=desc, **kwargs)
    return SimpleProgress(total=total, desc=desc)

def main():
    # Show dependency warnings
    if not HAVE_NETIFACES:
        print("Warning: netifaces module not found. Automatic subnet detection disabled.")
        print("Install with: pip install netifaces")
        print()
    
    if not HAVE_TQDM:
        print("Warning: tqdm module not found. Using simple progress display.")
        print("Install with: pip install tqdm")
        print()

    args = parse_arguments()
    start_time = time.time()
    total_ports_found = 0
    hosts_with_open_ports = 0
    
    csv_file = "scan_results.csv"
    subnets = args.subnet

    # Validate subnets
    for subnet in subnets:
        if '/' not in subnet:
            log_message(f"❌ Error: Invalid subnet format '{subnet}'. Must be in CIDR notation (e.g., 192.168.1.0/24)")
            return
    
    log_message(f"🎯 Starting scan of {len(subnets)} subnet(s)")
    
    write_lock = Lock()
    
    with open(csv_file, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "Host IP",
            "Hostname",
            "Open Ports Count",
            "Port Details (Port, Service/Product, Version, State)"
        ])

        for subnet in subnets:
            log_message(f"Starting scan of subnet: {subnet}")
            
            try:
                scanner = nmap.PortScanner()
                
                # First discover hosts
                hosts = list(discover_hosts(subnet, scanner))
                total_hosts = len(hosts)
                
                if total_hosts == 0:
                    log_message(f"❌ No hosts found in subnet {subnet}")
                    continue
                    
                log_message(f"✨ Found {total_hosts} hosts in subnet {subnet}")
                
                # Now scan ports for each host
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = []
                    
                    # Use appropriate progress bar
                    with create_progress_bar(
                            total=total_hosts,
                            desc="Initializing scan...",
                            unit="host",
                            dynamic_ncols=True,
                            position=0,
                            leave=True,
                            ascii=True,
                            ncols=80,
                            miniters=1
                    ) as pbar:
                        
                        # Create appropriate logger
                        log_message.logger = SimpleLogger() if not HAVE_TQDM else ProgressLogger(pbar)
                        
                        for i, host in enumerate(hosts):
                            future = executor.submit(
                                scan_single_host,
                                host,
                                hostname_cache.get(host, 'Unknown'),
                                scanner,
                                writer,
                                write_lock,
                                total_hosts,
                                i+1,
                                args.timeout  # Pass timeout from arguments
                            )
                            future.add_done_callback(lambda _: pbar.update(1))
                            futures.append(future)
                        
                        for future in as_completed(futures):
                            try:
                                ports_count, _ = future.result()
                                if ports_count > 0:
                                    hosts_with_open_ports += 1
                                    total_ports_found += ports_count
                            except Exception as e:
                                log_message(f"❌ Error in scan: {str(e)}")

                    # Clear progress bar attributes after completion
                    delattr(log_message, 'logger')

                # After all scans complete, show summary
                print("\n") # Add extra newline for cleaner output
                end_time = time.time()
                runtime = end_time - start_time
                log_message("📋 Scan Summary:")
                log_message(f"⏱️ Total runtime: {runtime:.2f} seconds")
                log_message(f"🖥️ Total hosts scanned: {total_hosts}")
                log_message(f"🔓 Hosts with open ports: {hosts_with_open_ports}")
                log_message(f"🎯 Total open ports found: {total_ports_found}")
                
            except Exception as e:
                log_message(f"Error scanning subnet {subnet}: {e}")
                continue

if __name__ == "__main__":
    main()