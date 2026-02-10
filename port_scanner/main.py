#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """

    banner = "No banner"
    try:
        # TODO: Create a socket
        # TODO: Set timeout
        # TODO: Try to connect to target:port
        # TODO: Close the socket
        # TODO: Return True if connection successful
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    # Attempt to receive the banner (first 1024 bytes)
                    # We send a small newline to nudge some services to respond
                    s.sendall(b'\r\n') 
                    banner_bytes = s.recv(1024)
                    if banner_bytes:
                        banner = banner_bytes.decode(errors='ignore').strip()
                except:
                    # If we can't get a banner, we still know the port is open
                    banner = "Service detected (no banner)"
                
                return True, banner
            return False, None
        # pass  # Remove this and implement

    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, None


def scan_range(target, start_port, end_port, threads = 100):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance

    # for port in range(start_port, end_port + 1):
    #     # TODO: Scan this port
    #     # TODO: If open, add to open_ports list
    #     # TODO: Print progress (optional)
    #     is_open, banner = scan_port(target, port)
        
    #     if is_open:
    #         open_ports.append((port, banner))
    #         print(f"[+] Found open port: {port} | Service: {banner}")

    # return open_ports

    # Using ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Create a dictionary mapping the future object to the port number
        future_to_port = {executor.submit(scan_port, target, port): port for port in range(start_port, end_port + 1)}
        
        try:
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        open_ports.append((port, banner))
                        print(f"[+] Found open port: {port} | Service: {banner}")
                except Exception as e:
                    print(f" [!] Error scanning port {port}: {e}")
        except KeyboardInterrupt:
            print("\n[!] User interrupted scan. Shutting down threads...")
            executor.shutdown(wait=False)
            return open_ports

    return sorted(open_ports) # Sort so the output is in order


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    # TODO: Validate inputs
    # TODO: Call scan_range()
    # TODO: Display results

    # Example usage (you should improve this):
    # 1. Accept target IP/hostname and port range as arguments (Requirement 1.1.1)
    parser = argparse.ArgumentParser(description="Professional TCP Port Scanner")
    parser.add_argument("--target", required=True, help="Target IP address or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range to scan (e.g., 1-10000)")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads")
    
    args = parser.parse_args()

    # 2. Validate inputs and handle errors gracefully (Requirement 1.1.4)
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
        
        if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
            raise ValueError("Ports must be between 0 and 65535")
    except ValueError as e:
        print(f"Error: Invalid port range. {e}")
        sys.exit(1)

    # 3. Timing (Requirement 1.1.3)
    start_time = time.time()

    print(f"[*] Starting port scan on {args.target}")

    results = scan_range(args.target, start_port, end_port, args.threads)
    end_time = time.time()
    duration = end_time - start_time

    # 4. Display results showing state and timing (Requirement 1.1.3)
    print(f"\n[+] Scan complete in {duration:.2f} seconds")
    print(f"[+] Found {len(results)} open ports:")
    for port, banner in results:
        print(f"    Port {port}: OPEN | Banner: {banner}")


if __name__ == "__main__":
    main()
