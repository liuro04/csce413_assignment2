#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import time
import struct
import subprocess
from scapy.all import sniff, TCP

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    # TODO: Use iptables/nftables to allow access to protected_port.
    # logging.info("TODO: Open firewall for port %s", protected_port)
    print(f"[!] Sequence correct! Opening port {protected_port} for {src_ip}")
subprocess.run(["iptables", "-I", "INPUT", "1", "-s", src_ip, "-p", "tcp", "--dport", str(protected_port), "-j", "ACCEPT"], check=True)
def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    # TODO: Remove firewall rules for protected_port.
    # logging.info("TODO: Close firewall for port %s", protected_port)
    os.system(f"iptables -D INPUT -s {src_ip} -p tcp --dport {protected_port} -j ACCEPT")


def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # TODO: Create UDP or TCP listeners for each knock port.
    # TODO: Track each source IP and its progress through the sequence.
    # TODO: Enforce timing window per sequence.
    # TODO: On correct sequence, call open_protected_port().
    # TODO: On incorrect sequence, reset progress.
    # client_states = {}
    
    # # Create a raw socket to sniff TCP packets
    # sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # print(f"[*] Monitoring for sequence: {sequence}")

    # while True:
    #     raw_packet, addr = sniffer.recvfrom(65535)
    #     src_ip = addr[0]
        
    #     # TCP header starts after the 20-byte IP header
    #     # Destination port is at bytes 2-4 of the TCP header (offset 22 total)
    #     dest_port = struct.unpack('!H', raw_packet[22:24])[0]

    #     if dest_port in sequence:
    #         now = time.time()
    #         state = client_states.get(src_ip, {'index': 0, 'last_knock': now})

    #         # Check timing window
    #         if now - state['last_knock'] > window_seconds:
    #             state = {'index': 0, 'last_knock': now}

    #         # Check if knock is the next in sequence
    #         if dest_port == sequence[state['index']]:
    #             state['index'] += 1
    #             state['last_knock'] = now
    #             print(f"[*] {src_ip}: Correct knock {state['index']}/{len(sequence)}")
                
    #             if state['index'] == len(sequence):
    #                 open_protected_port(src_ip, protected_port)
    #                 del client_states[src_ip] # Reset
    #             else:
    #                 client_states[src_ip] = state
    #         else:
    #             client_states[src_ip] = {'index': 0, 'last_knock': now} # Reset on wrong port
    logging.info(f"[*] Monitoring for sequence {sequence} to unlock port {protected_port}")

    def packet_callback(pkt):
        if TCP in pkt:
            src_ip = pkt[0][1].src
            dest_port = pkt[TCP].dport
            
            if dest_port in sequence:
                now = time.time()
                state = client_states.get(src_ip, {'index': 0, 'last_knock': now})

                # Check if the sequence window has timed out
                if now - state['last_knock'] > window_seconds:
                    logging.info(f"[*] {src_ip}: Sequence timed out. Resetting.")
                    state = {'index': 0, 'last_knock': now}

                # Verify if this is the expected next port in the sequence
                if dest_port == sequence[state['index']]:
                    state['index'] += 1
                    state['last_knock'] = now
                    logging.info(f"[*] {src_ip}: Correct knock {state['index']}/{len(sequence)}")
                    
                    if state['index'] == len(sequence):
                        open_protected_port(src_ip, protected_port)
                        client_states[src_ip] = {'index': 0, 'last_knock': now} # Reset after success
                    else:
                        client_states[src_ip] = state
                else:
                    # Wrong port in sequence: Reset progress for this IP
                    logging.warning(f"[*] {src_ip}: Wrong port {dest_port}. Sequence reset.")
                    client_states[src_ip] = {'index': 0, 'last_knock': now}

    # Start sniffing (requires root/privileged permissions)
    sniff(filter="tcp", prn=packet_callback, store=0)


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def setup_firewall():
    logging.info(f"[*] Locking Port {PROTECTED_PORT}...")
    # Drop traffic to 2222. -I inserts it at the top.
subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(protected_port), "-j", "DROP"], check=False)
def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    setup_firewall()

    try:
        listen_for_knocks(sequence, args.window, args.protected_port)
    except KeyboardInterrupt:
        logging.info("[*] Server shutting down.")

if __name__ == "__main__":
    main()
