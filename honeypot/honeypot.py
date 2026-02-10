#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import socket
import logging
import os
import time
from datetime import datetime

LOG_PATH = "/app/logs/honeypot.log"


def setup_logging():
    os.makedirs("/app/logs", exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()],
    )


def run_honeypot(port = 22):
    logger = logging.getLogger("Honeypot")
    logger.info("Honeypot starter template running.")
    logger.info("TODO: Implement protocol simulation, logging, and alerting.")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', port))
        server.listen(10)
        logger.info(f"Honeypot active and simulating SSH on port {port}")
    except Exception as e:
        logger.error(f"Failed to bind to port {port}: {e}")
        return

    while True:
        client_sock, addr = server.accept()
        src_ip, src_port = addr
        logger.info(f"INTRUSION DETECTED: Connection from {src_ip}:{src_port}")

        try:
            # 1. Send a convincing SSH banner
            # This makes the attacker think it's a real Ubuntu server
            client_sock.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")

            # 2. Receive the attacker's handshake/identification
            attacker_data = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if attacker_data:
                logger.info(f"Attacker Identification: {attacker_data}")

            # 3. Simulate a login prompt to bait credentials
            # Note: In raw sockets, we just log whatever they send next
            client_sock.send(b"Password: ")
            captured_payload = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if captured_payload:
                logger.warning(f"CAPTURED CREDENTIALS/COMMANDS from {src_ip}: {captured_payload}")

            # 4. Always reject and close
            client_sock.send(b"\r\nAccess denied.\r\n")
            
        except Exception as e:
            logger.error(f"Error handling connection from {src_ip}: {e}")
        finally:
            client_sock.close()
            logger.info(f"Connection with {src_ip} terminated.")


if __name__ == "__main__":
    setup_logging()
    run_honeypot()
