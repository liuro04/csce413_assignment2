from scapy.all import sniff, TCP, Raw, wrpcap
import os

# Create a list to store packets for the deliverable
captured_packets = []

def packet_handler(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 3306 or packet[TCP].sport == 3306):
        captured_packets.append(packet)
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Decode payload, ignoring non-printable bytes
            decoded_payload = "".join([chr(b) if 32 <= b < 127 else "." for b in payload])
            
            # Look for SQL or Flags
            if "SELECT" in decoded_payload:
                print(f"[!] SQL Query Intercepted: {decoded_payload}")
            
            if "FLAG" in decoded_payload:
                print(f"\n[***] FLAG/TOKEN FOUND: {decoded_payload}\n")

print("[*] Monitoring MySQL traffic (Port 3306)...")
print("[*] Press Ctrl+C to stop and save the PCAP file.")

try:
    # Sniff traffic.
    # sniff(prn=packet_handler, store=0)
    # Change the filter to Redis
    sniff(filter="tcp port 6379", prn=packet_handler, store=0)
except KeyboardInterrupt:
    print("\n[*] Stopping capture...")
    if captured_packets:
        pcap_file = "mitm/mysql_traffic.pcap"
        wrpcap(pcap_file, captured_packets)
        print(f"[+] Evidence saved to {pcap_file}")
    else:
        print("[-] No packets captured.")