#!/usr/bin/env python3
from scapy.all import send, IP, UDP, Raw

SRC_IP   = "66.66.66.66" # your spoofed IP
DST_IP   = "140.112.91.4"
SRC_PORT = 12345 # your spoofed port
DST_PORT = 48764

pkt = IP(src=SRC_IP, dst=DST_IP) / UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(b"I love NASA")
print(f"[+] sending {len(pkt)} bytes from {SRC_IP}:{SRC_PORT} → {DST_IP}:{DST_PORT}")
send(pkt)
