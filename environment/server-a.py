#!/usr/bin/env python3
import time
import random
import socket
from typing import Any, Optional
from utils import (
    RecordType,
    ResponseCode,
    build_query_packet,
    build_response_packet,
    parse_query_packet,
    parse_response_packet
)
from secret import FLAG1

# ---------------------------
# Configuration for Network and forged (attacker-controlled) response
# ---------------------------
RESPONSE_TIMEOUT = 4  # seconds
DEFAULT_RESOLVER = "140.112.30.191"  # where we send queries by default (ws6.csie.ntu.edu.tw)

# ---------------------------
# Cache
# ---------------------------
# format: (domain, record_type) -> { 'data': <A or TXT record> or None, 'expiry': <timestamp> }
cache: dict[tuple[str, RecordType], dict[str, Any]] = {}

# ---------------------------
# Utility Functions
# ---------------------------
def cleanup_cache():
    """
    Flush expired cache entries.
    """
    global cache
    now = int(time.time())
    expired: list[Any] = [key for key, entry in cache.items() if entry["expiry"] <= now]
    for key in expired:
        del cache[key]

def process_query(domain: str, qtype: RecordType):
    """
    Process a DNS query:
     - If the domain is cached (and TTL valid), return the cached result.
     - Otherwise, send a DNS query.
    """
    global cache

    # --- check if cache hits ---
    cleanup_cache()
    if (domain, qtype) in cache:
        # --- cache hit ---
        entry: dict[str, Any] = cache[(domain, qtype)]
        ttl: int = entry['expiry'] - int(time.time())
        if entry['data'] is None:
            print(f"DNS Response: {qtype.name}=NXDOMAIN/NODATA TTL={ttl}")
        else:
            print(f"DNS Response: {qtype.name}={entry['data']} TTL={ttl}")
        return

    # --- cache miss ---
    # --- determine the apex (parent) domain and the resolver to query ---
    apex_domain: Optional[str] = domain.split('.', maxsplit=1)[-1]
    if apex_domain == "" or apex_domain == domain:
        apex_domain = None
    if apex_domain is not None \
            and (apex_domain, RecordType.A) in cache \
            and cache[(apex_domain, RecordType.A)]['data'] is not None:
        next_resolver: str = cache[(apex_domain, RecordType.A)]['data']
    else:
        next_resolver: str = DEFAULT_RESOLVER # resort to the default resolver

    # --- create UDP socket ---
    query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    query_socket.bind(("0.0.0.0", 0)) # bind to any available source port
    query_socket.settimeout(RESPONSE_TIMEOUT) # timeout = 10 seconds

    # --- build and send DNS query (via UDP) to port 53053 of the resolver ---
    listening_port: int = query_socket.getsockname()[1]
    print(f"Querying for the {qtype.name} record for domain {domain} on source port {listening_port} ...")

    transaction_id: int = random.randint(0, 255) # select a transaction id between 0 ~ 255

    query_packet: bytes = build_query_packet(
        tid=transaction_id,
        domain=domain,
        qtype=qtype
    )
    query_socket.sendto(query_packet, (next_resolver, 53053)) # send to port 53053 of the chosen resolver

    # --- wait for response ---
    response: dict[str, Any] = {}
    try:
        while True:
            packet, source_addr = query_socket.recvfrom(512) # type: bytes, str

            # in practice dns servers verify the source ip and port of the response to detect spoofed responses
            # but for simplicity, we do not check these information here
            # if source_addr != (next_resolver, 53053):
            #    print('WARNING: Received an invalid response packet (invalid source IP or port)')
            #    continue

            try:
                response = parse_response_packet(packet)
            except Exception:
                print('WARNING: Received an invalid response packet')
                continue

            if response['tid'] != transaction_id \
                    or response['qtype'] != qtype \
                    or response['domain'] != domain:
                print('WARNING: Received an invalid response packet')
                continue
            break
    except socket.timeout:
        print("DNS query TIMEOUT")
        return
    finally:
        query_socket.close()

    answer: str = response['answer']
    ttl: int = response['ttl']
    auth_ip: Optional[str] = response['auth_ip']

    # -- queried domain is non-existent (NXDOMAIN response)
    #    OR there is no record of the queried type (NODATA) --
    if response['rcode'] != ResponseCode.NOERROR:
        cache[(domain, qtype)] = {
            'data':    None,
            'expiry':  int(time.time()) + ttl
        }
        print(f"DNS Response: {qtype.name}=NXDOMAIN/NODATA TTL={ttl}")
        return

    # -- return FLAG1 if the A record of TARGET_DOMAIN in cache
    #    is poisoned with ATTACKER_CONTROLLED_IP ---
    if domain == 'www.google.com' and qtype == RecordType.A and answer == '11.4.5.14':
        print(f'Cache polluted successfully! Flag: {FLAG1}')

    cache[(domain, qtype)] = {
        'data':    answer,
        'expiry':  int(time.time()) + ttl
    }

    # -- return the response to client --
    if auth_ip is not None and apex_domain is not None:
        # might overwrite the existing A record for the authoritative nameserver
        # but we dont care as we assume auth_ip to be legit
        cache[(apex_domain, RecordType.A)] = {
            'data':    auth_ip,
            'expiry':  int(time.time()) + ttl
        }
        print(f"DNS Response: {qtype.name}={answer} Authoritative={auth_ip} TTL={ttl}")
    else:
        print(f"DNS Response: {qtype.name}={answer} TTL={ttl}")

# ---------------------------
# Main Function
# ---------------------------
def main():
    """
    Expect each TCP request to be a line of plaintext:
      "<domain> <record_type>"
    where record_type is "A" or "TXT".
    """
    print("------------------------------------------------------")
    print("| Welcome to the FATCAT DNS                          |")
    print("| We have the most secure DNS service of the world!  |")
    print("------------------------------------------------------")

    global cache
    # initialize the cache
    cache = {
        ('nasa.csie.org', RecordType.A): {
            'data': None, # NXDOMAIN
            'expiry':  999999999999999 # very long
        }
    }

    while True:
        query: str = input('Provide a query in the form "<domain> <record_type>": ').strip()
        if not query:
            break

        parts: list[str] = query.split()
        if len(parts) != 2:
            print('Invalid input!')
            continue

        domain: str = parts[0].rstrip('.')
        try:
            qtype = RecordType[parts[1].upper()]
        except KeyError:
            print('Unknown record type')
            continue

        process_query(domain, qtype)

    print('No input. Goodbye!')


# ---------------------------
# Entry Point
# ---------------------------
if __name__ == "__main__":
    main()
