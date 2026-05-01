#!/usr/bin/env python3
import socketserver
import re
import dns.message
import dns.query
import dns.rdatatype
import dns.exception
from utils import (
    parse_query_packet,
    build_response_packet,
    RecordType,
    ResponseCode
)
from secret import FLAG2

TARGET_DOMAIN = 'nasa.csie.org'
TARGET_SUBDOMAIN = r'team\d+'
MALICIOUS_IP = "11.4.5.14"

UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
RESPONSE_TIMEOUT = 3  # seconds
DEFAULT_TTL = 86400 # TTL = 1 day

class DNSForwarderHandler(socketserver.BaseRequestHandler):
    def setup(self):
        print(f"[+] Connection from {self.client_address[0]}:{self.client_address[1]}")

    def handle(self):
        data, sock = self.request
        client_address = self.client_address

        try:
            # Parse the incoming custom DNS query
            query = parse_query_packet(data)
            tid = query['tid']
            domain = query['domain']
            qtype = query['qtype']
        except Exception as e:
            print(f"[!] Failed to parse query from {client_address}: {e}")
            return

        print(f"[+] transaction id: {tid}")

        # Map custom RecordType to dnspython rdatatype
        if qtype == RecordType.A:
            rdtype = dns.rdatatype.A
        elif qtype == RecordType.TXT:
            rdtype = dns.rdatatype.TXT
        else:
            print(f"[!] Unsupported query type: {qtype.name}")
            return

        response_packet: bytes = b""

        # Check if the query is for the target domain
        subdomain, apex_domain = domain.rstrip('.').split('.', maxsplit=1)
        if apex_domain == TARGET_DOMAIN:
            rcode: ResponseCode = ResponseCode.NODATA
            answer: str = ""
            if qtype == RecordType.A:
                answer = MALICIOUS_IP
                rcode = ResponseCode.NOERROR
            elif qtype == RecordType.TXT and re.fullmatch(TARGET_SUBDOMAIN, subdomain):
                FLAG2.additional = subdomain
                answer = str(FLAG2)
                rcode = ResponseCode.NOERROR

            try:
                response_packet = build_response_packet(
                    tid=tid,
                    domain=domain,
                    qtype=qtype,
                    rcode=rcode,
                    answer=answer,
                    ttl=DEFAULT_TTL,
                    auth_ip=None  # Modify if authoritative IP is needed
                )
            except Exception as e:
                print(f"[!] Failed to build response packet: {e}")
                return
        else:
            # Create a standard DNS query
            dns_query = dns.message.make_query(domain, rdtype)
            try:
                # Send the query to the upstream DNS server
                response = dns.query.udp(dns_query, UPSTREAM_DNS, timeout=RESPONSE_TIMEOUT)
            except dns.exception.Timeout:
                print(f"[!] Timeout querying {UPSTREAM_DNS} for {domain}")
                return
            except Exception as e:
                print(f"[!] Error querying {UPSTREAM_DNS}: {e}")
                return

            if response.rcode() == dns.rcode.NXDOMAIN:
                print(f"[!] NXDOMAIN received for {domain}")
                try:
                    response_packet = build_response_packet(
                        tid=tid,
                        domain=domain,
                        qtype=qtype,
                        rcode=ResponseCode.NXDOMAIN,
                        answer='',
                        ttl=DEFAULT_TTL,
                        auth_ip=None
                    )
                except Exception as e:
                    print(f"[!] Failed to build response packet: {e}")
                    return
            else:
                # Extract the answer from the response
                answer = None
                for rrset in response.answer:
                    if rrset.rdtype == rdtype:
                        for rdata in rrset:
                            if rdtype == dns.rdatatype.A:
                                answer = rdata.address
                            elif rdtype == dns.rdatatype.TXT:
                                # rdata.strings is a tuple of byte strings
                                answer = ''.join(s.decode('utf-8') for s in rdata.strings)
                            break
                    if answer is not None:
                        break

                if answer is None:
                    print(f"[!] No answer found for {domain} with type {qtype.name}")
                    try:
                        response_packet = build_response_packet(
                            tid=tid,
                            domain=domain,
                            qtype=qtype,
                            rcode=ResponseCode.NODATA,
                            answer='',
                            ttl=DEFAULT_TTL,
                            auth_ip=None,
                        )
                    except Exception as e:
                        print(f"[!] Failed to build response packet: {e}")
                        return
                else:
                    # Build the custom response packet
                    try:
                        response_packet = build_response_packet(
                            tid=tid,
                            domain=domain,
                            qtype=qtype,
                            rcode=ResponseCode.NOERROR,
                            answer=answer,
                            ttl=DEFAULT_TTL,
                            auth_ip=None  # Modify if authoritative IP is needed
                        )
                    except Exception as e:
                        print(f"[!] Failed to build response packet: {e}")
                        return

        try:
            sock.sendto(response_packet, client_address)
            print(f"[+] Responded to {client_address} for {domain}")
        except Exception as e:
            print(f"[!] Failed to send response to {client_address}: {e}")


# Define the server class
class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53053  # Listen on localhost port 53
    with ThreadingUDPServer((HOST, PORT), DNSForwarderHandler) as server:
        print(f"[*] Malicious DNS Forwarder running on {HOST}:{PORT}, forwarding to {UPSTREAM_DNS}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Shutting down Malicious DNS Forwarder.")
            server.shutdown()
