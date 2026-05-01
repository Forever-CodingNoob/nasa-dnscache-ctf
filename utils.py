from enum import IntEnum
import socket
from typing import Optional, Any

class RecordType(IntEnum):
    A   = 1
    TXT = 2

class ResponseCode(IntEnum):
    NOERROR  = 0
    NXDOMAIN = 1
    NODATA   = 2

QR_MASK       = 0b10000000  # 1 bit  for query/response: 0=query, 1=response
TYPE_MASK     = 0b01110000  # 3 bits for the record type (qtype): 1=A, 2=TXT
RCODE_MASK    = 0b00001111  # 4 bits for the response code (rcode): 0=NOERROR, 1=NXDOMAIN, 2=NODATA


def build_query_packet(
    tid: int,
    domain: str,
    qtype: RecordType
) -> bytes:
    """
    Build a minimal DNS‐style QUERY packet:
      - 2 bytes: transaction ID (0–65535)
      - 1 byte: 0x00 | qtype
        - MSB: 0 (indicating a QUERY)
        - middle 3 bits: queried record type (qtype): 1=A, 2=TXT
        - lower 4 bits: response code (rcode): 0=NOERROR, 1=NXDOMAIN, 2=NODATA
      - domain name UTF-8 + null terminator
    """
    if not (0 <= tid <= 65535):
        raise ValueError("TID must be 0–65535")
    kind: int = 0 << 7 | int(qtype) << 4 # MSB=0 for query
    packet: bytes = tid.to_bytes(2, 'big', signed=False) \
                    + kind.to_bytes(1, 'big', signed=False) \
                    + domain.encode('utf-8') + b'\x00'
    return packet

def build_response_packet(
    tid: int,
    domain: str,
    qtype: RecordType,
    rcode: ResponseCode,
    answer: str, ttl: int,
    auth_ip: Optional[str] = None,
) -> bytes:
    """
    Build a minimal DNS‐style RESPONSE packet:
      - 2 bytes: transaction ID (0–65535)
      - 1 byte: 0x80 | qtype
        - MSB: 1 (indicating a RESPONSE)
        - middle 3 bits: queried record type (qtype): 1=A, 2=TXT
        - lower 4 bits: response code (rcode): 0=NOERROR, 1=NXDOMAIN, 2=NODATA
      - domain name UTF-8 + null terminator
      - 4 bytes: TTL (unsigned 32-bit network order)
      - payload: (answer)
         * A: 4 bytes of IPv4
         * TXT: 1 byte length + UTF-8 text
      - optional 4 bytes: authoritative NS IPv4
    """
    if not (0 <= tid <= 65535):
        raise ValueError("TID must be 0–65535")
    if ttl < 0 or ttl > 0xFFFFFFFF:
        raise ValueError("TTL must fit in 32 bits")

    kind: int = 1 << 7 | int(qtype) << 4 | int(rcode) # MSB=1 for response
    packet: bytes = tid.to_bytes(2, 'big', signed=False) \
                    + kind.to_bytes(1, 'big', signed=False) \
                    + domain.encode('utf-8') + b'\x00' \
                    + ttl.to_bytes(4, 'big', signed=False)

    if rcode == ResponseCode.NOERROR:
        if qtype == RecordType.A:
            packet += socket.inet_aton(answer)
        elif qtype == RecordType.TXT:
            txt: bytes = answer.encode('utf-8')
            if len(txt) > 255:
                raise ValueError("TXT record too long")
            packet += len(txt).to_bytes(1, 'big', signed=False) + txt
        else:
            raise ValueError(f"Unknown record type {qtype}")

    if auth_ip:
        packet += socket.inet_aton(auth_ip)
    return packet


def parse_query_packet(packet: bytes) -> dict[str, Any]:
    """
    Parse a minimal DNS‐style QUERY packet back into its components:
      - Validates MSB of the third byte = 0
      - Extracts record type (qtype) from middle 3 bits of the third byte
      - Reads null-terminated domain
    Returns a dict with keys:
      'tid'      : int
      'domain'   : str
      'qtype'    : RecordType (basically int)
    """

    if len(packet) < 3:
        raise ValueError("Packet too short for QUERY")

    tid: int = int.from_bytes(packet[0:2], 'big', signed=False)
    kind: int = packet[2]

    if (kind & QR_MASK)>>7 != 0:
        raise ValueError("Not a QUERY packet (response bit set)")

    try:
        qtype: RecordType = RecordType((kind & TYPE_MASK) >> 4)
    except ValueError:
        raise ValueError(f"Unknown query type {(kind & TYPE_MASK) >> 4}")

    try:
        end: int = packet.index(b'\x00', 3)
    except ValueError:
        raise ValueError("QUERY packet missing null terminator for domain")
    domain: str = packet[3:end].decode('utf-8')

    return {'tid': tid, 'domain': domain, 'qtype': qtype}


def parse_response_packet(packet: bytes) -> dict[str, Any]:
    """
    Parse a minimal DNS‐style RESPONSE packet back into its components:
      - Validates MSB of the third byte = 1
      - Extracts record type (qtype) from middle 3 bits of the third byte
      - Extracts response code (rcode) from lower 4 bits of the third byte
      - Reads null-terminated domain
      - Parses payload (A or TXT) and optional auth_ip
    Returns a dict with keys:
      'tid'         : int
      'domain'      : str
      'qtype'       : RecordType (basically int)
      'rcode'       : ResponseCode
      'answer'      : str (IP string for A, text for TXT)
      'ttl'         : int
      'auth_ip'     : str or None
    """

    if len(packet) < 3:
        raise ValueError("Packet too short for RESPONSE")

    tid: int = int.from_bytes(packet[0:2], 'big', signed=False)
    kind: int = packet[2]
    pos: int = 3

    if (kind & QR_MASK)>>7 != 1:
        raise ValueError("Not a RESPONSE packet (query bit set)")

    try:
        qtype: RecordType = RecordType((kind & TYPE_MASK) >> 4)
    except ValueError:
        raise ValueError(f"Unknown record type {(kind & TYPE_MASK) >> 4}")

    try:
        rcode: ResponseCode = ResponseCode(kind & RCODE_MASK)
    except ValueError:
        raise ValueError(f"Unknown response code {kind & RCODE_MASK}")

    # parse domain
    try:
        end: int = packet.index(b'\x00', pos)
    except ValueError:
        raise ValueError("RESPONSE packet missing null terminator for domain")
    domain: str = packet[pos:end].decode('utf-8')
    pos = end + 1

    # parse ttl
    if len(packet) < pos + 4:
        raise ValueError("Missing TTL in RESPONSE")
    ttl: int = int.from_bytes(packet[pos:pos+4], 'big', signed=False)
    pos += 4

    # parse answer
    answer: str = ""
    if rcode == ResponseCode.NOERROR:
        if qtype == RecordType.A:
            if len(packet) < pos + 4:
                raise ValueError("Incomplete A record")
            answer = socket.inet_ntoa(packet[pos:pos+4])
            pos += 4
        elif qtype == RecordType.TXT:
            if len(packet) < pos + 1:
                raise ValueError("Incomplete TXT length")
            length: int = packet[pos]
            pos += 1
            if len(packet) < pos + length:
                raise ValueError("Incomplete TXT data")
            answer = packet[pos:pos+length].decode('utf-8')
            pos += length
        else:
            raise ValueError(f"Unknown record type {qtype}")

    # parse optional auth_ip
    auth_ip: Optional[str] = None
    if len(packet) >= pos + 4:
        auth_ip = socket.inet_ntoa(packet[pos:pos+4])

    return {
        'tid': tid,
        'domain': domain,
        'qtype': qtype,
        'rcode': rcode,
        'answer': answer,
        'ttl': ttl,
        'auth_ip': auth_ip
    }


# Example Usage
if __name__ == '__main__':
    # DNS query
    pkt1: bytes = build_query_packet(
        tid = 65533,
        domain = 'fatcat.net',
        qtype = RecordType.TXT
    )
    obj1: dict[str, Any] = parse_query_packet(pkt1)
    print(obj1)

    # DNS response (response code = NOERROR)
    pkt2: bytes = build_response_packet(
        tid = 65534,
        domain = 'fatcat.net',
        qtype = RecordType.A,
        rcode = ResponseCode.NOERROR,
        answer = "4.8.7.63",
        ttl = 86400,
        auth_ip="19.19.8.10"
    )
    obj2: dict[str, Any] = parse_response_packet(pkt2)
    print(obj2)

    # DNS response (response code = NXDOMAIN)
    pkt3: bytes = build_response_packet(
        tid = 65535,
        domain = 'fatcat.net',
        qtype = RecordType.A,
        rcode = ResponseCode.NXDOMAIN,
        answer = "",
        ttl = 86400,
        auth_ip="19.19.8.10"
    )
    obj3: dict[str, Any] = parse_response_packet(pkt3)
    print(obj3)
