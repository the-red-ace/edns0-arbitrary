#!/usr/bin/env python3
"""
Gerador de tráfego DNS legítimo para baseline.
Simula padrão realista de navegação corporativa.
"""

import dns.resolver
import random
import time
import argparse
import logging


def generate_baseline(resolver_ip, domains_file, duration, rate=10):
    """Gerar tráfego DNS legítimo.

    Args:
        resolver_ip: IP do resolver DNS
        domains_file: arquivo com lista de domínios (um por linha)
        duration: duração em segundos
        rate: queries por segundo (média)
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.timeout = 5
    resolver.lifetime = 5

    with open(domains_file) as f:
        domains = [line.strip() for line in f if line.strip()]

    end_time = time.time() + duration
    query_count = 0
    error_count = 0

    logging.info(f"Baseline: {len(domains)} dominios, "
                 f"{duration}s, ~{rate} qps")

    while time.time() < end_time:
        domain = random.choice(domains)

        # Distribuição realista de tipos de query
        qtype_weights = {'A': 60, 'AAAA': 20, 'MX': 5,
                         'TXT': 10, 'NS': 5}
        qtype = random.choices(
            list(qtype_weights.keys()),
            weights=list(qtype_weights.values())
        )[0]

        try:
            resolver.resolve(domain, qtype)
            query_count += 1
        except Exception:
            error_count += 1

        # Simular padrão realista (burst + pausa)
        if random.random() < 0.1:  # 10% chance de burst
            time.sleep(random.uniform(0.001, 0.01))
        else:
            time.sleep(1.0 / rate + random.uniform(-0.05, 0.05))

    logging.info(f"Baseline concluido: {query_count} queries OK, "
                 f"{error_count} erros, {duration}s")
    return query_count


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s')

    parser = argparse.ArgumentParser(
        description='Gerador de trafego DNS legitimo')
    parser.add_argument('--mode', default='baseline')
    parser.add_argument('--duration', type=int, default=300)
    parser.add_argument('--resolver', default='10.0.1.2')
    parser.add_argument('--domains-file',
                        default='data/tranco-top1000.txt')
    parser.add_argument('--rate', type=int, default=10)

    args = parser.parse_args()
    generate_baseline(args.resolver, args.domains_file,
                      args.duration, args.rate)
