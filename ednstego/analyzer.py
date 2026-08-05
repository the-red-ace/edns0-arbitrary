#!/usr/bin/env python3
"""
EDNStego Analyzer — Analisador de entropia e anomalias em tráfego EDNS0.
Usado para validar detecção e gerar métricas para o artigo.
"""

import pyshark
import math
import json
import csv
import sys
from collections import Counter, defaultdict


def shannon_entropy(data: bytes) -> float:
    """Calcular entropia de Shannon"""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )


def analyze_pcap(pcap_file: str) -> dict:
    """Analisar PCAP completo em busca de anomalias EDNS0"""
    cap = pyshark.FileCapture(pcap_file, display_filter='dns')

    results = {
        'file': pcap_file,
        'total_dns_packets': 0,
        'edns0_packets': 0,
        'edns0_percentage': 0.0,
        'avg_packet_size': 0,
        'opt_codes_seen': {},
        'experimental_opt_count': 0,
        'padding_with_data_count': 0,
        'cookie_anomaly_count': 0,
        'buffer_sizes': [],
        'entropy_scores': [],
        'per_source': {},
    }

    total_size = 0

    for pkt in cap:
        results['total_dns_packets'] += 1

        try:
            src_ip = pkt.ip.src
            pkt_size = int(pkt.length)
            total_size += pkt_size

            if src_ip not in results['per_source']:
                results['per_source'][src_ip] = {
                    'queries': 0, 'edns0': 0, 'anomalies': 0
                }
            results['per_source'][src_ip]['queries'] += 1

            # Verificar presença de EDNS0
            if hasattr(pkt, 'dns'):
                dns_layer = pkt.dns

                # Checar EDNS0 OPT RR
                if hasattr(dns_layer, 'opt'):
                    results['edns0_packets'] += 1
                    results['per_source'][src_ip]['edns0'] += 1

                # Checar campos adicionais que indicam EDNS0
                if hasattr(dns_layer, 'resp_type') and str(getattr(dns_layer, 'resp_type', '')) == '41':
                    results['edns0_packets'] += 1

                # Buffer size do OPT RR
                if hasattr(dns_layer, 'rr_udp_payload_size'):
                    buf_size = int(dns_layer.rr_udp_payload_size)
                    results['buffer_sizes'].append(buf_size)

                    # Detectar buffer sizes anômalos
                    if buf_size not in [512, 1232, 1452, 4096]:
                        results['per_source'][src_ip]['anomalies'] += 1

        except AttributeError:
            continue
        except Exception as e:
            continue

    cap.close()

    if results['total_dns_packets'] > 0:
        results['edns0_percentage'] = (
            results['edns0_packets'] / results['total_dns_packets'] * 100
        )
        results['avg_packet_size'] = total_size / results['total_dns_packets']

    # Calcular estatísticas de buffer size
    if results['buffer_sizes']:
        results['buffer_size_stats'] = {
            'min': min(results['buffer_sizes']),
            'max': max(results['buffer_sizes']),
            'mean': sum(results['buffer_sizes']) / len(results['buffer_sizes']),
            'unique_values': len(set(results['buffer_sizes'])),
            'distribution': dict(Counter(results['buffer_sizes']).most_common(10)),
        }

    return results


def compare_baseline_vs_attack(baseline_pcap: str, attack_pcap: str):
    """Comparar métricas de baseline vs ataque"""
    baseline = analyze_pcap(baseline_pcap)
    attack = analyze_pcap(attack_pcap)

    print(f"\n{'=' * 60}")
    print(f"COMPARACAO: Baseline vs Ataque")
    print(f"{'=' * 60}")
    print(f"{'Metrica':<35} {'Baseline':>10} {'Ataque':>10}")
    print(f"{'-' * 60}")
    print(f"{'Total DNS packets':<35} "
          f"{baseline['total_dns_packets']:>10} "
          f"{attack['total_dns_packets']:>10}")
    print(f"{'EDNS0 packets':<35} "
          f"{baseline['edns0_packets']:>10} "
          f"{attack['edns0_packets']:>10}")
    print(f"{'EDNS0 %':<35} "
          f"{baseline['edns0_percentage']:>9.1f}% "
          f"{attack['edns0_percentage']:>9.1f}%")
    print(f"{'Avg packet size':<35} "
          f"{baseline['avg_packet_size']:>9.0f}B "
          f"{attack['avg_packet_size']:>9.0f}B")
    print(f"{'Experimental OPT options':<35} "
          f"{baseline['experimental_opt_count']:>10} "
          f"{attack['experimental_opt_count']:>10}")
    print(f"{'Padding with data':<35} "
          f"{baseline['padding_with_data_count']:>10} "
          f"{attack['padding_with_data_count']:>10}")

    # Fontes com anomalias
    print(f"\n{'=' * 60}")
    print("FONTES COM ANOMALIAS (ataque):")
    print(f"{'=' * 60}")
    for ip, stats in sorted(attack['per_source'].items(),
                             key=lambda x: x[1]['anomalies'],
                             reverse=True):
        if stats['anomalies'] > 0:
            print(f"  {ip}: {stats['queries']} queries, "
                  f"{stats['edns0']} EDNS0, "
                  f"{stats['anomalies']} anomalias")

    print(f"{'=' * 60}")

    return baseline, attack


def export_csv(results: dict, output_file: str):
    """Exportar resultados para CSV"""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['source_ip', 'queries', 'edns0_count', 'anomalies'])
        for ip, stats in results['per_source'].items():
            writer.writerow([ip, stats['queries'],
                            stats['edns0'], stats['anomalies']])
    print(f"CSV exportado: {output_file}")


if __name__ == '__main__':
    if len(sys.argv) == 2:
        results = analyze_pcap(sys.argv[1])
        # Remove non-serializable items
        output = {k: v for k, v in results.items()
                  if k != 'buffer_sizes'}
        print(json.dumps(output, indent=2, default=str))
    elif len(sys.argv) == 3:
        compare_baseline_vs_attack(sys.argv[1], sys.argv[2])
    else:
        print("Uso: python3 analyzer.py <pcap>")
        print("     python3 analyzer.py <baseline.pcap> <attack.pcap>")
