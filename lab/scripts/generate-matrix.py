#!/usr/bin/env python3
"""
Gerar matriz T× × S× × D× a partir dos resultados coletados.
Exporta CSV e tabela formatada para o artigo.
"""

import json
import glob
import csv
from pathlib import Path

TECHNIQUES = ['t1', 't2', 't3', 't4', 't5', 't6']
SOLUTIONS = ['suricata', 'snort', 'paloalto', 'fortigate', 'pihole-zeek']
DIMENSIONS = ['d1_detection', 'd2_prevention', 'd3_fragmentation',
              'd4_volume_100', 'd4_volume_500', 'd4_volume_1000',
              'd5_compliance_delta']

RESULTS_DIR = Path.home() / 'edns0-lab' / 'results'

matrix = {}

for sol in SOLUTIONS:
    sol_dir = RESULTS_DIR / sol

    for tech in TECHNIQUES:
        key = f'{sol}_{tech}'

        # Procurar arquivos de resultado
        eve_files = sorted(glob.glob(str(sol_dir / f'{tech}_*_eve.json')))

        entry = {
            'd1_detection': 0,
            'd2_prevention': 0,
            'd3_fragmentation': 'N/A',
            'd4_volume_100': 0.0,
            'd4_volume_500': 0.0,
            'd4_volume_1000': 0.0,
            'd5_compliance_delta': 0.0,
        }

        # Analisar logs de alertas (Suricata eve.json)
        for eve_file in eve_files:
            try:
                with open(eve_file) as f:
                    for line in f:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            sig = event.get('alert', {}).get('signature', '')
                            if 'dns' in sig.lower() or 'edns' in sig.lower():
                                severity = event['alert'].get('severity', 0)
                                entry['d1_detection'] = max(
                                    entry['d1_detection'], severity)
            except (json.JSONDecodeError, FileNotFoundError):
                continue

        matrix[key] = entry

# Exportar CSV
output_file = RESULTS_DIR / 'matrix.csv'
with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)

    # Header
    writer.writerow(['Solucao', 'Tecnica'] + DIMENSIONS)

    # Data
    for key, vals in sorted(matrix.items()):
        sol, tech = key.rsplit('_', 1)
        row = [sol, tech] + [vals[d] for d in DIMENSIONS]
        writer.writerow(row)

print(f"Matriz exportada para: {output_file}")
print(f"Total de combinacoes: {len(matrix)}")

# Tabela formatada para o artigo
print(f"\n{'=' * 80}")
print(f"{'Solucao':<15} {'Tecnica':<8} {'D1':>4} {'D2':>4} {'D3':>6} "
      f"{'D4-100':>7} {'D4-500':>7} {'D4-1k':>7} {'D5':>6}")
print(f"{'-' * 80}")
for key, vals in sorted(matrix.items()):
    sol, tech = key.rsplit('_', 1)
    print(f"{sol:<15} {tech:<8} "
          f"{vals['d1_detection']:>4} "
          f"{vals['d2_prevention']:>4} "
          f"{str(vals['d3_fragmentation']):>6} "
          f"{vals['d4_volume_100']:>7.1f} "
          f"{vals['d4_volume_500']:>7.1f} "
          f"{vals['d4_volume_1000']:>7.1f} "
          f"{vals['d5_compliance_delta']:>6.1f}")
print(f"{'=' * 80}")
