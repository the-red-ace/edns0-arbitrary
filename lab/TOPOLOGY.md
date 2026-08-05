# Topologia do laboratório

Cinco máquinas virtuais sobre KVM/QEMU em Ubuntu 24.04, interligadas por duas bridges
Open vSwitch. A separação em dois segmentos (interno e externo ao resolvedor) é o que
permite medir a remoção de opções EDNS no encaminhamento pelo BIND9.

```
        br-internal (10.0.1.0/24)              br-external (10.0.3.0/24)
   ┌──────────────────────────────┐      ┌──────────────────────────────────┐
   │                              │      │                                  │
victim-linux ───            dns-resolver ──┐                    resolvedores públicos
10.0.1.20                  10.0.1.2       │                    Cloudflare / Google / Quad9
agente        ──[leg int.]──  BIND9       ├──[leg ext.]──  c2-server 10.0.3.100
EDNStego                   forward-only   │                    traffic-monitor 10.0.3.200
                           Zeek 8.1.2     │
                                          │
                                     fw-test (escuta passiva)
                              Suricata 6.0.10 + Snort 3.12.1.0
                          duas NICs alimentadas pelo espelhamento OVS
```

## Máquinas

| VM | Rede | IP | Função |
|---|---|---|---|
| victim-linux | br-internal | 10.0.1.20 | agente EDNStego, emite T1–T6 |
| dns-resolver | br-internal + br-external | 10.0.1.2 | BIND9 forward-only; roda o Zeek 8.1.2 |
| c2-server | br-external | 10.0.3.100 | servidor C2, decodifica o payload |
| traffic-monitor | br-external | 10.0.3.200 | coleta e armazenamento de PCAPs |
| fw-test | br-internal + br-external | espelho OVS | Suricata 6.0.10 e Snort 3.12.1.0 em escuta passiva |

## Pontos de captura

O espelhamento de portas do Open vSwitch fornece cópias passivas do tráfego em cada
bridge, capturadas via tcpdump em dois pontos:

- **leg interno** — entre victim-linux e dns-resolver, antes do encaminhamento. É onde
  as opções EDNS adversariais ainda estão intactas, inclusive códigos não-RFC.
- **leg externo** — entre dns-resolver e os resolvedores públicos, depois do
  encaminhamento. Comparar os dois legs quantifica quais opções o BIND9 remove.

Essa captura nos dois pontos é o que sustenta a Seção 8 do artigo: códigos não-RFC
(65001, 12, 13) desaparecem no leg externo, o que demonstra que a detecção precisa estar
posicionada no leg interno.

## Provisionamento

Os scripts em `lab/scripts/` criam as VMs e as redes; os playbooks em `lab/ansible/`
configuram cada host e executam a matriz de testes.

```bash
# criar redes OVS e VMs
lab/scripts/setup-host.sh
lab/scripts/create-all-vms.sh

# configurar o espelhamento de portas nas duas bridges
lab/scripts/setup-mirror-v2.sh

# rodar a matriz de testes (todas as técnicas contra todas as ferramentas)
lab/scripts/run-all-tests.sh
```

O inventário Ansible (`lab/ansible/inventory.ini`) usa o usuário `researcher` e uma chave
SSH em `~/.ssh/lab_key`, que não é distribuída neste repositório — gere a sua e ajuste o
caminho no inventário antes de rodar os playbooks.
