# edns0-arbitrary

Artefato do artigo **"EDNS0 como Vetor Adversarial: Lacunas de Visibilidade Empírica
em Ferramentas Populares de DPI e Detecção de Intrusão"**, aceito no SBSeg 2026.

O artigo mostra que Suricata, Snort e Zeek em configuração padrão não detectam canais
encobertos via opções EDNS0 — zero alertas contra seis técnicas adversariais. O artefato
contém o gerador EDNStego (técnicas T1–T6), o plugin Spicy que expõe as opções EDNS antes
invisíveis ao Zeek, e as heurísticas de detecção H1a–H4.

# Estrutura do readme.md

- `ednstego/` — gerador adversarial em Python. `agent.py` emite as consultas, `server.py`
  é o C2 que decodifica, `traffic_gen.py` gera o baseline benigno a partir da lista Tranco.
  `techniques/` tem um módulo por técnica (T1–T6, T3-variante, T4-variante nos 4 regimes).
- `plugin-spicy/` — o plugin Spicy em três arquivos (`edns0_arbitrary.spicy` parser,
  `edns0_arbitrary.evt` mapeamento, `edns0_arbitrary.zeek` handler), que enumera todas as
  opções do pseudo-RR OPT e as expõe ao script-land do Zeek. Inclui também
  `edns0-options.zeek`, o modo auxiliar da primeira etapa (limitado aos códigos 8/10/11 do
  BIF nativo), mantido para referência.
- `regras/zeek/` — heurísticas H1a–H4 mais o loader `edns0-detection.zeek`.
- `regras/suricata/` — regra H1a v3 e o script Lua de detecção de anomalia de bufsize.
- `lab/` — playbooks Ansible, scripts de provisionamento das cinco VMs e a topologia
  detalhada do laboratório em `lab/TOPOLOGY.md` (KVM + Open vSwitch).
- `corpora/` — hashes SHA-256 dos PCAPs. Todos os PCAPs de validação estão nos
  [Releases](https://github.com/the-red-ace/edns0-arbitrary/releases): os canônicos T1–T6
  e as variantes T3 e T4.

# Selos Considerados

Os selos considerados são: **Disponível**, **Funcional**, **Sustentável** e **Reprodutível**.

# Informações básicas

| Componente | Versão |
|---|---|
| Sistema operacional | Ubuntu 24.04 (VMs KVM/QEMU) |
| Python | 3.12 |
| Zeek | 8.1.2 (validado também em 8.2.1) |
| Spicy | embutido no Zeek 8.1+ (`spicyz`) |
| Suricata | 7.0.x (H1a); 6.0.10 (avaliação stock) |
| BIND9 | 9.18.x |
| Open vSwitch | 3.x |

O laboratório usa cinco VMs numa bridge OVS isolada, sem rota para a Internet. **A geração
de tráfego (agente + C2) foi desenhada para esse ambiente multi-VM.** Para reproduzir os
resultados de detecção numa única máquina, o caminho recomendado é rodar o Zeek e o
Suricata diretamente sobre os PCAPs (os das variantes estão nos Releases; os canônicos
T1–T6 podem ser regenerados no laboratório) — isso valida as mesmas reivindicações sem
depender da topologia completa. Os playbooks em `lab/` documentam o ambiente para quem
quiser replicá-lo.

# Dependências

Python, em ambiente virtual (o Ubuntu 24.04 bloqueia `pip` global por PEP 668):

```
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython scapy
```

Como alternativa via apt, sem venv: `sudo apt install python3-dnspython python3-scapy`.

Zeek 8.1+ com Spicy (https://zeek.org/get-zeek/); o pacote traz o compilador `spicyz`.
Suricata 7.0+ (`add-apt-repository ppa:oisf/suricata-stable`). Sem dependências de nuvem
ou hardware especial.

# Preocupações com segurança

O EDNStego envia consultas DNS com opções EDNS0 carregando payload arbitrário. **Deve ser
usado apenas em laboratório isolado.** O payload é um arquivo de teste neutro; nada
exfiltra dados reais do sistema. O `server.py` (C2) apenas decodifica e registra o que
recebe. Não há persistência nem modificação de arquivos do sistema.

# Instalação

```bash
git clone https://github.com/the-red-ace/edns0-arbitrary.git
cd edns0-arbitrary

python3 -m venv .venv
source .venv/bin/activate
pip install dnspython scapy

# compilar o plugin Spicy (gera edns0_arbitrary.hlto)
cd plugin-spicy
spicyz -o edns0_arbitrary.hlto edns0_arbitrary.spicy edns0_arbitrary.evt
cd ..

# verificar
zeek -N | grep -i spicy   # confirma que o Spicy está disponível
```

PCAPs das variantes nos [Releases](https://github.com/the-red-ace/edns0-arbitrary/releases):
`T3-variant-pcaps.zip` (50 PCAPs, H3) e `T4-variant-pcaps.zip` (200 PCAPs, H4).

# Teste mínimo

Confirma que o plugin compila e enumera uma opção EDNS não-padrão. Usa `dig` para gerar
uma query com opção Padding (código 12), sem depender do laboratório.

```bash
cd plugin-spicy
spicyz -o edns0_arbitrary.hlto edns0_arbitrary.spicy edns0_arbitrary.evt

# gerar uma query com opção EDNS código 12 (Padding) e capturar
dumpcap -i lo -w /tmp/smoke.pcap -f "udp port 53" &
dig +ednsopt=12:00 @127.0.0.1 example.com
sleep 1 && pkill dumpcap

# processar com o plugin
zeek -C -r /tmp/smoke.pcap edns0_arbitrary.hlto edns0_arbitrary.zeek
cat edns0_arbitrary.log
```

Saída esperada: uma linha com `opt_code=12`, `opt_length=1` e
`opt_data_sha256=6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`
(o SHA-256 do byte 0x00). O `dns.log` é gerado em paralelo pelo parser nativo, confirmando
a coexistência sem `replaces`.

# Experimentos

Todas as reivindicações rodam sobre PCAPs disponíveis nos
[Releases](https://github.com/the-red-ace/edns0-arbitrary/releases), e são reproduzíveis
numa única máquina, sem montar o laboratório. Baixe e extraia os três pacotes:

```bash
# canônicos T1–T6 (Reivindicações #1, #2, #4) e variantes (Reivindicação #3)
unzip canonical-T1-T6.zip     # -> canonical-T1-T6/T{1..6}-{internal,external}.pcap
unzip T3-variant-pcaps.zip    # -> T3-variant-pcaps/*.pcap
unzip T4-variant-pcaps.zip    # -> T4-variant-pcaps/r{1..4}/*.pcap

# verificar integridade
cd canonical-T1-T6 && sha256sum -c SHA256SUMS && cd ..
```

Compile o plugin uma vez antes:

```bash
cd plugin-spicy && spicyz -o edns0_arbitrary.hlto edns0_arbitrary.spicy edns0_arbitrary.evt && cd ..
```

## Reivindicação #1 — Zero detecções em configuração padrão (Tabela 2 do artigo)

Zeek stock não detecta nenhuma das seis técnicas.

```bash
for t in T1 T2 T3 T4 T5 T6; do
    zeek -C -r canonical-T1-T6/$t-internal.pcap local
    echo "$t: $(grep -c . notice.log 2>/dev/null || echo 0) alertas"; rm -f notice.log
done
# Esperado: 0 alertas em todas as técnicas
```

## Reivindicação #2 — Plugin expõe códigos antes invisíveis (Tabela 3 do artigo)

```bash
# Com o plugin: o código 12 (T2) aparece
zeek -C -r canonical-T1-T6/T2-internal.pcap plugin-spicy/edns0_arbitrary.hlto plugin-spicy/edns0_arbitrary.zeek
grep -c . edns0_arbitrary.log   # opções enumeradas

# Sem o plugin: o mesmo PCAP não mostra o código 12
zeek -C -r canonical-T1-T6/T2-internal.pcap
```

Contagens esperadas de opções por técnica (leg interno): T1=9, T2=9, T3=165, T4=11,
T5=43, T6=15.

## Reivindicação #3 — Heurísticas com P=1,00 e R=1,00 (Tabela 4 do artigo)

```bash
# H1a, H1b, H2 sobre os canônicos T1–T6
for t in T1 T2 T3 T4 T5 T6; do
    zeek -C -r canonical-T1-T6/$t-internal.pcap \
        plugin-spicy/edns0_arbitrary.hlto plugin-spicy/edns0_arbitrary.zeek \
        regras/zeek/edns0-detection.zeek
    echo "$t: $(grep -c . notice.log 2>/dev/null || echo 0) notices"; rm -f notice.log
done
# T1,T5 -> H1a; T2 -> H1b; T3,T6 -> H2; T4 -> H4

# H3 (corpus T3-variante) e H4 (corpus T4-variante) dos Releases
for pcap in T3-variant-pcaps/*.pcap; do
    zeek -C -r $pcap plugin-spicy/edns0_arbitrary.hlto plugin-spicy/edns0_arbitrary.zeek regras/zeek/edns0-detection.zeek
    grep -q H3 notice.log && echo "H3 ok: $pcap"; rm -f notice.log
done
for regime in r1 r2 r3 r4; do
    n=0
    for pcap in T4-variant-pcaps/$regime/*.pcap; do
        zeek -C -r $pcap plugin-spicy/edns0_arbitrary.hlto plugin-spicy/edns0_arbitrary.zeek regras/zeek/edns0-detection.zeek
        grep -q H4 notice.log && n=$((n+1)); rm -f notice.log
    done
    echo "regime $regime: $n/50"
done
# Esperado: r1=50, r2=0 (fora de escopo), r3=50, r4=50
```

## Reivindicação #4 — Teto de revocação do Suricata (Tabela 6 do artigo)

```bash
for t in T1 T2 T3 T4 T5 T6; do
    suricata -r canonical-T1-T6/$t-internal.pcap -S regras/suricata/h1a-codes-whitelist-v3.rules -l /tmp/suri/
    echo "$t: $(wc -l < /tmp/suri/fast.log) alertas"; rm -f /tmp/suri/fast.log
done
# Esperado: T1=1, T5=1, demais=0 (T6 perde o segundo código, limitação do artigo)
```

# LICENSE

MIT License. Texto completo em `LICENSE`.
