# H4 — Variabilidade anomala de udp_payload_size por origem
#
# Clientes DNS legitimos negociam udp_payload_size no inicio
# da sessao e o mantem fixo (ou variam dentro de um conjunto
# pequeno de valores canonicos: 512, 1232, 1452, 4096). A
# tecnica T4 do EDNStego codifica payload variando esse campo
# a cada consulta, produzindo alta unicidade.
#
# Cobre: T4 (payload em udp_payload_size, header OPT pseudo-RR).
#
# Definicao:
#   ratio = |unique_ups_set| / total_events > UNIQUENESS_THRESHOLD
#   AND total_events >= MIN_EVENTS_FOR_H4
#
# Chave de agregacao: id.orig_h (source IP do cliente).
#
# Justificativa para nao usar c$uid: tráfego DNS UDP típico tem
# 1 query = 1 conexao Zeek = uid distinto. Agregar por uid daria
# max 2-4 events por agrupamento (query + response + retries),
# impossibilitando atingir MIN_EVENTS=5. Agregar por id.orig_h
# captura "tudo que esse cliente enviou ao resolver" — semantica
# adequada para DNS UDP onde "sessao" nao e nocao do protocolo.
#
# Calibragem (2026-05-18, baseline alpha-50k + T1-T6):
#   alpha (172.16.10.21): 92825 events agregados, 3 ups unicos
#                         ratio = 3/92825 = 3.2e-5 → NAO dispara (qualquer threshold)
#   T4-internal (10.0.1.20): aos 5 events iniciais: 3 ups unicos {1232,1337,4096}
#                            ratio = 3/5 = 0.6 → dispara
#   T3-internal (10.0.1.20): aos 5 events iniciais: 2 ups unicos {1232,4096}
#                            (cookie warmup + payload subsequente, sem variacao real)
#                            ratio = 2/5 = 0.4 → spurio se threshold=0.3
#   T5-internal (10.0.1.20): mesmo padrao de T3, ratio = 2/5 = 0.4 spurio
#   T1,T2,T6: total < MIN_EVENTS → nao avalia
#   weberblog, CIC: 0 OPT queries por orig_h legitimo no leg interno → nao dispara
#
# Threshold adotado: 0.5
#   - Separa T4 (genuino, 0.6) de T3/T5 (warmup espurio, 0.4)
#   - Preserva P=1.00 em todos os baselines benignos
#   - Recall de T4 = 1.0 (1/1 PCAP T4-internal)
# MIN_EVENTS_FOR_H4: 5 (suficiente para significancia estatistica;
# tambem filtra T1/T2/T6 que tem <5 OPT queries por design).

@load base/frameworks/notice

module EDNS0Detect;

export {
    redef enum Notice::Type += {
        H4_BufferVariability,
    };

    const MIN_EVENTS_FOR_H4: count = 5 &redef;
    const UNIQUENESS_RATIO_THRESHOLD_H4: double = 0.5 &redef;
}

type BufferStats: record {
    total: count &default=0;
    unique_ups: set[count] &default=set();
    fired: bool &default=F;
};

global ups_stats_by_orig: table[addr] of BufferStats;

event edns0_opt_record(c: connection, is_query: bool,
                       udp_payload_size: count,
                       extended_rcode: count, version: count,
                       flags: count, opt_count: count)
    {
    # Apenas queries — udp_payload_size do cliente. Responses
    # carregam o ups que o resolver oferece, valor canonico
    # do BIND9/Unbound, nao adversarial.
    if ( ! is_query )
        return;

    local orig = c$id$orig_h;

    if ( orig !in ups_stats_by_orig )
        ups_stats_by_orig[orig] = BufferStats();

    local stats = ups_stats_by_orig[orig];

    if ( stats$fired )
        return;

    stats$total += 1;
    add stats$unique_ups[udp_payload_size];

    if ( stats$total < MIN_EVENTS_FOR_H4 )
        return;

    local ratio = (|stats$unique_ups| + 0.0) / stats$total;

    if ( ratio > UNIQUENESS_RATIO_THRESHOLD_H4 )
        {
        stats$fired = T;
        NOTICE([$note=H4_BufferVariability,
                $conn=c,
                $msg=fmt("udp_payload_size variability ratio %.3f > %.2f over %d events from %s",
                         ratio, UNIQUENESS_RATIO_THRESHOLD_H4, stats$total, orig),
                $sub=fmt("unique_ups=%d total=%d values=%s",
                         |stats$unique_ups|, stats$total, cat(stats$unique_ups)),
                $identifier=cat("h4", orig)]);
        }
    }

# Liberar estado quando conn associada termina. Como agregamos
# por orig_h e nao por uid, esse cleanup so e parcial — orig_h
# pode ter outras conexoes ativas. Mantemos para sanidade mas
# nao e estritamente correto.
event connection_state_remove(c: connection)
    {
    # Nao deletar — orig_h pode ter outras conns. Em deploy
    # longo, periodicamente expirar via zeek_done ou timer.
    # Para offline (zeek -r), nao ha vazamento real.
    }
