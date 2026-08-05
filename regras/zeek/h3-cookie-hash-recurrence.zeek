# H3 — Recorrencia de hash em code 10 por sessao
#
# Cookies legitimos recorrem em sessao DNS (mesmo cookie em
# multiplas queries). Cookie carregando payload steg tem hashes
# unicos por chunk. Razao (hashes unicos / total) > 0.5 em
# sessao com massa estatistica suficiente eh assinatura de
# payload embutido em cookie.
#
# Cobre: cenario hipotetico complementar a H2 (adversario mantem
# length nominal 8/24 mas varia conteudo).
#
# Caveat conhecido: snaplen reduzido na captura (e.g. 96 bytes
# do CIC) trunca opt_data, inflando artificialmente unicidade
# de hash. Mensurar e documentar, nao alterar threshold.

@load base/frameworks/notice

module EDNS0Detect;

export {
    redef enum Notice::Type += {
        H3_CookieHashHighUniqueness,
    };

    const MIN_EVENTS_FOR_H3: count = 5 &redef;
    const UNIQUENESS_RATIO_THRESHOLD: double = 0.5 &redef;
}

type CookieStats: record {
    total: count &default=0;
    unique_hashes: set[string] &default=set();
    fired: bool &default=F;
};

global cookie_stats_by_conn: table[string] of CookieStats;

event edns0_arbitrary_opt(c: connection, is_query: bool, code: count,
                          length: count, data: string)
    {
    if ( code != 10 )
        return;

    if ( c$uid !in cookie_stats_by_conn )
        cookie_stats_by_conn[c$uid] = CookieStats();

    local stats = cookie_stats_by_conn[c$uid];

    if ( stats$fired )
        return;

    stats$total += 1;
    local hash = sha256_hash(data);
    add stats$unique_hashes[hash];

    if ( stats$total < MIN_EVENTS_FOR_H3 )
        return;

    local ratio = (|stats$unique_hashes| + 0.0) / stats$total;

    if ( ratio > UNIQUENESS_RATIO_THRESHOLD )
        {
        stats$fired = T;
        NOTICE([$note=H3_CookieHashHighUniqueness,
                $conn=c,
                $msg=fmt("Cookie hash uniqueness ratio %.2f > %.2f over %d events",
                         ratio, UNIQUENESS_RATIO_THRESHOLD, stats$total),
                $sub=fmt("unique_hashes=%d total=%d",
                         |stats$unique_hashes|, stats$total),
                $identifier=c$uid]);
        }
    }

event connection_state_remove(c: connection)
    {
    if ( c$uid in cookie_stats_by_conn )
        delete cookie_stats_by_conn[c$uid];
    }
