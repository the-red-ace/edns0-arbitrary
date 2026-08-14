# Handler script-land do plugin Spicy edns0-arbitrary.
# 1 linha de log por opcao EDNS encontrada — independente do codigo.
#
# ADR-5 compliance: opt_data NUNCA e logado em forma reversivel.
# Apenas SHA-256 do conteudo (identidade entre transacoes sem
# expor bytes) e length (para analise heuristica).

@load base/protocols/conn

# Evento global emitido pelo plugin Spicy.
# Recebe data: string (bytes brutos) — usado APENAS para hash,
# nunca logado em forma reversivel.
global edns0_arbitrary_opt: event(c: connection,
                                  is_query: bool,
                                  code: count,
                                  length: count,
                                  data: string);

# Evento por pseudo-RR OPT (usado pela heuristica H4). Exposto pelo
# mapeamento .evt a partir da unit ResourceRecord quando rtype==41.
global edns0_opt_record: event(c: connection,
                               is_query: bool,
                               udp_payload_size: count,
                               extended_rcode: count,
                               version: count,
                               flags: count,
                               opt_count: count);

module EDNS0Arbitrary;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:              time     &log;
        uid:             string   &log;
        id:              conn_id  &log;
        is_query:        bool     &log;
        opt_code:        count    &log;
        opt_length:      count    &log;
        opt_data_sha256: string   &log;
    };
}

event zeek_init() &priority=5 {
    Log::create_stream(LOG, [$columns=Info, $path="edns0_arbitrary"]);
}

event edns0_arbitrary_opt(c: connection, is_query: bool, code: count,
                          length: count, data: string) {
    local rec: Info = [
        $ts              = network_time(),
        $uid             = c$uid,
        $id              = c$id,
        $is_query        = is_query,
        $opt_code        = code,
        $opt_length      = length,
        $opt_data_sha256 = sha256_hash(data)
    ];
    Log::write(LOG, rec);
}
