##! edns0-options.zeek - registra presença de opções EDNS0 em queries DNS
##! Contribuição da rodada v2 da pesquisa SBSeg 2026 EDNStego.
##!
##! Foco em VISIBILITY, não detection. Não decodifica payload —
##! apenas atesta que opções não-padrão chegaram a este ponto da rede.
##!
##! Limitação importante: o BIF do Zeek 8.1.2 só dispara eventos
##! dedicados para 4 codes específicos:
##!   8  (ECS, RFC 7871)              — dns_EDNS_ecs
##!   10 (COOKIE, RFC 7873)           — dns_EDNS_cookie       — T3
##!   11 (TCP Keepalive, RFC 7828)    — dns_EDNS_tcp_keepalive
##! Demais codes (12 Padding T2, 13 CHAIN T5, 65001 exp T1)
##! aparecem só como OPT pseudo-RR genérico em dns_EDNS_addl,
##! sem code/length individual. Documentado no relatório §5.

@load base/protocols/dns

# Por default Zeek 8.x define dns_skip_all_addl = T, o que descarta toda
# a seção additional incluindo o pseudo-RR EDNS — eventos dns_EDNS_* nunca
# disparam. Sobrescrever para que possamos observar opções EDNS0.
redef dns_skip_all_addl = F;

module EDNS0Options;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time   &log;
        uid:          string &log;
        id_orig_h:    addr   &log;
        id_resp_h:    addr   &log;
        query:        string &log &default="-";
        edns_event:   string &log;     # qual sub-evento disparou
        edns_code:    count  &log &default=0;
        edns_length:  count  &log &default=0;
        payload_size: count  &log &default=0;
    };

    global log_edns0_opts: event(rec: Info);
}

event zeek_init() &priority=5
    {
    Log::create_stream(EDNS0Options::LOG,
        [$columns=Info, $ev=log_edns0_opts, $path="edns0_opts"]);
    }

# OPT pseudo-RR genérico — sempre dispara para qualquer mensagem DNS com
# EDNS0. Marca presença mas não enumera opções individuais.
event dns_EDNS_addl(c: connection, msg: dns_msg, ans: dns_edns_additional)
    {
    local info: Info;
    info$ts           = network_time();
    info$uid          = c$uid;
    info$id_orig_h    = c$id$orig_h;
    info$id_resp_h    = c$id$resp_h;
    info$query        = ans$query;
    info$edns_event   = "addl";
    info$payload_size = ans$payload_size;
    Log::write(EDNS0Options::LOG, info);
    }

# COOKIE option (RFC 7873, code 10) — disparado pela técnica T3.
event dns_EDNS_cookie(c: connection, msg: dns_msg, opt: dns_edns_cookie)
    {
    local info: Info;
    info$ts         = network_time();
    info$uid        = c$uid;
    info$id_orig_h  = c$id$orig_h;
    info$id_resp_h  = c$id$resp_h;
    if ( c?$dns && c$dns?$query )
        info$query = c$dns$query;
    info$edns_event  = "cookie";
    info$edns_code   = 10;
    info$edns_length = |opt$client_cookie| + |opt$server_cookie|;
    Log::write(EDNS0Options::LOG, info);
    }

# ECS option (RFC 7871, code 8). Não usada por T1-T6, logada para baseline.
event dns_EDNS_ecs(c: connection, msg: dns_msg, opt: dns_edns_ecs)
    {
    local info: Info;
    info$ts         = network_time();
    info$uid        = c$uid;
    info$id_orig_h  = c$id$orig_h;
    info$id_resp_h  = c$id$resp_h;
    if ( c?$dns && c$dns?$query )
        info$query = c$dns$query;
    info$edns_event  = "ecs";
    info$edns_code   = 8;
    info$edns_length = opt$source_prefix_len + opt$scope_prefix_len;
    Log::write(EDNS0Options::LOG, info);
    }

# TCP Keepalive (RFC 7828, code 11). Não usada por T1-T6, logada para baseline.
event dns_EDNS_tcp_keepalive(c: connection, msg: dns_msg, opt: dns_edns_tcp_keepalive)
    {
    local info: Info;
    info$ts         = network_time();
    info$uid        = c$uid;
    info$id_orig_h  = c$id$orig_h;
    info$id_resp_h  = c$id$resp_h;
    if ( c?$dns && c$dns?$query )
        info$query = c$dns$query;
    info$edns_event  = "tcp_keepalive";
    info$edns_code   = 11;
    info$edns_length = opt$keepalive_timeout_omitted ? 0 : 2;
    Log::write(EDNS0Options::LOG, info);
    }
