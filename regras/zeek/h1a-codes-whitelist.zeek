# H1a — Codigos EDNS fora da whitelist RFC
#
# Whitelist: codes {0 (sentinela), 8 (ECS), 10 (Cookie),
# 11 (TCP keepalive), 12 (Padding)}. Codes fora dessa lista
# (notavelmente 13 CHAIN, raro em producao, e codes >= 65000
# experimentais) disparam NOTICE.
#
# Cobre: T1 (65001), T5 (13), T6 (componente t1).

@load base/frameworks/notice

module EDNS0Detect;

export {
    redef enum Notice::Type += {
        H1a_NonWhitelistCode,
    };

    const WHITELIST_CODES: set[count] = {
        0, 8, 10, 11, 12
    } &redef;
}

event edns0_arbitrary_opt(c: connection, is_query: bool, code: count,
                          length: count, data: string)
    {
    if ( code in WHITELIST_CODES )
        return;

    NOTICE([$note=H1a_NonWhitelistCode,
            $conn=c,
            $msg=fmt("EDNS option code %d outside RFC whitelist", code),
            $sub=fmt("code=%d length=%d is_query=%s", code, length, is_query),
            $identifier=cat(c$uid, code)]);
    }
