# H2 — Cookie length anomalo
#
# RFC 7873 §4: client cookie eh 8 bytes; server cookie eh 8-32
# bytes; combinacao cliente+servidor mais comum eh 16 ou 24
# bytes. Length fora de {8, 16, 24} indica cookie stuffed com
# payload (T3).
#
# Validacao empirica: 100% dos cookies legitimos no baseline
# weberblog (n=58) caem em {8, 24}.
#
# Cobre: T3, T6 (componente t3).

@load base/frameworks/notice

module EDNS0Detect;

export {
    redef enum Notice::Type += {
        H2_CookieLengthAnomalous,
    };

    const LEGITIMATE_COOKIE_LENGTHS: set[count] = {
        8, 16, 24
    } &redef;
}

event edns0_arbitrary_opt(c: connection, is_query: bool, code: count,
                          length: count, data: string)
    {
    if ( code != 10 )
        return;

    if ( length in LEGITIMATE_COOKIE_LENGTHS )
        return;

    NOTICE([$note=H2_CookieLengthAnomalous,
            $conn=c,
            $msg=fmt("EDNS cookie (code 10) with anomalous length %d", length),
            $sub=fmt("length=%d is_query=%s", length, is_query),
            $identifier=cat(c$uid, length)]);
    }
