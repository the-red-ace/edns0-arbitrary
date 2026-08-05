# H1b — Code 12 (Padding) com payload nao-zero
#
# RFC 7830 estipula que padding deve ser bytes zero. Qualquer
# byte != 0x00 em data de uma opcao code 12 indica abuso do
# campo padding como veiculo de payload (T2).
#
# Cobre: T2.

@load base/frameworks/notice

module EDNS0Detect;

export {
    redef enum Notice::Type += {
        H1b_PaddingNonZero,
    };
}

function bytes_all_zero(b: string): bool
    {
    local i = 0;
    while ( i < |b| )
        {
        if ( b[i] != "\x00" )
            return F;
        i += 1;
        }
    return T;
    }

event edns0_arbitrary_opt(c: connection, is_query: bool, code: count,
                          length: count, data: string)
    {
    if ( code != 12 )
        return;

    if ( length == 0 )
        return;  # padding vazio (apenas signaling) eh legitimo

    if ( bytes_all_zero(data) )
        return;  # padding zero conforme RFC 7830

    NOTICE([$note=H1b_PaddingNonZero,
            $conn=c,
            $msg="EDNS padding (code 12) contains non-zero bytes",
            $sub=fmt("length=%d is_query=%s", length, is_query),
            $identifier=cat(c$uid, "padding")]);
    }
