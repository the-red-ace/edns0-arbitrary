-- Lua script para Suricata: detectar buffer sizes anômalos no EDNS0
-- Valores legítimos típicos: 512, 1232, 1452, 4096

function init(args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

-- Buffer sizes considerados normais
local normal_sizes = {
    [512] = true,
    [1232] = true,
    [1452] = true,
    [4096] = true,
    [1280] = true,
    [1400] = true,
    [1472] = true,
    [4000] = true,
}

function match(args)
    local packet = args["packet"]
    if packet == nil then
        return 0
    end

    -- Buscar OPT RR (type 41 = 0x0029) no pacote
    -- O UDP Payload Size está nos 2 bytes após o tipo OPT RR
    local pkt_bytes = packet
    local len = #pkt_bytes

    -- Procurar pelo padrão OPT RR type (0x00 0x29)
    for i = 1, len - 10 do
        if pkt_bytes:byte(i) == 0x00 and pkt_bytes:byte(i + 1) == 0x29 then
            -- Os próximos 2 bytes são o UDP Payload Size (CLASS field)
            local buf_size = pkt_bytes:byte(i + 2) * 256 + pkt_bytes:byte(i + 3)

            if not normal_sizes[buf_size] then
                return 1  -- Buffer size anômalo detectado
            end
        end
    end

    return 0
end
