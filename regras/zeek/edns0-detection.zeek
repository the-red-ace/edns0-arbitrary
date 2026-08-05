# Loader das cinco heuristicas de deteccao EDNS0.
# Requer o parser de opcoes (plugin-spicy/edns0-options.zeek) carregado antes.
#
# Uso:
#   zeek -C -r <pcap> \
#        plugin-spicy/edns0-options.zeek \
#        regras/zeek/edns0-detection.zeek

@load ./h1a-codes-whitelist
@load ./h1b-padding-payload
@load ./h2-cookie-length
@load ./h3-cookie-hash-recurrence
@load ./h4-buffer-variability
