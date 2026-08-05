#!/bin/bash
# setup-mirror-v2.sh
#
# Configura port-mirror OVS para entregar tráfego das bridges do lab
# em interfaces DEDICADAS da VM fw-test (modo IDS passivo p/ Suricata).
#
# Substitui o setup-mirror.sh original (que só espelhava br-dmz para
# uma porta "mirror0" inexistente). Aquele arquivo é mantido como
# referência histórica da intenção original.
#
# Configuração v2 (esta versão):
#   - fw-test tem 5 NICs: 3 originais (enp1s0/enp2s0/enp3s0) para
#     gerência + 2 dedicadas a mirror (enp9s0/enp10s0).
#   - select_all=true para capturar TODO o tráfego das bridges.
#   - output_port = NIC de mirror (de:ad:01 ou de:ad:02), nunca uma
#     NIC ativa de gerência: usar uma NIC ativa como output_port
#     quebra a conectividade dela (visto na tentativa anterior).
#
# Mapeamento:
#   br-internal -> fw-test enp9s0  (MAC 52:54:00:de:ad:01)
#   br-external -> fw-test enp10s0 (MAC 52:54:00:de:ad:02)
#
# Idempotente: remove mirrors com mesmo nome antes de recriar.
# Resolve nome OVS port a partir do MAC do guest (52:54:..) → MAC do
# host vnet (fe:54:..) — robusto a renumeração de vnetN.

set -u

# MACs do guest (das NICs dedicadas a mirror, definidas via attach-device)
MIRROR_INT_MAC=52:54:00:de:ad:01   # enp9s0  da fw-test (br-internal)
MIRROR_EXT_MAC=52:54:00:de:ad:02   # enp10s0 da fw-test (br-external)

guest_to_host_mac() { echo "${1/#52:54/fe:54}"; }

port_by_mac() {
    local target_mac="$1"
    for iface in /sys/class/net/vnet*; do
        [ -e "$iface/address" ] || continue
        if [ "$(cat "$iface/address")" = "$target_mac" ]; then
            basename "$iface"; return 0
        fi
    done
    return 1
}

setup_mirror_select_all() {
    local name="$1" bridge="$2" output_port="$3"

    local old_uuid
    old_uuid=$(sudo ovs-vsctl --bare --columns=_uuid find Mirror name="$name" 2>/dev/null)
    if [ -n "$old_uuid" ]; then
        sudo ovs-vsctl -- --id=@m get Mirror "$name" -- remove Bridge "$bridge" mirrors @m 2>/dev/null || true
        sudo ovs-vsctl destroy Mirror "$old_uuid" 2>/dev/null || true
        echo "  [reset] removido mirror anterior $name"
    fi

    sudo ovs-vsctl \
        -- --id=@out get Port "$output_port" \
        -- --id=@m create Mirror name="$name" \
            select-all=true \
            output-port=@out \
        -- add Bridge "$bridge" mirrors @m

    echo "  [ok] mirror $name: $bridge select-all -> $output_port"
}

echo "=== setup-mirror-v2 ==="

INT_OUT=$(port_by_mac "$(guest_to_host_mac "$MIRROR_INT_MAC")") \
    || { echo "ERROR: NIC mirror-int ($MIRROR_INT_MAC) não encontrada em br-internal. fw-test rodando?"; exit 1; }
EXT_OUT=$(port_by_mac "$(guest_to_host_mac "$MIRROR_EXT_MAC")") \
    || { echo "ERROR: NIC mirror-ext ($MIRROR_EXT_MAC) não encontrada em br-external. fw-test rodando?"; exit 1; }

echo "Output ports: br-internal -> $INT_OUT  br-external -> $EXT_OUT"

# Validação extra: a NIC de saída precisa estar na bridge correta
INT_BR=$(sudo ovs-vsctl iface-to-br "$INT_OUT" 2>/dev/null)
EXT_BR=$(sudo ovs-vsctl iface-to-br "$EXT_OUT" 2>/dev/null)
[ "$INT_BR" = "br-internal" ] || { echo "ERROR: $INT_OUT está em $INT_BR, não em br-internal"; exit 1; }
[ "$EXT_BR" = "br-external" ] || { echo "ERROR: $EXT_OUT está em $EXT_BR, não em br-external"; exit 1; }

setup_mirror_select_all edns0-internal-mirror br-internal "$INT_OUT"
setup_mirror_select_all edns0-external-mirror br-external "$EXT_OUT"

echo "=== mirrors ativos ==="
sudo ovs-vsctl list Mirror | grep -E "^name|^output_port|^select_all" | sed 's/^/  /'
exit 0
