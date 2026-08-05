#!/bin/bash
# Criar snapshots de estado limpo para todas as VMs
set -e

echo "[*] Criando snapshots de estado limpo..."

for vm in victim-linux dns-resolver c2-server traffic-monitor; do
    if virsh dominfo $vm &>/dev/null; then
        echo "  Snapshot: $vm -> clean-state"
        virsh snapshot-create-as $vm clean-state \
            --description "Estado limpo pre-testes - $(date +%Y%m%d)"
    else
        echo "  [!] VM não encontrada: $vm"
    fi
done

echo "[+] Snapshots criados!"
echo ""
for vm in victim-linux dns-resolver c2-server traffic-monitor; do
    echo "  $vm:"
    virsh snapshot-list $vm 2>/dev/null || echo "    (não encontrada)"
done
