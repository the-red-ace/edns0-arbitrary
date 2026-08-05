#!/bin/bash
# Desliga a solução atual e liga a próxima
set -e

SOLUTION=$1

if [ -z "$SOLUTION" ]; then
    echo "Uso: $0 <suricata|snort|paloalto|fortigate|pihole-zeek>"
    exit 1
fi

echo "[*] Desligando todas as soluções de firewall..."
for fw in suricata-fw snort-fw paloalto-fw fortigate-fw pihole-fw; do
    virsh destroy $fw 2>/dev/null || true
done

echo "[*] Iniciando solução: $SOLUTION"
case $SOLUTION in
    suricata)
        virsh start suricata-fw
        sleep 10
        ssh -i ~/edns0-lab/scripts/lab_key researcher@10.0.2.1 \
            "sudo systemctl restart suricata"
        ;;
    snort)
        virsh start snort-fw
        sleep 10
        ssh -i ~/edns0-lab/scripts/lab_key researcher@10.0.2.1 \
            "sudo snort -c /etc/snort/snort.lua -i ens3 -D"
        ;;
    paloalto)
        virsh start paloalto-fw
        echo "[!] Aguarde ~3 minutos para boot completo"
        sleep 180
        ;;
    fortigate)
        virsh start fortigate-fw
        echo "[!] Aguarde ~2 minutos para boot completo"
        sleep 120
        ;;
    pihole-zeek)
        virsh start pihole-fw
        sleep 10
        ssh -i ~/edns0-lab/scripts/lab_key researcher@10.0.2.1 \
            "sudo /opt/zeek/bin/zeekctl restart"
        ;;
    *)
        echo "[!] Solução desconhecida: $SOLUTION"
        exit 1
        ;;
esac

echo "[+] Solução $SOLUTION ativa!"
