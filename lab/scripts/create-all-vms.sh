#!/bin/bash
# Cria todas as VMs Linux do laboratório
set -e

DEBIAN_IMG=~/edns0-lab/isos/debian-12-generic-amd64.qcow2
LAB_KEY=~/edns0-lab/scripts/lab_key
IMAGES_DIR=~/edns0-lab/images
CLOUD_INIT_DIR=~/edns0-lab/scripts/cloud-init

# Verificar pré-requisitos
if [ ! -f "$DEBIAN_IMG" ]; then
    echo "[!] Imagem Debian não encontrada: $DEBIAN_IMG"
    echo "    Execute: wget -O $DEBIAN_IMG https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
    exit 1
fi

if [ ! -f "$LAB_KEY" ]; then
    echo "[*] Gerando chave SSH para o laboratório..."
    ssh-keygen -t ed25519 -f "$LAB_KEY" -N ""
fi

PUBKEY=$(cat ${LAB_KEY}.pub)

# Substituir chave pública nos cloud-init
for yaml in $CLOUD_INIT_DIR/*.yaml; do
    sed -i "s|REPLACE_WITH_PUBKEY|$PUBKEY|g" "$yaml"
done

echo "[*] Chave SSH configurada em todos os cloud-init"

# Definição das VMs: nome:ip:ram:vcpu:disco:rede
declare -A VMS
VMS[victim-linux]="10.0.1.20:4096:2:20G:edns0-internal"
VMS[dns-resolver]="10.0.1.2:2048:2:10G:edns0-internal"
VMS[c2-server]="10.0.3.100:4096:4:30G:edns0-external"
VMS[traffic-monitor]="10.0.3.200:4096:2:100G:edns0-external"

for vm_name in "${!VMS[@]}"; do
    IFS=':' read -r ip ram vcpu disco rede <<< "${VMS[$vm_name]}"

    echo ""
    echo "[*] Criando $vm_name (IP: $ip, RAM: ${ram}MB, vCPU: $vcpu, Disco: $disco)"

    # Verificar se VM já existe
    if virsh dominfo $vm_name &>/dev/null; then
        echo "[!] VM $vm_name já existe. Pulando..."
        continue
    fi

    # Copiar imagem base
    cp "$DEBIAN_IMG" "$IMAGES_DIR/${vm_name}.qcow2"
    qemu-img resize "$IMAGES_DIR/${vm_name}.qcow2" "$disco"

    # Verificar se existe cloud-init específico
    CLOUD_YAML="$CLOUD_INIT_DIR/${vm_name}.yaml"
    if [ ! -f "$CLOUD_YAML" ]; then
        echo "[!] Cloud-init não encontrado: $CLOUD_YAML"
        continue
    fi

    # Gerar seed ISO para cloud-init
    cloud-localds "$IMAGES_DIR/${vm_name}-seed.iso" "$CLOUD_YAML"

    # Criar VM
    sudo virt-install \
        --name "$vm_name" \
        --ram "$ram" --vcpus "$vcpu" \
        --disk "path=$IMAGES_DIR/${vm_name}.qcow2,format=qcow2" \
        --disk "path=$IMAGES_DIR/${vm_name}-seed.iso,device=cdrom" \
        --network "network=$rede" \
        --os-variant debian12 \
        --graphics none --console pty,target_type=serial \
        --import --noautoconsole

    echo "[+] $vm_name criada com sucesso!"
    sleep 5
done

echo ""
echo "[+] Todas as VMs Linux criadas!"
echo "[*] Aguarde ~2 minutos para boot e configuração via cloud-init."
echo ""
echo "Para verificar: sudo virsh list --all"
echo "Para acessar:   ssh -i $LAB_KEY researcher@<IP>"
