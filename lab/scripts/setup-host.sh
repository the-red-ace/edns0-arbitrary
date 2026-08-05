#!/bin/bash
# Setup completo do host para o laboratório EDNStego
# Executar como root ou com sudo
set -e

echo "============================================"
echo "EDNStego Lab - Setup do Host"
echo "============================================"

# 1. Atualizar e instalar pacotes
echo "[1/7] Instalando pacotes..."
apt update
apt install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients virtinst \
    virt-manager bridge-utils openvswitch-switch \
    ansible python3-pip python3-venv python3-libvirt \
    git curl wget tcpdump tshark wireshark-common nmap \
    python3-scapy python3-dnspython python3-pyshark \
    build-essential linux-headers-$(uname -r) \
    cloud-image-utils genisoimage jq net-tools \
    dnsutils bind9-utils tmux htop iotop

# 2. Verificar virtualização
echo "[2/7] Verificando suporte a virtualização..."
VMX_COUNT=$(egrep -c '(vmx|svm)' /proc/cpuinfo)
if [ "$VMX_COUNT" -eq 0 ]; then
    echo "[!] AVISO: Virtualização por hardware não detectada!"
    echo "    Verifique se VT-x/AMD-V está habilitado na BIOS."
fi
echo "    CPU flags de virtualização: $VMX_COUNT"

# 3. Habilitar serviços
echo "[3/7] Habilitando serviços..."
systemctl enable --now libvirtd
systemctl enable --now openvswitch-switch

# Adicionar usuário atual aos grupos
CURRENT_USER=${SUDO_USER:-$(whoami)}
usermod -aG libvirt,kvm "$CURRENT_USER"

# 4. Criar bridges OVS
echo "[4/7] Criando bridges Open vSwitch..."
for br in br-internal br-dmz br-external br-mirror; do
    if ! ovs-vsctl br-exists "$br" 2>/dev/null; then
        ovs-vsctl add-br "$br"
        echo "    Criada: $br"
    else
        echo "    Já existe: $br"
    fi
done

# 5. Atribuir IPs às bridges
echo "[5/7] Configurando IPs nas bridges..."
ip addr add 10.0.1.254/24 dev br-internal 2>/dev/null || true
ip addr add 10.0.2.254/24 dev br-dmz 2>/dev/null || true
ip addr add 10.0.3.254/24 dev br-external 2>/dev/null || true
ip link set br-internal up
ip link set br-dmz up
ip link set br-external up

# Persistência via netplan (Ubuntu)
cat > /etc/netplan/99-edns0-lab.yaml << 'NETPLAN'
network:
  version: 2
  bridges:
    br-internal:
      addresses: [10.0.1.254/24]
      openvswitch: {}
    br-dmz:
      addresses: [10.0.2.254/24]
      openvswitch: {}
    br-external:
      addresses: [10.0.3.254/24]
      openvswitch: {}
NETPLAN

# 6. Registrar redes no libvirt
echo "[6/7] Registrando redes no libvirt..."
SCRIPTS_DIR=$(dirname "$(readlink -f "$0")")
for net in net-internal.xml net-dmz.xml net-external.xml; do
    NET_FILE="$SCRIPTS_DIR/$net"
    if [ -f "$NET_FILE" ]; then
        NET_NAME=$(basename "$net" .xml | sed 's/net-/edns0-/')
        if ! virsh net-info "$NET_NAME" &>/dev/null; then
            virsh net-define "$NET_FILE"
            virsh net-start "$NET_NAME"
            virsh net-autostart "$NET_NAME"
            echo "    Rede criada: $NET_NAME"
        else
            echo "    Rede já existe: $NET_NAME"
        fi
    fi
done

# 7. Download da imagem Debian cloud
echo "[7/7] Verificando imagem Debian cloud..."
DEBIAN_IMG="$HOME/edns0-lab/isos/debian-12-generic-amd64.qcow2"
if [ ! -f "$DEBIAN_IMG" ]; then
    # Usar home do usuário real (não root)
    REAL_HOME=$(eval echo "~$CURRENT_USER")
    DEBIAN_IMG="$REAL_HOME/edns0-lab/isos/debian-12-generic-amd64.qcow2"
    echo "    Baixando imagem Debian 12 cloud..."
    wget -q --show-progress -O "$DEBIAN_IMG" \
        https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2
    chown "$CURRENT_USER:$CURRENT_USER" "$DEBIAN_IMG"
else
    echo "    Imagem já existe: $DEBIAN_IMG"
fi

# Gerar chave SSH se não existe
REAL_HOME=$(eval echo "~$CURRENT_USER")
LAB_KEY="$REAL_HOME/edns0-lab/scripts/lab_key"
if [ ! -f "$LAB_KEY" ]; then
    echo "    Gerando chave SSH..."
    su - "$CURRENT_USER" -c "ssh-keygen -t ed25519 -f '$LAB_KEY' -N ''"
fi

echo ""
echo "============================================"
echo "[+] Setup do host concluído!"
echo "============================================"
echo ""
echo "Próximos passos:"
echo "  1. Faça logout e login (para grupos libvirt/kvm)"
echo "  2. Execute: bash ~/edns0-lab/scripts/create-all-vms.sh"
echo "  3. Aguarde boot das VMs (~2 min)"
echo "  4. Valide com: ansible all -m ping -i ~/edns0-lab/ansible/inventory.ini"
echo ""
ovs-vsctl show
echo ""
virsh net-list --all
