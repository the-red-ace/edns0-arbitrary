#!/bin/bash
# Configurar port mirroring da br-dmz para traffic-monitor
set -e

echo "[*] Configurando espelhamento de tráfego..."

# Espelhar tráfego da br-dmz para a br-mirror
sudo ovs-vsctl -- set bridge br-dmz mirrors=@m \
  -- --id=@p get port br-dmz \
  -- --id=@mirror get port mirror0 \
  -- --id=@m create mirror name=dmz-mirror \
     select-all=true output-port=@mirror

echo "[+] Espelhamento configurado!"
sudo ovs-vsctl list mirror
