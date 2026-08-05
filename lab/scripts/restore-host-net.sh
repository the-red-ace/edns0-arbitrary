#!/bin/bash
# Re-aplica regras iptables (NAT + FORWARD) para o laboratório EDNStego.
# Os IPs nas bridges OVS são persistidos via /etc/netplan/99-edns0-lab.yaml;
# este script só cuida do iptables (não-persistido) após reboot.
# Idempotente: usa iptables -C ... || iptables -A/-I.

set -u

LOG=/var/log/edns0-lab-net.log
WAN=ens1f0np0
SUBNETS=(10.0.1.0/24 10.0.2.0/24 10.0.3.0/24)

log() { echo "$(date -Is) $*" >> "$LOG"; }

log "=== restore-host-net.sh start ==="

if ! ip link show "$WAN" >/dev/null 2>&1; then
    log "ERROR: WAN interface $WAN not found, aborting"
    exit 1
fi

for sub in "${SUBNETS[@]}"; do
    if iptables -t nat -C POSTROUTING -s "$sub" -o "$WAN" -j MASQUERADE 2>/dev/null; then
        log "nat MASQUERADE $sub -> $WAN already present"
    else
        iptables -t nat -A POSTROUTING -s "$sub" -o "$WAN" -j MASQUERADE \
            && log "nat MASQUERADE $sub -> $WAN added" \
            || log "ERROR adding nat MASQUERADE $sub"
    fi

    if iptables -C FORWARD -s "$sub" -j ACCEPT 2>/dev/null; then
        log "FORWARD -s $sub ACCEPT already present"
    else
        iptables -I FORWARD -s "$sub" -j ACCEPT \
            && log "FORWARD -s $sub ACCEPT added" \
            || log "ERROR adding FORWARD -s $sub"
    fi

    if iptables -C FORWARD -d "$sub" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        log "FORWARD -d $sub ESTABLISHED,RELATED already present"
    else
        iptables -I FORWARD -d "$sub" -m state --state ESTABLISHED,RELATED -j ACCEPT \
            && log "FORWARD -d $sub ESTABLISHED,RELATED added" \
            || log "ERROR adding FORWARD -d $sub"
    fi
done

log "=== restore-host-net.sh end ==="
exit 0
