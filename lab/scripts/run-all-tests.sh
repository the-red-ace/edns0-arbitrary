#!/bin/bash
# Executa toda a matriz de testes: T× × S× com 3 repetições
set -e

TECHNIQUES=(t1 t2 t3 t4 t5 t6)
SOLUTIONS=(suricata snort paloalto fortigate pihole-zeek)
REPEATS=3

ANSIBLE_DIR=~/edns0-lab/ansible
LOG_FILE=~/edns0-lab/results/test-run-$(date +%Y%m%d_%H%M%S).log

echo "========================================" | tee -a $LOG_FILE
echo "EDNStego - Execucao Completa da Matriz" | tee -a $LOG_FILE
echo "Inicio: $(date)" | tee -a $LOG_FILE
echo "Tecnicas: ${TECHNIQUES[*]}" | tee -a $LOG_FILE
echo "Solucoes: ${SOLUTIONS[*]}" | tee -a $LOG_FILE
echo "Repeticoes: $REPEATS" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

total_tests=$((${#TECHNIQUES[@]} * ${#SOLUTIONS[@]} * $REPEATS))
current=0

for solution in "${SOLUTIONS[@]}"; do
    echo "" | tee -a $LOG_FILE
    echo "[===] Configurando solucao: $solution" | tee -a $LOG_FILE

    # Trocar solução de segurança
    bash ~/edns0-lab/scripts/switch-solution.sh $solution 2>&1 | tee -a $LOG_FILE
    sleep 30

    # Testes de controle
    echo "[CTL] Controle positivo: dnscat2..." | tee -a $LOG_FILE
    ansible-playbook $ANSIBLE_DIR/playbooks/control-positive.yaml \
        -e "solution=$solution" \
        -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE || true

    echo "[CTL] Controle negativo: trafego legitimo..." | tee -a $LOG_FILE
    ansible-playbook $ANSIBLE_DIR/playbooks/control-negative.yaml \
        -e "solution=$solution" \
        -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE || true

    for technique in "${TECHNIQUES[@]}"; do
        for repeat in $(seq 1 $REPEATS); do
            current=$((current + 1))
            echo "" | tee -a $LOG_FILE
            echo "[$current/$total_tests] $solution / $technique / rep $repeat" | tee -a $LOG_FILE

            # Reverter VMs ao estado limpo
            for vm in victim-linux c2-server; do
                virsh snapshot-revert $vm clean-state 2>/dev/null || true
            done
            sleep 10

            # Teste padrão (D1 + D2)
            echo "  [D1/D2] Teste padrao..." | tee -a $LOG_FILE
            ansible-playbook $ANSIBLE_DIR/playbooks/run-test.yaml \
                -e "technique=$technique solution=$solution" \
                -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE

            # Teste com fragmentação (D3)
            echo "  [D3] Teste com fragmentacao IP..." | tee -a $LOG_FILE
            ansible-playbook $ANSIBLE_DIR/playbooks/run-test.yaml \
                -e "technique=$technique solution=$solution force_fragmentation=true" \
                -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE

            # Teste com volume variável (D4)
            for ratio in 100 500 1000; do
                echo "  [D4] Teste com ratio 1:$ratio..." | tee -a $LOG_FILE
                ansible-playbook $ANSIBLE_DIR/playbooks/run-test.yaml \
                    -e "technique=$technique solution=$solution legit_ratio=$ratio" \
                    -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE
            done

            # Teste com pacotes malformados vs conformes (D5)
            echo "  [D5] Teste conformidade RFC..." | tee -a $LOG_FILE
            ansible-playbook $ANSIBLE_DIR/playbooks/run-test.yaml \
                -e "technique=$technique solution=$solution test_malformed=true" \
                -i $ANSIBLE_DIR/inventory.ini 2>&1 | tee -a $LOG_FILE

            sleep 10
        done
    done

    echo "[===] Limpeza: desligando $solution" | tee -a $LOG_FILE
done

echo "" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
echo "[+] Todos os $total_tests testes concluidos!" | tee -a $LOG_FILE
echo "Fim: $(date)" | tee -a $LOG_FILE
echo "Resultados em: ~/edns0-lab/results/" | tee -a $LOG_FILE
echo "PCAPs em: ~/edns0-lab/pcaps/" | tee -a $LOG_FILE
echo "Log completo: $LOG_FILE" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE
