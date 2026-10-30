#!/bin/bash
echo "Iniciando agente simulador NetSentinel..."

IPS=("192.168.1.45" "10.0.0.12" "172.16.0.8" "203.0.113.5")
SEVERITY=("HIGH" "CRITICAL" "MEDIUM")
EVENTS=("SQL Injection Attempt" "DDoS Pattern Detected" "Unauthorized SSH Access" "Malware Signature Match")

for i in {1..5}
do
    RAND_IP=${IPS[$RANDOM % ${#IPS[@]}]}
    RAND_SEV=${SEVERITY[$RANDOM % ${#SEVERITY[@]}]}
    RAND_EV=${EVENTS[$RANDOM % ${#EVENTS[@]}]}
    
    curl -X POST http://localhost:3001/api/alerts \
         -H "Content-Type: application/json" \
         -d "{
               \"severity\": \"$RAND_SEV\",
               \"source_ip\": \"$RAND_IP\",
               \"event_type\": \"$RAND_EV\",
               \"description\": \"Alerta automatizada generada por agente SIEM.\"
             }" \
         -s > /dev/null

    echo "[!] Alerta enviada: $RAND_EV desde $RAND_IP"
    sleep 2
done

echo "Simulación completada."