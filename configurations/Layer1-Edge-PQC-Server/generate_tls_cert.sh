#!/bin/bash
# MSI-TESE — Geração de Certificado TLS para o Servidor PQC
# Executar em: viper-keysb (192.168.20.200) no directório do servidor
# Uso: bash generate_tls_cert.sh
set -e

echo "===================================================="
echo " MSI-TESE — TLS Certificate Generation"
echo " Servidor PQC: viper-keysb (192.168.20.200)"
echo "===================================================="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TLS_DIR="$SCRIPT_DIR/tls"
SERVER_IP="192.168.20.200"
SERVER_CN="viper-keysb"
CERT_DAYS=3650

mkdir -p "$TLS_DIR"

# ── 1. Gerar chave EC P-256 e certificado auto-assinado com IP SAN ──────────
echo "[TLS] A gerar chave EC P-256..."

cat > "$TLS_DIR/openssl.cnf" << EOF
[req]
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_cert

[dn]
C  = PT
O  = MSI-TESE
CN = $SERVER_CN

[v3_cert]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, keyCertSign
subjectAltName         = @alt_names

[alt_names]
IP.1  = $SERVER_IP
DNS.1 = $SERVER_CN
DNS.2 = $SERVER_CN.local
DNS.3 = $SERVER_IP
EOF
# DNS.3 = IP é essencial: o mbedTLS do core ESP32 2.0.17 só valida SANs DNS ao
# ligar por IP; sem esta entrada o handshake TLS do ESP32 falha (HTTP -1).

openssl ecparam -name prime256v1 -genkey -noout -out "$TLS_DIR/server.key"
openssl req -new -x509 \
    -key  "$TLS_DIR/server.key" \
    -out  "$TLS_DIR/server.crt" \
    -days "$CERT_DAYS" \
    -config "$TLS_DIR/openssl.cnf"

chmod 600 "$TLS_DIR/server.key"

echo "[TLS] Certificado gerado com sucesso:"
openssl x509 -in "$TLS_DIR/server.crt" -noout \
    -subject -issuer -dates \
    -ext subjectAltName 2>/dev/null || \
openssl x509 -in "$TLS_DIR/server.crt" -noout -subject -issuer -dates

# ── 2. Gerar header C++ para os firmwares ESP32 ──────────────────────────────
echo "[TLS] A gerar pqc_server_cert.h..."

EXPIRY=$(openssl x509 -enddate -noout -in "$TLS_DIR/server.crt" | cut -d= -f2)

python3 -c "
cert = open('$TLS_DIR/server.crt').read().strip()
expiry = '$EXPIRY'
h  = '#pragma once\n'
h += '// Auto-gerado por generate_tls_cert.sh — NAO EDITAR MANUALMENTE\n'
h += '// Certificado TLS: viper-keysb ($SERVER_IP)\n'
h += '// Algoritmo : EC P-256 (ECDSA), auto-assinado\n'
h += f'// Valido ate: {expiry}\n'
h += '// =====================================================================\n'
h += '#define PQC_CERT_READY\n\n'
h += 'const char PQC_SERVER_CERT[] = R\"===(\n'
h += cert + '\n'
h += ')===\";\n'
open('$TLS_DIR/pqc_server_cert.h', 'w').write(h)
print('[TLS] pqc_server_cert.h gerado.')
"

# ── 3. Copiar header para as pastas dos firmwares ESP32 (se repo presente) ──
REPO_ROOT=""
for candidate in "$SCRIPT_DIR/../.." "$HOME/MSI-TESE" "$HOME/git/MSI-TESE"; do
    candidate="$(cd "$candidate" 2>/dev/null && pwd || true)"
    if [ -n "$candidate" ] && [ -f "$candidate/CLAUDE.md" ]; then
        REPO_ROOT="$candidate"
        break
    fi
done

if [ -n "$REPO_ROOT" ]; then
    echo "[TLS] Repositório: $REPO_ROOT"
    for fw in \
        "Configurations/Layer0-Field-ESP32/Secure-TempSensor" \
        "Configurations/Layer0-Field-ESP32/Secure-KineticNode" \
        "Configurations/Layer0-Field-ESP32/Secure-Relay"; do
        if [ -d "$REPO_ROOT/$fw" ]; then
            cp "$TLS_DIR/pqc_server_cert.h" "$REPO_ROOT/$fw/"
            echo "[TLS]   → $fw/pqc_server_cert.h actualizado"
        fi
    done
else
    echo "[TLS] Repo não detectado — copie manualmente:"
    echo "      $TLS_DIR/pqc_server_cert.h"
    echo "  para cada pasta: Secure-TempSensor/ Secure-KineticNode/ Secure-Relay/"
fi

# ── 4. Copiar certificado para o volume do container Bridge ──────────────────
BRIDGE_TLS="/home/pi/msi-bridge/tls"
mkdir -p "$BRIDGE_TLS"
cp "$TLS_DIR/server.crt" "$BRIDGE_TLS/"
echo "[TLS] Certificado copiado para $BRIDGE_TLS/ (volume Docker bridge)"

# ── 5. Actualizar systemd pqc-server se existir ──────────────────────────────
SERVICE_FILE="/etc/systemd/system/pqc-server.service"
if [ -f "$SERVICE_FILE" ]; then
    if ! grep -q "ssl-keyfile" "$SERVICE_FILE"; then
        sudo sed -i \
            "s|uvicorn main:app|uvicorn main:app --ssl-keyfile $TLS_DIR/server.key --ssl-certfile $TLS_DIR/server.crt|g" \
            "$SERVICE_FILE"
        sudo systemctl daemon-reload
        echo "[TLS] Serviço pqc-server.service actualizado com TLS."
        echo "[TLS] A reiniciar pqc-server..."
        sudo systemctl restart pqc-server
    else
        echo "[TLS] pqc-server.service já tem TLS configurado."
    fi
else
    echo "[TLS] Serviço systemd não encontrado. Arranque manual:"
    echo ""
    echo "  cd $SCRIPT_DIR && source venv/bin/activate"
    echo "  uvicorn main:app --host 0.0.0.0 --port 8000 \\"
    echo "    --ssl-keyfile $TLS_DIR/server.key \\"
    echo "    --ssl-certfile $TLS_DIR/server.crt"
fi

# ── 6. Enviar certificado para viper-gateway-b ────────────────────────────────
echo ""
echo "[TLS] A copiar certificado para viper-gateway-b..."
scp "$TLS_DIR/server.crt" pi@192.168.20.100:/home/pi/msi-bridge/tls/ \
    && echo "[TLS] Certificado enviado para viper-gateway-b." \
    || echo "[TLS] AVISO: scp falhou — copie manualmente:"
echo "      scp $TLS_DIR/server.crt pi@192.168.20.100:/home/pi/msi-bridge/tls/"

echo ""
echo "===================================================="
echo " CONCLUÍDO. Próximos passos:"
echo "===================================================="
echo "  1. Reflashar os ESP32 com o novo pqc_server_cert.h"
echo "  2. Reiniciar a bridge em viper-gateway-b: bridge-restart"
echo "  3. Verificar: curl -k https://$SERVER_IP:8000/monitor"
echo "===================================================="
