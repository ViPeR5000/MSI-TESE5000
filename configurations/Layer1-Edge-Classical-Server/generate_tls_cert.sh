#!/bin/bash
# MSI-TESE — Geração do certificado TLS do servidor clássico (Charlie).
# Executar em viper-pki-c (192.168.30.200), no diretório do servidor.
#   bash generate_tls_cert.sh
#
# Gera um certificado EC P-256 auto-assinado (pinado pelos clientes). O IP entra
# como iPAddress SAN (para curl/Python/Node) E como dNSName SAN — o mbedTLS do
# core ESP32 2.0.17 só valida SANs DNS ao ligar por IP, por isso sem a entrada
# DNS o handshake do ESP32 falha (HTTP -1) mesmo com o servidor e o cert corretos.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/tls"
IP="192.168.30.200"; CN="viper-pki-c"; DAYS=3650
mkdir -p "$DIR"

cat > "$DIR/openssl.cnf" <<EOF
[req]
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_cert
[dn]
C = PT
O = MSI-TESE
CN = $CN
[v3_cert]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, keyCertSign
subjectAltName = @alt_names
[alt_names]
IP.1 = $IP
DNS.1 = $CN
DNS.2 = $CN.local
DNS.3 = $IP
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/server.key"
openssl req -new -x509 -key "$DIR/server.key" -out "$DIR/server.crt" -days "$DAYS" -config "$DIR/openssl.cnf"
chmod 600 "$DIR/server.key"
openssl x509 -in "$DIR/server.crt" -noout -subject -ext subjectAltName

# Header C++ para os firmwares Charlie
python3 - "$DIR/server.crt" "$DIR/classical_server_cert.h" <<'PY'
import sys
cert = open(sys.argv[1]).read().strip()
h  = '#pragma once\n'
h += '// Auto-gerado por generate_tls_cert.sh — cert TLS viper-pki-c (EC P-256).\n'
h += '#define CLASSICAL_CERT_READY\n\n'
h += 'const char CLASSICAL_SERVER_CERT[] = R"===(\n' + cert + '\n)===";\n'
open(sys.argv[2], 'w').write(h)
print('[TLS] classical_server_cert.h gerado.')
PY

echo "[TLS] Próximos passos:"
echo "  1. charlie-pki.service: uvicorn ... --ssl-keyfile $DIR/server.key --ssl-certfile $DIR/server.crt"
echo "  2. Copiar $DIR/server.crt para o bridge (gateway-c:/home/pi/msi-bridge-charlie/tls/) e scada-c:/home/pi/tls/"
echo "  3. charlie-bridge env: CLASSICAL_SERVER_URL=https://$IP:8000/monitor, CLASSICAL_TLS_CERT_PATH=.../server.crt"
echo "  4. Copiar $DIR/classical_server_cert.h para Charlie-KineticNode/ Charlie-Relay/ Charlie-TempSensor/ e reflashar"
