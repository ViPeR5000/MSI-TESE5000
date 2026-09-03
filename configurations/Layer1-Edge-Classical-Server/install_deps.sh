#!/bin/bash
# Instala dependências do servidor clássico Charlie (sem liboqs — só Python cryptography)
set -e

echo "Actualizando pacotes..."
sudo apt-get update -q
sudo apt-get install -y python3-pip python3-venv

echo "Criando ambiente virtual..."
python3 -m venv venv
source venv/bin/activate

echo "Instalando dependências Python..."
pip install -r requirements.txt

echo "================================================"
echo "Instalação concluída."
echo ""
echo "Iniciar o servidor:"
echo "  source venv/bin/activate"
echo "  uvicorn main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Com TLS (depois de generate_tls_cert.sh):"
echo "  uvicorn main:app --host 0.0.0.0 --port 8000 \\"
echo "    --ssl-keyfile tls/server.key --ssl-certfile tls/server.crt"
echo "================================================"
