#!/bin/bash
# Script para instalar liboqs e liboqs-python no Raspberry Pi 4 (Debian/Ubuntu)

echo "Atualizando pacotes e instalando dependências de compilação..."
sudo apt-get update
sudo apt-get install -y astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-pip python3-venv

# Criando ambiente virtual Python para não conflitar com pacotes do sistema
echo "Criando ambiente virtual Python..."
python3 -m venv venv
source venv/bin/activate

echo "Clonando e compilando liboqs (C library)..."
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
# Compilando com suporte a ARM e otimizações genéricas
cmake -GNinja -DOQS_USE_OPENSSL=ON ..
ninja
sudo ninja install
cd ../..

echo "Instalando dependências Python do servidor..."
pip install -r requirements.txt

# Para instalar a versão mais recente do liboqs-python via source (recomendado para pegar as bibliotecas compiladas)
echo "Instalando liboqs-python a partir do código fonte..."
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
python3 setup.py install
cd ..

echo "=========================================================="
echo "Instalação concluída com sucesso!"
echo ""
echo "1. Gerar certificado TLS (primeira vez):"
echo "   bash generate_tls_cert.sh"
echo ""
echo "2. Arrancar o servidor com TLS:"
echo "   source venv/bin/activate"
echo "   uvicorn main:app --host 0.0.0.0 --port 8000 \\"
echo "     --ssl-keyfile tls/server.key \\"
echo "     --ssl-certfile tls/server.crt"
echo ""
echo "3. Verificar:"
echo "   curl -k https://localhost:8000/monitor"
echo "=========================================================="
