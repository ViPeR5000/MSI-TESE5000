FROM python:3.10-slim

WORKDIR /app

# Instala dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código fonte
COPY *.py .

# Inicia script de ponte
CMD ["python", "-u", "bridge.py"]
