import os
import time
import json
import base64
import requests
import urllib3
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import ascon

# ====================================================================
# CONFIGURAÇÕES DA PONTE (VIA VARIÁVEIS DE AMBIENTE)
# ====================================================================
MQTT_HOST = os.getenv("MQTT_BROKER_HOST", "emqx")
MQTT_PORT = int(os.getenv("MQTT_BROKER_PORT", 1883))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "BRAVO/#")

PQC_SERVER_URL = os.getenv("PQC_SERVER_URL", "https://192.168.20.200:8000/monitor")

# Caminho para o certificado TLS do Servidor PQC (montado no container)
# Se não definido, a verificação TLS é desactivada (apenas para desenvolvimento)
PQC_TLS_CERT = os.getenv("PQC_TLS_CERT_PATH")
if PQC_TLS_CERT:
    print(f"[TLS] Certificado PQC configurado: {PQC_TLS_CERT}")
else:
    print("[TLS] AVISO: PQC_TLS_CERT_PATH não definido — TLS sem verificação de certificado!")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_tls_verify = PQC_TLS_CERT if PQC_TLS_CERT else False

INFLUXDB_URL = os.getenv("INFLUXDB_URL", "http://192.168.20.60:8086")
INFLUXDB_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-auth-token-12345678")
INFLUXDB_ORG = os.getenv("INFLUXDB_ORG", "msi-tese")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "telemetry")

# Cache de chaves: lista de bytes ordenada da mais recente para a mais antiga
recent_keys: list = []

# ====================================================================
# COMUNICAÇÃO COM O SERVIDOR DE CHAVES PQC (GATEWAY / LAYER 1)
# ====================================================================
def fetch_recent_keys() -> list:
    """Obtém o histórico de chaves recentes do Servidor PQC (suporta ESP32 com handshake frequente)."""
    try:
        print(f"[BRIDGE] A contactar o Servidor PQC em {PQC_SERVER_URL}...")
        r = requests.get(PQC_SERVER_URL, timeout=5, verify=_tls_verify)
        if r.status_code == 200:
            data = r.json()
            keys = []
            # Histórico completo (mais recente primeiro)
            history = data.get("recent_session_keys_b64", [])
            for k in reversed(history):
                keys.append(base64.b64decode(k))
            # Fallback para chave activa se sem histórico
            if not keys:
                active = data.get("active_session_key_b64")
                if active:
                    keys.append(base64.b64decode(active))
            if keys:
                print(f"[BRIDGE] {len(keys)} chave(s) em cache (mais recente: {base64.b64encode(keys[0]).decode()[:12]}...)")
            else:
                print("[BRIDGE] Servidor PQC sem chave activa (aguardar handshake ESP32).")
            return keys
        else:
            print(f"[BRIDGE] Erro na resposta do Servidor PQC. Código: {r.status_code}")
    except Exception as e:
        print(f"[BRIDGE] Não foi possível ligar ao Servidor PQC: {e}")
    return []

def get_or_refresh_keys(force_refresh=False) -> list:
    """Retorna lista de chaves em cache, actualiza se necessário."""
    global recent_keys
    if not recent_keys or force_refresh:
        keys = fetch_recent_keys()
        if keys:
            recent_keys = keys
        elif not recent_keys:
            print("[BRIDGE] Sem chaves disponíveis. À espera de handshake ESP32...")
    return recent_keys

def decrypt_with_any_key(payload_str: str) -> bytes:
    """Tenta decifrar com cada chave do histórico. Retorna plaintext ou lança ValueError."""
    keys = get_or_refresh_keys()
    for i, key in enumerate(keys):
        pt = ascon.decrypt_from_b64(key[:16], payload_str)
        if pt is not None:
            if i > 0:
                print(f"[BRIDGE] Decifrado com chave #{i+1} do histórico")
            return pt
    # Falhou com todas — actualizar e tentar de novo
    print("[BRIDGE] Todas as chaves em cache falharam. A actualizar histórico...")
    keys = get_or_refresh_keys(force_refresh=True)
    for key in keys:
        pt = ascon.decrypt_from_b64(key[:16], payload_str)
        if pt is not None:
            return pt
    raise ValueError(f"Falha de autenticação ASCON-128 com todas as {len(keys)} chave(s) conhecidas")

# ====================================================================
# ARMAZENAMENTO NO INFLUXDB (CAMADA STORAGE / TIME-SERIES)
# ====================================================================
def write_to_influx(data: dict):
    """Grava as métricas decifradas do sensor no InfluxDB v2."""
    node       = data.get("node", "unknown")
    fw_version = data.get("fw", "unknown")
    temp = data.get("temp")
    hum  = data.get("hum")

    # Campos de telemetria de performance enviados pelo ESP32
    PERF_FIELDS = {
        "ram_mb":        float,
        "throughput_bps": float,
        "loss_pct":      float,
        "deadline_pct":  float,
        "avg_lat_ms":    float,
        "jitter_ms":     float,
        "lwc_cpu_us":    float,
        "lwc_ram_kb":    float,
    }

    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            write_api = client.write_api(write_options=SYNCHRONOUS)

            # Payload ambiental: temp + hum
            if temp is not None and hum is not None:
                point = Point("telemetry_environment") \
                    .tag("node", node) \
                    .tag("fw_version", fw_version) \
                    .field("temperature", float(temp)) \
                    .field("humidity",    float(hum))
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                print(f"[BRIDGE] [INFLUXDB] Gravado -> Nó: {node} | Temp: {temp}°C | Hum: {hum}%")

            # Payload de performance/métricas LWC
            perf_fields = {k: cast(data[k]) for k, cast in PERF_FIELDS.items() if k in data}
            if perf_fields:
                point = Point("telemetry_performance").tag("node", node).tag("fw_version", fw_version)
                for field, value in perf_fields.items():
                    point = point.field(field, value)
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                print(f"[BRIDGE] [INFLUXDB] Gravado perf -> Nó: {node} | {list(perf_fields.keys())}")

            # Payload de estado do relé
            relay = data.get("relay")
            if relay is not None:
                point = Point("telemetry_relay") \
                    .tag("node", node) \
                    .tag("fw_version", fw_version) \
                    .field("relay_state", int(relay)) \
                    .field("status", str(data.get("status", "unknown")))
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                print(f"[BRIDGE] [INFLUXDB] Gravado relay -> Nó: {node} | Estado: {relay}")

            # Payload do handshake (custo assimétrico Kyber768)
            has_hs = "hs_latency_ms" in data
            if has_hs:
                point = Point("telemetry_handshake").tag("node", node).tag("fw_version", fw_version) \
                    .tag("kex_algo", str(data.get("kex_algo", "")))
                for field in ("hs_latency_ms", "hs_req_bytes", "hs_resp_bytes"):
                    if field in data:
                        point = point.field(field, float(data[field]))
                write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=point)
                print(f"[BRIDGE] [INFLUXDB] Gravado handshake -> Nó: {node} | {data.get('hs_latency_ms')}ms")

            if temp is None and hum is None and not perf_fields and relay is None and not has_hs:
                print(f"[BRIDGE] [INFLUXDB] Payload sem campos reconhecidos, ignorado: {data}")

    except Exception as e:
        print(f"[BRIDGE] [INFLUXDB] Erro de escrita: {e}")

# ====================================================================
# CALLBACKS MQTT (BROKER EMQX CONNECTION)
# ====================================================================
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[BRIDGE] Ligado com sucesso ao broker EMQX ({MQTT_HOST}:{MQTT_PORT})!")
        client.subscribe(MQTT_TOPIC)
        print(f"[BRIDGE] Subscrito ao tópico seguro: {MQTT_TOPIC}")
    else:
        print(f"[BRIDGE] Falha ao ligar ao EMQX. Código de retorno: {rc}")

def on_message(client, userdata, msg):
    try:
        # Extrai o MAC do tópico MQTT: "BRAVO/<MAC>/telemetria" → parts[1]
        topic_parts = msg.topic.split("/")
        topic_mac = topic_parts[1] if len(topic_parts) >= 2 else "unknown"

        payload_str = msg.payload.decode('utf-8')
        print(f"\n[BRIDGE] [{msg.topic}] Payload recebido: {payload_str[:60]}...")

        if not get_or_refresh_keys():
            print("[BRIDGE] Sem chaves disponíveis. Mensagem ignorada.")
            return

        pt_bytes = decrypt_with_any_key(payload_str)
        decrypted = pt_bytes.decode('utf-8')
        data = json.loads(decrypted)
        print(f"[BRIDGE] Decifrado ASCON-128: {decrypted}")

        # Garante que o nó corresponde ao MAC do tópico MQTT
        payload_node = data.get("node")
        if payload_node and payload_node != topic_mac:
            print(f"[BRIDGE] AVISO: node no payload ({payload_node}) != MAC do tópico ({topic_mac})")
        data["node"] = topic_mac  # tópico é a fonte autoritária

        write_to_influx(data)

    except Exception as e:
        print(f"[BRIDGE] Erro no processamento da telemetria: {e}")

# ====================================================================
# LOOP PRINCIPAL
# ====================================================================
if __name__ == "__main__":
    print("==========================================================")
    print(" PQC TELEMETRY INGESTION BRIDGE INICIADA ")
    print("==========================================================")
    
    # Aguarda inicialização do InfluxDB e EMQX na Stack
    time.sleep(5)
    
    # Inicia primeira tentativa de obter o histórico de chaves
    get_or_refresh_keys()
    
    # Configura e liga cliente MQTT
    client = mqtt.Client("msi_pqc_ingestion_bridge")
    client.on_connect = on_connect
    client.on_message = on_message
    
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, 60)
            break
        except Exception as e:
            print(f"[BRIDGE] A aguardar broker EMQX no host {MQTT_HOST}... Tentativa em 5s.")
            time.sleep(5)
            
    client.loop_forever()
