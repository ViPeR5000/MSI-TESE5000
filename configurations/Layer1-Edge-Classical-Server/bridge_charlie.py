"""
Bridge Charlie — MQTT → InfluxDB
Decifra AES-128-GCM (wire: Base64(iv[12]|ct|tag[16])) e grava em InfluxDB.
Chave obtida via GET /monitor → active_session_key_b64 (HKDF output, 16 bytes).
"""
import os, base64, json, time, logging
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests, urllib3

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bridge-charlie")

MQTT_BROKER   = os.getenv("MQTT_BROKER",   "192.168.30.100")
MQTT_PORT     = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC    = os.getenv("MQTT_TOPIC",    "CHARLIE/#")

INFLUX_URL    = os.getenv("INFLUX_URL",    "http://192.168.30.100:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN",  "my-super-secret-auth-token-12345678")
INFLUX_ORG    = os.getenv("INFLUX_ORG",    "msi-tese")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "telemetry")

CLASSICAL_SERVER_URL = os.getenv("CLASSICAL_SERVER_URL", "http://192.168.30.200:8000/monitor")
CLASSICAL_TLS_CERT   = os.getenv("CLASSICAL_TLS_CERT_PATH", "")
_tls_verify = CLASSICAL_TLS_CERT if CLASSICAL_TLS_CERT else False
if not _tls_verify:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session_keys: list[bytes] = []   # rolling history, newest last

influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx.write_api(write_options=SYNCHRONOUS)


def fetch_keys():
    global session_keys
    try:
        r = requests.get(CLASSICAL_SERVER_URL, verify=_tls_verify, timeout=5)
        r.raise_for_status()
        data = r.json()
        keys = []
        if data.get("active_session_key_b64"):
            keys.append(base64.b64decode(data["active_session_key_b64"]))
        for k in data.get("recent_session_keys_b64", []):
            kb = base64.b64decode(k)
            if kb not in keys:
                keys.append(kb)
        session_keys = keys
        log.info(f"Chaves obtidas do servidor clássico: {len(session_keys)} disponíveis.")
    except Exception as e:
        log.error(f"Falha ao obter chave do servidor: {e}")


def decrypt_aes_gcm(b64_payload: str) -> bytes | None:
    try:
        wire = base64.b64decode(b64_payload)
        if len(wire) < 28: return None      # iv(12) + tag(16) minimum
        iv  = wire[:12]
        ct  = wire[12:]                     # AESGCM expects ct+tag concatenated
        for key in reversed(session_keys):  # newest first
            try:
                return AESGCM(key).decrypt(iv, ct, None)
            except Exception:
                pass
        return None
    except Exception:
        return None


def write_to_influx(data: dict):
    node = data.get("node", "unknown")
    fw   = data.get("fw",   "unknown")

    if "temp" in data or "hum" in data:
        p = (Point("telemetry_environment")
             .tag("node", node).tag("fw_version", fw)
             .tag("phase", "charlie"))
        if "temp" in data: p = p.field("temperature", float(data["temp"]))
        if "hum"  in data: p = p.field("humidity",    float(data["hum"]))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] environment → InfluxDB")

    if "throughput_bps" in data or "aead_cpu_us" in data:
        p = (Point("telemetry_performance")
             .tag("node", node).tag("fw_version", fw)
             .tag("phase", "charlie"))
        for field in ("ram_mb","throughput_bps","loss_pct","deadline_pct",
                      "avg_lat_ms","jitter_ms","aead_cpu_us","aead_ram_kb"):
            if field in data: p = p.field(field, float(data[field]))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] performance → InfluxDB")

    if "relay" in data:
        p = (Point("telemetry_relay")
             .tag("node", node).tag("fw_version", fw)
             .tag("phase", "charlie")
             .field("relay_state", int(data["relay"]))
             .field("status", str(data.get("status", ""))))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] relay → InfluxDB")

    if "hs_latency_ms" in data:
        p = (Point("telemetry_handshake")
             .tag("node", node).tag("fw_version", fw)
             .tag("phase", "charlie")
             .tag("kex_algo", str(data.get("kex_algo", ""))))
        for field in ("hs_latency_ms", "hs_req_bytes", "hs_resp_bytes"):
            if field in data:
                p = p.field(field, float(data[field]))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] handshake → InfluxDB")


def on_message(client, userdata, msg):
    try:
        parts = msg.topic.split("/")
        node_mac = parts[1] if len(parts) >= 2 else "unknown"
        b64_payload = msg.payload.decode("utf-8")

        pt = decrypt_aes_gcm(b64_payload)
        if pt is None:
            log.warning(f"[{node_mac}] Decifração AES-GCM falhou — a refrescar chave...")
            fetch_keys()
            pt = decrypt_aes_gcm(b64_payload)
        if pt is None:
            log.error(f"[{node_mac}] Decifração falhou mesmo após refresh.")
            return

        data = json.loads(pt)
        data["node"] = node_mac    # tópico é autoritativo
        write_to_influx(data)

    except Exception as e:
        log.error(f"Erro em on_message: {e}")


def on_connect(client, userdata, flags, rc):
    log.info(f"MQTT conectado (rc={rc}), a subscrever {MQTT_TOPIC}")
    client.subscribe(MQTT_TOPIC)


fetch_keys()

mqttc = mqtt.Client()
mqttc.on_connect = on_connect
mqttc.on_message = on_message
mqttc.connect(MQTT_BROKER, MQTT_PORT, 60)

log.info("Bridge Charlie iniciada.")
mqttc.loop_start()

while True:
    time.sleep(3600)
    fetch_keys()
