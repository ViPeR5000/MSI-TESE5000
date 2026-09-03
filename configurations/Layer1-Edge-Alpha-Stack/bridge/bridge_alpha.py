#!/usr/bin/env python3
"""
Bridge Alpha — MQTT → InfluxDB (baseline plaintext, sem criptografia).

Substitui o Telegraf por um bridge Python coerente com o Bravo/Charlie: subscreve
o broker Alpha, faz o parse do JSON em claro (não há nada para decifrar) e grava
nas mesmas medições/campos que as fases seguras (`temperature`/`humidity`,
`telemetry_performance`, tag `phase=alpha`), para a comparação entre fases ser
directa. Sem servidor de chaves, sem handshake — é a baseline.
"""
import os, json, logging
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("bridge-alpha")

MQTT_BROKER   = os.getenv("MQTT_BROKER",   "192.168.100.100")
MQTT_PORT     = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC    = os.getenv("MQTT_TOPIC",    "ALPHA/#")

INFLUX_URL    = os.getenv("INFLUX_URL",    "http://192.168.100.60:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN",  "my-super-secret-auth-token-12345678")
INFLUX_ORG    = os.getenv("INFLUX_ORG",    "msi-tese")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "telemetry")

PERF_FIELDS = ("ram_mb", "throughput_bps", "loss_pct", "deadline_pct",
               "avg_lat_ms", "jitter_ms", "lwc_cpu_us", "lwc_ram_kb")

influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx.write_api(write_options=SYNCHRONOUS)


def write_to_influx(data: dict):
    node = data.get("node", "unknown")
    fw   = data.get("fw",   "unknown")

    if "temp" in data or "hum" in data:
        p = (Point("telemetry_environment")
             .tag("node", node).tag("fw_version", fw).tag("phase", "alpha"))
        if "temp" in data: p = p.field("temperature", float(data["temp"]))
        if "hum"  in data: p = p.field("humidity",    float(data["hum"]))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] environment → InfluxDB")

    if any(f in data for f in PERF_FIELDS):
        p = (Point("telemetry_performance")
             .tag("node", node).tag("fw_version", fw).tag("phase", "alpha"))
        for f in PERF_FIELDS:
            if f in data:
                p = p.field(f, float(data[f]))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] performance → InfluxDB")

    if "relay" in data:
        p = (Point("telemetry_relay")
             .tag("node", node).tag("fw_version", fw).tag("phase", "alpha")
             .field("relay_state", int(data["relay"]))
             .field("status", str(data.get("status", ""))))
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        log.info(f"[{node}] relay → InfluxDB")


def on_message(client, userdata, msg):
    try:
        parts = msg.topic.split("/")
        node_mac = parts[1] if len(parts) >= 2 else "unknown"
        data = json.loads(msg.payload.decode("utf-8"))
        data["node"] = node_mac    # o tópico é autoritativo
        write_to_influx(data)
    except Exception as e:
        log.error(f"Erro em on_message ({msg.topic}): {e}")


def on_connect(client, userdata, flags, rc):
    log.info(f"MQTT conectado (rc={rc}), a subscrever {MQTT_TOPIC}")
    client.subscribe(MQTT_TOPIC)


mqttc = mqtt.Client()
mqttc.on_connect = on_connect
mqttc.on_message = on_message
log.info(f"Bridge Alpha iniciada. Broker {MQTT_BROKER}:{MQTT_PORT} → InfluxDB {INFLUX_URL}")
mqttc.connect(MQTT_BROKER, MQTT_PORT, 60)
mqttc.loop_forever()
