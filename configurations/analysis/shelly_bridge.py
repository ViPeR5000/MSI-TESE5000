#!/usr/bin/env python3
"""
shelly_bridge.py — Shelly Plug S Gen3 (MQTT) -> InfluxDB (measurement `energy`).

Subscreve shelly/+/status/switch:0 no broker e escreve, por fase:
  measurement energy, tag phase=<alpha|bravo|charlie|test>,
  fields power_w (apower), total_wh (aenergy.total), voltage_v.
Corre como serviço systemd no viper-scada-a (alcança o broker 100.100 e o InfluxDB 100.60).
"""
import json, os
import paho.mqtt.client as mqtt
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

BROKER = os.getenv("MQTT_BROKER", "192.168.100.100")
BPORT  = int(os.getenv("MQTT_PORT", "1883"))
INFLUX = os.getenv("INFLUX_URL", "http://192.168.100.60:8086")
TOKEN  = os.getenv("INFLUX_TOKEN", "my-super-secret-auth-token-12345678")
ORG    = os.getenv("INFLUX_ORG", "msi-tese")
BUCKET = os.getenv("INFLUX_BUCKET", "telemetry")

influx = InfluxDBClient(url=INFLUX, token=TOKEN, org=ORG)
wapi = influx.write_api(write_options=SYNCHRONOUS)

def on_message(c, u, m):
    try:
        parts = m.topic.split("/")          # shelly/<phase>/status/switch:0
        phase = parts[1] if len(parts) > 1 else "unknown"
        d = json.loads(m.payload.decode())
        p = Point("energy").tag("phase", phase)
        got = False
        if d.get("apower") is not None:  p.field("power_w", float(d["apower"])); got = True
        if d.get("voltage") is not None: p.field("voltage_v", float(d["voltage"]))
        tot = (d.get("aenergy") or {}).get("total")
        if tot is not None:              p.field("total_wh", float(tot)); got = True
        if got:
            wapi.write(bucket=BUCKET, record=p)
            print(f"[{phase}] power={d.get('apower')}W total={tot}Wh -> InfluxDB", flush=True)
    except Exception as e:
        print("erro on_message:", e, flush=True)

def on_connect(c, u, flags, rc):
    print(f"MQTT conectado (rc={rc}), a subscrever shelly/+/status/switch:0", flush=True)
    c.subscribe("shelly/+/status/switch:0")

mqttc = mqtt.Client()
mqttc.on_connect = on_connect
mqttc.on_message = on_message
print(f"Shelly bridge: broker {BROKER}:{BPORT} -> InfluxDB {INFLUX}", flush=True)
mqttc.connect(BROKER, BPORT, 60)
mqttc.loop_forever()
