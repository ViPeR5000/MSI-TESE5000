#!/usr/bin/env python3
"""
suricata_influx.py — tails Suricata's eve.json and streams IDS alerts (and light
stats) into the phase InfluxDB, so they can be analysed in Grafana alongside the
rest of the MSI-TESE telemetry.

Runs ON the sensor host (e.g. viper-suricata-b @ 192.168.20.250) as a systemd
service. Follows the log across rotation/truncation and persists its read offset
so a restart does not replay old alerts.

Measurements written to bucket `telemetry`:
  suricata_alerts  tags: sensor, signature, category, severity, action, proto,
                         src_ip, dest_ip   (IP cardinality is tiny in a lab VLAN)
                   fields: count=1, sid, src_port, dest_port
  suricata_stats   tags: sensor
                   fields: pkts, drops, alerts  (from Suricata's periodic stats)

TPR/FPR/FNR are NOT computed here — they require labelled ground truth (which
flows were attack vs benign) and are derived offline in Configurations/analysis.
This service only records what Suricata actually fired.
"""
import os, json, time, sys
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

INFLUXDB_URL    = os.getenv("INFLUXDB_URL", "http://192.168.20.60:8086")
INFLUXDB_TOKEN  = os.getenv("INFLUXDB_TOKEN", "my-super-secret-auth-token-12345678")
INFLUXDB_ORG    = os.getenv("INFLUXDB_ORG", "msi-tese")
INFLUXDB_BUCKET = os.getenv("INFLUXDB_BUCKET", "telemetry")
EVE_PATH        = os.getenv("SURICATA_EVE", "/var/log/suricata/eve.json")
SENSOR          = os.getenv("SURICATA_SENSOR", "bravo")   # phase tag
STATE_FILE      = os.getenv("SURICATA_STATE", "/var/lib/suricata-influx/pos.json")


def log(m): print(f"[SURICATA-INFLUX] {m}", flush=True)


def load_pos():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
            return d.get("inode"), d.get("offset", 0)
    except Exception:
        return None, 0


def save_pos(inode, offset):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump({"inode": inode, "offset": offset}, f)
    except Exception as e:
        log(f"warn: could not persist offset: {e}")


_PHASE_BY_VLAN = {"100": "alpha", "20": "bravo", "30": "charlie"}


def vlan_of(ev):
    """VLAN id for the event: prefer Suricata's decoded 802.1Q tag, else derive
    from the 192.168.<vlan>.x subnet of dest/src (works even on an untagged span)."""
    v = ev.get("vlan")
    if v:
        return str(v[0])
    for ip in (ev.get("dest_ip", ""), ev.get("src_ip", "")):
        octs = ip.split(".")
        if len(octs) == 4 and octs[0] == "192" and octs[1] == "168" and octs[2] in _PHASE_BY_VLAN:
            return octs[2]
    return "untagged"


def alert_point(ev):
    a = ev.get("alert", {})
    vlan = vlan_of(ev)
    # tags kept low-cardinality; per-host IPs go in fields
    p = (Point("suricata_alerts")
         .tag("sensor", SENSOR)
         .tag("vlan", vlan)
         .tag("phase", _PHASE_BY_VLAN.get(vlan, "unknown"))
         .tag("signature", str(a.get("signature", "unknown"))[:120])
         .tag("category", str(a.get("category", "uncategorized"))[:80])
         .tag("severity", str(a.get("severity", 0)))
         .tag("action", str(a.get("action", "")))
         .tag("proto", str(ev.get("proto", "")))
         .tag("src_ip", str(ev.get("src_ip", "")))
         .tag("dest_ip", str(ev.get("dest_ip", "")))
         .field("count", 1)
         .field("sid", int(a.get("signature_id", 0)))
         .field("src_port", int(ev.get("src_port", 0) or 0))
         .field("dest_port", int(ev.get("dest_port", 0) or 0)))
    return p


def stats_point(ev):
    s = ev.get("stats", {})
    cap = s.get("capture", {})
    dec = s.get("decoder", {})
    det = s.get("detect", {})
    return (Point("suricata_stats")
            .tag("sensor", SENSOR)
            .field("pkts", int(dec.get("pkts", 0)))
            .field("drops", int(cap.get("kernel_drops", 0)))
            .field("alerts", int(det.get("alert", 0))))


def handle_line(line, write_api):
    line = line.strip()
    if not line:
        return
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return
    et = ev.get("event_type")
    pt = None
    if et == "alert":
        pt = alert_point(ev)
    elif et == "stats":
        pt = stats_point(ev)
    if pt is not None:
        write_api.write(bucket=INFLUXDB_BUCKET, org=INFLUXDB_ORG, record=pt)


def follow(write_api):
    inode, offset = load_pos()
    f = None
    cur_inode = None
    while True:
        try:
            st = os.stat(EVE_PATH)
        except FileNotFoundError:
            time.sleep(2); continue
        if f is None or st.st_ino != cur_inode:
            if f: f.close()
            f = open(EVE_PATH, "r", errors="replace")
            cur_inode = st.st_ino
            if inode is None:
                # first run ever: tail from EOF — do NOT replay a huge historical eve.json
                f.seek(0, 2)
            elif inode == cur_inode and offset <= st.st_size:
                f.seek(offset)              # resume where we left off
            else:
                f.seek(0)                   # log rotated: read the new file from the start
            inode = cur_inode               # subsequent reopens are rotations, not first run
            log(f"opened {EVE_PATH} inode={cur_inode} at offset {f.tell()}")
        # truncated?
        if f.tell() > st.st_size:
            f.seek(0)
        line = f.readline()
        if line:
            handle_line(line, write_api)
            save_pos(cur_inode, f.tell())
        else:
            time.sleep(0.5)


def main():
    log(f"eve={EVE_PATH} sensor={SENSOR} -> {INFLUXDB_URL} bucket={INFLUXDB_BUCKET}")
    while True:
        try:
            with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
                write_api = client.write_api(write_options=SYNCHRONOUS)
                follow(write_api)
        except KeyboardInterrupt:
            log("stopping"); return
        except Exception as e:
            log(f"error: {e} — retry in 5s"); time.sleep(5)


if __name__ == "__main__":
    main()
