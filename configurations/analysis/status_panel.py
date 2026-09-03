#!/usr/bin/env python3
"""
Painel de status de TODOS os equipamentos do testbed MSI-TESE (Alpha/Bravo/
Charlie/Delta). Sonda cada host por TCP (porta de liveness) e reporta ONLINE/
OFFLINE. Imprime uma tabela no terminal e escreve um painel HTML (snapshot).

Corre de qualquer host que alcance as VLANs 20/30/100:
  python3 status_panel.py            # tabela + status_panel.html
"""
import socket, sys, subprocess
from concurrent.futures import ThreadPoolExecutor

# (fase, nome, ip, porta, papel)
INV = [
    # ---- ALPHA (VLAN 100, plaintext) ----
    ("Alpha","viper-gateway-a","192.168.100.100",22,"EMQX/gateway"),
    ("Alpha","viper-scada-a",  "192.168.100.60", 22,"InfluxDB/Grafana/Node-RED"),
    ("Alpha","viper-plc-a",    "192.168.100.50", 22,"OpenPLC"),
    ("Alpha","viper-suricata-a","192.168.100.250",22,"IDS (SPAN 100/20/30)"),
    ("Alpha","esp-tempsensor", "192.168.100.11", 80,"ESP32 TempSensor"),
    ("Alpha","esp-kineticnode","192.168.100.12", 80,"ESP32 KineticNode"),
    ("Alpha","esp-relay",      "192.168.100.13", 80,"ESP32 Relay"),
    # ---- BRAVO (VLAN 20, PQC/LWC) ----
    ("Bravo","viper-keysb",    "192.168.20.200",8000,"PQC Key Server (via gw)"),
    ("Bravo","viper-gateway-b","192.168.20.100",22,"EMQX/gateway"),
    ("Bravo","viper-scada-b",  "192.168.20.60", 22,"InfluxDB/Grafana/Node-RED"),
    ("Bravo","viper-plc-b",    "192.168.20.50", 22,"OpenPLC"),
    ("Bravo","viper-suricata-b","192.168.20.250",22,"IDS Suricata 7.0.10 (wlan0 — sem tráfego; precisa eth0+SPAN)"),
    ("Bravo","esp-tempsensor", "192.168.20.11", 80,"ESP32 TempSensor"),
    ("Bravo","esp-kineticnode","192.168.20.12", 80,"ESP32 KineticNode"),
    ("Bravo","esp-relay",      "192.168.20.13", 80,"ESP32 Relay"),
    # ---- CHARLIE (VLAN 30, clássico) ----
    ("Charlie","viper-pki-c",    "192.168.30.200",8000,"Classical Key Server (via gw)"),
    ("Charlie","viper-gateway-c","192.168.30.100",22,"EMQX/gateway"),
    ("Charlie","viper-scada-c",  "192.168.30.60", 22,"InfluxDB/Grafana/Node-RED"),
    ("Charlie","viper-plc-c",    "192.168.30.50", 22,"OpenPLC"),
    ("Charlie","viper-suricata-c","192.168.30.250",22,"IDS Suricata 7.0.10 (eth0)"),
    ("Charlie","esp-tempsensor", "192.168.30.11", 80,"ESP32 TempSensor"),
    ("Charlie","esp-kineticnode","192.168.30.12", 80,"ESP32 KineticNode"),
    ("Charlie","esp-relay",      "192.168.30.13", 80,"ESP32 Relay"),
    # ---- DELTA (VLAN 40, digital twin — planeado) ----
    ("Delta","viper-keys-d",   "192.168.40.200",22,"Key Server (planeado)"),
    ("Delta","viper-gateway-d","192.168.40.100",22,"Gateway (planeado)"),
    ("Delta","viper-scada-d",  "192.168.40.60", 22,"SCADA (planeado)"),
]

def _direct(ip, port, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False

def probe(ip, port, timeout=2.0):
    if _direct(ip, port, timeout):
        return True
    # Os key servers .200 nao sao rotaveis a partir do WSL -> sondar via o
    # gateway .100 da fase (que os alcanca) no proprio servico.
    if ip.endswith(".200"):
        gw = ip.rsplit(".", 1)[0] + ".100"
        try:
            r = subprocess.run(
                ["sshpass", "-p", "password", "ssh",
                 "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 f"pi@{gw}",
                 f'timeout 3 bash -c "cat </dev/null >/dev/tcp/{ip}/{port}"'],
                capture_output=True, timeout=12)
            return r.returncode == 0
        except Exception:
            return False
    return False

def main():
    with ThreadPoolExecutor(max_workers=32) as ex:
        results = list(ex.map(lambda r: (r, probe(r[2], r[3])), INV))

    # terminal
    C={"g":"\033[92m","r":"\033[91m","y":"\033[93m","d":"\033[0m","b":"\033[1m"}
    up=sum(1 for _,ok in results if ok)
    print(f"\n{C['b']}MSI-TESE — Status dos Equipamentos{C['d']}  ({up}/{len(results)} online)\n")
    ph=None
    for (fase,nome,ip,port,papel),ok in results:
        if fase!=ph: print(f"{C['b']}── {fase} ──{C['d']}"); ph=fase
        mark=f"{C['g']}● ONLINE {C['d']}" if ok else f"{C['r']}○ OFFLINE{C['d']}"
        print(f"  {mark} {nome:<18} {ip:<16} :{port:<3} {papel}")

    # HTML snapshot
    rows=""
    ph=None
    for (fase,nome,ip,port,papel),ok in results:
        if fase!=ph:
            rows+=f'<tr class="ph"><td colspan="5">{fase}</td></tr>'; ph=fase
        cls="on" if ok else "off"
        badge="● ONLINE" if ok else "○ OFFLINE"
        rows+=(f'<tr><td class="{cls}">{badge}</td><td class="n">{nome}</td>'
               f'<td class="mono">{ip}:{port}</td><td>{papel}</td></tr>')
    html=f"""<!doctype html><meta charset=utf-8><title>MSI-TESE Status</title>
<meta http-equiv=refresh content=30>
<style>
 body{{background:#0b1020;color:#e5e7eb;font-family:system-ui,sans-serif;margin:0;padding:28px}}
 h1{{font-weight:700;font-size:1.4rem;margin:0 0 4px}} .sub{{color:#94a3b8;margin-bottom:20px}}
 table{{border-collapse:collapse;width:100%;max-width:900px}}
 td{{padding:8px 12px;border-bottom:1px solid #1e293b}}
 tr.ph td{{background:#111827;color:#93c5fd;font-weight:700;text-transform:uppercase;letter-spacing:.5px;font-size:.8rem}}
 .on{{color:#4ade80;font-weight:700}} .off{{color:#f87171;font-weight:700}}
 .n{{font-weight:600}} .mono{{font-family:ui-monospace,monospace;color:#cbd5e1}}
 .k{{display:inline-block;background:#1e293b;border-radius:8px;padding:6px 12px;margin-right:8px}}
</style>
<h1>MSI-TESE · Status dos Equipamentos</h1>
<div class=sub><span class=k><b style="color:#4ade80">{up}</b> online</span>
<span class=k><b style="color:#f87171">{len(results)-up}</b> offline</span>
<span class=k>total {len(results)}</span> · auto-refresh 30s</div>
<table>{rows}</table>"""
    with open("status_panel.html","w") as f: f.write(html)
    print(f"\nHTML: status_panel.html")

if __name__=="__main__": main()
