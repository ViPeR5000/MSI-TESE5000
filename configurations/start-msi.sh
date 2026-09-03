#!/bin/bash
# MSI-TESE — Start all edge services on viper-gateway-b
# Run on: pi@192.168.20.100

set -e
PW="password"

echo "╔══════════════════════════════════════════╗"
echo "║   MSI-TESE  —  Start Services            ║"
echo "║   viper-gateway-b (192.168.20.100)        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

start_svc() {
    local name=$1
    echo -n "  [→] $name ... "
    echo "$PW" | sudo -S systemctl start "$name" 2>/dev/null
    sleep 1
    status=$(systemctl is-active "$name" 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo "OK"
    else
        echo "FALHOU ($status)"
    fi
}

echo "── Infraestrutura ──────────────────────────"
start_svc emqx
start_svc influxdb
start_svc grafana-server

echo ""
echo "── Bridges PQC ─────────────────────────────"
start_svc pqc-bridge
start_svc pqc-gateway

echo ""
echo "── Estado Final ────────────────────────────"
for svc in emqx influxdb grafana-server pqc-bridge pqc-gateway; do
    state=$(systemctl is-active "$svc" 2>/dev/null)
    if [ "$state" = "active" ]; then
        printf "  ✓ %-22s %s\n" "$svc" "RUNNING"
    else
        printf "  ✗ %-22s %s\n" "$svc" "$state"
    fi
done

echo ""
echo "── Endpoints ───────────────────────────────"
echo "  PQC Dashboard  →  http://192.168.20.200:8000/dashboard"
echo "  EMQX           →  http://192.168.20.100:18083"
echo "  Grafana        →  http://192.168.20.100:3000"
echo "  InfluxDB       →  http://192.168.20.100:8086"
echo ""
