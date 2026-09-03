#!/bin/bash
# MSI-TESE — Stop all edge services on viper-gateway-b
# Run on: pi@192.168.20.100

PW="password"

echo "╔══════════════════════════════════════════╗"
echo "║   MSI-TESE  —  Stop Services             ║"
echo "║   viper-gateway-b (192.168.20.100)        ║"
echo "╚══════════════════════════════════════════╝"
echo ""

stop_svc() {
    local name=$1
    echo -n "  [■] $name ... "
    echo "$PW" | sudo -S systemctl stop "$name" 2>/dev/null
    sleep 1
    status=$(systemctl is-active "$name" 2>/dev/null)
    if [ "$status" = "inactive" ] || [ "$status" = "failed" ]; then
        echo "PARADO"
    else
        echo "($status)"
    fi
}

echo "── Bridges PQC ─────────────────────────────"
stop_svc pqc-gateway
stop_svc pqc-bridge

echo ""
echo "── Infraestrutura ──────────────────────────"
stop_svc grafana-server
stop_svc influxdb
stop_svc emqx

echo ""
echo "── Estado Final ────────────────────────────"
for svc in emqx influxdb grafana-server pqc-bridge pqc-gateway; do
    state=$(systemctl is-active "$svc" 2>/dev/null)
    if [ "$state" = "inactive" ]; then
        printf "  ✓ %-22s %s\n" "$svc" "STOPPED"
    else
        printf "  ✗ %-22s %s\n" "$svc" "$state"
    fi
done
echo ""
