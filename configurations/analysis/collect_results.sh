#!/bin/bash
# collect_results.sh — Recolhe TODAS as evidencias do run de 24h para results/run-<DIA>/.
# Corre no WSL, DEPOIS do teste terminar (janela 00:00-23:59 hora local WEST=UTC+1).
# Uso: bash collect_results.sh [YYYY-MM-DD]     (default: 2026-07-21)
#
# Produz:
#   results/run-<DIA>/influx/    CSV por fase e measurement (InfluxDB export, janela do run)
#   results/run-<DIA>/pcaps/     pcaps por VLAN (do suricata-a)
#   results/run-<DIA>/suricata/  eve.json (alertas) do sensor SPAN
#   results/run-<DIA>/metrics/   saida do extract_24h.py (metricas crypto normalizadas)
#   results/run-<DIA>/status/    status_panel.html + validate_telemetry
#   results/run-<DIA>/MANIFEST.txt
set -u
DAY="${1:-2026-07-21}"
REPO=/mnt/c/viper5000/git/MSI-TESE
ANA="$REPO/Configurations/analysis"
OUT="$REPO/results/run-$DAY"
export SSHPASS=password
TOK=my-super-secret-auth-token-12345678
SURICATA=192.168.100.250
SSH="sshpass -e ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
# janela do run em RFC3339 (UTC). Este run começou 00:09 e acabou 00:10 do dia seguinte
# (offset do fix inicial do tcpdump); alargada com margem p/ cobrir tudo. Override: START/STOP env.
START="${START:-2026-07-20T23:00:00Z}"
STOP="${STOP:-2026-07-21T23:15:00Z}"
mkdir -p "$OUT"/{influx,pcaps,suricata,metrics,status}

echo "### 1/5 — Export InfluxDB (3 fases, janela $START .. $STOP)"
declare -A PH=( [alpha]=192.168.100.60 [bravo]=192.168.20.60 [charlie]=192.168.30.60 )
for ph in alpha bravo charlie; do
  ip=${PH[$ph]}
  for meas in telemetry_environment telemetry_performance telemetry_handshake telemetry_relay suricata_alerts suricata_stats energy; do
    curl -s -X POST "http://$ip:8086/api/v2/query?org=msi-tese" \
      -H "Authorization: Token $TOK" -H "Accept: application/csv" -H "Content-type: application/vnd.flux" \
      --data "from(bucket:\"telemetry\") |> range(start: ${START}, stop: ${STOP}) |> filter(fn:(r)=>r._measurement==\"$meas\")" \
      2>/dev/null | tr -d '\r' > "$OUT/influx/${ph}_${meas}.csv"
    echo "   $ph/$meas: $(($(wc -l < "$OUT/influx/${ph}_${meas}.csv")-1)) linhas"
  done
done

echo "### 2/5 — pcaps (do suricata-a $SURICATA)"
D=$($SSH pi@$SURICATA 'cat /home/pi/pcaps/.current 2>/dev/null' 2>/dev/null | tr -d '\r')
if [ -n "$D" ]; then
  # tar via sudo (pcaps sao root) e extrair no destino
  $SSH pi@$SURICATA "echo password | sudo -S -p '' tar cf - -C '$D' ." 2>/dev/null | tar xf - -C "$OUT/pcaps/" 2>/dev/null
  echo "   $(ls "$OUT/pcaps"/*.pcap* 2>/dev/null | wc -l) ficheiros pcap ($(du -sh "$OUT/pcaps" 2>/dev/null | cut -f1))"
else echo "   AVISO: dir de pcaps nao encontrado (.current vazio)"; fi

echo "### 3/5 — Suricata eve.json (alertas do SPAN)"
$SSH pi@$SURICATA "echo password | sudo -S -p '' bash -c 'grep -h \"\\\"event_type\\\":\\\"alert\\\"\" /var/log/suricata/eve.json 2>/dev/null; zcat /var/log/suricata/eve.json.*.gz 2>/dev/null | grep -h \"\\\"event_type\\\":\\\"alert\\\"\"'" 2>/dev/null > "$OUT/suricata/alerts.json"
echo "   $(wc -l < "$OUT/suricata/alerts.json") alertas"

echo "### 4/5 — extract_24h.py (metricas crypto normalizadas)"
python3 "$ANA/extract_24h.py" --start "2026-07-20T23:10:00Z" --stop "2026-07-21T23:10:00Z" --out "$OUT/metrics/extract" > "$OUT/metrics/extract_summary.txt" 2>&1 || echo "   (ver extract_summary.txt)"

echo "### 5/5 — snapshots status + validacao"
( cd "$ANA" && python3 status_panel.py >/dev/null 2>&1 && cp status_panel.html "$OUT/status/" )
( cd "$ANA" && python3 validate_telemetry.py > "$OUT/status/validate_telemetry.txt" 2>&1 )

{ echo "MSI-TESE — Run de 24h — $DAY (00:00-23:59 WEST)"; echo "Recolhido: $(date '+%Y-%m-%d %H:%M:%S %Z')";
  echo; echo "InfluxDB CSV:"; ls "$OUT/influx"; echo; echo "pcaps:"; ls -lh "$OUT/pcaps" 2>/dev/null;
  echo; echo "alertas Suricata: $(wc -l < "$OUT/suricata/alerts.json") linhas"; } > "$OUT/MANIFEST.txt"

echo ""
echo ">>> Recolha completa em: $OUT"
du -sh "$OUT"
