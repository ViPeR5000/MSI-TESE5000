#!/usr/bin/env bash
# Verificação de saúde do run de 24 h: conta pontos nos últimos 5 min por fase.
# Correr de hora a hora (ou via cron/loop) para apanhar gaps cedo.
#   watch -n 3600 ./healthcheck.sh   # ou:  ./healthcheck.sh
set -u
TOKEN="my-super-secret-auth-token-12345678"; ORG="msi-tese"
declare -A H=( [alpha]=192.168.100.60 [bravo]=192.168.20.60 [charlie]=192.168.30.60 )
Q='from(bucket:"telemetry")|>range(start:-5m)|>filter(fn:(r)=>r._field=="avg_lat_ms")|>count()'
echo "== healthcheck $(date -u +%H:%M:%SZ) =="
for ph in alpha bravo charlie; do
  n=$(curl -s -XPOST "http://${H[$ph]}:8086/api/v2/query?org=$ORG" \
        -H "Authorization: Token $TOKEN" -H "Accept: application/csv" \
        -H "Content-Type: application/vnd.flux" --data-binary "$Q" 2>/dev/null \
      | awk -F, 'NR>1 && $6!=""{print $6}' | tail -1)
  if [ -n "${n:-}" ] && [ "$n" -gt 0 ] 2>/dev/null; then
    echo "  OK   $ph  ($n amostras/5min)"
  else
    echo "  FALHA $ph  (0 amostras — verificar nó/bridge)"
  fi
done
