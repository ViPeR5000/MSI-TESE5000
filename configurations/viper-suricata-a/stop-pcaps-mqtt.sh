#!/bin/bash
# Para SO as capturas MQTT (filtro "tcp port 1883") — nao toca na full-take de 24h.
pkill -INT -f "tcp port 1883"; sleep 3
D=$(cat /home/pi/pcaps/.mqtt.current 2>/dev/null)
echo "Capturas MQTT paradas. Ficheiros em $D:"; ls -lh "$D" 2>/dev/null
for f in "$D"/*; do [ -f "$f" ] && echo "  $(basename "$f"): $(tcpdump -nn -r "$f" 2>/dev/null | wc -l) pkts"; done
