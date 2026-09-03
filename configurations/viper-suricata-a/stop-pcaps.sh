#!/bin/bash
# Para as capturas (SIGINT -> fecha os pcap limpos) e mostra tamanhos + contagens.
pkill -INT tcpdump; sleep 3
D=$(cat /home/pi/pcaps/.current 2>/dev/null)
echo "Capturas paradas. Ficheiros em $D:"; ls -lh "$D" 2>/dev/null
for f in "$D"/*; do [ -f "$f" ] && echo "  $(basename "$f"): $(tcpdump -nn -r "$f" 2>/dev/null | wc -l) pkts"; done
