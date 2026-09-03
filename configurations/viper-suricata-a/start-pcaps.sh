#!/bin/bash
# Arranca 3 capturas pcap (1 por VLAN testbed) no SSD do viper-suricata-a, destacadas p/ 24h.
# Filtro por TAG VLAN (SPAN e 802.1Q-tagged). Rotacao aos 500MB por ficheiro (-C 500, mantem
# todos os chunks: nome.pcap, nome.pcap1, nome.pcap2, ...). Corre COM sudo no 100.250.
# -Z root: sem isto o tcpdump larga privilegios p/ o user 'tcpdump' e leva Permission denied
#          na pasta de run (que e do root) -> morre logo sem gravar nada.
DIR=/home/pi/pcaps/run-$(date +%Y%m%d-%H%M%S)
mkdir -p "$DIR"
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 500 -w "$DIR/alpha-vlan100.pcap"  vlan 100 </dev/null >/dev/null 2>&1 &
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 500 -w "$DIR/bravo-vlan20.pcap"   vlan 20  </dev/null >/dev/null 2>&1 &
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 500 -w "$DIR/charlie-vlan30.pcap" vlan 30  </dev/null >/dev/null 2>&1 &
sleep 4
echo "$DIR" > /home/pi/pcaps/.current
echo "Capturas a correr em: $DIR  (rotacao 500MB/ficheiro)"; ls -la "$DIR"
echo "PIDs tcpdump:"; pgrep -a tcpdump
df -h / | awk 'NR==2{print "SSD livre:",$4}'
