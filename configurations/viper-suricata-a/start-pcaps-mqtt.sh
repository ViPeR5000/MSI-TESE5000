#!/bin/bash
# Como start-pcaps.sh mas SO trafego MQTT (tcp/1883) por VLAN testbed. Dir proprio -> coexiste
# com a captura full-take. Parar com stop-pcaps-mqtt.sh (mata so estes, pelo filtro 1883).
# -Z root: senao o tcpdump larga privilegios p/ user 'tcpdump' e leva Permission denied.
DIR=/home/pi/pcaps/mqtt-$(date +%Y%m%d-%H%M%S)
mkdir -p "$DIR"
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 200 -w "$DIR/alpha-vlan100.pcap"  vlan 100 and tcp port 1883 </dev/null >/dev/null 2>&1 &
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 200 -w "$DIR/bravo-vlan20.pcap"   vlan 20  and tcp port 1883 </dev/null >/dev/null 2>&1 &
setsid tcpdump -i eth0 -nn -s 0 -Z root -C 200 -w "$DIR/charlie-vlan30.pcap" vlan 30  and tcp port 1883 </dev/null >/dev/null 2>&1 &
sleep 4
echo "$DIR" > /home/pi/pcaps/.mqtt.current
echo "Capturas MQTT a correr em: $DIR  (rotacao 200MB/ficheiro)"; ls -la "$DIR"
echo "PIDs tcpdump MQTT:"; pgrep -af "tcp port 1883"
df -h / | awk 'NR==2{print "SSD livre:",$4}'
