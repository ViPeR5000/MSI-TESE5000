#!/usr/bin/env bash
# Run ON the viper-suricata-c Pi (it's on ethernet now @ 192.168.1.70).
# Joins the ViPeR5000-Charlie WiFi with static 192.168.30.250, matching the
# other Charlie hosts (netplan + NetworkManager, gateway/DNS 192.168.30.1).
set -e

echo "######## DIAGNOSTIC ########"
echo "--- rfkill (WiFi soft/hard block?) ---";      sudo rfkill list || true
echo "--- wlan0 present/up? ---";                   ip link show wlan0 || echo "NO wlan0!"
echo "--- regulatory / country (blank => WiFi stays blocked) ---"; iw reg get | grep -m1 country || true
echo "--- NetworkManager / device state ---";       nmcli dev status || true
echo "--- can it even see the SSID? ---";           sudo nmcli dev wifi list 2>/dev/null | grep -i ViPeR || echo "SSID ViPeR5000-Charlie NOT visible"
echo "--- driver/firmware errors ---";              dmesg | grep -iE 'brcm|wlan|firmware|cfg80211' | tail -8 || true

echo "######## FIX ########"
# 1. #1 cause on RPi: WiFi country unset => rfkill blocks the radio.
sudo raspi-config nonint do_wifi_country PT || true
sudo rfkill unblock wifi || true
sudo rfkill unblock wlan || true

# 2. netplan config (same renderer as 30.60/30.100), static .250
sudo tee /etc/netplan/60-charlie-wifi.yaml >/dev/null <<'YAML'
network:
  version: 2
  renderer: NetworkManager
  wifis:
    wlan0:
      dhcp4: no
      addresses: [192.168.30.250/24]
      routes:
        - to: default
          via: 192.168.30.1
      nameservers:
        addresses: [192.168.30.1]
      access-points:
        "ViPeR5000-Charlie":
          password: "0000011111"
YAML
sudo chmod 600 /etc/netplan/60-charlie-wifi.yaml
sudo netplan apply
sleep 8

echo "######## VERIFY ########"
ip -br addr show wlan0
nmcli -t -f GENERAL.STATE dev show wlan0 2>/dev/null || true
echo -n "gateway ping: "; ping -c1 -W3 192.168.30.1 >/dev/null 2>&1 && echo OK || echo FAIL
echo "If wlan0 shows 192.168.30.250 -> done. You can unplug ethernet."
