#!/usr/bin/env bash
# Kiosk mode for viper-suricata-a: console autologin + fullscreen Grafana on the
# Waveshare 4.3" DSI LCD, auto-rotating through the three VLAN dashboards.
# X11 + openbox + chromium kiosk (works on Lite, no desktop needed).
# Run ON the Pi:  sudo bash setup-kiosk.sh
# ponytail: rotate via a local HTML iframe timer, not xdotool keystroke hacks.
#
# NOTE: rotation uses an <iframe>, so the Grafana host (192.168.100.60) needs
#   [security] allow_embedding = true   AND   [auth.anonymous] enabled = true (Viewer)
# in grafana.ini (or GF_SECURITY_ALLOW_EMBEDDING=true + GF_AUTH_ANONYMOUS_* in Docker).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }

KIOSK_USER="${SUDO_USER:-pi}"
HOME_DIR="$(getent passwd "$KIOSK_USER" | cut -d: -f6)"
ROTATE_SECS=30                       # seconds per VLAN
VLANS='["100","20","30"]'            # rotation order
BASE='http://192.168.100.60:3000/d/suricata-vlan/msi-tese-c2b7-suricata-by-vlan?orgId=1&from=now-6h&to=now&timezone=browser&var-DS=dfri19baoc0zke&refresh=30&kiosk'

# 1. Minimal X + window manager + chromium + cursor hider
apt-get update
apt-get install -y --no-install-recommends xserver-xorg xinit x11-xserver-utils openbox unclutter
apt-get install -y chromium-browser 2>/dev/null || apt-get install -y chromium
CHROMIUM="$(command -v chromium-browser || command -v chromium)"

# 2. Boot to console with tty1 autologin, and stop any graphical login manager
#    (a display manager such as lightdm grabs the screen before startx runs).
raspi-config nonint do_boot_behaviour B2 2>/dev/null || true
systemctl set-default multi-user.target
systemctl disable lightdm 2>/dev/null || true
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat >/etc/systemd/system/getty@tty1.service.d/autologin.conf <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin ${KIOSK_USER} --noclear %I \$TERM
EOF
systemctl daemon-reload

# 3. Local rotating page: iframe cycles var-vlan every ROTATE_SECS
cat >"$HOME_DIR/kiosk.html" <<EOF
<!doctype html><html><head><meta charset="utf-8">
<style>html,body,iframe{margin:0;padding:0;border:0;width:100%;height:100%;overflow:hidden}</style></head>
<body><iframe id="f" allowfullscreen></iframe><script>
const base=${BASE@Q}, vlans=${VLANS}, every=${ROTATE_SECS}*1000;
let i=0; const f=document.getElementById('f');
function show(){f.src=base+'&var-vlan='+vlans[i];i=(i+1)%vlans.length;}
show(); setInterval(show, every);
</script></body></html>
EOF

# 4. Openbox autostart -> chromium kiosk on the local page
install -d -o "$KIOSK_USER" -g "$KIOSK_USER" "$HOME_DIR/.config/openbox"
cat >"$HOME_DIR/.config/openbox/autostart" <<EOF
xset s off; xset -dpms; xset s noblank
unclutter -idle 0.1 &
PREF="\$HOME/.config/chromium/Default/Preferences"
[ -f "\$PREF" ] && sed -i 's/"exit_type":"[^"]*"/"exit_type":"Normal"/; s/"exited_cleanly":false/"exited_cleanly":true/' "\$PREF" || true
$CHROMIUM --kiosk --noerrdialogs --disable-infobars --disable-session-crashed-bubble \\
  --disable-features=Translate --check-for-update-interval=31536000 \\
  --app="file://$HOME_DIR/kiosk.html" &
EOF

# 5. Start X on tty1 login only
echo "exec openbox-session" > "$HOME_DIR/.xinitrc"
grep -q 'startx' "$HOME_DIR/.bash_profile" 2>/dev/null || cat >>"$HOME_DIR/.bash_profile" <<'EOF'

# kiosk: start X on tty1
if [ "$(tty)" = "/dev/tty1" ] && [ -z "${DISPLAY:-}" ]; then exec startx -- -nocursor; fi
EOF
chown -R "$KIOSK_USER:$KIOSK_USER" "$HOME_DIR/.config" "$HOME_DIR/.xinitrc" "$HOME_DIR/.bash_profile" "$HOME_DIR/kiosk.html"

echo "Kiosk configured for '$KIOSK_USER' (rotating VLANs ${VLANS} every ${ROTATE_SECS}s)."
echo "Reboot to start:  sudo reboot"
