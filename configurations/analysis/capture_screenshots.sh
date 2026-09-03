#!/usr/bin/env bash
# Capture the 4 appendix screenshots for the thesis (app:screenshots).
# Run from a host that can reach the testbed VLANs. Needs chromium.
# Grafana needs a logged-in session -> capture that one manually in a browser.
# Output PNGs -> upload to Overleaf images/. Filenames match \IfFileExists in body.tex.
set -euo pipefail

OUT="${1:-.}"                        # output dir (default: cwd)
BROWSER="$(command -v chromium || command -v chromium-browser || command -v google-chrome)"
SHOT() { # url  file
  "$BROWSER" --headless --disable-gpu --no-sandbox --hide-scrollbars \
    --window-size=1600,1000 --virtual-time-budget=8000 \
    --screenshot="$OUT/$2" "$1" && echo "  ok  $2"
}

echo "Capturing to $OUT (chromium: $BROWSER)"
SHOT "http://192.168.20.11/"                     screenshot-esp-webgui.png
SHOT "http://192.168.20.200:8000/dashboard"      screenshot-key-manager.png
SHOT "http://192.168.20.60:1880"                 screenshot-nodered.png
echo "Grafana needs login -> capture http://192.168.20.60:3000 manually (admin/adminpassword123)"
echo "  -> save as screenshot-grafana.png"
# ponytail: chromium one-shot per URL; if a page renders slow, bump --virtual-time-budget.
