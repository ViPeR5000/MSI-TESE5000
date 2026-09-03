#!/usr/bin/env python3
"""
viper-scada-c — Waveshare 2.7" e-Paper SCADA display (Phase Charlie)
Receives AES-128-GCM encrypted telemetry via MQTT from EMQX (same path as ESP32s).
Session key fetched from the Classical Key Management Server — identical flow to bridge_charlie.
Physical buttons: KEY1 (GPIO 5) = all relays ON, KEY2 (GPIO 6) = all relays OFF.
Button press shows a 5-second command notification on the display.
Wire format: Base64( iv[12] | ciphertext | tag[16] )
"""
import os, time, signal, logging, requests, json, base64, threading
import paho.mqtt.client as mqtt
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('epd-scada')

CLASSICAL_SERVER = os.getenv('CLASSICAL_SERVER', 'https://192.168.30.200:8000/monitor')
CLASSICAL_TLS_CERT = os.getenv('CLASSICAL_TLS_CERT_PATH', '/home/pi/tls/server.crt')
_TLS_VERIFY = CLASSICAL_TLS_CERT if os.path.exists(CLASSICAL_TLS_CERT) else False
MQTT_HOST  = '192.168.30.100'
MQTT_PORT  = 1883
CLIENT_ID  = 'scada-epd-display'
REFRESH_S  = 30
KEY_TTL    = 300
NOTIF_S    = 5   # seconds to show button-press notification

FONT_DIR  = '/usr/share/fonts/truetype/dejavu/'
FONT_BOLD = FONT_DIR + 'DejaVuSans-Bold.ttf'
FONT_REG  = FONT_DIR + 'DejaVuSans.ttf'
FONT_MONO = FONT_DIR + 'DejaVuSansMono.ttf'

_keys       = []
_keys_ts    = 0.0
_state      = {'temp': None, 'hum': None, 'relay': None, 'updated': None}
_relay_macs = set()
_lock       = threading.Lock()
_running    = True
_mqtt_client = None
_notif      = None   # {'text': str, 'sub': str, 'until': float}


# ── Key management ─────────────────────────────────────────────────────────────

def _fetch_keys():
    global _keys, _keys_ts
    try:
        r = requests.get(CLASSICAL_SERVER, timeout=5, verify=_TLS_VERIFY)
        r.raise_for_status()
        d = r.json()
        keys = []
        if d.get('active_session_key_b64'):
            keys.append(base64.b64decode(d['active_session_key_b64']))
        for k in reversed(d.get('recent_session_keys_b64', [])):
            kb = base64.b64decode(k)
            if kb not in keys:
                keys.append(kb)
        if keys:
            _keys = keys
            _keys_ts = time.time()
            log.info(f'Classical KMS: {len(keys)} key(s) cached')
        else:
            log.warning('Classical KMS: no active session key yet')
    except Exception as e:
        log.warning(f'Classical KMS fetch error: {e}')


def _ensure_keys(force=False):
    if force or not _keys or (time.time() - _keys_ts) > KEY_TTL:
        _fetch_keys()


def _decrypt_aes_gcm(key: bytes, b64_payload: str):
    try:
        wire = base64.b64decode(b64_payload)
        if len(wire) < 28:               # iv(12) + tag(16) minimum
            return None
        return AESGCM(key).decrypt(wire[:12], wire[12:], None)
    except Exception:
        return None


def _try_decrypt(b64_payload: str):
    _ensure_keys()
    for key in _keys:
        pt = _decrypt_aes_gcm(key, b64_payload)
        if pt is not None:
            return pt
    _fetch_keys()
    for key in _keys:
        pt = _decrypt_aes_gcm(key, b64_payload)
        if pt is not None:
            return pt
    return None


# ── Relay commands ─────────────────────────────────────────────────────────────

def send_relay_cmd_all(cmd: str):
    """AES-GCM-encrypt cmd and publish to every discovered relay. Sets display notification."""
    global _notif
    _ensure_keys()
    if not _keys:
        log.error('no session keys available')
        return
    payload_bytes = json.dumps({'command': cmd}).encode('utf-8')
    iv = os.urandom(12)
    b64 = base64.b64encode(iv + AESGCM(_keys[0]).encrypt(iv, payload_bytes, None)).decode()
    if _relay_macs:
        for mac in _relay_macs:
            topic = f'CHARLIE/{mac}/comando'
            _mqtt_client.publish(topic, b64, qos=1)
            log.info(f'relay cmd AES-GCM-encrypted → {topic}: {cmd}')
    else:
        log.warning('no relay MACs discovered yet — command queued but not sent')

    label = 'RELAY ON' if cmd == 'relay_on' else 'RELAY OFF'
    with _lock:
        _notif = {'text': label, 'sub': 'Command sent', 'until': time.time() + NOTIF_S}


# ── MQTT callbacks ─────────────────────────────────────────────────────────────

def on_connect(client, userdata, connect_flags, reason_code, properties):
    if reason_code == 0:
        client.subscribe('CHARLIE/#', qos=1)
        log.info('MQTT connected — subscribed CHARLIE/#')
    else:
        log.error(f'MQTT connect failed: {reason_code}')


def on_message(client, userdata, msg):
    global _relay_macs
    parts = msg.topic.split('/')
    if len(parts) < 3 or parts[2] == 'comando':
        return
    mac  = parts[1]
    kind = parts[2]
    try:
        pt = _try_decrypt(msg.payload.decode('utf-8').strip())
        if pt is None:
            log.debug(f'AES-GCM decrypt failed {msg.topic}')
            return
        data = json.loads(pt.decode('utf-8'))
        log.info(f'[{msg.topic}] {data}')
        with _lock:
            if 'temp'  in data: _state['temp']  = float(data['temp'])
            if 'hum'   in data: _state['hum']   = float(data['hum'])
            if 'relay' in data:
                _state['relay'] = bool(int(data['relay']))
                _relay_macs.add(mac)
            _state['updated'] = datetime.now()
    except Exception as e:
        log.debug(f'on_message [{msg.topic}]: {e}')


# ── Display builders ───────────────────────────────────────────────────────────

def _fonts():
    try:
        return (ImageFont.truetype(FONT_BOLD, 14),
                ImageFont.truetype(FONT_REG,  11),
                ImageFont.truetype(FONT_BOLD, 22),
                ImageFont.truetype(FONT_MONO,  9),
                ImageFont.truetype(FONT_BOLD, 28))
    except Exception:
        d = ImageFont.load_default()
        return d, d, d, d, d


def build_image(epd_width, epd_height, temp, hum, relay, updated):
    W, H = epd_height, epd_width
    img  = Image.new('1', (W, H), 255)
    draw = ImageDraw.Draw(img)
    f_title, f_label, f_value, f_small, _ = _fonts()

    draw.rectangle([0, 0, W, 22], fill=0)
    draw.text((4, 4),      'MSI-TESE  CHARLIE', font=f_title, fill=255)
    draw.text((W - 28, 5), 'ECC',               font=f_small, fill=255)

    y = 28
    draw.text((4, y),      'Temperature',  font=f_label, fill=0)
    draw.text((4, y + 13), f'{temp:.1f} C' if temp is not None else '--.- C', font=f_value, fill=0)
    y += 42
    draw.text((4, y),      'Humidity',     font=f_label, fill=0)
    draw.text((4, y + 13), f'{hum:.1f} %'  if hum  is not None else '--.- %', font=f_value, fill=0)
    y += 42
    draw.line([(4, y), (W - 4, y)], fill=0, width=1)
    y += 4
    draw.text((4, y), 'Relay', font=f_label, fill=0)
    draw.text((60, y), ('ON' if relay else 'OFF') if relay is not None else 'N/A', font=f_value, fill=0)
    y += 30
    draw.text((4, y), 'ECDH-P384 + AES-128-GCM', font=f_small, fill=0)
    ts = updated.strftime('%H:%M:%S  %d/%m') if updated else '--:--'
    draw.text((4, H - 14),      ts,       font=f_small, fill=0)
    draw.text((W - 50, H - 14), 'v2.0-C', font=f_small, fill=0)
    return img


def build_notif_image(epd_width, epd_height, text, sub):
    """Full-screen notification: large command text centred, sub-label below."""
    W, H = epd_height, epd_width
    img  = Image.new('1', (W, H), 255)
    draw = ImageDraw.Draw(img)
    f_title, f_label, _, f_small, f_big = _fonts()

    # Header bar
    draw.rectangle([0, 0, W, 22], fill=0)
    draw.text((4, 4),      'MSI-TESE  CHARLIE', font=f_title, fill=255)
    draw.text((W - 28, 5), 'ECC',               font=f_small, fill=255)

    # Border around the notification area
    draw.rectangle([4, 26, W - 4, H - 4], outline=0, width=2)

    # Large command text centred vertically in the notification area
    try:
        bbox = draw.textbbox((0, 0), text, font=f_big)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    except AttributeError:
        tw, th = f_big.getsize(text)
    cx = (W - tw) // 2
    cy = 26 + ((H - 26 - th) // 2) - 12
    draw.text((cx, cy), text, font=f_big, fill=0)

    # Sub-label centred below
    try:
        sbbox = draw.textbbox((0, 0), sub, font=f_label)
        sw = sbbox[2] - sbbox[0]
    except AttributeError:
        sw, _ = f_label.getsize(sub)
    draw.text(((W - sw) // 2, cy + th + 8), sub, font=f_label, fill=0)

    return img


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    global _running, _mqtt_client

    epd, hw_epd = None, False
    for drv in ('epd2in7_V2', 'epd2in7'):
        try:
            import importlib
            mod = importlib.import_module(f'waveshare_epd.{drv}')
            epd = mod.EPD()
            epd.init()
            try:
                epd.Clear(0xFF)        # epd2in7 (V1) signature
            except TypeError:
                epd.Clear()            # epd2in7_V2 signature
            log.info(f'EPD init OK ({drv})  {epd.width}x{epd.height}')
            hw_epd = True
            break
        except ImportError:
            log.warning('waveshare_epd not installed — headless mode')
            break
        except Exception as e:
            log.warning(f'EPD driver {drv} failed: {e}')
    if not hw_epd:
        class FakeEPD:
            width, height = 176, 264
        epd = FakeEPD()

    # Physical buttons: KEY1 (GPIO 5) = all ON, KEY2 (GPIO 6) = all OFF
    try:
        from gpiozero import Button
        btn_on  = Button(5, pull_up=True, bounce_time=0.1)
        btn_off = Button(6, pull_up=True, bounce_time=0.1)
        btn_on.when_pressed  = lambda: send_relay_cmd_all('relay_on')
        btn_off.when_pressed = lambda: send_relay_cmd_all('relay_off')
        log.info('GPIO buttons active: KEY1=ALL ON  KEY2=ALL OFF')
    except Exception as e:
        log.warning(f'GPIO buttons not available: {e}')

    _fetch_keys()

    _mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, CLIENT_ID)
    _mqtt_client.on_connect = on_connect
    _mqtt_client.on_message = on_message
    try:
        _mqtt_client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
        _mqtt_client.loop_start()
    except Exception as e:
        log.error(f'MQTT connect failed: {e}')

    def _stop(sig, frame):
        global _running
        _running = False
    signal.signal(signal.SIGINT,  _stop)
    signal.signal(signal.SIGTERM, _stop)

    last_display  = 0.0
    notif_showing = False

    while _running:
        now = time.time()

        with _lock:
            notif = _notif
            snap  = dict(_state)

        if notif and now < notif['until']:
            # Show notification immediately on first tick, stay until expiry
            if not notif_showing:
                img = build_notif_image(epd.width, epd.height, notif['text'], notif['sub'])
                log.info(f'notif: {notif["text"]}')
                if hw_epd:
                    img = img.rotate(90, expand=True)
                    epd.display(epd.getbuffer(img))
                notif_showing = True
        else:
            # Notification expired or none — show telemetry when due
            if notif_showing or (now - last_display >= REFRESH_S):
                img = build_image(epd.width, epd.height,
                                  snap['temp'], snap['hum'], snap['relay'], snap['updated'])
                log.info(f'display: temp={snap["temp"]} hum={snap["hum"]} relay={snap["relay"]}')
                if hw_epd:
                    img = img.rotate(90, expand=True)
                    epd.display(epd.getbuffer(img))
                notif_showing = False
                last_display  = now

        time.sleep(1)

    _mqtt_client.loop_stop()
    _mqtt_client.disconnect()
    if hw_epd:
        try:
            epd.sleep()
        except Exception:
            pass
    log.info('epd-scada stopped')


if __name__ == '__main__':
    main()
