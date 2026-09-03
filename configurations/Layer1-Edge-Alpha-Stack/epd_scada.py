#!/usr/bin/env python3
"""
viper-scada-a — Waveshare 2.7" e-Paper SCADA display (Alpha phase)
Receives plaintext telemetry via MQTT from EMQX (no encryption).
Physical buttons: KEY1 (GPIO 5) = relay ON, KEY2 (GPIO 6) = relay OFF.
"""
import time, signal, logging, json, threading
import paho.mqtt.client as mqtt
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('epd-scada')

MQTT_HOST = '192.168.100.100'
MQTT_PORT = 1883
CLIENT_ID = 'scada-epd-display-alpha'
REFRESH_S = 30
NOTIF_S   = 5

FONT_DIR  = '/usr/share/fonts/truetype/dejavu/'
FONT_BOLD = FONT_DIR + 'DejaVuSans-Bold.ttf'
FONT_REG  = FONT_DIR + 'DejaVuSans.ttf'
FONT_MONO = FONT_DIR + 'DejaVuSansMono.ttf'

_state       = {'temp': None, 'hum': None, 'relay': None, 'updated': None}
_relay_macs  = set()
_lock        = threading.Lock()
_running     = True
_mqtt_client = None
_notif       = None


# ── Relay commands ─────────────────────────────────────────────────────────────

def send_relay_cmd_all(cmd: str):
    global _notif
    payload = json.dumps({'command': cmd})
    if _relay_macs:
        for mac in _relay_macs:
            topic = f'ALPHA/{mac}/comando'
            _mqtt_client.publish(topic, payload, qos=1)
            log.info(f'relay cmd → {topic}: {cmd}')
    else:
        log.warning('no relay MACs discovered yet')

    label = 'RELAY ON' if cmd == 'relay_on' else 'RELAY OFF'
    with _lock:
        _notif = {'text': label, 'sub': 'Command sent', 'until': time.time() + NOTIF_S}


# ── MQTT callbacks ─────────────────────────────────────────────────────────────

def on_connect(client, userdata, connect_flags, reason_code, properties):
    if reason_code == 0:
        client.subscribe('ALPHA/#', qos=0)
        log.info('MQTT connected — subscribed ALPHA/#')
    else:
        log.error(f'MQTT connect failed: {reason_code}')


def on_message(client, userdata, msg):
    parts = msg.topic.split('/')
    if len(parts) < 3 or parts[2] == 'comando':
        return
    mac  = parts[1]
    kind = parts[2]
    try:
        data = json.loads(msg.payload.decode('utf-8'))
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
    draw.text((4, 4),      'MSI-TESE  ALPHA',  font=f_title, fill=255)
    draw.text((W - 40, 5), 'PLAIN',             font=f_small, fill=255)

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
    draw.text((4, y), 'No Crypto — Baseline', font=f_small, fill=0)
    ts = updated.strftime('%H:%M:%S  %d/%m') if updated else '--:--'
    draw.text((4, H - 14),      ts,       font=f_small, fill=0)
    draw.text((W - 50, H - 14), 'v1.0-A', font=f_small, fill=0)
    return img


def build_notif_image(epd_width, epd_height, text, sub):
    W, H = epd_height, epd_width
    img  = Image.new('1', (W, H), 255)
    draw = ImageDraw.Draw(img)
    f_title, f_label, _, f_small, f_big = _fonts()

    draw.rectangle([0, 0, W, 22], fill=0)
    draw.text((4, 4),      'MSI-TESE  ALPHA', font=f_title, fill=255)
    draw.text((W - 40, 5), 'PLAIN',            font=f_small, fill=255)

    draw.rectangle([4, 26, W - 4, H - 4], outline=0, width=2)

    try:
        bbox = draw.textbbox((0, 0), text, font=f_big)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    except AttributeError:
        tw, th = f_big.getsize(text)
    cx = (W - tw) // 2
    cy = 26 + ((H - 26 - th) // 2) - 12
    draw.text((cx, cy), text, font=f_big, fill=0)

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

    try:
        from waveshare_epd import epd2in7_V2
        epd = epd2in7_V2.EPD()
        epd.init()
        epd.Clear()
        log.info(f'EPD init OK  {epd.width}x{epd.height}')
        hw_epd = True
    except ImportError:
        log.warning('waveshare_epd not installed — headless mode')
        hw_epd = False
        class FakeEPD:
            width, height = 176, 264
        epd = FakeEPD()
    except Exception as e:
        log.error(f'EPD init failed: {e}')
        hw_epd = False
        class FakeEPD:
            width, height = 176, 264
        epd = FakeEPD()

    try:
        from gpiozero import Button
        btn_on  = Button(5, pull_up=True, bounce_time=0.1)
        btn_off = Button(6, pull_up=True, bounce_time=0.1)
        btn_on.when_pressed  = lambda: send_relay_cmd_all('relay_on')
        btn_off.when_pressed = lambda: send_relay_cmd_all('relay_off')
        log.info('GPIO buttons active: KEY1=ON  KEY2=OFF')
    except Exception as e:
        log.warning(f'GPIO buttons not available: {e}')

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
            if not notif_showing:
                img = build_notif_image(epd.width, epd.height, notif['text'], notif['sub'])
                log.info(f'notif: {notif["text"]}')
                if hw_epd:
                    img = img.rotate(90, expand=True)
                    epd.display(epd.getbuffer(img))
                notif_showing = True
        else:
            if notif_showing or (now - last_display >= REFRESH_S):
                img = build_image(epd.width, epd.height,
                                  snap['temp'], snap['hum'], snap['relay'], snap['updated'])
                log.info(f'display: temp={snap["temp"]} hum={snap["hum"]}')
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
